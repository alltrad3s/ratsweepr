package main

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ------------------------------ quarantine ------------------------------------

// QuarantinablePaths extracts HIGH/MED file paths from a report.
func QuarantinablePaths(e *Env, reportPath string) ([]string, error) {
	f, err := os.Open(reportPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "\t", 4)
		if len(p) < 3 || (p[0] != SevHigh && p[0] != SevMed) {
			continue
		}
		item := p[2]
		if item == "-" || strings.HasPrefix(item, "post:") ||
			strings.HasPrefix(item, "option:") || strings.HasPrefix(item, "user:") {
			continue
		}
		full := filepath.Join(e.WPRoot, filepath.FromSlash(item))
		if fi, serr := os.Stat(full); serr != nil || fi.IsDir() {
			continue
		}
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out, nil
}

// QuarantineFiles moves paths (relative to webroot) into a manifest-tracked batch.
func QuarantineFiles(e *Env, rels []string) (batch string, moved int, err error) {
	batch = e.RunStamp
	dir := filepath.Join(e.Quarantine, batch)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	mf, err := os.OpenFile(filepath.Join(dir, "MANIFEST.tsv"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer mf.Close()
	if st, _ := mf.Stat(); st.Size() == 0 {
		fmt.Fprintln(mf, "sha256\toriginal_path\tquarantined_at")
	}
	for _, rel := range rels {
		src := filepath.Join(e.WPRoot, filepath.FromSlash(rel))
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if merr := os.MkdirAll(filepath.Dir(dst), 0o700); merr != nil {
			continue
		}
		sum := sha256File(src)
		if merr := os.Rename(src, dst); merr != nil {
			// cross-device fallback: copy+remove
			if cerr := copyFile(src, dst); cerr != nil {
				continue
			}
			_ = os.Remove(src)
		}
		_ = os.Chmod(dst, 0)
		fmt.Fprintf(mf, "%s\t%s\t%s\n", sum, rel, time.Now().Format(time.RFC3339))
		moved++
	}
	return
}

func RestoreBatch(e *Env, batch string) (int, error) {
	dir := filepath.Join(e.Quarantine, batch)
	f, err := os.Open(filepath.Join(dir, "MANIFEST.tsv"))
	if err != nil {
		return 0, fmt.Errorf("no quarantine batch named %q", batch)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "\t", 3)
		if len(p) < 2 || p[0] == "sha256" {
			continue
		}
		rel := p[1]
		src := filepath.Join(dir, filepath.FromSlash(rel))
		dst := filepath.Join(e.WPRoot, filepath.FromSlash(rel))
		if _, serr := os.Stat(src); serr != nil {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(dst), 0o755)
		_ = os.Chmod(src, 0o644)
		if rerr := os.Rename(src, dst); rerr != nil {
			if cerr := copyFile(src, dst); cerr != nil {
				continue
			}
			_ = os.Remove(src)
		}
		n++
	}
	return n, nil
}

func ListBatches(e *Env) []string {
	ents, _ := os.ReadDir(e.Quarantine)
	var out []string
	for _, en := range ents {
		if en.IsDir() {
			out = append(out, en.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ------------------------------ clean core ------------------------------------

// FailingCoreFiles returns core files (outside wp-content) that fail checksums.
func FailingCoreFiles(e *Env, s *Scanner) ([]string, error) {
	man, err := s.coreManifest()
	if err != nil {
		return nil, err
	}
	var out []string
	for rel, want := range man {
		if strings.HasPrefix(rel, "wp-content/") {
			continue
		}
		got, ferr := md5File(filepath.Join(e.WPRoot, rel))
		if ferr != nil || got != want {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out, nil
}

// CleanCore quarantines the current copies then writes clean ones from the
// official release zip. Only the listed files are touched.
func CleanCore(e *Env, failing []string, progress func(string)) (int, error) {
	progress("Downloading wordpress-" + e.WPVersion + ".zip")
	zb, err := fetch("https://wordpress.org/wordpress-" + e.WPVersion + ".zip")
	if err != nil {
		return 0, err
	}
	zr, err := zip.NewReader(strings.NewReader(string(zb)), int64(len(zb)))
	if err != nil {
		return 0, err
	}
	inZip := map[string]*zip.File{}
	for _, zf := range zr.File {
		inZip[strings.TrimPrefix(zf.Name, "wordpress/")] = zf
	}
	batchDir := filepath.Join(e.Quarantine, e.RunStamp+"-core")
	_ = os.MkdirAll(batchDir, 0o700)
	mf, _ := os.OpenFile(filepath.Join(batchDir, "MANIFEST.tsv"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	defer mf.Close()
	fmt.Fprintln(mf, "sha256\toriginal_path\tquarantined_at")

	replaced := 0
	for _, rel := range failing {
		zf, ok := inZip[rel]
		if !ok {
			progress("  no clean copy for " + rel + " in release zip, skipping")
			continue
		}
		dst := filepath.Join(e.WPRoot, filepath.FromSlash(rel))
		if _, serr := os.Stat(dst); serr == nil { // quarantine the old copy first
			q := filepath.Join(batchDir, filepath.FromSlash(rel))
			_ = os.MkdirAll(filepath.Dir(q), 0o700)
			fmt.Fprintf(mf, "%s\t%s\t%s\n", sha256File(dst), rel, time.Now().Format(time.RFC3339))
			_ = os.Rename(dst, q)
		}
		rc, oerr := zf.Open()
		if oerr != nil {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(dst), 0o755)
		out, oerr := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if oerr != nil {
			rc.Close()
			continue
		}
		_, _ = io.Copy(out, rc)
		out.Close()
		rc.Close()
		replaced++
		progress("  replaced " + rel)
	}
	return replaced, nil
}

// ------------------------------ salts -----------------------------------------

var saltDefineRe = regexp.MustCompile(
	`define\(\s*.\s*(AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)`)

// ShuffleSalts rotates the 8 auth keys via api.wordpress.org, keeping a backup
// of the previous wp-config.php.
func ShuffleSalts(e *Env) (backupPath string, err error) {
	salts, err := fetch("https://api.wordpress.org/secret-key/1.1/salt/")
	if err != nil {
		return "", err
	}
	if !strings.Contains(string(salts), "AUTH_KEY") {
		return "", fmt.Errorf("salt API returned unexpected data")
	}
	cfg := filepath.Join(e.WPRoot, "wp-config.php")
	orig, err := os.ReadFile(cfg)
	if err != nil {
		return "", err
	}
	backupPath = cfg + ".rs-backup-" + e.RunStamp
	if err = os.WriteFile(backupPath, orig, 0o600); err != nil {
		return "", err
	}
	var b strings.Builder
	printed := false
	for _, line := range strings.SplitAfter(string(orig), "\n") {
		if saltDefineRe.MatchString(line) {
			if !printed {
				b.Write(salts)
				if !strings.HasSuffix(string(salts), "\n") {
					b.WriteString("\n")
				}
				printed = true
			}
			continue
		}
		b.WriteString(line)
	}
	if !printed {
		return "", fmt.Errorf("no salt defines found in wp-config.php; file untouched")
	}
	if err = os.WriteFile(cfg, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return backupPath, nil
}

// ------------------------------ baselines -------------------------------------

func BaselineGenerate(e *Env, progress func(string)) (int, error) {
	n := 0
	for _, kind := range []string{"plugins", "themes"} {
		root := filepath.Join(e.WPRoot, "wp-content", kind)
		ents, _ := os.ReadDir(root)
		for _, en := range ents {
			if !en.IsDir() {
				continue
			}
			dir := filepath.Join(root, en.Name())
			out, err := os.Create(filepath.Join(e.Baselines, kind+"-"+en.Name()+".md5"))
			if err != nil {
				return n, err
			}
			cnt := 0
			_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				h, herr := md5File(p)
				if herr != nil {
					return nil
				}
				rel, _ := filepath.Rel(dir, p)
				fmt.Fprintf(out, "%s  %s\n", h, filepath.ToSlash(rel))
				cnt++
				return nil
			})
			out.Close()
			progress(fmt.Sprintf("baseline: %s/%s (%d files)", kind, en.Name(), cnt))
			n++
		}
	}
	return n, nil
}

func BaselineVerify(e *Env, s *Scanner) {
	for _, kind := range []string{"plugins", "themes"} {
		root := filepath.Join(e.WPRoot, "wp-content", kind)
		ents, _ := os.ReadDir(root)
		for _, en := range ents {
			if !en.IsDir() {
				continue
			}
			base := filepath.Join(e.Baselines, kind+"-"+en.Name()+".md5")
			bf, err := os.Open(base)
			if err != nil {
				continue
			}
			dir := filepath.Join(root, en.Name())
			known := map[string]bool{}
			sc := bufio.NewScanner(bf)
			for sc.Scan() {
				line := sc.Text()
				if len(line) < 35 {
					continue
				}
				want, rel := line[:32], line[34:]
				known[rel] = true
				got, ferr := md5File(filepath.Join(dir, filepath.FromSlash(rel)))
				prefix := "wp-content/" + kind + "/" + en.Name() + "/" + rel
				switch {
				case ferr != nil:
					s.add(SevMed, "baseline-missing", prefix, "file present in baseline but missing")
				case got != want:
					s.add(SevHigh, "baseline-modified", prefix, "differs from your clean baseline — diff it!")
				}
			}
			bf.Close()
			_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(dir, p)
				if !known[filepath.ToSlash(rel)] {
					s.add(SevMed, "baseline-unknown-file",
						"wp-content/"+kind+"/"+en.Name()+"/"+filepath.ToSlash(rel),
						"file not present in your clean baseline")
				}
				return nil
			})
		}
	}
	s.WriteReport()
}
