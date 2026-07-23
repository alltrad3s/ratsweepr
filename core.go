package main

import (
	"bufio"
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "embed"
)

const appVersion = "3.9.2"

//go:embed patterns_default.conf
var defaultPatterns string

//go:embed ratsweepr.yar
var defaultYaraRules string

// Finding severities.
const (
	SevHigh = "HIGH"
	SevMed  = "MED"
	SevInfo = "INFO"
	SevWarn = "WARN"
)

type Finding struct {
	Sev    string
	Cat    string
	Item   string
	Detail string
}

// Env holds everything about the site + tool home.
type Env struct {
	WPRoot     string
	WPVersion  string
	Home       string // ~/.ratsweepr
	SigDir     string
	Quarantine string
	Baselines  string
	Cache      string
	RunStamp   string
	ReportPath string

	RfxnURL    string
	PatternURL string
	PubKeyPath string
	WPScanTok  string
}

type sigPattern struct {
	Name string
	Rex  *regexp.Regexp
}

type CoreVuln struct{ Label, Min, Max, Fixed, Note, Disclosed string }

type Signatures struct {
	Greps     []sigPattern
	GrepsHigh []sigPattern
	FNames    []struct{ Name, Glob string }
	Domains   []struct{ Name, Domain string }
	Options    []string
	AllowHosts []string
	AllowPaths []struct{ Prefix, URL string }
	CoreVulns  []CoreVuln
	HDB       map[string]string // md5 -> signature name
}

var versionRe = regexp.MustCompile(`\$wp_version\s*=\s*['"]([0-9.]+)['"]`)

func DetectEnv() (*Env, error) {
	if os.Geteuid() == 0 && os.Getenv("RS_ALLOW_ROOT") != "1" {
		return nil, fmt.Errorf("refusing to run as root; run as the site user (RS_ALLOW_ROOT=1 to override)")
	}
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(wd, "wp-config.php")); err != nil {
		return nil, fmt.Errorf("no wp-config.php here — cd into the WordPress root first")
	}
	vb, err := os.ReadFile(filepath.Join(wd, "wp-includes", "version.php"))
	if err != nil {
		return nil, fmt.Errorf("wp-includes/version.php missing — not a WordPress root?")
	}
	m := versionRe.FindSubmatch(vb)
	if m == nil {
		return nil, fmt.Errorf("could not determine WordPress version")
	}
	home := os.Getenv("RS_HOME")
	if home == "" {
		uh, _ := os.UserHomeDir()
		home = filepath.Join(uh, ".ratsweepr")
	}
	e := &Env{
		WPRoot:    wd,
		WPVersion: string(m[1]),
		Home:      home,
		RunStamp:  time.Now().Format("2006-01-02_150405"),
	}
	e.SigDir = filepath.Join(home, "signatures")
	e.Quarantine = filepath.Join(home, "quarantine")
	e.Baselines = filepath.Join(home, "baselines")
	e.Cache = filepath.Join(home, "cache")
	for _, d := range []string{e.SigDir, e.Quarantine, e.Baselines, e.Cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	e.ReportPath = filepath.Join(wd, "ratsweepr-"+e.RunStamp+".report")
	e.RfxnURL = envOr("RS_RFXN_URL", "https://www.rfxn.com/downloads/rfxn.hdb")
	e.PatternURL = os.Getenv("RS_PATTERN_URL")
	e.PubKeyPath = filepath.Join(home, "ratsweepr-pub.pem")
	e.WPScanTok = os.Getenv("WPSCAN_API_TOKEN")
	return e, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var httpClient = &http.Client{Timeout: 60 * time.Second}

func fetch(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}

// ---------------------------- signatures -------------------------------------

func (e *Env) patternsPath() string { return filepath.Join(e.SigDir, "patterns.conf") }
func (e *Env) hdbPath() string      { return filepath.Join(e.SigDir, "rfxn.hdb") }

func (e *Env) ensurePatterns() {
	if _, err := os.Stat(e.patternsPath()); err != nil {
		_ = os.WriteFile(e.patternsPath(), []byte(defaultPatterns), 0o600)
	}
}

// UpdateSignatures refreshes rfxn.hdb and (optionally) the signed pattern file.
// Returns human-readable progress lines.
func (e *Env) UpdateSignatures() []string {
	var out []string
	if b, err := fetch(e.RfxnURL); err == nil && looksLikeHDB(b) {
		_ = os.WriteFile(e.hdbPath(), b, 0o600)
		out = append(out, fmt.Sprintf("rfxn.hdb updated: %d MD5 signatures", countLines(b)))
	} else {
		out = append(out, "could not fetch/validate rfxn.hdb — keeping existing copy")
	}
	if e.PatternURL != "" {
		pb, err := fetch(e.PatternURL)
		if err != nil || len(pb) == 0 {
			out = append(out, "could not fetch pattern file: "+errStr(err))
		} else if pub, perr := loadRSAPub(e.PubKeyPath); perr == nil {
			sb, serr := fetch(e.PatternURL + ".sig")
			if serr == nil && verifyRSA(pub, pb, sb) {
				_ = os.WriteFile(e.patternsPath(), pb, 0o600)
				out = append(out, "pattern file updated (RSA signature VERIFIED)")
			} else {
				out = append(out, "pattern file signature FAILED verification — rejected")
			}
		} else {
			_ = os.WriteFile(e.patternsPath(), pb, 0o600)
			out = append(out, "pattern file updated UNVERIFIED (no public key at "+e.PubKeyPath+")")
		}
	}
	e.ensurePatterns()
	return out
}

func looksLikeHDB(b []byte) bool {
	i := 0
	for i < len(b) && i < 33 {
		c := b[i]
		if i == 32 {
			return c == ':'
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
		i++
	}
	return false
}

func countLines(b []byte) int { return strings.Count(string(b), "\n") }
func errStr(e error) string {
	if e == nil {
		return "empty response"
	}
	return e.Error()
}

func loadRSAPub(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rpub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA key")
	}
	return rpub, nil
}

// verifyRSA matches `openssl dgst -sha256 -sign` output (PKCS1v15).
func verifyRSA(pub *rsa.PublicKey, data, sig []byte) bool {
	h := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil
}

func (e *Env) LoadSignatures() (*Signatures, error) {
	e.ensurePatterns()
	s := &Signatures{HDB: map[string]string{}}
	f, err := os.Open(e.patternsPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			continue
		}
		if parts[0] == "CORE_VULN" {
			f := strings.Split(line, "|")
			if len(f) >= 6 {
				disc := ""
				if len(f) >= 7 {
					disc = f[6]
				}
				s.CoreVulns = append(s.CoreVulns, CoreVuln{f[1], f[2], f[3], f[4], f[5], disc})
			}
			continue
		}
		switch parts[0] {
		case "GREP":
			if len(parts) == 3 {
				if re, err := regexp.CompilePOSIX(parts[2]); err == nil {
					s.Greps = append(s.Greps, sigPattern{parts[1], re})
				}
			}
		case "GREPHIGH":
			if len(parts) == 3 {
				if re, err := regexp.CompilePOSIX(parts[2]); err == nil {
					s.GrepsHigh = append(s.GrepsHigh, sigPattern{parts[1], re})
				}
			}
		case "FNAME":
			if len(parts) == 3 {
				s.FNames = append(s.FNames, struct{ Name, Glob string }{parts[1], parts[2]})
			}
		case "DOMAIN":
			if len(parts) == 3 {
				s.Domains = append(s.Domains, struct{ Name, Domain string }{parts[1], parts[2]})
			}
		case "OPTION":
			s.Options = append(s.Options, parts[1])
		case "ALLOWHOST":
			s.AllowHosts = append(s.AllowHosts, parts[1])
		case "ALLOWPATH":
			f := strings.Split(line, "|")
			url := ""
			if len(f) >= 3 {
				url = f[2]
			}
			if len(f) >= 2 {
				s.AllowPaths = append(s.AllowPaths, struct{ Prefix, URL string }{f[1], url})
			}
		}
	}
	if b, err := os.ReadFile(e.hdbPath()); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			p := strings.SplitN(ln, ":", 3)
			if len(p) == 3 && len(p[0]) == 32 {
				s.HDB[p[0]] = p[2]
			}
		}
	}
	return s, nil
}

// ---------------------------- file helpers -----------------------------------

func md5File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "-"
	}
	defer f.Close()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

// phpishFiles walks the webroot collecting php-like files (the only ones the
// heuristic/hash scanners look at), skipping the cache dir.
func (e *Env) phpishFiles() []string {
	var out []string
	skip := filepath.Join(e.WPRoot, "wp-content", "cache")
	_ = filepath.WalkDir(e.WPRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p == skip {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		switch {
		case strings.HasSuffix(name, ".php"),
			strings.HasSuffix(name, ".phtml"),
			strings.HasSuffix(name, ".php5"), strings.HasSuffix(name, ".php7"),
			strings.HasSuffix(name, ".suspected"),
			strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".ico"):
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func (e *Env) rel(p string) string {
	r, err := filepath.Rel(e.WPRoot, p)
	if err != nil {
		return p
	}
	return r
}
