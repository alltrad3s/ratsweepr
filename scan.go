package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// Scanner runs all read-only checks. Progress lines go to progress(), findings
// are accumulated and also streamed via found().
type Scanner struct {
	Env      *Env
	Sigs     *Signatures
	Since    string // optional YYYY-MM-DD forensics window for the DB scan
	progress func(string)
	found    func(Finding)
	Findings []Finding
	verified map[string]bool // files byte-identical to official releases
}

func NewScanner(e *Env, sigs *Signatures, progress func(string), found func(Finding)) *Scanner {
	if progress == nil {
		progress = func(string) {}
	}
	s := &Scanner{Env: e, Sigs: sigs, progress: progress, verified: map[string]bool{}}
	s.found = func(f Finding) {
		s.Findings = append(s.Findings, f)
		if found != nil {
			found(f)
		}
	}
	return s
}

func (s *Scanner) add(sev, cat, item, detail string) {
	s.found(Finding{sev, cat, item, detail})
}

func verLE(a, b string) bool {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return true // equal
}

var batchRe = regexp.MustCompile(`(?i)batch-route|wp2shell|63030`)

func (s *Scanner) ScanCoreVulns() {
	s.progress("Checking WordPress " + s.Env.WPVersion + " against known core vulnerabilities")
	v := s.Env.WPVersion
	for _, cv := range s.Sigs.CoreVulns {
		if verLE(cv.Min, v) && verLE(v, cv.Max) {
			detail := cv.Label + " — fixed in " + cv.Fixed + ". " + cv.Note
			if batchRe.MatchString(cv.Label) {
				detail += "\n  UPGRADE: wp core update  (real fix)\n" +
					"  STOPGAP if you cannot upgrade — block BOTH endpoint forms at the server/WAF:\n" +
					"    Apache (.htaccess, before WP rules):\n" +
					"      RewriteRule ^wp-json/batch/v1 - [F,L]\n" +
					"      RewriteCond %{QUERY_STRING} (^|&)rest_route=/?batch/v1 [NC]\n" +
					"      RewriteRule .* - [F,L]\n" +
					"    Nginx:\n" +
					"      location ~* ^/wp-json/batch/v1 { return 403; }\n" +
					"      if ($args ~* \"(^|&)rest_route=/?batch/v1\") { return 403; }"
			} else {
				detail += "\n  UPGRADE: wp core update"
			}
			s.add(SevHigh, "core-vulnerable", "WordPress "+v, detail)
		}
	}
}

func (s *Scanner) RunAll() {
	files := s.Env.phpishFiles()
	s.ScanCoreVulns()
	s.ScanCoreChecksums()
	s.ScanPluginChecksums()
	s.ScanUploadsPHP()
	s.ScanHashDB(files)
	s.ScanHeuristics(files)
	s.ScanNulled(files)
	s.ScanExternalRequests(files)
	s.ScanHtaccess()
	s.ScanDatabase()
	s.ScanVulnerabilities()
	s.WriteReport()
}

func (s *Scanner) WriteReport() {
	var b strings.Builder
	for _, f := range s.Findings {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", f.Sev, f.Cat, f.Item, f.Detail)
	}
	_ = os.WriteFile(s.Env.ReportPath, []byte(b.String()), 0o600)
}

// ------------------------- core checksum scan --------------------------------

type coreChecksumResp struct {
	Checksums map[string]string `json:"checksums"`
}

func (s *Scanner) coreManifest() (map[string]string, error) {
	cachef := filepath.Join(s.Env.Cache, "core-"+s.Env.WPVersion+".json")
	b, err := os.ReadFile(cachef)
	if err != nil {
		b, err = fetch("https://api.wordpress.org/core/checksums/1.0/?version=" +
			url.QueryEscape(s.Env.WPVersion) + "&locale=en_US")
		if err != nil {
			return nil, err
		}
		_ = os.WriteFile(cachef, b, 0o600)
	}
	var r coreChecksumResp
	if err := json.Unmarshal(b, &r); err != nil || len(r.Checksums) == 0 {
		return nil, fmt.Errorf("no checksum data for %s", s.Env.WPVersion)
	}
	return r.Checksums, nil
}

func (s *Scanner) ScanCoreChecksums() {
	s.progress("Verifying WordPress " + s.Env.WPVersion + " core against api.wordpress.org checksums")
	man, err := s.coreManifest()
	if err != nil {
		s.add(SevWarn, "core", "-", "core checksum verification skipped: "+err.Error())
		return
	}
	for rel, want := range man {
		p := filepath.Join(s.Env.WPRoot, rel)
		got, err := md5File(p)
		if err != nil {
			switch {
			case rel == "wp-config-sample.php":
				s.add(SevInfo, "core-sample-missing", rel,
					"wp-config-sample.php absent — commonly removed as hardening, not an infection sign")
			case strings.HasPrefix(rel, "wp-content/"):
				s.add(SevInfo, "core-bundled-missing", rel, "bundled default theme/plugin file absent (often intentional)")
			default:
				s.add(SevHigh, "core-missing", rel, "core file missing or unreadable")
			}
			continue
		}
		if got != want {
			s.add(SevHigh, "core-modified", rel, "does not match official "+s.Env.WPVersion+" checksum")
		} else {
			s.verified[rel] = true
		}
	}
	// files present in core areas but not in the manifest = dropped files
	expected := map[string]bool{}
	for rel := range man {
		expected[rel] = true
	}
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		root := filepath.Join(s.Env.WPRoot, dir)
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel := s.Env.rel(p)
			if !expected[filepath.ToSlash(rel)] {
				s.add(SevHigh, "core-unknown-file", rel,
					"file exists in core area but not in official "+s.Env.WPVersion+" manifest")
			}
			return nil
		})
	}
	ents, _ := os.ReadDir(s.Env.WPRoot)
	for _, en := range ents {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".php") || en.Name() == "wp-config.php" {
			continue
		}
		if !expected[en.Name()] {
			s.add(SevHigh, "core-unknown-file", en.Name(),
				"file exists in core area but not in official "+s.Env.WPVersion+" manifest")
		}
	}
}

// ------------------------ plugin checksum scan --------------------------------

var headerRe = func(field string) *regexp.Regexp {
	return regexp.MustCompile(`(?im)^[\s*/]*` + field + `:\s*(.+)$`)
}
var pluginNameRe = headerRe("Plugin Name")
var pluginVersionRe = headerRe("Version")
var verNumRe = regexp.MustCompile(`([0-9]+\.)+[0-9]+|[0-9]+`)

type pluginChecksumResp struct {
	Files map[string]struct {
		MD5 json.RawMessage `json:"md5"`
	} `json:"files"`
}

func pluginHeader(dir string) (main, version string) {
	ents, _ := os.ReadDir(dir)
	for _, en := range ents {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".php") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, en.Name()))
		if err != nil || !pluginNameRe.Match(b) {
			continue
		}
		if m := pluginVersionRe.FindSubmatch(b); m != nil {
			return en.Name(), strings.TrimSpace(string(m[1]))
		}
		return en.Name(), ""
	}
	return "", ""
}

func md5Set(raw json.RawMessage) map[string]bool {
	set := map[string]bool{}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		set[one] = true
		return set
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, m := range many {
			set[m] = true
		}
	}
	return set
}

func (s *Scanner) ScanPluginChecksums() {
	s.progress("Verifying plugins against downloads.wordpress.org plugin-checksums")
	plugRoot := filepath.Join(s.Env.WPRoot, "wp-content", "plugins")
	ents, err := os.ReadDir(plugRoot)
	if err != nil {
		return
	}
	for _, en := range ents {
		if !en.IsDir() {
			continue
		}
		slug := en.Name()
		dir := filepath.Join(plugRoot, slug)
		_, verRaw := pluginHeader(dir)
		ver := verNumRe.FindString(verRaw)
		if ver == "" {
			s.add(SevInfo, "plugin-noversion", "wp-content/plugins/"+slug, "could not read version header")
			continue
		}
		s.progress("  plugin " + slug + " " + ver)
		cachef := filepath.Join(s.Env.Cache, "plugin-"+slug+"-"+ver+".json")
		b, rerr := os.ReadFile(cachef)
		if rerr != nil {
			b, rerr = fetch("https://downloads.wordpress.org/plugin-checksums/" +
				url.PathEscape(slug) + "/" + url.PathEscape(ver) + ".json")
			if rerr == nil {
				_ = os.WriteFile(cachef, b, 0o600)
			}
		}
		var r pluginChecksumResp
		if rerr != nil || json.Unmarshal(b, &r) != nil || len(r.Files) == 0 {
			s.add(SevInfo, "plugin-premium", "wp-content/plugins/"+slug+" ("+ver+")",
				"not on wordpress.org — verify via the baseline workflow")
			continue
		}
		known := map[string]bool{}
		for rel, info := range r.Files {
			known[rel] = true
			p := filepath.Join(dir, filepath.FromSlash(rel))
			got, ferr := md5File(p)
			if ferr != nil {
				continue // missing files in a plugin are common after partial updates
			}
			if !md5Set(info.MD5)[got] {
				s.add(SevHigh, "plugin-modified", "wp-content/plugins/"+slug+"/"+rel,
					"does not match official "+slug+" "+ver+" checksums")
			} else {
				s.verified["wp-content/plugins/"+slug+"/"+rel] = true
			}
		}
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			if !known[filepath.ToSlash(rel)] {
				s.add(SevMed, "plugin-unknown-file", "wp-content/plugins/"+slug+"/"+rel,
					"file not in official "+slug+" "+ver+" package")
			}
			return nil
		})
	}
}

// --------------------------- filesystem scans ---------------------------------

func (s *Scanner) ScanUploadsPHP() {
	s.progress("Scanning wp-content/uploads for PHP files")
	up := filepath.Join(s.Env.WPRoot, "wp-content", "uploads")
	_ = filepath.WalkDir(up, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		n := d.Name()
		if strings.HasSuffix(n, ".php") || strings.HasSuffix(n, ".phtml") ||
			strings.HasSuffix(n, ".php5") || strings.HasSuffix(n, ".php7") {
			s.add(SevHigh, "php-in-uploads", s.Env.rel(p), "executable PHP inside uploads — almost always malicious")
		}
		return nil
	})
}

func (s *Scanner) ScanHashDB(files []string) {
	if len(s.Sigs.HDB) == 0 {
		s.add(SevWarn, "hashdb", "-", "rfxn.hdb not present — run update-sigs to enable hash scanning")
		return
	}
	s.progress(fmt.Sprintf("Scanning against rfxn/maldet MD5 database (%d signatures)", len(s.Sigs.HDB)))
	for _, p := range files {
		h, err := md5File(p)
		if err != nil {
			continue
		}
		if name, hit := s.Sigs.HDB[h]; hit {
			s.add(SevHigh, "known-malware", s.Env.rel(p), "matches maldet signature: "+name)
		}
	}
}

func (s *Scanner) allowPathURL(rel string) (bool, string) {
	for _, ap := range s.Sigs.AllowPaths {
		if rel == ap.Prefix || strings.HasPrefix(rel, ap.Prefix+"/") {
			return true, ap.URL
		}
	}
	return false, ""
}

func (s *Scanner) ScanHeuristics(files []string) {
	s.progress(fmt.Sprintf("Heuristic pattern scan (%d patterns, %d files)", len(s.Sigs.Greps), len(files)))
	for _, p := range files {
		if s.verified[filepath.ToSlash(s.Env.rel(p))] {
			continue // byte-identical to the official release; cannot be injected
		}
		b, err := os.ReadFile(p)
		if err != nil || !looksText(b) {
			continue
		}
		rel := s.Env.rel(p)
		trusted, _ := s.allowPathURL(filepath.ToSlash(rel))
		for _, g := range s.Sigs.Greps {
			if g.Rex.Match(b) {
				if trusted {
					s.add(SevInfo, "heuristic:"+g.Name, rel,
						"matched '"+g.Name+"' in trusted vendor path — expected")
				} else {
					s.add(SevMed, "heuristic:"+g.Name, rel,
						"matched pattern '"+g.Name+"' — REVIEW, may be legitimate")
				}
			}
		}
	}
	for _, fn := range s.Sigs.FNames {
		_ = filepath.WalkDir(s.Env.WPRoot, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if ok, _ := filepath.Match(fn.Glob, d.Name()); ok {
				s.add(SevMed, "filename:"+fn.Name, s.Env.rel(p), "suspicious file name pattern")
			}
			return nil
		})
	}
}

func looksText(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
	}
	return true
}

func (s *Scanner) ScanNulled(files []string) {
	s.progress("Checking for nulled-plugin indicators")
	for _, p := range files {
		if s.verified[filepath.ToSlash(s.Env.rel(p))] {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil || !looksText(b) {
			continue
		}
		for _, d := range s.Sigs.Domains {
			if strings.Contains(string(b), d.Domain) {
				s.add(SevHigh, "nulled-domain:"+d.Name, s.Env.rel(p),
					"references piracy/nulled domain "+d.Domain)
			}
		}
	}
	plugRoot := filepath.Join(s.Env.WPRoot, "wp-content", "plugins")
	ents, _ := os.ReadDir(plugRoot)
	for _, en := range ents {
		if !en.IsDir() {
			continue
		}
		_, verRaw := pluginHeader(filepath.Join(plugRoot, en.Name()))
		first := regexp.MustCompile(`[0-9]+`).FindString(verRaw)
		if n, err := strconv.Atoi(first); err == nil && n >= 999 && n <= 99999 {
			s.add(SevHigh, "nulled-version-pin", "wp-content/plugins/"+en.Name(),
				fmt.Sprintf("version pinned at %d — classic nulled-plugin update blocker", n))
		}
	}
}

var htSuspRe = regexp.MustCompile(`base64|AddHandler|AddType\s+application/x-httpd-php|auto_(ap|pre)pend_file`)
var htProtectRe = regexp.MustCompile(`php_flag\s+engine\s+off|Deny from all|Require all denied`)


var reqCallRe = regexp.MustCompile(`(?i)(wp_remote_(get|post|request|head)|wp_safe_remote|file_get_contents|curl_setopt|curl_init|fopen|fsockopen|readfile|copy)\s*\(`)
var urlRe = regexp.MustCompile(`https?://[^"'` + "`" + ` )]+`)
var sslOffRe = regexp.MustCompile(`(?i)sslverify[^,]*(=>|:)\s*(false|0)`)
var varHostRe = regexp.MustCompile(`^\$\{?[a-zA-Z_]`)

var defaultAllowHosts = []string{
	"wordpress.org", "api.wordpress.org", "downloads.wordpress.org", "s.w.org",
	"gravatar.com", "secure.gravatar.com", "google.com", "googleapis.com",
	"gstatic.com", "youtube.com", "youtu.be", "vimeo.com", "fonts.googleapis.com",
	"fonts.gstatic.com", "facebook.com", "graph.facebook.com", "twitter.com",
	"x.com", "github.com", "githubusercontent.com", "w3.org", "schema.org",
	"gmpg.org", "paypal.com", "stripe.com", "cloudflare.com", "jsdelivr.net", "unpkg.com",
}

func hostFromURL(u string) string {
	h := u
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	if i := strings.IndexAny(h, "/:?"); i >= 0 {
		h = h[:i]
	}
	return h
}

func (s *Scanner) ScanExternalRequests(files []string) {
	s.progress("Discovering external request destinations (runtime HTTP calls)")
	allow := map[string]bool{}
	for _, h := range defaultAllowHosts {
		allow[h] = true
	}
	for _, h := range s.Sigs.AllowHosts {
		allow[h] = true
	}
	allowed := func(host string) bool {
		for a := range allow {
			if host == a || strings.HasSuffix(host, "."+a) {
				return true
			}
		}
		return false
	}

	// files that hook pre_http_request (license/update interception context)
	hookFile := map[string]bool{}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err == nil && regexp.MustCompile(`add_filter\s*\(\s*['` + "`" + `"]pre_http_request`).Match(b) {
			hookFile[s.Env.rel(p)] = true
		}
	}

	seen := map[string]bool{}
	for _, p := range files {
		if s.verified[filepath.ToSlash(s.Env.rel(p))] {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil || !looksText(b) {
			continue
		}
		rel := s.Env.rel(p)
		for i, line := range strings.Split(string(b), "\n") {
			if !reqCallRe.MatchString(line) {
				continue
			}
			u := urlRe.FindString(line)
			if u == "" {
				continue
			}
			host := hostFromURL(u)
			if host == "" || varHostRe.MatchString(host) {
				continue
			}
			key := host + "\x00" + rel
			if seen[key] {
				continue
			}
			seen[key] = true

			var flags []string
			known := allowed(host)
			if !known {
				flags = append(flags, "unknown-host")
			}
			http := strings.HasPrefix(u, "http://")
			if http {
				flags = append(flags, "http")
			}
			noverify := sslOffRe.MatchString(line)
			if noverify {
				flags = append(flags, "sslverify-off")
			}
			hook := hookFile[rel]
			if hook {
				flags = append(flags, "near-license-hook")
			}

			sev := SevInfo
			switch {
			case !known && (http || noverify || hook):
				sev = SevHigh
			case !known:
				sev = SevMed
			case hook:
				sev = SevMed
			}
			s.add(sev, "external-request", fmt.Sprintf("%s:%d", rel, i+1),
				"external request to "+host+" ["+strings.Join(flags, ",")+"]")
		}
	}
}

func (s *Scanner) ScanHtaccess() {
	s.progress("Auditing .htaccess files")
	uploads := filepath.Join(s.Env.WPRoot, "wp-content", "uploads")
	_ = filepath.WalkDir(s.Env.WPRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != ".htaccess" {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		if htSuspRe.Match(b) {
			s.add(SevMed, "htaccess-suspicious", s.Env.rel(p),
				"contains handler/append/base64 directives — REVIEW")
		}
		if strings.HasPrefix(p, uploads) && !htProtectRe.Match(b) {
			s.add(SevInfo, "htaccess-uploads", s.Env.rel(p), ".htaccess in uploads without PHP-off directives")
		}
		return nil
	})
}

// ------------------------------ database scan ---------------------------------

var defineRe = regexp.MustCompile(`define\(\s*['"]([A-Z_]+)['"]\s*,\s*['"]([^'"]*)['"]`)
var prefixRe = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([^'"]+)['"]`)

type dbCreds struct{ name, user, pass, host, prefix string }

func (s *Scanner) dbConfig() (*dbCreds, error) {
	b, err := os.ReadFile(filepath.Join(s.Env.WPRoot, "wp-config.php"))
	if err != nil {
		return nil, err
	}
	c := &dbCreds{prefix: "wp_", host: "localhost"}
	for _, m := range defineRe.FindAllSubmatch(b, -1) {
		switch string(m[1]) {
		case "DB_NAME":
			c.name = string(m[2])
		case "DB_USER":
			c.user = string(m[2])
		case "DB_PASSWORD":
			c.pass = string(m[2])
		case "DB_HOST":
			c.host = string(m[2])
		}
	}
	if m := prefixRe.FindSubmatch(b); m != nil {
		c.prefix = string(m[1])
	}
	if c.name == "" || c.user == "" {
		return nil, fmt.Errorf("could not parse DB credentials from wp-config.php")
	}
	return c, nil
}

func (c *dbCreds) dsn() string {
	host := c.host
	if !strings.Contains(host, ":") {
		host += ":3306"
	}
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?timeout=10s&readTimeout=30s", c.user, c.pass, host, c.name)
}

func (s *Scanner) ScanDatabase() {
	s.progress("Scanning database (posts, options, users, cron)")
	c, err := s.dbConfig()
	if err != nil {
		s.add(SevWarn, "db", "-", "database scan skipped: "+err.Error())
		return
	}
	db, err := sql.Open("mysql", c.dsn())
	if err == nil {
		err = db.Ping()
	}
	if err != nil {
		s.add(SevWarn, "db", "-", "database scan skipped (cannot connect): "+err.Error())
		return
	}
	defer db.Close()
	P := c.prefix

	q := func(sev, cat, itemPrefix, detail, query string, args ...any) {
		rows, qerr := db.Query(query, args...)
		if qerr != nil {
			return
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			if rows.Scan(ptrs...) != nil {
				continue
			}
			parts := make([]string, len(cols))
			for i, v := range vals {
				switch t := v.(type) {
				case []byte:
					parts[i] = string(t)
				case nil:
					parts[i] = ""
				default:
					parts[i] = fmt.Sprint(t)
				}
			}
			s.add(sev, cat, itemPrefix+parts[0], strings.Join(parts[1:], " | ")+" — "+detail)
		}
	}

	q(SevMed, "db-post-injection", "post:", "contains script/eval/iframe patterns — REVIEW (restore via revisions)",
		`SELECT ID, post_type, post_modified FROM `+P+`posts
		 WHERE post_status='publish'
		   AND post_content REGEXP '<script[^>]*src=|eval\\(|String\\.fromCharCode|base64_decode|<iframe'
		 LIMIT 200`)

	if s.Since != "" {
		q(SevInfo, "db-recently-modified", "post:", "modified since "+s.Since,
			`SELECT ID, post_type, post_modified FROM `+P+`posts WHERE post_modified >= ? LIMIT 500`, s.Since)
	}

	q(SevInfo, "db-url", "", "confirm this is YOUR domain",
		`SELECT option_name, option_value FROM `+P+`options WHERE option_name IN ('siteurl','home')`)

	q(SevMed, "db-option-injection", "option:", "widget/theme option contains script/eval — REVIEW in wp-admin",
		`SELECT option_name FROM `+P+`options
		 WHERE (option_name LIKE 'widget\_%' OR option_name LIKE 'theme\_mods\_%')
		   AND option_value REGEXP '<script|eval\\(|base64_decode' LIMIT 50`)

	q(SevInfo, "db-option-oversized", "option:", "autoloaded option is unusually large — worth a look",
		`SELECT option_name, LENGTH(option_value) FROM `+P+`options
		 WHERE autoload='yes' AND LENGTH(option_value) > 100000 LIMIT 20`)

	if len(s.Sigs.Options) > 0 {
		ph := strings.Repeat("?,", len(s.Sigs.Options))
		args := make([]any, len(s.Sigs.Options))
		for i, o := range s.Sigs.Options {
			args[i] = o
		}
		q(SevHigh, "db-nulled-residue", "option:", "license residue from nulled plugin — delete after replacing plugin",
			`SELECT option_name FROM `+P+`options WHERE option_name IN (`+ph[:len(ph)-1]+`)`, args...)
	}

	q(SevInfo, "db-admin-user", "user:", "do you recognize this admin account?",
		`SELECT u.ID, u.user_login, u.user_email, u.user_registered
		 FROM `+P+`users u JOIN `+P+`usermeta m ON m.user_id=u.ID
		 WHERE m.meta_key=? AND m.meta_value LIKE '%administrator%'`, P+"capabilities")

	var cron string
	if db.QueryRow(`SELECT option_value FROM `+P+`options WHERE option_name='cron'`).Scan(&cron) == nil {
		if regexp.MustCompile(`eval\(|base64_decode`).MatchString(cron) {
			s.add(SevMed, "db-cron", "option:cron", "cron blob contains eval/base64 — inspect with: wp cron event list")
		}
	}
}

// -------------------------- vulnerability lookup -------------------------------

func (s *Scanner) ScanVulnerabilities() {
	if s.Env.WPScanTok == "" {
		return
	}
	s.progress("Checking plugins against the WPScan vulnerability API")
	plugRoot := filepath.Join(s.Env.WPRoot, "wp-content", "plugins")
	ents, _ := os.ReadDir(plugRoot)
	for _, en := range ents {
		if !en.IsDir() {
			continue
		}
		slug := en.Name()
		req, _ := http.NewRequest("GET", "https://wpscan.com/api/v3/plugins/"+url.PathEscape(slug), nil)
		req.Header.Set("Authorization", "Token token="+s.Env.WPScanTok)
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		var data map[string]struct {
			Vulnerabilities []struct {
				Title string `json:"title"`
			} `json:"vulnerabilities"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		for _, info := range data {
			for _, v := range info.Vulnerabilities {
				s.add(SevInfo, "vulnerability", "wp-content/plugins/"+slug, v.Title)
			}
		}
	}
}
