package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var gitCommit = "unknown" // set via -ldflags "-X main.gitCommit=..."

const usage = `RatSweepr %s — WordPress malware scanner & cleanup assistant

Usage:
  ratsweepr                     interactive TUI
  ratsweepr scan [--since DATE] read-only scan -> ratsweepr-<date>.report
  ratsweepr update-sigs         refresh rfxn.hdb + pattern file
  ratsweepr baseline            hash premium plugins/themes (CLEAN site!)
  ratsweepr verify-baseline     compare current files to baselines
  ratsweepr quarantine REPORT   quarantine HIGH/MED file findings from a report
  ratsweepr restore BATCH-ID    restore a quarantine batch
  ratsweepr clean-core          replace only core files failing checksums
  ratsweepr shuffle-salts       rotate wp-config.php auth salts

Environment:
  RS_HOME            tool home (default ~/.ratsweepr)
  RS_PATTERN_URL     URL of your signed patterns.conf
  RS_RFXN_URL        override the rfxn.hdb feed URL
  WPSCAN_API_TOKEN   enable known-CVE lookups (free tier at wpscan.com)
`

func main() {
	env, err := DetectEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}

	args := os.Args[1:]
	if len(args) == 0 {
		if err := runTUI(env); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			os.Exit(1)
		}
		return
	}

	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "scan":
		since := ""
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--since" && i+1 < len(rest) {
				since = rest[i+1]
			}
		}
		headlessScan(env, since)
	case "update-sigs":
		for _, l := range env.UpdateSignatures() {
			fmt.Println("..", l)
		}
	case "baseline":
		n, err := BaselineGenerate(env, func(p string) { fmt.Println("..", p) })
		exitIf(err)
		fmt.Printf("OK stored %d baseline manifest(s) in %s\n", n, env.Baselines)
	case "verify-baseline":
		sigs, _ := env.LoadSignatures()
		sc := NewScanner(env, sigs, printProgress, printFinding)
		BaselineVerify(env, sc)
		fmt.Println("Report:", env.ReportPath)
	case "quarantine":
		if len(rest) < 1 {
			fatal("usage: ratsweepr quarantine <report-file>")
		}
		rels, err := QuarantinablePaths(env, rest[0])
		exitIf(err)
		if len(rels) == 0 {
			fmt.Println("Nothing quarantinable in this report.")
			return
		}
		fmt.Printf("The following %d file(s) will be MOVED out of the webroot:\n", len(rels))
		for _, r := range rels {
			fmt.Println("  " + r)
		}
		mustType("I HAVE A BACKUP", "Make a FULL backup (files + database) first.")
		mustType("QUARANTINE", "")
		batch, n, err := QuarantineFiles(env, rels)
		exitIf(err)
		fmt.Printf("OK quarantined %d file(s) -> %s\n", n, batch)
		fmt.Println("Restore with: ratsweepr restore " + batch)
	case "restore":
		if len(rest) < 1 {
			fatal("usage: ratsweepr restore <batch-id>  (see " + env.Quarantine + ")")
		}
		mustType("RESTORE", "Files will be moved back into the webroot.")
		n, err := RestoreBatch(env, rest[0])
		exitIf(err)
		fmt.Printf("OK restored %d file(s)\n", n)
	case "clean-core":
		sigs, _ := env.LoadSignatures()
		sc := NewScanner(env, sigs, nil, nil)
		failing, err := FailingCoreFiles(env, sc)
		exitIf(err)
		if len(failing) == 0 {
			fmt.Println("All core files already verify. Nothing to do.")
			return
		}
		fmt.Printf("These %d core file(s) will be replaced with clean %s copies:\n",
			len(failing), env.WPVersion)
		for _, f := range failing {
			fmt.Println("  " + f)
		}
		mustType("I HAVE A BACKUP", "Make a FULL backup (files + database) first.")
		mustType("REPLACE", "")
		n, err := CleanCore(env, failing, func(p string) { fmt.Println("..", p) })
		exitIf(err)
		fmt.Printf("OK replaced %d core file(s); originals quarantined\n", n)
	case "shuffle-salts":
		mustType("I HAVE A BACKUP", "wp-config.php will be modified (a backup copy is kept).")
		mustType("ROTATE", "")
		backup, err := ShuffleSalts(env)
		exitIf(err)
		fmt.Println("OK salts rotated; previous config kept at", backup)
	case "help", "-h", "--help":
		fmt.Printf(usage, appVersion)
	default:
		fmt.Printf(usage, appVersion)
		fatal("unknown command: " + cmd)
	}
}

func headlessScan(env *Env, since string) {
	fmt.Printf("RatSweepr v%s (%s)\n", appVersion, gitCommit)
	for _, l := range env.UpdateSignatures() {
		fmt.Println("..", l)
	}
	sigs, err := env.LoadSignatures()
	exitIf(err)
	sc := NewScanner(env, sigs, printProgress, printFinding)
	sc.Since = since
	sc.RunAll()
	high, med, info := 0, 0, 0
	for _, f := range sc.Findings {
		switch f.Sev {
		case SevHigh:
			high++
		case SevMed:
			med++
		case SevInfo:
			info++
		}
	}
	fmt.Printf("\nSUMMARY  HIGH:%d  MED:%d  INFO:%d\n", high, med, info)
	printClustered(sc.Findings, SevHigh)
	printClustered(sc.Findings, SevMed)
	fmt.Printf("Report: %s\n", env.ReportPath)
}

// printClustered groups findings by (category + file basename) so a malware
// family sprayed across many dirs collapses to one line with a count.
func printClustered(findings []Finding, sev string) {
	type cl struct {
		cat, base string
		count     int
		samples   []string
	}
	clusters := map[string]*cl{}
	catTotals := map[string]int{}
	var order []string
	for _, f := range findings {
		if f.Sev != sev {
			continue
		}
		path := f.Item
		if i := strings.Index(path, " ("); i >= 0 {
			path = path[:i]
		}
		if i := strings.LastIndex(path, ":"); i >= 0 && len(path) > i+1 && path[i+1] >= '0' && path[i+1] <= '9' {
			path = path[:i]
		}
		base := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			base = path[i+1:]
		}
		key := f.Cat + "\x1f" + base
		c := clusters[key]
		if c == nil {
			c = &cl{cat: f.Cat, base: base}
			clusters[key] = c
			order = append(order, key)
		}
		c.count++
		if len(c.samples) < 3 {
			c.samples = append(c.samples, path)
		}
		catTotals[f.Cat]++
	}
	if len(order) == 0 {
		return
	}
	fmt.Printf("  --- %s (clustered) ---\n", sev)
	for _, k := range order {
		c := clusters[k]
		if c.count > 1 {
			more := ""
			if c.count > 3 {
				more = ", ..."
			}
			fmt.Printf("  [%3dx] %-26s %s\n         in: %s%s\n", c.count, c.cat, c.base, strings.Join(c.samples, ", "), more)
		}
	}
	fmt.Println("  -- per-category totals --")
	for cat, n := range catTotals {
		fmt.Printf("  %-28s %d finding(s)\n", cat, n)
	}
}

func printProgress(p string) { fmt.Println("..", p) }
func printFinding(f Finding) {
	fmt.Printf("%-4s %-24s %s\n     %s\n", f.Sev, f.Cat, f.Item, f.Detail)
}

var stdinReader = bufio.NewScanner(os.Stdin)

func mustType(phrase, note string) {
	if note != "" {
		fmt.Println("WARN:", note)
	}
	fmt.Printf("Type exactly %q to continue: ", phrase)
	if !stdinReader.Scan() || strings.TrimSpace(stdinReader.Text()) != phrase {
		fatal("aborted — no changes made")
	}
}

func exitIf(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "FAIL:", msg)
	os.Exit(1)
}
