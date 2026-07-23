# RatSweepr

```
██████╗  █████╗ ████████╗███████╗██╗    ██╗███████╗███████╗██████╗ ██████╗
██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗██╔══██╗
██████╔╝███████║   ██║   ███████╗██║ █╗ ██║█████╗  █████╗  ██████╔╝██████╔╝
██╔══██╗██╔══██║   ██║   ╚════██║██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝ ██╔══██╗
██║  ██║██║  ██║   ██║   ███████║╚███╔███╔╝███████╗███████╗██║     ██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝
```

**WordPress malware scanner & cleanup assistant for shared hosting.**
No root. No agent. No deletions — ever.

RatSweepr ships in two flavors that share the same detection logic, report
format, signature files, and `~/.ratsweepr` home:

| | Go / TUI (recommended) | Bash (fallback) |
|---|---|---|
| File | `ratsweepr` binary (Releases) | `ratsweepr.sh` |
| Interface | Bubble Tea TUI + headless CLI | menu + CLI |
| Needs on server | nothing (static binary) | bash, curl/wget, coreutils; php-cli & mysql client for full coverage |
| DB scan | built-in MySQL driver | via WP-CLI or `mysql` client |
| Use when | almost always | host mounts `$HOME` noexec, or you want zero-install |

## Quick start

**Go/TUI version** (installer detects arch and verifies sha256):

```bash
cd ~/public_html    # your WordPress root — where wp-config.php lives
bash <(curl -sL https://raw.githubusercontent.com/alltrad3s/ratsweepr/main/install.sh)
./ratsweepr         # TUI
./ratsweepr scan    # headless / cron
```

**Bash version**, zero-install:

```bash
cd ~/public_html
bash <(curl -sL https://raw.githubusercontent.com/alltrad3s/ratsweepr/main/ratsweepr.sh) scan
```

> Pin a tag or commit SHA in these URLs for anything unattended
> (`.../ratsweepr/v3.0.0/ratsweepr.sh`) — never let cron run whatever
> `main` happens to be. Use `bash <(curl ...)`, not `curl | bash`:
> the pipe form breaks the interactive confirmation gates.

## Design principles

1. **Report first.** `scan` is strictly read-only and writes a tab-separated
   `ratsweepr-<timestamp>.report` (`SEVERITY  CATEGORY  ITEM  DETAIL`).
2. **Quarantine, never delete.** Cleanup MOVES files to
   `~/.ratsweepr/quarantine/<batch>/` with a SHA256 manifest. Any batch can be
   restored with one command. `rm` appears nowhere in the cleanup path.
3. **Integrity beats signatures.** Verification against wordpress.org
   checksums is the primary detector — it catches malware nobody has seen yet.
4. **Backup gates.** Destructive actions require typing `I HAVE A BACKUP`
   plus an action phrase (`QUARANTINE` / `REPLACE` / `ROTATE` / `RESTORE`).
   RatSweepr does not make backups for you; it makes sure you made one.
5. **No root.** Refuses to run as root (`RS_ALLOW_ROOT=1` to override, don't).

## Detection layers (all free)

1. **Core integrity** — api.wordpress.org checksums: modified, missing, and
   *unknown* files in core areas (the classic dropped-shell case).
2. **Plugin integrity** — downloads.wordpress.org plugin-checksums per
   installed version: modified and unknown files inside each plugin.
3. **Known malware** — rfxn/maldet MD5 database (~10k signatures, updated
   ~daily upstream), fetched by `update-sigs`, matched locally.
4. **Heuristics** — grep patterns from `ratsweepr-sigs.conf`: webshell
   constructs, eval/base64 chains, GIF-header PHP files, suspicious filenames.
   MED severity by design — review before acting.
5. **Nulled-plugin indicators** — piracy-domain references, version-9999
   update blockers, `pre_http_request` license interception,
   `sslverify => false`, leftover fake license options. Also detects
   **self-concealing fake plugins** (HIGH): components that hide themselves from
   the plugin list (`all_plugins` filter, `unset($plugins[...])`), hide admin
   users from queries (`pre_user_query`, `views_users` — the trick that makes a
   compromised site show only one user), variable-function eval of
   gzinflate/base64 payloads, and HMAC-authenticated backdoor endpoints.
6. **Vulnerable core versions** — checks the detected WordPress version against
   a known-vulnerable-core table (e.g. wp2shell / CVE-2026-63030+60137 unauth
   RCE affecting 6.9.0–6.9.4 and 7.0.0–7.0.1). Emits a HIGH finding with the
   CVE, the fixed version, the `wp core update` fix, and — for cases where you
   can't upgrade immediately — ready-to-paste Apache/Nginx rules to block the
   `/wp-json/batch/v1` endpoint (both permalink and `?rest_route=` forms). The
   table lives in the signature file, so new core CVEs ship via `update-sigs`
   without a code change.
7. **External request discovery** — extracts every host the code contacts via
   a real HTTP call (`wp_remote_*`, `file_get_contents`, cURL, etc.), ignoring
   URLs that only appear in comments or docs. Each destination is ranked by
   context: an *unknown* host reached over plaintext HTTP, with
   `sslverify => false`, or inside a file that hooks `pre_http_request`
   escalates to HIGH; known/allowlisted vendors stay silent. This is
   **discovery, not denylist** — it surfaces the malicious callback (e.g. a
   nulled plugin phoning a piracy server) even when that domain has never been
   blacklisted. Tune with `ALLOWHOST|host` lines in the signature file. The
   report ends with an "External contact points" digest, worst-severity-first.
8. **PHP in uploads** and suspicious **.htaccess** directives.
9. **Database** — script/iframe injection in posts, widget/option injection,
   oversized autoloads, siteurl/home hijack, admin-account audit, suspicious
   cron blobs, `--since DATE` forensic window.
10. **Premium baselines** — snapshot MD5 manifests on a clean site
   (`baseline`), diff live files later (`verify-baseline`).
11. **Known CVEs** (optional) — WPScan API per plugin
   (`export WPSCAN_API_TOKEN=...`, free tier at wpscan.com).

## Commands (identical in both versions)

```
ratsweepr                     interactive TUI (bash: menu)
ratsweepr scan [--since DATE] read-only scan -> ratsweepr-<date>.report
ratsweepr update-sigs         refresh rfxn.hdb + pattern file
ratsweepr baseline            hash premium plugins/themes (CLEAN site!)
ratsweepr verify-baseline     compare current files to baselines
ratsweepr quarantine REPORT   quarantine HIGH/MED file findings from a report
ratsweepr restore BATCH-ID    restore a quarantine batch
ratsweepr clean-core          replace only core files failing checksums
ratsweepr shuffle-salts       rotate wp-config.php auth salts
```

## Configuration

| Env var | Purpose |
|---|---|
| `RS_HOME` | tool home (default `~/.ratsweepr`) |
| `RS_PATTERN_URL` | URL of your hosted `ratsweepr-sigs.conf` (typically this repo's raw URL) |
| `RS_RFXN_URL` | override the maldet/rfxn MD5 feed |
| `WPSCAN_API_TOKEN` | enable known-CVE lookups |
| `RS_RULES_URL` | online YARA rule feed pulled each scan (signed if a public key is present); works with or without a local engine |
| `RS_YARA_RULES` | path to a directory of extra `.yar`/`.yara` rulesets |
| `RS_NO_ENGINE_DL=1` | disable the one-time static YARA engine download |
| `RS_YARAX_URL` | override the yara-x engine download URL (default: VirusTotal yara-x v1.19.0 release tarball for the host arch) |
| `RS_YARAX_VER` | pin a different yara-x release tag (e.g. `v1.19.0`) |
| `RS_ALLOW_ROOT=1` | bypass the root refusal (don't) |

YARA scanning runs three ways, in order of preference, so it works on any host:
a system `yara` binary if present; otherwise a one-time static `yara-x` engine
downloaded to `~/.ratsweepr/bin` (skipped on `noexec` homes); otherwise a
built-in matcher that runs the same rules with no engine at all. The engine is
a bonus (it also evaluates positional/module YARA conditions the built-in
matcher skips) — it is never required for detection, and a failed/absent engine
download costs no signature coverage. Rules with positional or module conditions only run under a real
engine; the native matcher skips them rather than misfire. Rules come from the
bundled `ratsweepr.yar`, any `RS_YARA_RULES` directory, and an optional signed
online feed (`RS_RULES_URL`) — so signatures update without a new release and
without needing anything installed on the server.

Trusted-but-unverifiable vendor components (e.g. Kinsta's mu-plugins, which
aren't on wordpress.org) are handled with `ALLOWPATH|prefix|reinstall-url`
lines in the signature file: heuristic and external-request findings under
that path are downgraded to INFO (integrity and malware-hash findings are
**not** downgraded), and `clean-core` surfaces the reinstall URL. The bundled
default covers `wp-content/mu-plugins/kinsta-mu-plugins`.

### Signed signature updates

If `~/.ratsweepr/ratsweepr-pub.pem` exists on a server, pattern downloads
must pass RSA-SHA256 verification or they're rejected:

```bash
# once, on your workstation (never commit priv.pem):
openssl genrsa -out priv.pem 4096
openssl rsa -in priv.pem -pubout -out ratsweepr-pub.pem

# after every edit to ratsweepr-sigs.conf:
make sign-sigs          # -> ratsweepr-sigs.conf.sig ; commit both
```

## Cleanup sequence after a confirmed infection

1. `ratsweepr scan --since <suspected-date>`; review the report. Heuristic
   (MED) findings can be legitimate code — check each file.
2. **Full backup**: `tar -czf ~/site-backup.tgz .` and `wp db export ~/db.sql`.
3. `ratsweepr quarantine ratsweepr-<date>.report`
4. `ratsweepr clean-core`; force-reinstall repo plugins/themes
   (`wp plugin install --force $(wp plugin list --field=name)`); premium ones
   fresh from the vendor, then re-run `baseline`.
5. `ratsweepr shuffle-salts`; reset all admin passwords; delete unrecognized
   admin users and nulled-license options flagged in the report.
6. Re-scan until clean. Check Sucuri SiteCheck / VirusTotal for blacklisting,
   and patch the entry point (see CVE findings) or it *will* come back.

## Developing

```bash
make build      # compile for this machine
make test       # go vet + build
make release    # dist/ratsweepr-linux-{amd64,arm64}, darwin-arm64 + checksums.txt
```

Releases are automated: push a tag and CI builds + attaches the binaries
that `install.sh` downloads.

```bash
git tag v3.0.1 && git push origin v3.0.1
```

Repo layout:

```
ratsweepr.sh            bash version (self-contained)
main.go                 CLI entry + headless commands
core.go                 env detection, signatures, hashing, HTTP
scan.go                 all scanners (filesystem, checksums, DB, CVEs)
actions.go              quarantine, restore, clean-core, salts, baselines
tui.go                  Bubble Tea interface
patterns_default.conf   embedded default heuristics (go:embed)
ratsweepr-sigs.conf     distributable copy servers pull via RS_PATTERN_URL
install.sh              release installer (arch detect + sha256 verify)
Makefile                build/release tooling
.github/workflows/      tag-triggered release builds
```

Note on `go.mod`: it currently contains `replace` directives pointing
`golang.org/x/*` at their GitHub mirrors (an artifact of the original build
environment). On a normal machine you may delete the `replace (...)` block
and run `make tidy`.

## Limitations — read this

- Heuristic patterns false-positive; that's why they're MED and why nothing
  is ever auto-deleted.
- Checksum APIs cover wordpress.org packages only; premium components depend
  on your baselines.
- Only the MD5 portion of the maldet feed is used (hex/YARA rules need engines
  that shared hosting can't run).
- A scanner running *on* a compromised server can be lied to. For serious
  incidents, also scan an offline copy of the site from a trusted machine.
- RatSweepr removes malware artifacts; it does not patch the vulnerability
  that let them in. Update everything and rotate every credential.
