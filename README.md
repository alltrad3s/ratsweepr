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

RatSweepr is a single self-contained bash script. It runs read-only by
default, writes a plain-text report, and never deletes anything — cleanup
*moves* files to a restorable quarantine. It needs only what a typical
shared host already has: `bash`, `curl`/`wget`, coreutils, and (for full
database and integrity coverage) WP-CLI or a `mysql` client plus `php-cli`.

> **Note:** RatSweepr previously shipped a second Go/TUI implementation.
> That has been sunset — bash is now the only implementation. One codebase,
> one version number, no parity to keep in sync.

## Quick start

Run the scanner in one line from your WordPress root (where `wp-config.php`
lives):

```bash
cd ~/public_html
bash <(curl -sL https://raw.githubusercontent.com/alltrad3s/ratsweepr/main/ratsweepr.sh) scan
```

Or install a local copy first:

```bash
cd ~/public_html
bash <(curl -sL https://raw.githubusercontent.com/alltrad3s/ratsweepr/main/install.sh)
./ratsweepr.sh scan
```

> **Restricted hosts:** some shared hosts disable process substitution
> (`/dev/fd`) or cap process counts. If `bash <(curl ...)` fails with a
> `/dev/fd/...: No such file or directory` error, download then run:
> ```bash
> curl -sL https://raw.githubusercontent.com/alltrad3s/ratsweepr/main/ratsweepr.sh -o ratsweepr.sh
> bash ratsweepr.sh scan
> ```

> Pin a tag or commit SHA for anything unattended
> (`.../ratsweepr/v2.9.10/ratsweepr.sh`) — never let cron run whatever
> `main` happens to be. Use `bash <(curl ...)`, not `curl | bash`: the pipe
> form breaks the interactive confirmation gates.

## Design principles

1. **Report first.** `scan` is strictly read-only and writes a tab-separated
   `ratsweepr-<timestamp>.report` (`SEVERITY  CATEGORY  ITEM  DETAIL`).
   Findings cluster in the summary — a malware family sprayed across dozens of
   directories collapses to one counted line (`[30x] ...`) instead of a wall.
2. **Quarantine, never delete.** Cleanup MOVES files to
   `~/.ratsweepr/quarantine/<batch>/` with a SHA256 manifest. Any batch can be
   restored with one command. `rm` appears nowhere in the cleanup path. The
   database has its own reversible quarantine (`quarantine-db` / `restore-db`):
   it exports affected rows to SQL, then neutralizes them (posts → a namespaced
   status, users → disabled login/caps) — never `DELETE`.
3. **Integrity beats signatures.** Verification against wordpress.org
   checksums is the primary detector — it catches malware nobody has seen yet,
   including injection into legitimate core files.
4. **Unexpected ≠ malicious.** An unfamiliar file is classified by *what it
   is* (executable PHP, obfuscated payload, benign config) before it is
   escalated — not flagged HIGH merely for being absent from a manifest.
5. **Backup gates.** Destructive actions require typing `I HAVE A BACKUP`
   plus an action phrase. RatSweepr does not make backups for you; it makes
   sure you made one.
6. **No root.** Refuses to run as root (`RS_ALLOW_ROOT=1` to override, don't).

## Detection layers

1. **Core integrity** — api.wordpress.org checksums: modified, missing, and
   *unknown* files in core areas (the classic dropped-shell case, and
   injection into real core files). Bundled default plugins/themes
   (akismet, hello, twentytwenty*) are checked against their own checksums,
   not the core manifest, so they don't false-fail. A manifest-independent
   fallback (`core-orphan-file`) still surfaces unexpected PHP in core
   directories when the checksum API can't be reached.
2. **Plugin integrity** — downloads.wordpress.org plugin-checksums per
   installed version: modified and unknown files inside each plugin.
3. **YARA content rules** — a bundled ruleset (`ratsweepr.yar`) matched by a
   real engine when available, or a built-in matcher otherwise (see below).
   Covers obfuscated eval chains, `pack()`/`str_rot13`/`gzinflate` droppers,
   cookie- and header-fed backdoors (`$_COOKIE`/`getallheaders()` dynamic
   calls), command-exec webshells (disable_functions-bypass, hardcoded-secret
   gated), `$GLOBALS`-flood backdoors, self-hiding fake plugins, dual-use file
   managers (Tiny File Manager / CCP), obfuscated client-side JS injection
   (crypto-drainers appended to theme files), and access-control malware
   (`.htaccess` that denies everyone but the attacker's own shells).
4. **Known malware** — the rfxn/maldet MD5 database (~45k signatures, updated
   ~daily upstream), refreshed by `update-sigs` and matched locally.
5. **Heuristics** — grep patterns from the signature file: webshell
   constructs, eval/base64 chains, suspicious filenames. MED severity by
   design — review before acting.
6. **Nulled-plugin indicators** — piracy-domain references, version-9999
   update blockers, `pre_http_request` license interception,
   `sslverify => false`, leftover fake license options, and self-concealing
   fake plugins that hide themselves from the plugin list and hide admin
   users from queries (`pre_user_query`, `views_users`).
7. **Vulnerable core versions** — checks the detected version against a
   known-vulnerable-core table (e.g. wp2shell / CVE-2026-63030+60137, and
   CVE-2026-87902 — the unauth path-traversal LFI->RCE affecting 4.7.0–7.1.1,
   fixed in 7.1.2, exploited in the wild via PEAR pearcmd). Emits a
   HIGH finding with the CVE, the fixed version, the `wp core update` fix, and
   ready-to-paste Apache/Nginx WAF rules. The table lives in the signature
   file, so new core CVEs ship via `update-sigs` without a code change.
8. **Post-exploitation trace sweep** — when a matched (or previously-matched)
   core CVE gives an exposure window, RatSweepr looks for the fingerprints a
   mass-exploitation leaves behind, **regardless of the current core version**
   (a patched site can still carry a prior breach): user-ID gaps
   (created-then-deleted accounts), admins registered in the window, orphaned
   admin usermeta (deleted-account ghosts), suspicious admin logins/emails,
   PoC post markers, oembed spam, and PHP files written to uploads/mu-plugins
   in the window. All UNSCORED INFO — none proves breach alone; their
   correlation does.
9. **External request discovery** — extracts every host the code contacts via
   a real HTTP call (`wp_remote_*`, `file_get_contents`, cURL), ignoring URLs
   that only appear in comments. Each destination is ranked by context: an
   unknown host over plaintext HTTP, with `sslverify => false`, or near a
   `pre_http_request` hook escalates to HIGH; known/allowlisted vendors stay
   silent. **Discovery, not denylist** — it surfaces the malicious callback
   even when that domain has never been blacklisted. Tune with `ALLOWHOST|host`
   lines. The report ends with an "External contact points" digest.
10. **PHP in uploads** (content-aware — benign silence-guard `index.php` files
    are distinguished from real payloads) and suspicious **.htaccess**
    directives, including anti-cleanup lockout `.htaccess` (HIGH).
11. **Database** — script/iframe injection in posts, widget/option injection,
    oversized autoloads, siteurl/home hijack, admin-account audit, suspicious
    cron blobs, `--since DATE` forensic window.
12. **Premium baselines** — snapshot MD5 manifests on a clean site
    (`baseline`), diff live files later (`verify-baseline`).
13. **Known CVEs** (optional) — WPScan API per plugin
    (`export WPSCAN_API_TOKEN=...`, free tier at wpscan.com).

## Commands

```
ratsweepr.sh scan [--since DATE]  read-only scan -> ratsweepr-<date>.report
ratsweepr.sh menu                 interactive menu
ratsweepr.sh update-sigs          refresh rfxn.hdb + pattern/rule files
ratsweepr.sh baseline             hash premium plugins/themes (CLEAN site!)
ratsweepr.sh verify-baseline      compare current files to baselines
ratsweepr.sh quarantine REPORT    quarantine HIGH/MED file findings from a report
ratsweepr.sh restore BATCH-ID     restore a file quarantine batch
ratsweepr.sh quarantine-db        reversibly neutralize DB compromise findings
                                  (dry-run by default; --force to apply)
ratsweepr.sh restore-db BATCH-ID  restore a DB quarantine batch
ratsweepr.sh clean-core           replace only core files failing checksums
ratsweepr.sh shuffle-salts        rotate wp-config.php auth salts
```

## Configuration

| Env var | Purpose |
|---|---|
| `RS_HOME` | tool home (default `~/.ratsweepr`) |
| `RS_PATTERN_URL` | URL of your hosted `ratsweepr-sigs.conf` |
| `RS_RFXN_URL` | override the maldet/rfxn MD5 feed |
| `WPSCAN_API_TOKEN` | enable known-CVE lookups |
| `RS_RULES_URL` | online YARA rule feed pulled each scan (signed if a public key is present) |
| `RS_YARA_RULES` | path to a directory of extra `.yar`/`.yara` rulesets |
| `RS_NO_ENGINE_DL=1` | disable the one-time static YARA engine download |
| `RS_YARAX_URL` | override the yara-x engine download URL (default: VirusTotal yara-x v1.19.0 release tarball for the host arch) |
| `RS_YARAX_VER` | pin a different yara-x release tag (e.g. `v1.19.0`) |
| `RS_ALLOW_ROOT=1` | bypass the root refusal (don't) |

### YARA engine

YARA scanning runs three ways, in order of preference, so it works on any host:
a system `yara` binary if present; otherwise a one-time static `yara-x` engine
(the `yr` CLI) downloaded to `~/.ratsweepr/bin` (skipped on `noexec` homes);
otherwise a built-in matcher that runs the same rules with no engine at all.
The engine is a bonus — it also evaluates positional/module conditions the
built-in matcher skips — but it is never required for detection, and a
failed or absent download costs no signature coverage. Rules come from the
bundled `ratsweepr.yar`, any `RS_YARA_RULES` directory, and an optional signed
online feed (`RS_RULES_URL`).

### Trusted vendor components

Components that can't be verified against wordpress.org (e.g. Kinsta's
mu-plugins) are handled with `ALLOWPATH|prefix|reinstall-url` lines: heuristic
and external-request findings under that path are downgraded to INFO
(integrity and malware-hash findings are **not** downgraded), and `clean-core`
surfaces the reinstall URL. The bundled default covers
`wp-content/mu-plugins/kinsta-mu-plugins`.

### Signed signature updates

If `~/.ratsweepr/ratsweepr-pub.pem` exists on a server, pattern/rule downloads
must pass verification or they're rejected:

```bash
# once, on your workstation (never commit priv.pem):
openssl genrsa -out priv.pem 4096
openssl rsa -in priv.pem -pubout -out ratsweepr-pub.pem
# after every edit to ratsweepr-sigs.conf:
make sign-sigs          # -> ratsweepr-sigs.conf.sig ; commit both
```

## Cleanup sequence after a confirmed infection

1. `ratsweepr.sh scan --since <suspected-date>`; review the report. Heuristic
   (MED) findings can be legitimate code — check each file.
2. **Full backup**: `tar -czf ~/site-backup.tgz .` and `wp db export ~/db.sql`.
3. **Kill anti-cleanup layers first.** If the scan reports `malicious-htaccess`
   (lockout files) or a recursive-chmod dropper, remove those before the
   payloads they protect — otherwise removal can fail with permission errors.
4. `ratsweepr.sh quarantine ratsweepr-<date>.report`; for DB findings,
   `ratsweepr.sh quarantine-db`.
5. `ratsweepr.sh clean-core`; force-reinstall repo plugins/themes
   (`wp plugin install --force $(wp plugin list --field=name)`); premium ones
   fresh from the vendor, then re-run `baseline`.
6. `ratsweepr.sh shuffle-salts`; reset all admin passwords; delete
   unrecognized admin users and nulled-license options flagged in the report.
7. Re-scan until clean, and **patch the entry point** (nulled plugins, an
   unpatched CVE) or it *will* come back.

> **On heavily-infected sites** (hundreds of shells across dozens of
> directories, injected core files): a full file reinstall — clean core +
> clean plugins/themes, keeping only the database and `uploads` — is more
> reliable than per-file quarantine. At that scale you *will* miss one shell,
> and one missed `eval($_REQUEST[...])` means reinfection. Use RatSweepr to
> diagnose the full scope (especially the DB layer), then rebuild the files.

## Limitations — read this

- Heuristic patterns false-positive; that's why they're MED and why nothing
  is ever auto-deleted.
- Checksum APIs cover wordpress.org packages only; premium components depend
  on your baselines.
- A scanner running *on* a compromised server can be lied to. For serious
  incidents, also scan an offline copy from a trusted machine.
- RatSweepr removes malware artifacts; it does not patch the vulnerability
  that let them in. Update everything and rotate every credential.
- **RatSweepr scans files and the database of the site it runs on. It cannot
  see infrastructure-level compromise** — DNS/subdomain hijacks, a rogue domain
  mapped to the container from another account, edge-cached spam, or malware
  served from a separate hosting account. If the site scans clean but still
  misbehaves (e.g. a redirect that only fires in a real browser), check DNS,
  domain mapping, and your host's other accounts, not just the filesystem.

## Repo layout

```
ratsweepr.sh            the scanner (single self-contained bash script)
ratsweepr.yar           bundled YARA ruleset
ratsweepr-sigs.conf     distributable signature/pattern file (RS_PATTERN_URL)
install.sh              downloads ratsweepr.sh into the current directory
Makefile                lint / sign-sigs / version helpers
.github/workflows/      push = syntax check; tag = publish a release
README.md               this file
```

## Releasing

RatSweepr is a script — there's nothing to compile. Bump `RS_VERSION` in
`ratsweepr.sh`, then tag:

```bash
git tag v2.9.10 && git push origin v2.9.10
```

CI syntax-checks the script and compiles the YARA ruleset on every push, and
on a version tag publishes a GitHub Release attaching `ratsweepr.sh`,
`ratsweepr.yar`, and `ratsweepr-sigs.conf`.
