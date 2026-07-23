#!/usr/bin/env bash
#
# ============================== RATSWEEPR =================================
#  WordPress malware scanner & cleanup assistant for shared hosting (no root).
#
#  Design principles:
#    * REPORT FIRST  - scanning never deletes or modifies anything.
#    * QUARANTINE    - "cleanup" moves files out of the webroot (recoverable),
#                      it never runs `rm`.
#    * VERIFY        - integrity checks against wordpress.org checksum APIs
#                      are the primary detector; signatures are secondary.
#    * FREE FEEDS    - wordpress.org checksums API (free), rfxn/maldet MD5
#                      malware DB (free, updated ~daily), plus a local
#                      heuristic pattern file you can host & sign yourself.
#
#  Requirements (all standard on shared hosts, none need root):
#    bash 4+, coreutils (md5sum, sort, comm), grep, awk, find,
#    curl or wget, and ideally: php-cli (JSON parsing, WP-CLI),
#    mysql client (DB scan), openssl (signature verification).
#
#  Usage:
#    ./ratsweepr.sh                  interactive menu
#    ./ratsweepr.sh scan             full read-only scan -> report
#    ./ratsweepr.sh scan --since 2026-07-01   also list DB content
#                                     modified since a date
#    ./ratsweepr.sh update-sigs      refresh rfxn hash DB + pattern file
#    ./ratsweepr.sh baseline         hash premium plugins/themes on a
#                                     KNOWN-CLEAN site -> local manifests
#    ./ratsweepr.sh verify-baseline  compare current files to baselines
#    ./ratsweepr.sh quarantine FILE.report   quarantine files listed
#                                     in a scan report (asks confirmation)
#    ./ratsweepr.sh restore ID       restore a quarantine batch
#    ./ratsweepr.sh clean-core       replace ONLY core files that fail
#                                     checksum verification
#    ./ratsweepr.sh shuffle-salts    rotate wp-config.php auth salts
#
# ==============================================================================

set -u
umask 077

RS_VERSION="2.8.0"

# ------------------------------ configuration --------------------------------
# Everything lives under the invoking user's home; nothing touches system dirs.
RS_HOME="${RS_HOME:-$HOME/.ratsweepr}"
RS_SIG_DIR="$RS_HOME/signatures"
RS_QUARANTINE="$RS_HOME/quarantine"
RS_BASELINES="$RS_HOME/baselines"
RS_BIN="$RS_HOME/bin"
RS_CACHE="$RS_HOME/cache"

# Free maldet/rfxn MD5 malware hash database (format md5:size:name).
# Updated by the maintainer roughly daily. See rfxn.com / linux-malware-detect.
RFXN_HDB_URL="${RS_RFXN_URL:-https://www.rfxn.com/downloads/rfxn.hdb}"

# Your own heuristic pattern file (host the sample ratsweepr-sigs.conf on e.g.
# a GitHub repo and point this at the raw URL). Leave empty to use only the
# local/bundled copy.
PATTERN_URL="${RS_PATTERN_URL:-}"
# Optional: URL of the openssl signature for the pattern file (PATTERN_URL.sig)
# and the local path to your public key. If the pubkey exists, downloaded
# pattern files MUST verify or they are rejected.
PATTERN_PUBKEY="$RS_HOME/ratsweepr-pub.pem"

# Optional WPScan vulnerability API token (free tier available) for flagging
# plugins with known CVEs:  export WPSCAN_API_TOKEN=xxxx
WPSCAN_API_TOKEN="${WPSCAN_API_TOKEN:-}"

# ------------------------------ tiny toolbox ---------------------------------
C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[0;33m'
C_CYN=$'\033[0;36m'; C_OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s[ OK ]%s %s\n'   "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%s[WARN]%s %s\n'   "$C_YEL" "$C_OFF" "$*"; }
bad()  { printf '%s[FIND]%s %s\n'   "$C_RED" "$C_OFF" "$*"; }
info() { printf '%s[ .. ]%s %s\n'   "$C_CYN" "$C_OFF" "$*"; }
die()  { printf '%s[FAIL]%s %s\n'   "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

# report(): append a finding line to the machine-readable report.
# Format:  SEVERITY <TAB> CATEGORY <TAB> PATH-OR-ITEM <TAB> DETAIL
report() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$REPORT"; }

fetch() { # fetch URL OUTFILE  (curl or wget, whichever exists)
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsL --connect-timeout 15 -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 15 -O "$out" "$url"
    else
        return 1
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

php_json() { # php_json 'php-expression-using-$d' < file.json
    # Parses JSON on stdin into $d and runs the given expression. Requires php.
    php -r '$d=json_decode(stream_get_contents(STDIN),true); if(!is_array($d)){exit(2);} '"$1"
}

# ------------------------------ preflight ------------------------------------
preflight() {
    mkdir -p "$RS_HOME" "$RS_SIG_DIR" "$RS_QUARANTINE" "$RS_BASELINES" \
             "$RS_BIN" "$RS_CACHE"

    for t in grep awk find sort comm md5sum sha256sum; do
        have "$t" || die "'$t' is required but not available."
    done
    have curl || have wget || die "Need 'curl' or 'wget'."

    HAVE_PHP=0;     have php     && HAVE_PHP=1
    HAVE_MYSQL=0;   have mysql   && HAVE_MYSQL=1
    HAVE_OPENSSL=0; have openssl && HAVE_OPENSSL=1

    # Refuse to run as root: on shared hosting you never should be, and a bug
    # as root is catastrophic. (Override only if you truly know why.)
    if [ "$(id -u)" = "0" ] && [ "${RS_ALLOW_ROOT:-0}" != "1" ]; then
        die "Refusing to run as root. Run as the site user (RS_ALLOW_ROOT=1 to override)."
    fi

    # Must be executed from a WordPress root.
    WPROOT="$(pwd)"
    [ -f "$WPROOT/wp-config.php" ] || die "No wp-config.php here. cd into the WordPress root first."
    [ -f "$WPROOT/wp-includes/version.php" ] || die "wp-includes/version.php missing. Not a WordPress root?"

    WPVER="$(grep -E "\\\$wp_version\s*=" "$WPROOT/wp-includes/version.php" \
             | grep -Eo "([0-9]+\.)+[0-9]+" | head -1)"
    [ -n "$WPVER" ] || die "Could not determine the WordPress version."

    # Locate WP-CLI (optional but recommended). We never auto-install silently.
    WPCLI=""
    if have wp; then WPCLI="wp"
    elif [ -f "$RS_BIN/wp-cli.phar" ] && [ "$HAVE_PHP" = "1" ]; then
        WPCLI="php $RS_BIN/wp-cli.phar"
    fi

    RUNSTAMP="$(date +%Y-%m-%d_%H%M%S)"
    REPORT="$WPROOT/ratsweepr-$RUNSTAMP.report"
    LOG="$WPROOT/ratsweepr-$RUNSTAMP.log"
}

banner() {
    say ""
    say "  RATSWEEPR  v$RS_VERSION   (report-first, quarantine, no-root)"
    say "  Site: $WPROOT"
    say "  WordPress: $WPVER    WP-CLI: ${WPCLI:-not found}    php: $HAVE_PHP  mysql: $HAVE_MYSQL"
    say ""
}

backup_gate() {
    say ""
    warn "==================== BACKUP CHECK ===================="
    warn "This action will MODIFY your site (quarantine/replace files"
    warn "or edit wp-config.php). RatSweepr does not create backups."
    warn "Before continuing, make a FULL backup yourself:"
    warn "  - all files (e.g. tar -czf ~/site-backup.tgz .)"
    warn "  - the database (e.g. wp db export ~/db-backup.sql)"
    warn "======================================================="
    printf 'Type exactly "I HAVE A BACKUP" to continue: '
    read -r answer
    [ "$answer" = "I HAVE A BACKUP" ] || die "Aborted. No changes were made."
}

# ========================== SIGNATURE MANAGEMENT ==============================
# Two feeds, both free:
#   1. rfxn.hdb        - MD5 hash DB from Linux Malware Detect (~10k sigs)
#   2. patterns.conf   - heuristic grep patterns + piracy domains + bad
#                        wp_options keys. Bundled defaults below; you can host
#                        an updated copy (PATTERN_URL) and sign it with openssl.

write_default_patterns() {
    # Bundled fallback so the scanner works offline out of the box.
    printf '# RatSweepr bundled patterns [bundled-version: %s]\n' "$RS_VERSION" \
        > "$RS_SIG_DIR/patterns.conf"
    cat >> "$RS_SIG_DIR/patterns.conf" << 'EOSIG'
# RatSweepr heuristic signature file
# Lines:  TYPE|NAME|VALUE          (TYPE: GREP, FNAME, DOMAIN, OPTION)
# GREP   = POSIX-extended regex applied to php/ico/suspected files (review!)
# FNAME  = suspicious file name glob for `find -name`
# DOMAIN = nulled/piracy or malware distribution domain to grep for
# OPTION = wp_options keys left behind by nulled plugins
#
# --- generic webshell / injection constructs (high signal, still REVIEW) ---
GREP|eval_base64|eval[[:space:]]*\(([[:space:]]*@)?[[:space:]]*base64_decode
GREP|eval_gzinflate|eval[[:space:]]*\(([[:space:]]*@)?[[:space:]]*gz(inflate|uncompress)
GREP|eval_request|(eval|assert)[[:space:]]*\([[:space:]]*(stripslashes[[:space:]]*\()?[[:space:]]*\$_(POST|GET|REQUEST|COOKIE)
GREP|preg_replace_e_modifier|preg_replace[[:space:]]*\([[:space:]]*['\"][^'\"]*/[a-zA-Z]*e[a-zA-Z]*['\"]
GREP|create_function_request|create_function[[:space:]]*\([^)]*\$_(POST|GET|REQUEST)
GREP|str_rot13_base64|str_rot13[[:space:]]*\([[:space:]]*base64_decode
GREP|globals_hex_obfuscation|\$\{["']\\x47L?\\x4[fF]
GREP|filesman_shell|FilesMan|Files[[:space:]]*Man
GREP|wso_shell|wso_version|WSOsetcookie
GREP|b374k_marker|b374k
GREP|c99_marker|c99sh_|c99shell
GREP|leaf_mailer|leafmailer|Leaf[[:space:]]PHP[[:space:]]Mailer
GREP|move_uploaded_generic|copy[[:space:]]*\([[:space:]]*\$_FILES\[[^]]+\]\[.tmp_name.\]
GREP|gif_header_in_php_file|^GIF89a
#
# --- nulled-plugin behaviors (CaptainCore drift findings) ---
GREP|pre_http_request_hook|add_filter[[:space:]]*\([[:space:]]*['\"]pre_http_request
GREP|update_hook_priority_abuse|add_filter[[:space:]]*\([^,]*update_plugins[^,]*,[^,]*,[[:space:]]*9{6,}
GREP|sslverify_disabled|['\"]sslverify['\"][[:space:]]*=>[[:space:]]*false
#
#
# --- self-concealment & fake-plugin behaviors (GREPHIGH = HIGH severity) ---
GREPHIGH|hides_self_unset_php|unset[[:space:]]*\([[:space:]]*\$[a-zA-Z_]+\[['"][^]]*/[^]]*\.php['"]
GREPHIGH|hides_admin_users_prequery|add_(action|filter)[[:space:]]*\([[:space:]]*['"]pre_user_query['"]
GREPHIGH|hides_admin_users_views|add_filter[[:space:]]*\([[:space:]]*['"]views_users['"]
GREPHIGH|variable_function_eval|\$[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([[:space:]]*gzinflate[[:space:]]*\([[:space:]]*base64_decode
#
# --- suspicious file names ---
FNAME|hidden_ico|.*.ico
FNAME|suspected_ext|*.suspected
FNAME|input_dropper|_input_*
FNAME|vuln_probe|vuln.php
#
# --- piracy / nulled distribution domains (extend as you find more) ---
DOMAIN|gpltimes|gpltimes.com
DOMAIN|gplvault|gplvault.com
DOMAIN|festinger|festingervault.com
DOMAIN|worldpressit|worldpressit.com
DOMAIN|gpldl|gpldl.com
DOMAIN|srmehranclub|srmehranclub.com
DOMAIN|weadown|weadown.com
DOMAIN|babiato|babiato.co
#
# --- wp_options residue from nulled plugins ---
OPTION|gplstatus
OPTION|gpltokenid
OPTION|rg_gforms_key
OPTION|fusion_registration_data
OPTION|monsterinsights_license
#
# --- known-vulnerable WordPress core versions (CORE_VULN|label|min|max|fixed|note) ---
# max is INCLUSIVE. Version compare is dotted-numeric. Update via signed feed.
CORE_VULN|wp2shell (CVE-2026-63030+60137, unauth RCE)|6.9.0|6.9.4|6.9.5|REST API batch-route RCE chain; block /wp-json/batch/v1 if you cannot upgrade
CORE_VULN|wp2shell (CVE-2026-63030+60137, unauth RCE)|7.0.0|7.0.1|7.0.2|REST API batch-route RCE chain; block /wp-json/batch/v1 if you cannot upgrade
CORE_VULN|CVE-2026-60137 (SQLi, author__not_in)|6.8.0|6.8.5|6.8.6|WP_Query SQL injection; upgrade to 6.8.6+
#
# --- external-request allowlist (ALLOWHOST|host, suffix match) ---
ALLOWHOST|elementor.com
ALLOWHOST|automattic.com
ALLOWHOST|akismet.com
ALLOWHOST|wordfence.com
ALLOWHOST|woocommerce.com
ALLOWHOST|kinsta.com
ALLOWHOST|kinsta.cloud
#
# --- trusted vendor paths (ALLOWPATH|prefix|reinstall-url-or-dash) ---
# Heuristic & external-request findings under these prefixes are downgraded to
# INFO (integrity/malware-hash findings are NOT downgraded). reinstall-url, if
# present, is surfaced so you can refresh the component.
ALLOWPATH|wp-content/mu-plugins/kinsta-mu-plugins|https://kinsta.com/kinsta-tools/kinsta-mu-plugins.zip
EOSIG
    ok "Wrote bundled heuristic patterns -> $RS_SIG_DIR/patterns.conf"
}

update_signatures() {
    info "Updating rfxn/maldet MD5 hash database..."
    local tmp="$RS_CACHE/rfxn.hdb.$$"
    if fetch "$RFXN_HDB_URL" "$tmp" && [ -s "$tmp" ] \
       && head -1 "$tmp" | grep -Eq '^[0-9a-f]{32}:'; then
        mv "$tmp" "$RS_SIG_DIR/rfxn.hdb"
        ok "rfxn.hdb updated: $(wc -l < "$RS_SIG_DIR/rfxn.hdb") MD5 signatures."
    else
        rm -f "$tmp"
        warn "Could not fetch/validate rfxn.hdb (offline or URL changed). Keeping existing copy."
    fi

    if [ -n "$PATTERN_URL" ]; then
        info "Updating heuristic pattern file from $PATTERN_URL ..."
        local ptmp="$RS_CACHE/patterns.conf.$$"
        if fetch "$PATTERN_URL" "$ptmp" && [ -s "$ptmp" ]; then
            if [ -f "$PATTERN_PUBKEY" ]; then
                if [ "$HAVE_OPENSSL" != "1" ]; then
                    warn "openssl missing; cannot verify signed patterns. Rejecting download."
                    rm -f "$ptmp"; return
                fi
                local stmp="$RS_CACHE/patterns.sig.$$"
                if fetch "${PATTERN_URL}.sig" "$stmp" \
                   && openssl dgst -sha256 -verify "$PATTERN_PUBKEY" \
                        -signature "$stmp" "$ptmp" >/dev/null 2>&1; then
                    mv "$ptmp" "$RS_SIG_DIR/patterns.conf"
                    ok "Pattern file updated (openssl signature VERIFIED)."
                else
                    warn "Pattern file signature FAILED verification. Rejected."
                    rm -f "$ptmp"
                fi
                rm -f "$stmp"
            else
                warn "No public key at $PATTERN_PUBKEY - installing UNVERIFIED pattern file."
                warn "Strongly consider signing (see README)."
                mv "$ptmp" "$RS_SIG_DIR/patterns.conf"
            fi
        else
            rm -f "$ptmp"; warn "Could not fetch pattern file."
        fi
    fi
    [ -f "$RS_SIG_DIR/patterns.conf" ] || write_default_patterns
}

load_signatures() {
    # Refresh bundled patterns if missing or stamped with an older version, so
    # `curl | bash` picks up new signatures on every script update. A signed
    # remote pattern file (PATTERN_URL) is never clobbered.
    local bundled_ver=""
    [ -f "$RS_SIG_DIR/patterns.conf" ] && \
        bundled_ver="$(sed -n 's/.*\[bundled-version: \([0-9.]*\)\].*/\1/p' "$RS_SIG_DIR/patterns.conf" | head -1)"
    if [ ! -s "$RS_SIG_DIR/patterns.conf" ] || \
       { [ -z "${PATTERN_URL:-}" ] && [ "$bundled_ver" != "$RS_VERSION" ]; }; then
        write_default_patterns
    fi
    PATTERNS_FILE="$RS_SIG_DIR/patterns.conf"
    HDB_FILE="$RS_SIG_DIR/rfxn.hdb"
}

# =============================== SCANNERS =====================================
# Every scanner is strictly read-only: findings go to $REPORT, nothing else.

# List of PHP-ish files once, reused by several scanners. Excludes quarantine
# and our own reports. NUL-safe.
build_php_filelist() {
    PHPLIST="$RS_CACHE/philist.$$"
    find "$WPROOT" \( -path "$WPROOT/wp-content/cache" -prune \) -o \
         -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' \
                    -o -name '*.suspected' -o -name '.*.ico' \) -print0 \
         > "$PHPLIST" 2>/dev/null
}

# ver_le A B  -> returns 0 (true) if dotted-numeric A <= B
ver_le() {
    [ "$1" = "$2" ] && return 0
    local lo
    lo="$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | head -1)"
    [ "$lo" = "$1" ]
}

scan_core_vulns() {
    info "Checking WordPress $WPVER against known core vulnerabilities..."
    local label lo hi fixed note hit=0
    while IFS='|' read -r type label lo hi fixed note; do
        [ "$type" = "CORE_VULN" ] || continue
        if ver_le "$lo" "$WPVER" && ver_le "$WPVER" "$hi"; then
            hit=1
            report "HIGH" "core-vulnerable" "WordPress $WPVER" \
                "$label — fixed in $fixed. $note"
            warn "VULNERABLE CORE: $label"
            warn "  Your version : $WPVER"
            warn "  Fixed in     : $fixed"
            warn "  ACTION: upgrade now ->  wp core update"
            case "$label" in
              *batch-route*|*wp2shell*|*63030*)
                warn "  If you cannot upgrade immediately, block the batch endpoint at the"
                warn "  server/WAF layer. BOTH forms must be blocked (permalink AND query):"
                warn "    Apache (.htaccess, before WP rules):"
                warn "      RewriteEngine On"
                warn "      RewriteRule ^wp-json/batch/v1 - [F,L]"
                warn "      RewriteCond %{QUERY_STRING} (^|&)rest_route=/?batch/v1 [NC]"
                warn "      RewriteRule .* - [F,L]"
                warn "    Nginx (server block):"
                warn "      location ~* ^/wp-json/batch/v1 { return 403; }"
                warn "      if (\$args ~* \"(^|&)rest_route=/?batch/v1\") { return 403; }"
                warn "  NOTE: this is a stopgap; some plugins use the batch API. Upgrading is the real fix.";;
            esac
        fi
    done < "$PATTERNS_FILE"
    [ "$hit" = "0" ] && ok "No known core vulnerabilities for $WPVER."
}

scan_core_checksums() {
    info "Verifying WordPress $WPVER core files against api.wordpress.org checksums..."
    if [ "$HAVE_PHP" != "1" ]; then
        warn "php-cli not found: skipping core checksum verification."
        report "WARN" "core" "-" "php missing, core checksums skipped"
        return
    fi
    local js="$RS_CACHE/core-$WPVER.json"
    if [ ! -s "$js" ]; then
        fetch "https://api.wordpress.org/core/checksums/1.0/?version=$WPVER&locale=en_US" "$js" \
            || { warn "Could not download core checksums."; return; }
    fi
    local manifest="$RS_CACHE/core-$WPVER.md5"
    php_json 'foreach($d["checksums"] as $f=>$m) echo $m."  ".$f."\n";' \
        < "$js" > "$manifest" 2>/dev/null
    if [ ! -s "$manifest" ]; then
        warn "Checksum API returned no data for $WPVER."; return
    fi

    local fails=0 faillist="$RS_CACHE/core-fails.$$"
    : > "$faillist"
    # md5sum -c reports FAILED / missing files; --quiet hides the OKs.
    while IFS= read -r line; do
        local f="${line%%:*}"
        printf '%s\n' "$f" >> "$faillist"
        case "$line" in
            *": FAILED open or read")
                case "$f" in
                    wp-config-sample.php) report "INFO" "core-sample-missing" "$f" \
                        "wp-config-sample.php absent - commonly removed as hardening, not an infection sign";;
                    wp-content/*) report "INFO" "core-bundled-missing" "$f" \
                        "bundled default theme/plugin file absent (often intentional)";;
                    *) report "HIGH" "core-missing" "$f" "core file missing or unreadable";;
                esac;;
            *": FAILED"*)
                report "HIGH" "core-modified" "$f" "does not match official $WPVER checksum";;
        esac
        fails=$((fails+1))
    done < <(cd "$WPROOT" && md5sum -c --quiet "$manifest" 2>/dev/null)
    # Every manifest file that did NOT fail is integrity-verified: heuristics
    # must never flag a file that is byte-identical to the official release.
    comm -23 <(awk '{print $2}' "$manifest" | sort) <(sort -u "$faillist") >> "$VERIFIED"

    # Files present on disk in core dirs but NOT in the manifest = dropped files.
    local expected="$RS_CACHE/core-expected.$$" actual="$RS_CACHE/core-actual.$$"
    awk '{print $2}' "$manifest" | grep -Ev '^wp-content/' | sort > "$expected"
    ( cd "$WPROOT" && find wp-admin wp-includes -type f 2>/dev/null ; \
      find . -maxdepth 1 -type f -name '*.php' ! -name 'wp-config.php' \
           -printf '%P\n' 2>/dev/null || \
      find . -maxdepth 1 -type f -name '*.php' ! -name 'wp-config.php' \
           | sed 's|^\./||' ) | sort -u > "$actual"
    while IFS= read -r extra; do
        report "HIGH" "core-unknown-file" "$extra" "file exists in core area but not in official $WPVER manifest"
    done < <(comm -13 "$expected" "$actual")
    rm -f "$expected" "$actual"
    ok "Core verification done."
}

scan_plugin_checksums() {
    info "Verifying plugins against downloads.wordpress.org plugin-checksums..."
    [ -d "$WPROOT/wp-content/plugins" ] || return
    if [ "$HAVE_PHP" != "1" ]; then
        warn "php-cli not found: skipping plugin checksum verification."
        return
    fi
    local plugdir slug ver mainfile js manifest
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        # find plugin version from its headers
        ver=""
        for mainfile in "$plugdir$slug.php" "$plugdir"*.php; do
            [ -f "$mainfile" ] || continue
            ver="$(grep -iE '^[[:space:]*/]*Version:' "$mainfile" 2>/dev/null \
                   | head -1 | grep -Eo '([0-9]+\.)+[0-9]+' | head -1)"
            [ -n "$ver" ] && break
        done
        if [ -z "$ver" ]; then
            report "INFO" "plugin-noversion" "wp-content/plugins/$slug" "could not read version header"
            continue
        fi
        js="$RS_CACHE/plugin-$slug-$ver.json"
        if [ ! -s "$js" ]; then
            fetch "https://downloads.wordpress.org/plugin-checksums/$slug/$ver.json" "$js" \
                || { report "INFO" "plugin-premium" "wp-content/plugins/$slug ($ver)" \
                     "not on wordpress.org - verify via 'baseline' workflow"; rm -f "$js"; continue; }
        fi
        manifest="$RS_CACHE/plugin-$slug-$ver.list"
        # Emits: relpath <TAB> md5a,md5b  (the API may list several valid md5s)
        php_json 'if(!isset($d["files"])) exit(2);
            foreach($d["files"] as $f=>$i){ $m=$i["md5"];
              if(is_array($m)) $m=implode(",",$m);
              echo $f."\t".$m."\n"; }' < "$js" > "$manifest" 2>/dev/null
        [ -s "$manifest" ] || { report "INFO" "plugin-premium" "wp-content/plugins/$slug ($ver)" \
                                "no checksum data on wordpress.org"; continue; }

        local rel md5s cur missing=0 modified=0
        while IFS=$'\t' read -r rel md5s; do
            if [ ! -f "$plugdir$rel" ]; then missing=$((missing+1)); continue; fi
            cur="$(md5sum "$plugdir$rel" | awk '{print $1}')"
            case ",$md5s," in
                *",$cur,"*) printf '%s\n' "wp-content/plugins/$slug/$rel" >> "$VERIFIED" ;;
                *) modified=$((modified+1))
                   report "HIGH" "plugin-modified" "wp-content/plugins/$slug/$rel" \
                          "does not match official $slug $ver checksums";;
            esac
        done < "$manifest"
        # extra files inside the plugin dir not in the manifest
        local expected="$RS_CACHE/pl-exp.$$" actual="$RS_CACHE/pl-act.$$"
        cut -f1 "$manifest" | sort > "$expected"
        ( cd "$plugdir" && find . -type f | sed 's|^\./||' ) | sort > "$actual"
        while IFS= read -r extra; do
            report "MED" "plugin-unknown-file" "wp-content/plugins/$slug/$extra" \
                   "file not in official $slug $ver package"
        done < <(comm -13 "$expected" "$actual")
        rm -f "$expected" "$actual"
        [ "$modified" = "0" ] || bad "$slug: $modified modified file(s)"
    done
    ok "Plugin verification done."
}

scan_uploads_php() {
    info "Scanning wp-content/uploads for PHP files (should contain none)..."
    [ -d "$WPROOT/wp-content/uploads" ] || return
    while IFS= read -r -d '' f; do
        report "HIGH" "php-in-uploads" "${f#"$WPROOT"/}" "executable PHP inside uploads - almost always malicious"
    done < <(find "$WPROOT/wp-content/uploads" -type f \
             \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' \) -print0)
    ok "Uploads scan done."
}

scan_hashdb() {
    if [ ! -s "${HDB_FILE:-}" ]; then
        warn "rfxn.hdb not present - run 'update-sigs' first to enable hash scanning."
        return
    fi
    info "Scanning against rfxn/maldet MD5 database ($(wc -l < "$HDB_FILE") signatures)..."
    local hashes="$RS_CACHE/site-hashes.$$"
    xargs -0 md5sum < "$PHPLIST" 2>/dev/null > "$hashes" || true
    # join site hashes against hdb (md5:size:name). md5sum output is
    # "32-char-hash<2 chars>path", so the path starts at column 35.
    awk 'NR==FNR { split($0, a, ":"); sig[a[1]] = a[3]; next }
         { h = substr($0, 1, 32); p = substr($0, 35);
           if (h in sig) printf "%s\t%s\n", p, sig[h] }' \
        "$HDB_FILE" "$hashes" | while IFS=$'\t' read -r f name; do
            report "HIGH" "known-malware" "${f#"$WPROOT"/}" "matches maldet signature: $name"
        done
    rm -f "$hashes"
    ok "Hash database scan done."
}

# allowpath_check REL -> returns 0 if REL is under a trusted vendor prefix,
# and sets ALLOWPATH_URL to its reinstall URL (or empty).
allowpath_check() {
    local rel="$1" pfx url
    ALLOWPATH_URL=""
    while IFS='|' read -r type pfx url; do
        [ "$type" = "ALLOWPATH" ] || continue
        case "$rel" in "$pfx"/*|"$pfx") ALLOWPATH_URL="$url"; return 0;; esac
    done < "$PATTERNS_FILE"
    return 1
}

write_bundled_yara() {
    printf '// bundled-version: %s\n' "$RS_VERSION" > "$1"
    cat >> "$1" << 'RSYARA'
/*
   RatSweepr bundled YARA rules — WordPress webshell & backdoor detection.
   Self-contained (no includes). Operators can supplement with maintained
   rulesets (php-malware-finder, signature-base) via RS_YARA_RULES=/path.
*/

rule RS_eval_user_input {
    meta:
        description = "eval/assert of user-controlled input"
        severity = "HIGH"
    strings:
        $a = /(eval|assert)\s*\(\s*(stripslashes\s*\()?\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $b = /(eval|assert)\s*\(\s*\$[a-zA-Z_]+\s*\)/ nocase
    condition:
        any of them
}

rule RS_command_exec_user_input {
    meta:
        description = "OS command execution with user input"
        severity = "HIGH"
    strings:
        $a = /(system|passthru|shell_exec|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $b = /(system|passthru|shell_exec)\s*\(\s*["']?\s*\$_(GET|POST|REQUEST)/ nocase
    condition:
        any of them
}

rule RS_obfuscated_eval_chain {
    meta:
        description = "eval of decoded/inflated payload"
        severity = "HIGH"
    strings:
        $a = /eval\s*\(\s*(gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(/ nocase
        $b = /\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*(gzinflate|gzuncompress)\s*\(\s*base64_decode/ nocase
    condition:
        any of them
}

rule RS_hex_obfuscated_hooks {
    meta:
        description = "WordPress hook names hex-escaped to evade grep (nulled/backdoor)"
        severity = "HIGH"
    strings:
        $a = /add_(action|filter)\s*\(\s*["'](\\x[0-9a-fA-F]{2}|\\[0-9]{2,3}){4,}/ nocase
    condition:
        $a
}

rule RS_fake_wordpress_plugin {
    meta:
        description = "Plugin falsely attributed to WordPress.org"
        severity = "HIGH"
    strings:
        $a = /Author URI:\s*https?:\/\/wordpress\.org\/#/ nocase
        $b = "Official WordPress plugin" nocase
    condition:
        any of them
}

rule RS_self_hiding_plugin {
    meta:
        description = "Plugin hides itself from the admin plugin list"
        severity = "HIGH"
    strings:
        $a = /unset\s*\([^)]*wp_list_table->items/ nocase
        $b = /unset\s*\(\s*\$[a-zA-Z_]+\[['"][^]]*\/[^]]*\.php['"]\s*\]\s*\)\s*;/
    condition:
        any of them
}

rule RS_php_in_disguise {
    meta:
        description = "PHP code with image/asset header (fake image shell)"
        severity = "HIGH"
    strings:
        $gif = /^GIF8[79]a/
        $php = "<?php"
    condition:
        $gif at 0 and $php
}

rule RS_hmac_authed_backdoor {
    meta:
        description = "HMAC-authenticated request handler feeding eval (RAT)"
        severity = "HIGH"
    strings:
        $h = /hash_hmac\s*\(\s*["']sha256["'][^)]*\$_(POST|GET|SERVER|REQUEST)/ nocase
        $e = /eval\s*\(\s*base64_decode/ nocase
    condition:
        $h and $e
}

rule RS_uploader_shell {
    meta:
        description = "File uploader (potential webshell dropper)"
        severity = "MEDIUM"
    strings:
        $a = /move_uploaded_file\s*\([^)]*\$_FILES/ nocase
        $b = /\$_FILES\[[^]]+\]\[['"]tmp_name/ nocase
    condition:
        all of them
}

rule RS_large_base64_payload {
    meta:
        description = "Large base64 blob decoded (packed payload)"
        severity = "HIGH"
    strings:
        $a = /base64_decode\s*\(\s*["'][A-Za-z0-9+\/]{200,}/ nocase
    condition:
        $a
}

RSYARA
}

scan_yara() {
    local rulesdir="$RS_SIG_DIR/yara"
    mkdir -p "$rulesdir"

    # --- rules: bundled (stale-refreshed) + operator dir + online feed (Path B) ---
    local bver=""
    [ -f "$rulesdir/ratsweepr.yar" ] && bver="$(sed -n 's#.*bundled-version: \([0-9.]*\).*#\1#p' "$rulesdir/ratsweepr.yar" | head -1)"
    [ "$bver" = "$RS_VERSION" ] || write_bundled_yara "$rulesdir/ratsweepr.yar"

    # Path B: pull an updatable rule feed over HTTPS (no engine needed to fetch).
    if [ -n "${RS_RULES_URL:-}" ]; then
        local rtmp="$RS_CACHE/remote.yar.$$"
        if fetch "$RS_RULES_URL" "$rtmp" && grep -q '^rule ' "$rtmp" 2>/dev/null; then
            if [ -f "$PATTERN_PUBKEY" ] && [ "$HAVE_OPENSSL" = "1" ]; then
                local rsig="$RS_CACHE/remote.yar.sig.$$"
                if fetch "${RS_RULES_URL}.sig" "$rsig" \
                   && openssl dgst -sha256 -verify "$PATTERN_PUBKEY" -signature "$rsig" "$rtmp" >/dev/null 2>&1; then
                    mv "$rtmp" "$rulesdir/remote.yar"; ok "Pulled online YARA rules (signature VERIFIED)."
                else
                    warn "Online YARA rules failed signature check - rejected."; rm -f "$rtmp"
                fi
                rm -f "$rsig"
            else
                mv "$rtmp" "$rulesdir/remote.yar"; info "Pulled online YARA rules (UNVERIFIED - set a public key to require signing)."
            fi
        else
            rm -f "$rtmp"
        fi
    fi

    # collect all rule files
    local rulefiles=(); rulefiles+=("$rulesdir/ratsweepr.yar")
    [ -f "$rulesdir/remote.yar" ] && rulefiles+=("$rulesdir/remote.yar")
    if [ -n "${RS_YARA_RULES:-}" ] && [ -d "$RS_YARA_RULES" ]; then
        while IFS= read -r rf; do rulefiles+=("$rf"); done \
            < <(find "$RS_YARA_RULES" \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null)
    fi

    # --- engine: system yara, else Path A (auto-download static yara-x), else native ---
    ensure_yara_engine
    local engine_desc="native (grep) matcher"
    [ -n "$YARA_ENGINE" ] && engine_desc="$($YARA_ENGINE --version 2>/dev/null | head -1 || echo engine)"

    local total_rules=0 rf
    for rf in "${rulefiles[@]}"; do
        total_rules=$((total_rules + $(grep -c '^rule ' "$rf" 2>/dev/null || echo 0)))
    done
    info "Running YARA scan: $total_rules rules via $engine_desc ..."

    local nmatch=0 rel
    while IFS= read -r -d '' f; do
        rel="${f#"$WPROOT"/}"
        grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
        for rf in "${rulefiles[@]}"; do
            local rulehits
            if [ -n "$YARA_ENGINE" ]; then
                rulehits="$("$YARA_ENGINE" "$rf" "$f" 2>/dev/null | awk '{print $1}')"
            else
                rulehits="$(native_yara "$rf" "$f")"
            fi
            local rule
            while IFS= read -r rule; do
                [ -n "$rule" ] || continue
                local sev="HIGH"; case "$rule" in *uploader*|*_MEDIUM*|*_MED*) sev="MED";; esac
                allowpath_check "$rel" && sev="INFO"
                report "$sev" "yara:$rule" "$rel" "matched YARA rule $rule"
                nmatch=$((nmatch+1))
            done <<< "$rulehits"
        done
    done < "$PHPLIST"
    ok "YARA scan done ($nmatch match(es))."
}

# ensure_yara_engine: sets YARA_ENGINE to a runnable binary, or "" for native.
ensure_yara_engine() {
    YARA_ENGINE=""
    if have yara; then YARA_ENGINE="yara"; return; fi
    if [ -x "$RS_BIN/yr" ]; then YARA_ENGINE="$RS_BIN/yr"; return; fi
    # Path A: try downloading a static yara-x binary (opt-out with RS_NO_ENGINE_DL=1)
    if [ "${RS_NO_ENGINE_DL:-0}" != "1" ]; then
        local arch="" ; case "$(uname -m)" in
            x86_64|amd64) arch="x86_64-unknown-linux-musl";;
            aarch64|arm64) arch="aarch64-unknown-linux-musl";;
        esac
        if [ -n "$arch" ]; then
            info "No YARA engine found; attempting one-time static engine download..."
            local url="${RS_YARAX_URL:-https://github.com/VirusTotal/yara-x/releases/latest/download/yara-x-cli-${arch}.gz}"
            local gz="$RS_CACHE/yrx.gz.$$"
            if fetch "$url" "$gz" && [ -s "$gz" ]; then
                if gunzip -c "$gz" > "$RS_BIN/yr" 2>/dev/null && chmod +x "$RS_BIN/yr" \
                   && "$RS_BIN/yr" --version >/dev/null 2>&1; then
                    YARA_ENGINE="$RS_BIN/yr"; ok "Static YARA engine installed -> $RS_BIN/yr"
                else
                    rm -f "$RS_BIN/yr"
                    warn "Downloaded engine did not run (host may be noexec) - using native matcher."
                fi
            else
                info "Engine download unavailable - using native matcher."
            fi
            rm -f "$gz"
        fi
    fi
}

# native_yara: minimal YARA-subset matcher (strings + regex + any/all-of-them),
# used when no engine binary is available. Rules with positional/module/complex
# conditions are skipped (only a real engine evaluates those faithfully).
native_yara() {
    local rulefile="$1" target="$2"
    awk -v TARGET="$target" '
    function reset(){ rule=""; nstr=0; delete strs; delete isregex; allof=0; skip=0; condtext="" }
    function q(s){ gsub(/\x27/,"\x27\\\x27\x27",s); return "\x27" s "\x27" }
    /^[[:space:]]*rule[[:space:]]+/ { reset(); rule=$2; sub(/[^a-zA-Z0-9_].*/,"",rule); next }
    /^[[:space:]]*\$[a-zA-Z0-9_]*[[:space:]]*=/ {
        line=$0; val=line
        sub(/^[[:space:]]*\$[a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*/,"",val)
        gsub(/[[:space:]]+(nocase|wide|ascii|fullword).*$/,"",val)
        if (val ~ /^".*"/) { s=val; sub(/^"/,"",s); sub(/".*$/,"",s); strs[nstr]=s; isregex[nstr]=0; nstr++ }
        else if (val ~ /^\/.*\//) { s=val; sub(/^\//,"",s); sub(/\/[a-z]*[[:space:]]*$/,"",s); strs[nstr]=s; isregex[nstr]=1; nstr++ }
        else { skip=1 }
        next
    }
    /^[[:space:]]*condition[[:space:]]*:/ { incond=1; condtext=$0; sub(/.*condition[[:space:]]*:/,"",condtext); next }
    incond && !/^[[:space:]]*\}/ { condtext=condtext " " $0 }
    /^[[:space:]]*\}/ {
        if (rule!="" && nstr>0 && !skip) {
            if (condtext ~ /at |in \(|filesize|@|# |hash\.|pe\.|math\.| and .* and | or .* and |not /) {
                # unsupported by native matcher -> skip
            } else {
                allof=(condtext ~ /all of them/); matched=0
                for (i=0;i<nstr;i++) {
                    cmd=(isregex[i]?"grep -lE -- ":"grep -lF -- ") q(strs[i]) " " q(TARGET) " 2>/dev/null"
                    if ((cmd|getline r)>0 && r!="") matched++
                    close(cmd)
                }
                if ((allof && matched==nstr) || (!allof && matched>0)) print rule
            }
        }
        incond=0; reset(); next
    }
    ' "$rulefile"
}

scan_heuristics() {
    info "Running heuristic pattern scan (grep, from patterns.conf)..."
    local name rex n=0
    while IFS='|' read -r type name rex; do
        case "$type" in \#*|"") continue;; esac
        if [ "$type" = "GREP" ] || [ "$type" = "GREPHIGH" ]; then
            n=$((n+1))
            local basesev="MED"; [ "$type" = "GREPHIGH" ] && basesev="HIGH"
            while IFS= read -r -d '' f; do
                rel="${f#"$WPROOT"/}"
                grep -Fxq "$rel" "$VERIFIED" 2>/dev/null && continue
                if allowpath_check "$rel"; then
                    report "INFO" "heuristic:$name" "$rel" "matched '$name' in trusted vendor path (kinsta-mu et al) - expected"
                else
                    report "$basesev" "heuristic:$name" "$rel" "matched pattern '$name' - REVIEW"
                fi
            done < <(xargs -0 grep -lIE --null -e "$rex" < "$PHPLIST" 2>/dev/null || true)
        elif [ "$type" = "FNAME" ]; then
            while IFS= read -r -d '' f; do
                report "MED" "filename:$name" "${f#"$WPROOT"/}" "suspicious file name pattern"
            done < <(find "$WPROOT" -type f -name "$rex" -print0 2>/dev/null)
        fi
    done < "$PATTERNS_FILE"
    ok "Heuristic scan done ($n grep patterns)."
}

scan_nulled() {
    info "Checking for nulled-plugin indicators..."
    # 1. piracy domain references anywhere in PHP
    local name dom
    while IFS='|' read -r type name dom; do
        [ "$type" = "DOMAIN" ] || continue
        while IFS= read -r -d '' f; do
            grep -Fxq "${f#"$WPROOT"/}" "$VERIFIED" 2>/dev/null && continue
            report "HIGH" "nulled-domain:$name" "${f#"$WPROOT"/}" "references piracy/nulled domain $dom"
        done < <(xargs -0 grep -lIF --null -e "$dom" < "$PHPLIST" 2>/dev/null || true)
    done < "$PATTERNS_FILE"

    # 2. absurd version pins (the 'version 9999' trick blocks all updates)
    local plugdir slug mainfile ver
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        for mainfile in "$plugdir"*.php; do
            [ -f "$mainfile" ] || continue
            grep -qiE '^[[:space:]*/]*Plugin Name:' "$mainfile" 2>/dev/null || continue
            ver="$(grep -iE '^[[:space:]*/]*Version:' "$mainfile" 2>/dev/null \
                   | head -1 | grep -Eo '[0-9]+' | head -1)"
            # 999-99999: the "version 9999" update-blocker. 8-digit date versions excluded.
            if [ -n "$ver" ] && [ "$ver" -ge 999 ] 2>/dev/null && [ "$ver" -le 99999 ] 2>/dev/null; then
                report "HIGH" "nulled-version-pin" "wp-content/plugins/$slug" \
                       "version pinned at $ver - classic nulled-plugin update blocker"
            fi
            break
        done
    done
    ok "Nulled-plugin check done."
}

scan_external_requests() {
    info "Discovering external request destinations (runtime HTTP calls)..."
    # Allowlist of hosts that are unremarkable for a WP site to contact. Extend
    # via ALLOWHOST lines in patterns.conf. Matched as suffix (api.x.com ~ x.com).
    local allow="$RS_CACHE/allowhosts.$$"
    {
        printf '%s\n' wordpress.org api.wordpress.org downloads.wordpress.org \
            s.w.org gravatar.com secure.gravatar.com google.com googleapis.com \
            gstatic.com youtube.com youtu.be vimeo.com fonts.googleapis.com \
            fonts.gstatic.com facebook.com graph.facebook.com twitter.com x.com \
            github.com githubusercontent.com w3.org schema.org gmpg.org \
            paypal.com stripe.com cloudflare.com jsdelivr.net unpkg.com
        awk -F'|' '$1=="ALLOWHOST"{print $2}' "$PATTERNS_FILE"
    } | sort -u > "$allow"

    # Pull lines where a URL is an argument to a real HTTP call. Emit host<TAB>file<TAB>line<TAB>flags
    local hits="$RS_CACHE/exthits.$$"; : > "$hits"
    while IFS= read -r -d '' f; do
        # scan PHP-ish files only; skip integrity-verified core/plugin files
        grep -Fxq "${f#"$WPROOT"/}" "$VERIFIED" 2>/dev/null && continue
        awk -v REL="${f#"$WPROOT"/}" '
            {
                line=$0
                # only lines that both contain a request primitive AND a url
                if (line ~ /(wp_remote_(get|post|request|head)|wp_safe_remote|file_get_contents|curl_setopt|curl_init|fopen|fsockopen|@?file|readfile|copy)\s*\(/ \
                    && match(line, /https?:\/\/[^"'"'"' )]+/)) {
                    url=substr(line, RSTART, RLENGTH)
                    host=url; sub(/^https?:\/\//,"",host); sub(/[\/:?].*/,"",host)
                    if (host=="" || host ~ /\$\{?[a-zA-Z_]/) next   # skip variable hosts
                    flags=""
                    if (url ~ /^http:\/\//) flags=flags "PLAINTEXT,"
                    if (line ~ /sslverify[^,]*(=>|:)[[:space:]]*(false|0)/) flags=flags "NOVERIFY,"
                    if (line ~ /\$[a-zA-Z_]/) flags=flags "DYNAMIC,"
                    printf "%s\t%s\t%d\t%s\n", host, REL, NR, flags
                }
            }' "$f" >> "$hits"
    done < "$PHPLIST"

    if [ ! -s "$hits" ]; then
        ok "No external request destinations found."
        rm -f "$allow" "$hits"; return
    fi

    # Rank: unknown host = base risk; plaintext/noverify/near-license-hook escalate.
    # A host is "near a license/update hook" if the same file also hooks pre_http_request.
    local hookfiles="$RS_CACHE/hookfiles.$$"
    xargs -0 grep -lE "add_filter\s*\(\s*['\"]pre_http_request" < "$PHPLIST" 2>/dev/null \
        | sed "s#^$WPROOT/##" | sort -u > "$hookfiles" || true

    local host file ln flags known esc detail sev
    # de-dup on host+file
    sort -u "$hits" | while IFS=$'\t' read -r host file ln flags; do
        # allowlisted (suffix match)?
        known=0
        while IFS= read -r a; do
            case "$host" in *".$a"|"$a") known=1; break;; esac
        done < "$allow"

        esc=""
        [ "$known" = "0" ] && esc="unknown-host,"
        case ",$flags" in *PLAINTEXT*) esc="${esc}http,";; esac
        case ",$flags" in *NOVERIFY*) esc="${esc}sslverify-off,";; esac
        if grep -Fxq "$file" "$hookfiles" 2>/dev/null; then esc="${esc}near-license-hook,"; fi

        detail="external request to $host [${esc%,}]"
        # severity: unknown host + (http|noverify|hook) = HIGH; unknown alone = MED; known w/ hook = MED; else INFO
        if [ "$known" = "0" ] && { case ",$esc" in *http,*|*sslverify-off,*|*near-license-hook,*) true;; *) false;; esac; }; then
            sev="HIGH"
        elif [ "$known" = "0" ]; then
            sev="MED"
        elif case ",$esc" in *near-license-hook,*) true;; *) false;; esac; then
            sev="MED"
        else
            sev="INFO"
        fi
        report "$sev" "external-request" "$file:$ln" "$detail"
    done
    rm -f "$allow" "$hits" "$hookfiles"
    ok "External-request discovery done."
}

scan_htaccess() {
    info "Auditing .htaccess files..."
    while IFS= read -r -d '' f; do
        if grep -qIE 'base64|AddHandler|AddType[[:space:]]+application/x-httpd-php|auto_(ap|pre)pend_file|RewriteRule[^#]*(\.ru|\.cn|\.top)/' "$f" 2>/dev/null; then
            report "MED" "htaccess-suspicious" "${f#"$WPROOT"/}" "contains handler/append/base64/redirect directives - REVIEW"
        fi
        case "$f" in
            "$WPROOT/wp-content/uploads/"*)
                grep -qIE 'php_flag[[:space:]]+engine[[:space:]]+off|Deny from all|Require all denied' "$f" 2>/dev/null \
                    || report "INFO" "htaccess-uploads" "${f#"$WPROOT"/}" ".htaccess in uploads without PHP-off directives";;
        esac
    done < <(find "$WPROOT" -type f -name '.htaccess' -print0 2>/dev/null)
    ok ".htaccess audit done."
}

# ------------------------------ database scan --------------------------------
wpconfig_val() { # extract define('KEY','val') from wp-config.php without executing it
    grep -E "define\(\s*['\"]$1['\"]" "$WPROOT/wp-config.php" \
        | head -1 | sed -E "s/.*define\(\s*['\"]$1['\"]\s*,\s*['\"]([^'\"]*)['\"].*/\1/"
}

db_query() { # db_query "SQL"  -> tab-separated rows on stdout
    if [ -n "$WPCLI" ]; then
        $WPCLI db query "$1" --skip-column-names 2>/dev/null
    elif [ "$HAVE_MYSQL" = "1" ]; then
        local host="${DB_HOST%%:*}" port=""
        case "$DB_HOST" in *:*) port="${DB_HOST##*:}";; esac
        MYSQL_PWD="$DB_PASSWORD" mysql -N -h "$host" ${port:+-P "$port"} \
            -u "$DB_USER" "$DB_NAME" -e "$1" 2>/dev/null
    fi
}

scan_database() {
    info "Scanning database (posts, options, users, cron)..."
    DB_NAME="$(wpconfig_val DB_NAME)"; DB_USER="$(wpconfig_val DB_USER)"
    DB_PASSWORD="$(wpconfig_val DB_PASSWORD)"; DB_HOST="$(wpconfig_val DB_HOST)"
    local P
    P="$(grep -E '^\s*\$table_prefix' "$WPROOT/wp-config.php" \
         | sed -E "s/.*=\s*['\"]([^'\"]+)['\"].*/\1/" | head -1)"
    P="${P:-wp_}"
    if [ -z "$WPCLI" ] && [ "$HAVE_MYSQL" != "1" ]; then
        warn "Neither WP-CLI nor mysql client found: skipping database scan."
        report "WARN" "db" "-" "database scan skipped (no wp-cli/mysql)"
        return
    fi

    # sanity check connectivity
    if ! db_query "SELECT 1" | grep -q 1; then
        warn "Could not connect to the database. Skipping DB scan."
        return
    fi

    # 1. injected scripts / obfuscation in published content
    db_query "SELECT ID, post_type, post_modified FROM ${P}posts
              WHERE post_status='publish'
                AND post_content REGEXP '<script[^>]*src=|eval\\\\(|String\\\\.fromCharCode|base64_decode|<iframe'
              LIMIT 200;" | while IFS=$'\t' read -r id ptype pmod; do
        report "MED" "db-post-injection" "post:$id" "$ptype modified $pmod contains script/eval/iframe patterns - REVIEW (use revisions to restore)"
    done

    # 2. optionally: everything modified since a suspected infection date
    if [ -n "${SINCE_DATE:-}" ]; then
        db_query "SELECT ID, post_type, post_modified FROM ${P}posts
                  WHERE post_modified >= '$SINCE_DATE' LIMIT 500;" \
        | while IFS=$'\t' read -r id ptype pmod; do
            report "INFO" "db-recently-modified" "post:$id" "$ptype modified $pmod (since $SINCE_DATE)"
        done
    fi

    # 3. siteurl / home hijack
    db_query "SELECT option_name, option_value FROM ${P}options
              WHERE option_name IN ('siteurl','home');" \
    | while IFS=$'\t' read -r name val; do
        [ -n "$name" ] || continue
        report "INFO" "db-url" "$name" "$val  <- confirm this is YOUR domain"
    done

    # 4. script tags inside widgets/options + oversized autoloads
    db_query "SELECT option_name FROM ${P}options
              WHERE (option_name LIKE 'widget_%' OR option_name LIKE 'theme_mods_%')
                AND option_value REGEXP '<script|eval\\\\(|base64_decode' LIMIT 50;" \
    | while IFS= read -r name; do
        report "MED" "db-option-injection" "option:$name" "widget/theme option contains script/eval - REVIEW in wp-admin"
    done
    db_query "SELECT option_name, LENGTH(option_value) FROM ${P}options
              WHERE autoload='yes' AND LENGTH(option_value) > 100000 LIMIT 20;" \
    | while IFS=$'\t' read -r name len; do
        report "INFO" "db-option-oversized" "option:$name" "autoloaded option is $len bytes - worth a look"
    done

    # 5. nulled-plugin license residue (keys from patterns.conf OPTION lines)
    local keys
    keys="$(awk -F'|' '$1=="OPTION"{printf "%s\x27%s\x27", (n++?",":""), $2}' "$PATTERNS_FILE")"
    if [ -n "$keys" ]; then
        db_query "SELECT option_name FROM ${P}options WHERE option_name IN ($keys);" \
        | while IFS= read -r name; do
            report "HIGH" "db-nulled-residue" "option:$name" "license residue from nulled plugin - delete after replacing plugin"
        done
    fi

    # 6. administrator accounts - eyeball every one of these
    db_query "SELECT u.ID, u.user_login, u.user_email, u.user_registered
              FROM ${P}users u JOIN ${P}usermeta m ON m.user_id=u.ID
              WHERE m.meta_key='${P}capabilities' AND m.meta_value LIKE '%administrator%';" \
    | while IFS=$'\t' read -r id login email reg; do
        [ -n "$id" ] || continue
        report "INFO" "db-admin-user" "user:$id" "admin '$login' <$email> registered $reg  <- do you recognize this account?"
    done

    # 7. cron blob with suspicious content
    if db_query "SELECT option_value FROM ${P}options WHERE option_name='cron';" \
        | grep -qE 'eval\(|base64_decode|https?://[^\"]*\.(ru|cn|top)/'; then
        report "MED" "db-cron" "option:cron" "cron option contains eval/base64/odd URLs - inspect with: wp cron event list"
    fi
    ok "Database scan done."
}

scan_vulnerabilities() {
    [ -n "$WPSCAN_API_TOKEN" ] || return 0
    have curl || return 0
    info "Checking installed plugins against WPScan vulnerability API..."
    local plugdir slug out
    for plugdir in "$WPROOT"/wp-content/plugins/*/; do
        [ -d "$plugdir" ] || continue
        slug="$(basename "$plugdir")"
        out="$(curl -fsS -H "Authorization: Token token=$WPSCAN_API_TOKEN" \
               "https://wpscan.com/api/v3/plugins/$slug" 2>/dev/null)" || continue
        if [ "$HAVE_PHP" = "1" ] && printf '%s' "$out" | php_json '
            foreach($d as $slug=>$info){ if(empty($info["vulnerabilities"])) continue;
              foreach($info["vulnerabilities"] as $v)
                echo ($v["title"]??"vulnerability")."\n"; }' >/dev/null 2>&1; then
            printf '%s' "$out" | php_json '
              foreach($d as $slug=>$info){ if(empty($info["vulnerabilities"])) continue;
                foreach($info["vulnerabilities"] as $v)
                  echo ($v["title"]??"vulnerability")."\n"; }' 2>/dev/null \
            | while IFS= read -r t; do
                report "INFO" "vulnerability" "wp-content/plugins/$slug" "$t"
            done
        fi
    done
    ok "Vulnerability lookup done."
}

# ======================= BASELINES (premium plugins) ==========================
# On a KNOWN-CLEAN site (fresh install of a licensed plugin), snapshot hashes.
# Later, verify-baseline diffs the live files against the snapshot. This is the
# per-site version of the CaptainCore "drift" idea.

baseline_generate() {
    info "Generating baseline manifests for plugins & themes NOT on wordpress.org..."
    warn "Only do this on a site you have verified as clean, or right after"
    warn "installing fresh copies from the vendor."
    local kind dir slug out
    for kind in plugins themes; do
        for dir in "$WPROOT"/wp-content/$kind/*/; do
            [ -d "$dir" ] || continue
            slug="$(basename "$dir")"
            out="$RS_BASELINES/$kind-$slug.md5"
            ( cd "$dir" && find . -type f -print0 | sort -z | xargs -0 md5sum ) > "$out"
            ok "baseline: $kind/$slug ($(wc -l < "$out") files)"
        done
    done
    ok "Baselines stored in $RS_BASELINES"
}

baseline_verify() {
    info "Verifying plugins & themes against stored baselines..."
    local kind dir slug base
    for kind in plugins themes; do
        for dir in "$WPROOT"/wp-content/$kind/*/; do
            [ -d "$dir" ] || continue
            slug="$(basename "$dir")"
            base="$RS_BASELINES/$kind-$slug.md5"
            [ -f "$base" ] || continue
            ( cd "$dir" && md5sum -c --quiet "$base" 2>&1 ) \
            | while IFS= read -r line; do
                case "$line" in
                    *": FAILED open or read") bf="${line%%:*}"; report "MED" "baseline-missing" \
                        "wp-content/$kind/$slug/${bf#./}" "file present in baseline but missing";;
                    *": FAILED"*) bf="${line%%:*}"; report "HIGH" "baseline-modified" \
                        "wp-content/$kind/$slug/${bf#./}" "differs from your clean baseline - diff it!";;
                esac
            done
            # new files not in baseline
            local expected="$RS_CACHE/bl-exp.$$" actual="$RS_CACHE/bl-act.$$"
            awk '{ $1=""; sub(/^  ?\.\//,""); print }' "$base" | sort > "$expected"
            ( cd "$dir" && find . -type f | sed 's|^\./||' ) | sort > "$actual"
            while IFS= read -r extra; do
                report "MED" "baseline-unknown-file" "wp-content/$kind/$slug/$extra" \
                       "file not present in your clean baseline"
            done < <(comm -13 "$expected" "$actual")
            rm -f "$expected" "$actual"
        done
    done
    ok "Baseline verification done."
}

# ============================== QUARANTINE ====================================
# Files are MOVED (never deleted) to ~/.ratsweepr/quarantine/<batch>/ with the
# original relative path preserved, chmod 000, and a manifest for restores.

quarantine_from_report() {
    local rpt="$1"
    [ -f "$rpt" ] || die "Report file not found: $rpt"
    # Quarantine only path-based findings (skip db:*/post:/option: items).
    local list="$RS_CACHE/quarantine-list.$$"
    awk -F'\t' '$1=="HIGH" || $1=="MED" { print $3 }' "$rpt" \
        | grep -Ev '^(post|option|user):' | grep -Ev '^-$' | sort -u > "$list"
    local n; n="$(wc -l < "$list")"
    [ "$n" -gt 0 ] || { ok "Nothing quarantinable in this report."; rm -f "$list"; return; }

    say ""; say "The following $n file(s) will be MOVED out of the webroot:"
    say "--------------------------------------------------------------"
    sed 's/^/  /' "$list"
    say "--------------------------------------------------------------"
    warn "Core/plugin files in this list should be REPLACED afterwards"
    warn "(clean-core / wp plugin install --force), or the site may break."
    backup_gate
    printf 'Type exactly "QUARANTINE" to proceed: '
    read -r answer
    [ "$answer" = "QUARANTINE" ] || die "Aborted. No changes made."

    local batch="$RS_QUARANTINE/$RUNSTAMP"
    mkdir -p "$batch"
    local manifest="$batch/MANIFEST.tsv"
    printf 'sha256\toriginal_path\tquarantined_at\n' > "$manifest"
    local f moved=0
    while IFS= read -r f; do
        local src="$WPROOT/$f"
        [ -f "$src" ] || continue
        local dst="$batch/$f"
        mkdir -p "$(dirname "$dst")"
        printf '%s\t%s\t%s\n' "$(sha256sum "$src" | awk '{print $1}')" \
               "$f" "$(date -Iseconds)" >> "$manifest"
        mv -- "$src" "$dst" && chmod 000 "$dst" && moved=$((moved+1))
    done < "$list"
    rm -f "$list"
    ok "Quarantined $moved file(s) -> $batch"
    ok "Restore any time with: $0 restore $RUNSTAMP"
    echo "QUARANTINE $RUNSTAMP: $moved files" >> "$LOG"
}

quarantine_restore() {
    local batch="$RS_QUARANTINE/$1"
    [ -f "$batch/MANIFEST.tsv" ] || die "No quarantine batch named '$1'. See: ls $RS_QUARANTINE"
    warn "Restoring quarantined files back into the webroot."
    printf 'Type exactly "RESTORE" to proceed: '
    read -r answer
    [ "$answer" = "RESTORE" ] || die "Aborted."
    local n=0
    while IFS=$'\t' read -r sha rel ts; do
        [ "$sha" = "sha256" ] && continue
        if [ -f "$batch/$rel" ]; then
            mkdir -p "$WPROOT/$(dirname "$rel")"
            chmod 644 "$batch/$rel"
            mv -- "$batch/$rel" "$WPROOT/$rel" && n=$((n+1))
        fi
    done < "$batch/MANIFEST.tsv"
    ok "Restored $n file(s) from batch $1."
}

# ============================ CLEAN ACTIONS ===================================

clean_core() {
    # Replaces ONLY files that fail checksum verification (surgical, not rm -rf).
    [ "$HAVE_PHP" = "1" ] || die "php-cli required for clean-core."
    info "Determining which core files fail verification..."
    local js="$RS_CACHE/core-$WPVER.json" manifest="$RS_CACHE/core-$WPVER.md5"
    [ -s "$js" ] || fetch "https://api.wordpress.org/core/checksums/1.0/?version=$WPVER&locale=en_US" "$js" \
        || die "Cannot download checksums."
    php_json 'foreach($d["checksums"] as $f=>$m) echo $m."  ".$f."\n";' < "$js" > "$manifest"
    [ -s "$manifest" ] || die "No checksum data for $WPVER."

    local failing="$RS_CACHE/core-failing.$$"
    ( cd "$WPROOT" && md5sum -c --quiet "$manifest" 2>/dev/null ) \
        | sed -n 's/: FAILED.*//p' | grep -Ev '^wp-content/' > "$failing" || true
    local n; n="$(wc -l < "$failing")"
    if [ "$n" = "0" ]; then ok "All core files already verify. Nothing to do."; rm -f "$failing"; return; fi

    say ""; say "These $n core file(s) will be replaced with clean $WPVER copies:"
    sed 's/^/  /' "$failing"
    backup_gate
    printf 'Type exactly "REPLACE" to proceed: '
    read -r answer
    [ "$answer" = "REPLACE" ] || die "Aborted."

    local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/rs-core.XXXXXX")"
    info "Downloading wordpress-$WPVER.zip ..."
    fetch "https://wordpress.org/wordpress-$WPVER.zip" "$tmp/wp.zip" || die "Download failed."
    have unzip || die "'unzip' not available."
    unzip -q "$tmp/wp.zip" -d "$tmp" || die "Extraction failed."

    # The originals go into quarantine first (never lost), then get replaced.
    local batch="$RS_QUARANTINE/$RUNSTAMP-core"
    mkdir -p "$batch"; printf 'sha256\toriginal_path\tquarantined_at\n' > "$batch/MANIFEST.tsv"
    local f replaced=0
    while IFS= read -r f; do
        local newf="$tmp/wordpress/$f"
        [ -f "$newf" ] || { warn "No clean copy for $f in release zip, skipping."; continue; }
        if [ -f "$WPROOT/$f" ]; then
            mkdir -p "$batch/$(dirname "$f")"
            printf '%s\t%s\t%s\n' "$(sha256sum "$WPROOT/$f" | awk '{print $1}')" \
                   "$f" "$(date -Iseconds)" >> "$batch/MANIFEST.tsv"
            mv -- "$WPROOT/$f" "$batch/$f"
        fi
        mkdir -p "$WPROOT/$(dirname "$f")"
        cp -- "$newf" "$WPROOT/$f" && replaced=$((replaced+1))
    done < "$failing"
    rm -rf "$tmp" "$failing"
    ok "Replaced $replaced core file(s). Originals quarantined in $batch"
    echo "CLEAN-CORE $RUNSTAMP: $replaced files" >> "$LOG"
    say ""
    info "Plugins/themes: use WP-CLI to force-reinstall from wordpress.org:"
    say  '    wp plugin install --force $(wp plugin list --field=name)'
    say  '    wp theme  install --force $(wp theme  list --field=name)'
    info "Premium plugins: reinstall from the vendor, then re-run 'baseline'."
    # Surface reinstall URLs for trusted vendor components (mu-plugins etc.)
    while IFS='|' read -r type pfx url; do
        [ "$type" = "ALLOWPATH" ] || continue
        [ -n "$url" ] && [ "$url" != "-" ] || continue
        [ -e "$WPROOT/$pfx" ] || continue
        info "Refresh $pfx from vendor:"
        say  "    curl -sL '$url' -o /tmp/vendor.zip && unzip -o /tmp/vendor.zip -d "$WPROOT/$(dirname "$pfx")""
    done < "$PATTERNS_FILE"
}

shuffle_salts() {
    # Rotating salts invalidates all stolen session cookies. Prefer WP-CLI.
    backup_gate
    if [ -n "$WPCLI" ]; then
        $WPCLI config shuffle-salts && ok "Salts rotated via WP-CLI." && return
    fi
    info "WP-CLI not available - rotating salts via api.wordpress.org..."
    local salts="$RS_CACHE/salts.$$"
    fetch "https://api.wordpress.org/secret-key/1.1/salt/" "$salts" || die "Could not fetch new salts."
    grep -q "AUTH_KEY" "$salts" || die "Salt API returned unexpected data."
    cp "$WPROOT/wp-config.php" "$WPROOT/wp-config.php.rs-backup-$RUNSTAMP"
    awk -v saltfile="$salts" '
        BEGIN { while ((getline l < saltfile) > 0) salts = salts l "\n" }
        /define\([[:space:]]*.[[:space:]]*(AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)/ {
            if (!printed) { printf "%s", salts; printed=1 }
            next
        }
        { print }
    ' "$WPROOT/wp-config.php.rs-backup-$RUNSTAMP" > "$WPROOT/wp-config.php.rs-new" \
        && grep -q "AUTH_KEY" "$WPROOT/wp-config.php.rs-new" \
        && mv "$WPROOT/wp-config.php.rs-new" "$WPROOT/wp-config.php" \
        && ok "Salts rotated. Previous wp-config kept as wp-config.php.rs-backup-$RUNSTAMP" \
        || die "Salt rotation failed; wp-config.php untouched."
    rm -f "$salts"
}

# ============================ SCAN ORCHESTRATOR ===============================

finalize_report() {
    # (a) Suppress plugin-premium INFO for any plugin that has a HIGH/MED finding.
    #     A contradictory "verify later" line on confirmed-bad plugins is misleading.
    local flagged="$RS_CACHE/flagged.$$"
    awk -F'\t' '($1=="HIGH"||$1=="MED") && $3 ~ /^wp-content\/plugins\// {
        n=split($3,a,"/"); print a[3]
    }' "$REPORT" | sort -u > "$flagged"

    # (b) Collapse duplicate findings: same severity+file+signature-basename.
    #     yara:RS_large_base64_payload and heuristic:large_base64_payload on the
    #     same file are the same detection -> keep one (prefer yara attribution).
    awk -F'\t' -v FLAGGED="$flagged" '
        BEGIN { while ((getline l < FLAGGED) > 0) isflag[l]=1 }
        {
            sev=$1; cat=$2; item=$3; detail=$4
            # drop contradictory plugin-premium
            if (cat=="plugin-premium") {
                n=split(item,a," "); slug=a[1]; sub(/^wp-content\/plugins\//,"",slug)
                if (slug in isflag) next
            }
            # normalize signature basename for dedup key
            base=cat
            sub(/^yara:RS_/,"SIG:",base); sub(/^heuristic:/,"SIG:",base)
            # canonicalize a few known yara<->heuristic name pairs
            gsub(/large_base64_payload|RS_large_base64_payload/,"large_base64",base)
            key=sev "|" item "|" base
            if (key in seen) next
            seen[key]=1
            # prefer yara attribution: if we later see yara for a heuristic already
            # printed, we cannot un-print; so we buffer instead
            lines[NR]=$0; order[++cnt]=NR; kk[NR]=key
        }
        END {
            for (i=1;i<=cnt;i++) print lines[order[i]]
        }
    ' "$REPORT" > "$REPORT.dedup" && mv "$REPORT.dedup" "$REPORT"
    rm -f "$flagged"
}

run_scan() {
    banner
    : > "$REPORT"
    VERIFIED="$RS_CACHE/verified.$RUNSTAMP"
    : > "$VERIFIED"
    load_signatures
    build_php_filelist
    scan_core_vulns
    scan_core_checksums
    scan_plugin_checksums
    scan_uploads_php
    scan_hashdb
    scan_yara
    scan_heuristics
    scan_nulled
    scan_external_requests
    scan_htaccess
    scan_database
    scan_vulnerabilities
    rm -f "$PHPLIST"
    finalize_report

    # ------- summary -------
    say ""
    say "==================== SCAN SUMMARY ===================="
    local high med infoc
    high="$(awk -F'\t' '$1=="HIGH"'  "$REPORT" | wc -l)"
    med="$(awk  -F'\t' '$1=="MED"'   "$REPORT" | wc -l)"
    infoc="$(awk -F'\t' '$1=="INFO"' "$REPORT" | wc -l)"
    say "  HIGH findings : $high   (very likely malicious / integrity failures)"
    say "  MED  findings : $med   (suspicious - review before acting)"
    say "  INFO findings : $infoc   (context for your review)"
    say ""
    if [ "$high" -gt 0 ]; then
        say "  --- HIGH ---"
        awk -F'\t' '$1=="HIGH"{printf "  %-22s %s\n      %s\n", $2, $3, $4}' "$REPORT"
    fi
    if [ "$med" -gt 0 ]; then
        say "  --- MED (first 25) ---"
        awk -F'\t' '$1=="MED"{printf "  %-22s %s\n", $2, $3}' "$REPORT" | head -25
    fi
    say ""
    # Grouped external-request digest: one line per unique host, worst severity.
    if grep -q $'\texternal-request\t' "$REPORT" 2>/dev/null; then
        say ""
        say "  --- External contact points (review unknowns) ---"
        awk -F'\t' '$2=="external-request"{
            n=split($4,a," "); h=""
            for(i=1;i<n;i++) if(a[i]=="to"){h=a[i+1];break}
            if(h==""){next}
            rank["HIGH"]=3;rank["MED"]=2;rank["INFO"]=1
            if(rank[$1]>best[h]){best[h]=rank[$1];bs[h]=$1}
            cnt[h]++
        } END{
            for(h in cnt) printf "  %-5s %-40s (%d call site%s)\n", bs[h], h, cnt[h], (cnt[h]>1?"s":"")
        }' "$REPORT" | sort
    fi
    say ""
    say "  Full report: $REPORT"
    say ""
    say "  Next steps:"
    say "    1. Review MED findings (heuristics DO false-positive - check each file)."
    say "    2. Make a full backup (files + database)."
    say "    3. Quarantine confirmed findings:  ratsweepr.sh quarantine $REPORT"
    say "    4. Replace what was quarantined:   ratsweepr.sh clean-core  + wp plugin install --force ..."
    say "    5. Rotate credentials:             ratsweepr.sh shuffle-salts  + reset admin passwords"
    say "======================================================="
}

# ================================ MENU / CLI ==================================

usage() {
    cat << 'EOU'
Usage:
  ratsweepr.sh                  interactive menu
  ratsweepr.sh scan             full read-only scan -> report
  ratsweepr.sh scan --since 2026-07-01   also list DB content modified since a date
  ratsweepr.sh update-sigs      refresh rfxn hash DB + pattern file
  ratsweepr.sh baseline         hash premium plugins/themes on a KNOWN-CLEAN site
  ratsweepr.sh verify-baseline  compare current files to baselines
  ratsweepr.sh quarantine FILE.report   quarantine files listed in a scan report
  ratsweepr.sh restore ID       restore a quarantine batch
  ratsweepr.sh clean-core       replace ONLY core files failing checksum verification
  ratsweepr.sh shuffle-salts    rotate wp-config.php auth salts
EOU
}

main_menu() {
    banner
    PS3=$'\nSelect an option: '
    select choice in \
        "Scan (read-only, recommended first step)" \
        "Update malware signatures (rfxn.hdb + patterns)" \
        "Quarantine findings from the latest report" \
        "Restore a quarantine batch" \
        "Clean core (replace only failing files)" \
        "Generate premium-plugin baselines (on a CLEAN site)" \
        "Verify against baselines" \
        "Rotate wp-config salts" \
        "Exit"
    do
        case "$REPLY" in
            1) run_scan; break;;
            2) update_signatures; break;;
            3) local last
               last="$(ls -1t "$WPROOT"/ratsweepr-*.report 2>/dev/null | head -1)"
               [ -n "$last" ] || { warn "No report found - run a scan first."; break; }
               quarantine_from_report "$last"; break;;
            4) say "Batches:"; ls -1 "$RS_QUARANTINE" 2>/dev/null
               printf 'Batch id to restore: '; read -r b
               quarantine_restore "$b"; break;;
            5) clean_core; break;;
            6) baseline_generate; break;;
            7) : > "$REPORT"; load_signatures; baseline_verify
               say "Findings written to $REPORT"; break;;
            8) shuffle_salts; break;;
            9) exit 0;;
            *) say "Pick a number from the list.";;
        esac
    done
}

preflight
SINCE_DATE=""
cmd="${1:-menu}"; shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --since) SINCE_DATE="${2:-}"; shift 2;;
        *) set -- "$1" "${@:2}"; break;;
    esac
done

case "$cmd" in
    menu)            main_menu;;
    scan)            update_signatures; run_scan;;
    update-sigs)     update_signatures;;
    baseline)        baseline_generate;;
    verify-baseline) : > "$REPORT"; load_signatures; baseline_verify; say "Report: $REPORT";;
    quarantine)      [ $# -ge 1 ] || die "Usage: $0 quarantine <report-file>"
                     quarantine_from_report "$1";;
    restore)         [ $# -ge 1 ] || die "Usage: $0 restore <batch-id>"
                     quarantine_restore "$1";;
    clean-core)      clean_core;;
    shuffle-salts)   shuffle_salts;;
    help|-h|--help)  usage;;
    *)               usage; die "Unknown command: $cmd";;
esac
