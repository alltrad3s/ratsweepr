#!/usr/bin/env bash
# RatSweepr installer — downloads the scanner script into the current directory.
# No root, no compilation, nothing to build. RatSweepr is a single bash script.
#
# Usage (from your WordPress root — where wp-config.php lives):
#   bash <(curl -sL https://raw.githubusercontent.com/alltrad3s/ratsweepr/main/install.sh)
#   ./ratsweepr.sh scan
#
# Or skip the installer entirely and run the scanner in one line:
#   bash <(curl -sL https://raw.githubusercontent.com/alltrad3s/ratsweepr/main/ratsweepr.sh) scan
#
# Pin a tag for anything unattended:
#   .../ratsweepr/v2.9.9/ratsweepr.sh

set -euo pipefail

REPO="alltrad3s/ratsweepr"
REF="${1:-main}"                       # branch, tag, or commit
RAW="https://raw.githubusercontent.com/$REPO/$REF/ratsweepr.sh"

command -v curl >/dev/null 2>&1 || { echo "FAIL: curl required"; exit 1; }

echo ".. downloading ratsweepr.sh ($REF)"
curl -fsSL -o ratsweepr.sh.tmp "$RAW"

# sanity: make sure we got a shell script, not an error page
if ! head -1 ratsweepr.sh.tmp | grep -q '^#!/'; then
    rm -f ratsweepr.sh.tmp
    echo "FAIL: downloaded file is not a script (bad ref '$REF'?)"; exit 1
fi
if ! bash -n ratsweepr.sh.tmp 2>/dev/null; then
    rm -f ratsweepr.sh.tmp
    echo "FAIL: downloaded script failed syntax check — refusing to install"; exit 1
fi

mv ratsweepr.sh.tmp ratsweepr.sh
chmod +x ratsweepr.sh
ver="$(grep -m1 '^RS_VERSION=' ratsweepr.sh | cut -d'"' -f2)"
echo "OK  installed ./ratsweepr.sh (v${ver:-?})"
echo "    run:  ./ratsweepr.sh scan"
