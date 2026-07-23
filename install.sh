#!/usr/bin/env bash
# RatSweepr installer — downloads the right release binary, verifies its
# checksum, and drops it in the current directory. No root required.
#
# Usage:
#   bash <(curl -sL https://raw.githubusercontent.com/YOU/ratsweepr/main/install.sh)
#   bash <(curl -sL .../install.sh) v3.0.0        # pin a specific release
#
# Repo layout expected (create with `gh release create` or the web UI):
#   Releases/<tag>/ratsweepr-linux-amd64
#   Releases/<tag>/ratsweepr-linux-arm64
#   Releases/<tag>/checksums.txt        <- `sha256sum ratsweepr-linux-* > checksums.txt`

set -euo pipefail

REPO="YOU/ratsweepr"                    # <-- change to your GitHub user/repo
TAG="${1:-latest}"

case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "FAIL: unsupported architecture $(uname -m)"; exit 1 ;;
esac

BIN="ratsweepr-linux-$ARCH"
if [ "$TAG" = "latest" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    BASE="https://github.com/$REPO/releases/download/$TAG"
fi

command -v curl >/dev/null 2>&1 || { echo "FAIL: curl required"; exit 1; }

echo ".. downloading $BIN ($TAG)"
curl -fsSL -o ratsweepr.tmp "$BASE/$BIN"
curl -fsSL -o ratsweepr.sums.tmp "$BASE/checksums.txt"

echo ".. verifying sha256"
want="$(awk -v b="$BIN" '$2==b {print $1}' ratsweepr.sums.tmp)"
got="$(sha256sum ratsweepr.tmp | awk '{print $1}')"
if [ -z "$want" ] || [ "$want" != "$got" ]; then
    rm -f ratsweepr.tmp ratsweepr.sums.tmp
    echo "FAIL: checksum mismatch — refusing to install"; exit 1
fi
rm -f ratsweepr.sums.tmp

mv ratsweepr.tmp ratsweepr
chmod +x ratsweepr

if ! ./ratsweepr help >/dev/null 2>&1; then
    echo "WARN: binary downloaded but won't execute — this host may mount"
    echo "      your home directory noexec. Use the bash version instead:"
    echo "      bash <(curl -sL https://raw.githubusercontent.com/$REPO/main/ratsweepr.sh)"
    exit 1
fi

echo "OK  installed ./ratsweepr ($("./ratsweepr" help 2>/dev/null | head -1 || echo ok))"
echo "    run:  ./ratsweepr        (TUI)"
echo "          ./ratsweepr scan   (headless)"
