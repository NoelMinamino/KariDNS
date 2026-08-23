#!/bin/bash
set -e

# update_formula.sh - Generate Homebrew Formula with calculated SHA256
# Usage: ./packaging/homebrew/update_formula.sh <tag> [tarball_path_or_url]

TAG="${1}"
TARBALL="${2}"

if [ -z "$TAG" ]; then
    echo "Usage: $0 <tag> [tarball_path_or_url]"
    exit 1
fi

if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
    SHA256=$(sha256sum "$TARBALL" | awk '{print $1}')
elif [ -n "$TARBALL" ] && [[ "$TARBALL" =~ ^https?:// ]]; then
    SHA256=$(curl -sL "$TARBALL" | sha256sum | awk '{print $1}')
else
    TARBALL_URL="https://github.com/NoelMinamino/KariDNS/archive/refs/tags/${TAG}.tar.gz"
    echo "Fetching archive checksum from ${TARBALL_URL}..."
    SHA256=$(curl -sL "${TARBALL_URL}" | sha256sum | awk '{print $1}')
fi

echo "Tag: ${TAG}"
echo "SHA256: ${SHA256}"

OUT_FORMULA="Formula/dag.rb"
mkdir -p Formula

sed -e "s/__TAG__/${TAG}/g" \
    -e "s/__SHA256__/${SHA256}/g" \
    packaging/homebrew/dag.rb.template > "${OUT_FORMULA}"

echo "==> Generated ${OUT_FORMULA} successfully."
cat "${OUT_FORMULA}"
