#!/bin/sh
set -e

# build_pkg.sh - Build FreeBSD .pkg package for KariDNS & tools
# Usage: ./packaging/freebsd/build_pkg.sh [version] [output_dir]

VERSION="${1:-1.0.0}"
VERSION="${VERSION#v}" # Strip leading 'v' if present
OUT_DIR="${2:-./dist}"

ARCH=$(pkg config ABI 2>/dev/null || echo "FreeBSD:$(uname -r | cut -d. -f1):$(uname -m)")
ABI_SUFFIX=$(echo "$ARCH" | tr ':' '-')
STAGE_DIR="$(mktemp -d -t karidns-pkg-stage)"
MANIFEST_DIR="$(mktemp -d -t karidns-pkg-manifest)"

echo "==> Building KariDNS binaries for FreeBSD (${ARCH}, version ${VERSION})..."
make clean
make VERSION="${VERSION}" all

echo "==> Preparing staging root..."
mkdir -p "${STAGE_DIR}/usr/local/sbin"
mkdir -p "${STAGE_DIR}/usr/local/bin"
mkdir -p "${STAGE_DIR}/usr/local/etc/rc.d"
mkdir -p "${STAGE_DIR}/usr/local/etc/karidns/zones"
mkdir -p "${OUT_DIR}"

# Install binaries
install -m 0755 karidns "${STAGE_DIR}/usr/local/sbin/karidns"
install -m 0755 karictl "${STAGE_DIR}/usr/local/bin/karictl"
install -m 0755 karicheck "${STAGE_DIR}/usr/local/bin/karicheck"
install -m 0755 dag "${STAGE_DIR}/usr/local/bin/dag"

# Install rc.d script
install -m 0555 packaging/freebsd/rc.d/karidns "${STAGE_DIR}/usr/local/etc/rc.d/karidns"

# Install sample configuration & sample zone
install -m 0644 karidns.conf.sample "${STAGE_DIR}/usr/local/etc/karidns/karidns.conf.sample"
install -m 0644 karictl.conf.sample "${STAGE_DIR}/usr/local/etc/karidns/karictl.conf.sample"
install -m 0644 packaging/freebsd/zones/example.local.zone.sample "${STAGE_DIR}/usr/local/etc/karidns/zones/example.local.zone.sample"

echo "==> Generating +MANIFEST..."
sed -e "s/__VERSION__/${VERSION}/g" \
    -e "s/__ARCH__/${ARCH}/g" \
    packaging/freebsd/MANIFEST.in > "${MANIFEST_DIR}/+MANIFEST"

echo "==> Creating FreeBSD pkg..."
pkg create -m "${MANIFEST_DIR}" -r "${STAGE_DIR}" -o "${OUT_DIR}"

# Rename pkg to include ABI suffix (e.g. karidns-1.0.0-FreeBSD-14-amd64.pkg / karidns-1.0.0-FreeBSD-15-amd64.pkg)
PKG_DEFAULT="${OUT_DIR}/karidns-${VERSION}.pkg"
PKG_TARGET="${OUT_DIR}/karidns-${VERSION}-${ABI_SUFFIX}.pkg"
if [ -f "$PKG_DEFAULT" ]; then
    mv "$PKG_DEFAULT" "$PKG_TARGET"
fi

# Cleanup
rm -rf "${STAGE_DIR}" "${MANIFEST_DIR}"

echo "==> Successfully created FreeBSD package in ${OUT_DIR}:"
ls -lh "${OUT_DIR}"/karidns-*.pkg*
