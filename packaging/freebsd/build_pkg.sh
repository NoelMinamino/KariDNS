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

# The package must link the base system OpenSSL (/lib, /usr/lib): the ports
# OpenSSL (security/openssl, /usr/local/lib/libcrypto.so.NN) is not a declared
# dependency, so a package linked against it fails to install on hosts without
# it ("Missing shlib libcrypto.so.12"). Set ALLOW_PORTS_OPENSSL=1 to override.
if [ "${ALLOW_PORTS_OPENSSL:-0}" != "1" ]; then
    for b in karidns karictl karicheck dag; do
        if ldd "$b" 2>/dev/null | grep -E 'lib(crypto|ssl)\.so' | grep -q '/usr/local/'; then
            echo "ERROR: $b links the ports OpenSSL:" >&2
            ldd "$b" | grep -E 'lib(crypto|ssl)\.so' >&2
            echo "Remove the openssl package (pkg delete openssl) and rebuild, or set ALLOW_PORTS_OPENSSL=1." >&2
            exit 1
        fi
    done
fi

# Runtime package dependencies, recorded in +MANIFEST so pkg can resolve them.
DEPS=""
if ldd dag 2>/dev/null | grep -q 'libidn2\.so'; then
    IDN2_VER=$(pkg query '%v' libidn2 2>/dev/null || true)
    IDN2_ORIGIN=$(pkg query '%o' libidn2 2>/dev/null || echo dns/libidn2)
    if [ -n "$IDN2_VER" ]; then
        DEPS="    libidn2: { origin: \"${IDN2_ORIGIN}\", version: \"${IDN2_VER}\" }"
    fi
fi

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
    packaging/freebsd/MANIFEST.in | tr -d '\r' | awk -v deps="$DEPS" '
    $0 == "__DEPS__" { if (deps != "") print deps; next }
    { print }' > "${MANIFEST_DIR}/+MANIFEST"

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
