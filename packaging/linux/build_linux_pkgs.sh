#!/bin/bash
set -e

# build_linux_pkgs.sh - Build Linux packages (RPM, DEB, tar.gz) for dag
# Usage: ./packaging/linux/build_linux_pkgs.sh [version] [output_dir]

VERSION="${1:-1.0.0}"
VERSION="${VERSION#v}" # Strip leading 'v'
OUT_DIR="${2:-./dist}"
ARCH="$(uname -m)"

# Normalize ARCH names
case "$ARCH" in
    x86_64)  DEB_ARCH="amd64"; RPM_ARCH="x86_64" ;;
    aarch64) DEB_ARCH="arm64"; RPM_ARCH="aarch64" ;;
    armv7l)  DEB_ARCH="armhf"; RPM_ARCH="armv7hl" ;;
    *)       DEB_ARCH="$ARCH"; RPM_ARCH="$ARCH" ;;
esac

if [ ! -f dag ]; then
    echo "==> Building dag binary for Linux (${ARCH}, version ${VERSION})..."
    make clean || true
    make VERSION="${VERSION}" dag
else
    echo "==> Using existing dag binary for Linux (${ARCH}, version ${VERSION})..."
fi

mkdir -p "${OUT_DIR}"

# 1. Create Standalone Binary Tarball
echo "==> Packaging tar.gz release..."
TAR_DIR="$(mktemp -d -t dag-tar-XXXXXX)"
mkdir -p "${TAR_DIR}/dag-${VERSION}"
cp dag "${TAR_DIR}/dag-${VERSION}/"
cp LICENSE "${TAR_DIR}/dag-${VERSION}/" 2>/dev/null || true
cp README.md "${TAR_DIR}/dag-${VERSION}/" 2>/dev/null || true
cp docs/dag.md "${TAR_DIR}/dag-${VERSION}/" 2>/dev/null || true
tar -czf "${OUT_DIR}/dag-${VERSION}-linux-${RPM_ARCH}.tar.gz" -C "${TAR_DIR}" "dag-${VERSION}"
rm -rf "${TAR_DIR}"

# 2. Create Debian Package (.deb)
if command -v dpkg-deb >/dev/null 2>&1; then
    echo "==> Packaging Debian (.deb) package..."
    DEB_DIR="$(mktemp -d -t dag-deb-XXXXXX)"
    mkdir -p "${DEB_DIR}/DEBIAN"
    mkdir -p "${DEB_DIR}/usr/bin"
    mkdir -p "${DEB_DIR}/usr/share/doc/dag"
    
    install -m 0755 dag "${DEB_DIR}/usr/bin/dag"
    cp LICENSE "${DEB_DIR}/usr/share/doc/dag/copyright" 2>/dev/null || true
    cp docs/dag.md "${DEB_DIR}/usr/share/doc/dag/README.md" 2>/dev/null || true

    cat <<EOF > "${DEB_DIR}/DEBIAN/control"
Package: dag
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Noel Minamino <noel@karidns.org>
Description: DNS Anomaly Generator - High-performance DNS query tool and fuzzer
 DAG is a lightweight and powerful DNS testing and query inspection client.
EOF

    dpkg-deb --build "${DEB_DIR}" "${OUT_DIR}/dag_${VERSION}_${DEB_ARCH}.deb"
    rm -rf "${DEB_DIR}"
fi

# 3. Create RPM Package (.rpm)
if command -v rpmbuild >/dev/null 2>&1; then
    if ls "${OUT_DIR}"/dag-*.rpm >/dev/null 2>&1; then
        echo "==> RPM package already exists in ${OUT_DIR}, skipping rpmbuild..."
    else
        echo "==> Packaging RPM (.rpm) package via rpmbuild..."
        RPM_TOPDIR="$(mktemp -d -t dag-rpm-XXXXXX)"
        mkdir -p "${RPM_TOPDIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
        
        # Prepare source tarball for rpmbuild
        TAR_SRC_DIR="$(mktemp -d -t dag-src-XXXXXX)"
        mkdir -p "${TAR_SRC_DIR}/KariDNS-${VERSION}"
        cp -r * "${TAR_SRC_DIR}/KariDNS-${VERSION}/" 2>/dev/null || true
        tar -czf "${RPM_TOPDIR}/SOURCES/dag-${VERSION}.tar.gz" -C "${TAR_SRC_DIR}" "KariDNS-${VERSION}"
        rm -rf "${TAR_SRC_DIR}"

        rpmbuild --define "_topdir ${RPM_TOPDIR}" \
                 --define "version ${VERSION}" \
                 --target "${RPM_ARCH}" \
                 --nodeps \
                 -bb packaging/linux/dag.spec

        cp "${RPM_TOPDIR}"/RPMS/*/*.rpm "${OUT_DIR}/"
        rm -rf "${RPM_TOPDIR}"
    fi
fi

echo "==> Linux packages generated in ${OUT_DIR}:"
ls -lh "${OUT_DIR}"/dag*
