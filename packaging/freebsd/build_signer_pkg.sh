#!/bin/sh
set -e

# build_signer_pkg.sh - Build the FreeBSD .pkg of karidns-signer (docs/karidns-signer.md)
# Usage: ./packaging/freebsd/build_signer_pkg.sh [version] [output_dir]
#
# karidns-signer is Node.js (no compiler): the program with its one npm dependency (pg, `npm ci --omit=dev --ignore-scripts`), a wrapper in sbin,
# the rc script, a sample configuration and the manual.  The package depends on node24 and bind-tools (the packages that provide them on the build host)
# and creates the user and group karidns-signer.  It needs karidns-zone, which the database packages (build_pkg.sh --db sqlite3|postgresql|both)
# install; those three conflict with each other, so the package cannot depend on one of them by name: its pre-install script refuses to install without
# /usr/local/bin/karidns-zone.  The build host needs node24, npm-node24 and bind-tools.

VERSION="${1:-1.0.0}"
VERSION="${VERSION#v}"
OUT_DIR="${2:-./dist}"
case "$VERSION" in -*) echo "build_signer_pkg.sh: usage: build_signer_pkg.sh [version] [output_dir]" >&2; exit 2 ;; esac

ARCH=$(pkg config ABI 2>/dev/null || echo "FreeBSD:$(uname -r | cut -d. -f1):$(uname -m)")
ABI_SUFFIX=$(echo "$ARCH" | tr ':' '-')
STAGE_DIR="$(mktemp -d -t karidns-signer-stage)"
MANIFEST_DIR="$(mktemp -d -t karidns-signer-manifest)"

DEPS=""
for p in node24 bind-tools; do
    if ! pkg query '%n' "$p" >/dev/null 2>&1; then
        echo "ERROR: ${p} is not installed on the build host (pkg install node24 npm-node24 bind-tools)" >&2
        exit 1
    fi
    DEPS="${DEPS}${DEPS:+,
}    $p: { origin: \"$(pkg query '%o' "$p")\", version: \"$(pkg query '%v' "$p")\" }"
    echo "==> depends on ${p}-$(pkg query '%v' "$p")"
done

SIGNER_DIR="usr/local/libexec/karidns-signer"
(cd signer && npm ci --omit=dev --ignore-scripts) || { echo "ERROR: npm ci in signer/ failed (pkg install npm-node24)" >&2; exit 1; }
mkdir -p "${STAGE_DIR}/${SIGNER_DIR}/signer" "${STAGE_DIR}/${SIGNER_DIR}/node" "${STAGE_DIR}/usr/local/sbin" "${STAGE_DIR}/usr/local/etc/rc.d" "${STAGE_DIR}/usr/local/etc/karidns" "${STAGE_DIR}/usr/local/share/doc/karidns" "${OUT_DIR}"
cp -R signer/bin signer/lib signer/package.json signer/package-lock.json "${STAGE_DIR}/${SIGNER_DIR}/signer/"
# the code signer/ shares with karidns-webadmin (node/lib: signer/lib imports ../../node/lib), and the one dependency, next to both
cp -R node/lib node/package.json "${STAGE_DIR}/${SIGNER_DIR}/node/"
cp -R signer/node_modules "${STAGE_DIR}/${SIGNER_DIR}/"
rm -rf "${STAGE_DIR}/${SIGNER_DIR}/node_modules/.bin"
find "${STAGE_DIR}/${SIGNER_DIR}" -type d -exec chmod 0755 {} +
find "${STAGE_DIR}/${SIGNER_DIR}" -type f -exec chmod 0444 {} +
chmod 0555 "${STAGE_DIR}/${SIGNER_DIR}/signer/bin/karidns-signer.js"
if [ -n "$(find "${STAGE_DIR}/${SIGNER_DIR}" ! -type f ! -type d)" ]; then
    echo "ERROR: the signer tree holds something that is neither a file nor a directory" >&2
    exit 1
fi
install -m 0555 packaging/freebsd/karidns-signer "${STAGE_DIR}/usr/local/sbin/karidns-signer"
install -m 0555 packaging/freebsd/rc.d/karidns_signer "${STAGE_DIR}/usr/local/etc/rc.d/karidns_signer"
install -m 0644 karidns-signer.conf.sample "${STAGE_DIR}/usr/local/etc/karidns/karidns-signer.conf.sample"
install -m 0644 docs/karidns-signer.md "${STAGE_DIR}/usr/local/share/doc/karidns/karidns-signer.md"

FILES="    /usr/local/sbin/karidns-signer: { uname: \"root\", gname: \"wheel\", perm: \"0555\" },
    /usr/local/etc/rc.d/karidns_signer: { uname: \"root\", gname: \"wheel\", perm: \"0555\" },
    /usr/local/etc/karidns/karidns-signer.conf.sample: { uname: \"root\", gname: \"wheel\", perm: \"0644\" },
    /usr/local/share/doc/karidns/karidns-signer.md: { uname: \"root\", gname: \"wheel\", perm: \"0644\" }"
for f in $(cd "${STAGE_DIR}" && find "${SIGNER_DIR}" -type f | sort); do
    case "$f" in
        *[!A-Za-z0-9_./+@-]*) echo "ERROR: unexpected file name in the signer tree: $f" >&2; exit 1 ;;
    esac
    perm=0444
    [ "$f" = "${SIGNER_DIR}/signer/bin/karidns-signer.js" ] && perm=0555
    FILES="${FILES},
    \"/${f}\": { uname: \"root\", gname: \"wheel\", perm: \"${perm}\" }"
done

echo "==> Generating +MANIFEST..."
printf '%s\n' "$DEPS" > "${MANIFEST_DIR}/deps.txt"
printf '%s\n' "$FILES" > "${MANIFEST_DIR}/files.txt"
sed -e "s/__VERSION__/${VERSION}/g" -e "s/__ARCH__/${ARCH}/g" packaging/freebsd/MANIFEST.signer.in | tr -d '\r' | awk -v dd="${MANIFEST_DIR}/deps.txt" -v ff="${MANIFEST_DIR}/files.txt" '
    function put(f,   l) { while ((getline l < f) > 0) print l; close(f) }
    $0 == "__DEPS__" { put(dd); next }
    $0 == "__FILES__" { put(ff); next }
    { print }' > "${MANIFEST_DIR}/+MANIFEST"
rm -f "${MANIFEST_DIR}/deps.txt" "${MANIFEST_DIR}/files.txt"
echo "==> Creating FreeBSD pkg..."
pkg create -m "${MANIFEST_DIR}" -r "${STAGE_DIR}" -o "${OUT_DIR}"
if [ -f "${OUT_DIR}/karidns-signer-${VERSION}.pkg" ]; then
    mv "${OUT_DIR}/karidns-signer-${VERSION}.pkg" "${OUT_DIR}/karidns-signer-${VERSION}-${ABI_SUFFIX}.pkg"
fi
rm -rf "${STAGE_DIR}" "${MANIFEST_DIR}"
echo "==> Successfully created FreeBSD package in ${OUT_DIR}:"
ls -lh "${OUT_DIR}/karidns-signer-${VERSION}"*.pkg*
