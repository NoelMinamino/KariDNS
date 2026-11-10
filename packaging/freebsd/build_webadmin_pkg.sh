#!/bin/sh
set -e

# build_webadmin_pkg.sh - Build the FreeBSD .pkg of karidns-webadmin (docs/karidns-webadmin.md)
# Usage: ./packaging/freebsd/build_webadmin_pkg.sh [version] [output_dir]
#
# karidns-webadmin is Node.js (no compiler): the program with its one npm dependency (pg, `npm ci --omit=dev --ignore-scripts`), the code it shares with
# karidns-signer (node/lib), a wrapper in sbin, the rc script, a sample configuration and the manuals.  The package depends on node24 and creates the user and
# group karidns-webadmin.  It needs karidns-zone (from karidns-sqlite3, karidns-postgresql or karidns-db) and karicheck (from karidns); the database packages
# conflict with each other, so the package cannot depend on one of them by name: its pre-install script refuses to install without /usr/local/bin/karidns-zone
# and /usr/local/bin/karicheck.  The build host needs node24 and npm-node24.

VERSION_ARG="${1:-}"; . packaging/version.sh   # the file VERSION when no number is given
OUT_DIR="${2:-./dist}"
case "$VERSION" in -*) echo "build_webadmin_pkg.sh: usage: build_webadmin_pkg.sh [version] [output_dir]" >&2; exit 2 ;; esac

ARCH=$(pkg config ABI 2>/dev/null || echo "FreeBSD:$(uname -r | cut -d. -f1):$(uname -m)")
ABI_SUFFIX=$(echo "$ARCH" | tr ':' '-')
STAGE_DIR="$(mktemp -d -t karidns-webadmin-stage)"
MANIFEST_DIR="$(mktemp -d -t karidns-webadmin-manifest)"

DEPS=""
for p in node24; do
    if ! pkg query '%n' "$p" >/dev/null 2>&1; then
        echo "ERROR: ${p} is not installed on the build host (pkg install node24 npm-node24)" >&2
        exit 1
    fi
    DEPS="${DEPS}${DEPS:+,
}    $p: { origin: \"$(pkg query '%o' "$p")\", version: \"$(pkg query '%v' "$p")\" }"
    echo "==> depends on ${p}-$(pkg query '%v' "$p")"
done

WEBADMIN_DIR="usr/local/libexec/karidns-webadmin"
(cd webadmin && npm ci --omit=dev --ignore-scripts) || { echo "ERROR: npm ci in webadmin/ failed (pkg install npm-node24)" >&2; exit 1; }
mkdir -p "${STAGE_DIR}/${WEBADMIN_DIR}/webadmin" "${STAGE_DIR}/${WEBADMIN_DIR}/node" "${STAGE_DIR}/usr/local/sbin" "${STAGE_DIR}/usr/local/etc/rc.d" "${STAGE_DIR}/usr/local/etc/karidns" "${STAGE_DIR}/usr/local/share/doc/karidns" "${OUT_DIR}"
cp -R webadmin/bin webadmin/lib webadmin/ui webadmin/package.json webadmin/package-lock.json "${STAGE_DIR}/${WEBADMIN_DIR}/webadmin/"
# the code webadmin/ shares with karidns-signer (node/lib: webadmin/lib imports ../../node/lib), and the one dependency, next to both
cp -R node/lib node/package.json "${STAGE_DIR}/${WEBADMIN_DIR}/node/"
cp -R webadmin/node_modules "${STAGE_DIR}/${WEBADMIN_DIR}/"
rm -rf "${STAGE_DIR}/${WEBADMIN_DIR}/node_modules/.bin"
find "${STAGE_DIR}/${WEBADMIN_DIR}" -type d -exec chmod 0755 {} +
find "${STAGE_DIR}/${WEBADMIN_DIR}" -type f -exec chmod 0444 {} +
chmod 0555 "${STAGE_DIR}/${WEBADMIN_DIR}/webadmin/bin/karidns-webadmin.js"
if [ -n "$(find "${STAGE_DIR}/${WEBADMIN_DIR}" ! -type f ! -type d)" ]; then
    echo "ERROR: the webadmin tree holds something that is neither a file nor a directory" >&2
    exit 1
fi
install -m 0555 packaging/freebsd/karidns-webadmin "${STAGE_DIR}/usr/local/sbin/karidns-webadmin"
install -m 0555 packaging/freebsd/rc.d/karidns_webadmin "${STAGE_DIR}/usr/local/etc/rc.d/karidns_webadmin"
install -m 0644 karidns-webadmin.conf.sample "${STAGE_DIR}/usr/local/etc/karidns/karidns-webadmin.conf.sample"
install -m 0644 docs/karidns-webadmin.md "${STAGE_DIR}/usr/local/share/doc/karidns/karidns-webadmin.md"
install -m 0644 docs/karidns-api.md "${STAGE_DIR}/usr/local/share/doc/karidns/karidns-api.md"
install -m 0644 docs/karidns-webadmin-gui.md "${STAGE_DIR}/usr/local/share/doc/karidns/karidns-webadmin-gui.md"
install -m 0644 docs/karidns-webadmin-gui-checklist.md "${STAGE_DIR}/usr/local/share/doc/karidns/karidns-webadmin-gui-checklist.md"

FILES="    /usr/local/sbin/karidns-webadmin: { uname: \"root\", gname: \"wheel\", perm: \"0555\" },
    /usr/local/etc/rc.d/karidns_webadmin: { uname: \"root\", gname: \"wheel\", perm: \"0555\" },
    /usr/local/etc/karidns/karidns-webadmin.conf.sample: { uname: \"root\", gname: \"wheel\", perm: \"0644\" },
    /usr/local/share/doc/karidns/karidns-webadmin.md: { uname: \"root\", gname: \"wheel\", perm: \"0644\" },
    /usr/local/share/doc/karidns/karidns-api.md: { uname: \"root\", gname: \"wheel\", perm: \"0644\" },
    /usr/local/share/doc/karidns/karidns-webadmin-gui.md: { uname: \"root\", gname: \"wheel\", perm: \"0644\" },
    /usr/local/share/doc/karidns/karidns-webadmin-gui-checklist.md: { uname: \"root\", gname: \"wheel\", perm: \"0644\" }"
for f in $(cd "${STAGE_DIR}" && find "${WEBADMIN_DIR}" -type f | sort); do
    case "$f" in
        *[!A-Za-z0-9_./+@-]*) echo "ERROR: unexpected file name in the webadmin tree: $f" >&2; exit 1 ;;
    esac
    perm=0444
    [ "$f" = "${WEBADMIN_DIR}/webadmin/bin/karidns-webadmin.js" ] && perm=0555
    FILES="${FILES},
    \"/${f}\": { uname: \"root\", gname: \"wheel\", perm: \"${perm}\" }"
done

echo "==> Generating +MANIFEST..."
printf '%s\n' "$DEPS" > "${MANIFEST_DIR}/deps.txt"
printf '%s\n' "$FILES" > "${MANIFEST_DIR}/files.txt"
sed -e "s/__VERSION__/${VERSION}/g" -e "s/__ARCH__/${ARCH}/g" packaging/freebsd/MANIFEST.webadmin.in | tr -d '\r' | awk -v dd="${MANIFEST_DIR}/deps.txt" -v ff="${MANIFEST_DIR}/files.txt" '
    function put(f,   l) { while ((getline l < f) > 0) print l; close(f) }
    $0 == "__DEPS__" { put(dd); next }
    $0 == "__FILES__" { put(ff); next }
    { print }' > "${MANIFEST_DIR}/+MANIFEST"
rm -f "${MANIFEST_DIR}/deps.txt" "${MANIFEST_DIR}/files.txt"
echo "==> Creating FreeBSD pkg..."
pkg create -m "${MANIFEST_DIR}" -r "${STAGE_DIR}" -o "${OUT_DIR}"
if [ -f "${OUT_DIR}/karidns-webadmin-${VERSION}.pkg" ]; then
    mv "${OUT_DIR}/karidns-webadmin-${VERSION}.pkg" "${OUT_DIR}/karidns-webadmin-${VERSION}-${ABI_SUFFIX}.pkg"
fi
rm -rf "${STAGE_DIR}" "${MANIFEST_DIR}"
echo "==> Successfully created FreeBSD package in ${OUT_DIR}:"
ls -lh "${OUT_DIR}/karidns-webadmin-${VERSION}"*.pkg*
