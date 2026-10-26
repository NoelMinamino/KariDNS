#!/bin/sh
set -e

# build_pkg.sh - Build a FreeBSD .pkg package for KariDNS & tools
# Usage: ./packaging/freebsd/build_pkg.sh [--db none|sqlite3|postgresql|both] [version] [output_dir]
#
# The server and the tools are the same in every package; --db only decides whether karidns-dbloader (the database
# loader, docs/karidns-dbloader.md) is built and installed, with which drivers, and which dependencies come with it
# (beta design 1.6):
#
#   --db none        (default)  karidns             no loader                      no database dependency
#   --db sqlite3                karidns-sqlite3     SQLite3 driver                 databases/sqlite3
#   --db postgresql             karidns-postgresql  PostgreSQL driver              databases/postgresqlNN-client (libpq)
#   --db both                   karidns-db          both drivers                   both
#
# The four packages install the same files, so pkg refuses to install a second one over the first (a file conflict; the
# manifest key `conflicts` is not used: pkg 2.x cannot register a conflict with a package that is not installed).  NN of postgresqlNN-client is
# the version of the package that provides the libpq the loader was linked against (found with ldd and pkg which); the
# build host decides, nothing is hard-coded.  Run once per package (each run rebuilds everything: `make clean`).

usage() {
    awk 'NR >= 4 && /^#/ { print; next } NR >= 4 { exit }' "$0" | sed 's/^# \{0,1\}//'
}

DB=none
while [ $# -gt 0 ]; do
    case "$1" in
        --db) DB="${2:-}"; shift 2 ;;
        --db=*) DB="${1#--db=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*) echo "build_pkg.sh: unknown option $1" >&2; usage >&2; exit 2 ;;
        *) break ;;
    esac
done
case "$DB" in
    none)       PKG_NAME=karidns;            DRIVERS="" ;;
    sqlite3)    PKG_NAME=karidns-sqlite3;    DRIVERS="sqlite3" ;;
    postgresql) PKG_NAME=karidns-postgresql; DRIVERS="postgresql" ;;
    both)       PKG_NAME=karidns-db;         DRIVERS="sqlite3 postgresql" ;;
    *) echo "build_pkg.sh: --db must be none, sqlite3, postgresql or both" >&2; exit 2 ;;
esac

VERSION="${1:-1.0.0}"
VERSION="${VERSION#v}" # Strip leading 'v' if present
OUT_DIR="${2:-./dist}"

ARCH=$(pkg config ABI 2>/dev/null || echo "FreeBSD:$(uname -r | cut -d. -f1):$(uname -m)")
ABI_SUFFIX=$(echo "$ARCH" | tr ':' '-')
STAGE_DIR="$(mktemp -d -t karidns-pkg-stage)"
MANIFEST_DIR="$(mktemp -d -t karidns-pkg-manifest)"

echo "==> Building KariDNS binaries for FreeBSD (${ARCH}, version ${VERSION}, package ${PKG_NAME})..."
make clean
# MARCH_FLAGS=: portable baseline ISA, not the build host CPU (-march=native)
make VERSION="${VERSION}" MARCH_FLAGS= all
if [ -n "$DRIVERS" ]; then
    make VERSION="${VERSION}" MARCH_FLAGS= DB_DRIVERS="${DRIVERS}" karidns-dbloader
    # the loader must report exactly the drivers of the package (the server refuses a driver the loader does not have)
    GOT=$(./karidns-dbloader --drivers | tr '\n' ' ' | sed 's/ $//')
    if [ "$GOT" != "$DRIVERS" ]; then
        echo "ERROR: karidns-dbloader has the drivers '${GOT}', expected '${DRIVERS}'" >&2
        exit 1
    fi
fi

# The package must link the base system OpenSSL (/lib, /usr/lib): the ports
# OpenSSL (security/openssl, /usr/local/lib/libcrypto.so.NN) is not a declared
# dependency, so a package linked against it fails to install on hosts without
# it ("Missing shlib libcrypto.so.12"). Set ALLOW_PORTS_OPENSSL=1 to override.
if [ "${ALLOW_PORTS_OPENSSL:-0}" != "1" ]; then
    for b in karidns karictl karicheck dag $( [ -n "$DRIVERS" ] && echo karidns-dbloader ); do
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
add_dep() {                                 # add_dep NAME ORIGIN VERSION
    DEPS="${DEPS}${DEPS:+,
}    $1: { origin: \"$2\", version: \"$3\" }"
}
# dep_of LIBRARY-PATTERN BINARY: the package that provides the shared library BINARY is linked against
dep_of() {
    _lib=$(ldd "$2" 2>/dev/null | awk -v pat="$1" '$1 ~ pat { print $3; exit }')
    [ -n "$_lib" ] || return 1
    _pkg=$(pkg which -q "$_lib" 2>/dev/null) || return 1   # prints name-version
    [ -n "$_pkg" ] || return 1
    _name=$(pkg query '%n' "$_pkg" 2>/dev/null) || return 1
    DEP_NAME=$_name
    DEP_ORIGIN=$(pkg query '%o' "$_name")
    DEP_VERSION=$(pkg query '%v' "$_name")
    return 0
}
if ldd dag 2>/dev/null | grep -q 'libidn2\.so'; then
    IDN2_VER=$(pkg query '%v' libidn2 2>/dev/null || true)
    IDN2_ORIGIN=$(pkg query '%o' libidn2 2>/dev/null || echo dns/libidn2)
    if [ -n "$IDN2_VER" ]; then
        add_dep libidn2 "${IDN2_ORIGIN}" "${IDN2_VER}"
    fi
fi
for d in $DRIVERS; do
    case "$d" in
        sqlite3)    PAT='^libsqlite3\.so'; WHAT=SQLite3 ;;
        postgresql) PAT='^libpq\.so';      WHAT=PostgreSQL ;;
    esac
    if dep_of "$PAT" karidns-dbloader; then
        add_dep "$DEP_NAME" "$DEP_ORIGIN" "$DEP_VERSION"
        echo "==> ${WHAT} driver: depends on ${DEP_NAME}-${DEP_VERSION} (${DEP_ORIGIN})"
    else
        echo "ERROR: cannot find the package that provides the ${WHAT} library of karidns-dbloader" >&2
        exit 1
    fi
done

echo "==> Preparing staging root..."
mkdir -p "${STAGE_DIR}/usr/local/sbin"
mkdir -p "${STAGE_DIR}/usr/local/bin"
mkdir -p "${STAGE_DIR}/usr/local/etc/rc.d"
mkdir -p "${STAGE_DIR}/usr/local/etc/karidns/zones"
mkdir -p "${STAGE_DIR}/usr/local/share/doc/karidns"
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

# Install the manuals
for m in karidns karictl karicheck dag dag_replay; do
    install -m 0644 "docs/${m}.md" "${STAGE_DIR}/usr/local/share/doc/karidns/${m}.md"
done

# The database loader, its manual and the SQL files (extension tables, change-log triggers, role script) of the drivers it has.
# The loader is installed where `loader-path` points by default; it has to be owned by root and not writable by group or others
# (karidns checks that), so the manifest names the owner instead of relying on the user who ran this script.
DB_FILES=""
DB_DESC=""
if [ -n "$DRIVERS" ]; then
    mkdir -p "${STAGE_DIR}/usr/local/libexec"
    mkdir -p "${STAGE_DIR}/usr/local/share/karidns/db"
    install -m 0555 karidns-dbloader "${STAGE_DIR}/usr/local/libexec/karidns-dbloader"
    install -m 0644 docs/karidns-dbloader.md "${STAGE_DIR}/usr/local/share/doc/karidns/karidns-dbloader.md"
    DB_FILES="    /usr/local/libexec/karidns-dbloader: { uname: \"root\", gname: \"wheel\", perm: \"0555\" },
    /usr/local/share/doc/karidns/karidns-dbloader.md: { uname: \"root\", gname: \"wheel\", perm: \"0644\" },"
    SQL_FILES=""
    for d in $DRIVERS; do
        case "$d" in
            sqlite3)    SQL_FILES="${SQL_FILES} db/karidns_ext.sqlite3.sql db/karidns_ext_v1_to_v2.sqlite3.sql" ;;
            postgresql) SQL_FILES="${SQL_FILES} db/karidns_ext.pgsql.sql db/karidns_ext_v1_to_v2.pgsql.sql db/karidns_loader_role.pgsql.sql" ;;
        esac
    done
    for f in $SQL_FILES; do
        install -m 0644 "$f" "${STAGE_DIR}/usr/local/share/karidns/db/$(basename "$f")"
        DB_FILES="${DB_FILES}
    /usr/local/share/karidns/db/$(basename "$f"): { uname: \"root\", gname: \"wheel\", perm: \"0644\" },"
    done
    DB_DESC="This package includes karidns-dbloader with the driver(s): ${DRIVERS}."
fi

echo "==> Generating +MANIFEST..."
printf '%s\n' "$DEPS" | sed '/^$/d' > "${MANIFEST_DIR}/deps.txt"
printf '%s\n' "$DB_FILES" | sed '/^$/d' > "${MANIFEST_DIR}/dbfiles.txt"
printf '%s\n' "$DB_DESC" | sed '/^$/d' > "${MANIFEST_DIR}/dbdesc.txt"
sed -e "s/__VERSION__/${VERSION}/g" \
    -e "s/__ARCH__/${ARCH}/g" \
    -e "s/__NAME__/${PKG_NAME}/g" \
    packaging/freebsd/MANIFEST.in | tr -d '\r' | awk -v dd="${MANIFEST_DIR}/deps.txt" -v df="${MANIFEST_DIR}/dbfiles.txt" -v dc="${MANIFEST_DIR}/dbdesc.txt" '
    function put(f,   l) { while ((getline l < f) > 0) print l; close(f) }
    $0 == "__DEPS__" { put(dd); next }
    $0 == "__DB_FILES__" { put(df); next }
    $0 == "__DB_DESC__" { put(dc); next }
    { print }' > "${MANIFEST_DIR}/+MANIFEST"

rm -f "${MANIFEST_DIR}"/deps.txt "${MANIFEST_DIR}"/dbfiles.txt "${MANIFEST_DIR}"/dbdesc.txt
echo "==> Creating FreeBSD pkg..."
pkg create -m "${MANIFEST_DIR}" -r "${STAGE_DIR}" -o "${OUT_DIR}"

# Rename pkg to include ABI suffix (e.g. karidns-1.0.0-FreeBSD-14-amd64.pkg / karidns-1.0.0-FreeBSD-15-amd64.pkg)
PKG_DEFAULT="${OUT_DIR}/${PKG_NAME}-${VERSION}.pkg"
PKG_TARGET="${OUT_DIR}/${PKG_NAME}-${VERSION}-${ABI_SUFFIX}.pkg"
if [ -f "$PKG_DEFAULT" ]; then
    mv "$PKG_DEFAULT" "$PKG_TARGET"
fi

# Cleanup
rm -rf "${STAGE_DIR}" "${MANIFEST_DIR}"

echo "==> Successfully created FreeBSD package in ${OUT_DIR}:"
ls -lh "${OUT_DIR}/${PKG_NAME}-${VERSION}"*.pkg*
