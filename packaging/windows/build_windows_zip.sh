#!/bin/sh
# build_windows_zip.sh - Build and package dag for Windows (x86_64) into ZIP
set -e

VERSION="${1:-0.0.0}"
OUT_DIR="${2:-./dist}"

mkdir -p "${OUT_DIR}"

echo "==> Building / packaging dag for Windows (x86_64, version ${VERSION})..."

# Find or build dag binary
if [ -f "dag.exe" ]; then
    DAG_BIN="dag.exe"
elif [ -f "dag" ]; then
    DAG_BIN="dag"
else
    echo "==> Compiling dag..."
    make clean
    make dag
    if [ -f "dag.exe" ]; then
        DAG_BIN="dag.exe"
    else
        DAG_BIN="dag"
    fi
fi

# Prepare staging directory
STAGING_DIR="$(mktemp -d -t dag-win-XXXXXX 2>/dev/null || mktemp -d)"
PKG_DIR="${STAGING_DIR}/dag-${VERSION}-windows-x86_64"
mkdir -p "${PKG_DIR}"

cp "${DAG_BIN}" "${PKG_DIR}/dag.exe"
[ -f "README.md" ] && cp "README.md" "${PKG_DIR}/"
[ -f "LICENSE" ] && cp "LICENSE" "${PKG_DIR}/"
mkdir -p "${PKG_DIR}/docs"
[ -f "docs/dag.md" ] && cp "docs/dag.md" "${PKG_DIR}/docs/"

# Auto-bundle non-system runtime DLLs if dynamically linked
if command -v ldd >/dev/null 2>&1; then
    for dll in $(ldd "${DAG_BIN}" 2>/dev/null | grep -iE 'mingw|msys|ucrt|clang' | awk '{print $3}' | grep -v '^/c/Windows'); do
        if [ -f "$dll" ]; then
            echo "==> Bundling dependent DLL: $dll"
            cp "$dll" "${PKG_DIR}/" 2>/dev/null || true
        fi
    done
fi

ZIP_NAME="dag-${VERSION}-windows-x86_64.zip"

if command -v zip >/dev/null 2>&1; then
    (cd "${STAGING_DIR}" && zip -r -q "${ZIP_NAME}" "dag-${VERSION}-windows-x86_64")
    mv "${STAGING_DIR}/${ZIP_NAME}" "${OUT_DIR}/"
else
    # Fallback to python or tar/gzip if zip is unavailable
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import shutil; shutil.make_archive('${OUT_DIR}/dag-${VERSION}-windows-x86_64', 'zip', '${STAGING_DIR}', 'dag-${VERSION}-windows-x86_64')"
    else
        tar -czf "${OUT_DIR}/dag-${VERSION}-windows-x86_64.tar.gz" -C "${STAGING_DIR}" "dag-${VERSION}-windows-x86_64"
    fi
fi

rm -rf "${STAGING_DIR}"

echo "==> Windows package created: ${OUT_DIR}/${ZIP_NAME}"
