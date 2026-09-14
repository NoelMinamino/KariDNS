#!/bin/sh
set -e

echo "=== Running Pre-rendered Wire-format Response Cache Tests ==="

CC="${CC:-clang}"
CFLAGS="${CFLAGS:--O1 -g -fsanitize=address,undefined -I.}"
LDFLAGS="${LDFLAGS:--lcrypto}"

$CC $CFLAGS tests/test_response_cache.c $LDFLAGS -o test_response_cache_bin
./test_response_cache_bin
rm -f test_response_cache_bin

echo "=== Pre-rendered Wire-format Response Cache Tests: ALL PASSED ==="
