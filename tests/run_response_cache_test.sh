#!/bin/sh
set -e

echo "=== Running Pre-rendered Wire-format Response Cache Tests ==="

CC="${CC:-clang}"
CFLAGS="${CFLAGS:--O1 -g -fsanitize=address,undefined -I.}"
LDFLAGS="${LDFLAGS:--lcrypto -lpthread -lm}"

SRCS="tests/test_response_cache.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c"

$CC $CFLAGS $SRCS $LDFLAGS -o test_response_cache_bin
./test_response_cache_bin
rm -f test_response_cache_bin

echo "=== Pre-rendered Wire-format Response Cache Tests: ALL PASSED ==="
