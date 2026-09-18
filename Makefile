# Makefile for karidns & dag (FreeBSD, Linux, macOS)

UNAME_S != uname -s 2>/dev/null || echo Unknown

# OS-specific flags
DARWIN_CFLAGS  != [ "`uname -s 2>/dev/null`" = "Darwin" ] && echo "-I`brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl`/include" || echo "-I/usr/local/include"
DARWIN_LDFLAGS != [ "`uname -s 2>/dev/null`" = "Darwin" ] && echo "-L`brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl`/lib" || echo "-L/usr/local/lib"

# Hardening LDFLAGS (macOS & Windows ld do not support ELF -z options)
HARDEN_LDFLAGS != case "`uname -s 2>/dev/null`" in Darwin) echo "-pie" ;; MINGW*|MSYS*|CYGWIN*) echo "" ;; *) echo "-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack" ;; esac

# libidn2 detection (portable for BSD make & GNU make)
IDN_CFLAGS != (pkg-config --exists libidn2 2>/dev/null && echo "-DHAVE_LIBIDN2 `pkg-config --cflags libidn2 2>/dev/null`") || (pkg info -e libidn2 >/dev/null 2>&1 && echo "-DHAVE_LIBIDN2") || ([ -f /usr/include/idn2.h ] || [ -f /usr/local/include/idn2.h ] && echo "-DHAVE_LIBIDN2") || true
IDN_LDFLAGS != (pkg-config --libs libidn2 2>/dev/null || (pkg info -e libidn2 >/dev/null 2>&1 && echo "-L/usr/local/lib -lidn2") || ([ -f /usr/lib/libidn2.so ] || [ -f /usr/local/lib/libidn2.so ] || [ -f /usr/lib64/libidn2.so ] && echo "-lidn2")) || true

# Windows / MinGW detection (static single-binary build)
WIN_LDFLAGS != case "`uname -s 2>/dev/null`" in MINGW*|MSYS*|CYGWIN*) echo "-static -lws2_32 -liphlpapi -lcrypt32" ;; *) echo "" ;; esac

# Homebrew & standard paths for macOS (Apple Silicon /opt/homebrew & Intel /usr/local) and BSD
BREW_CFLAGS  = -I/opt/homebrew/opt/openssl@3/include -I/usr/local/opt/openssl@3/include -I/opt/homebrew/include -I/usr/local/include
BREW_LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -L/usr/local/opt/openssl@3/lib -L/opt/homebrew/lib -L/usr/local/lib

# Version definition
VERSION ?= 0.3.0

CC ?= cc
CFLAGS += -O3 -flto -march=native -Wall -Wextra -std=c11 -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -DKARIDNS_VERSION=\"$(VERSION)\" $(BREW_CFLAGS) $(DARWIN_CFLAGS) $(IDN_CFLAGS)
LDFLAGS = -flto -pthread -lm $(BREW_LDFLAGS) $(DARWIN_LDFLAGS) $(HARDEN_LDFLAGS)


TARGET = karidns
SRCS = dns_server_core.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_rrl.c dns_tsig_acl.c dns_priv_sandbox.c dns_dynamic_update.c dns_axfr_ixfr.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c
OBJS = $(SRCS:.c=.o)

DAG_TARGET = dag
DAG_SRCS = tools/dag.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

DAG_OBJS = $(DAG_SRCS:.c=.o)

KARICTL_TARGET = karictl
KARICTL_SRCS = tools/karictl.c
KARICTL_OBJS = $(KARICTL_SRCS:.c=.o)

FUZZ_TARGET = tests/fuzz/fuzz_dns_wire
FUZZ_SRCS = tests/fuzz/fuzz_dns_wire.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_CORE_TARGET = tests/fuzz/fuzz_dns_server_core
FUZZ_CORE_SRCS = tests/fuzz/fuzz_dns_server_core.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_rrl.c dns_tsig_acl.c dns_priv_sandbox.c dns_dynamic_update.c dns_axfr_ixfr.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c

FUZZ_ZONE_TARGET = tests/fuzz/fuzz_zone_parser
FUZZ_ZONE_SRCS = tests/fuzz/fuzz_zone_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_wire.c dns_cidr.c

FUZZ_CONF_TARGET = tests/fuzz/fuzz_conf_parser
FUZZ_CONF_SRCS = tests/fuzz/fuzz_conf_parser.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c dns_tsig_acl.c

FUZZ_TSIG_TARGET = tests/fuzz/fuzz_tsig_sign
FUZZ_TSIG_SRCS = tests/fuzz/fuzz_tsig_sign.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_TARGET = tests/fuzz/fuzz_dag_response
FUZZ_DAG_SRCS = tests/fuzz/fuzz_dag_response.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_TSIG_VERIFY_TARGET = tests/fuzz/fuzz_tsig_verify
FUZZ_TSIG_VERIFY_SRCS = tests/fuzz/fuzz_tsig_verify.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_HASH_TARGET = tests/fuzz/fuzz_dag_hash
FUZZ_DAG_HASH_SRCS = tests/fuzz/fuzz_dag_hash.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_CHUNKED_HTTP_TARGET = tests/fuzz/fuzz_dag_chunked_http
FUZZ_DAG_CHUNKED_HTTP_SRCS = tests/fuzz/fuzz_dag_chunked_http.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_RDATA_YAML_TARGET = tests/fuzz/fuzz_dag_rdata_yaml
FUZZ_DAG_RDATA_YAML_SRCS = tests/fuzz/fuzz_dag_rdata_yaml.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_AXFR_STREAM_TARGET = tests/fuzz/fuzz_dag_axfr_stream
FUZZ_DAG_AXFR_STREAM_SRCS = tests/fuzz/fuzz_dag_axfr_stream.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_CLI_ARGS_TARGET = tests/fuzz/fuzz_dag_cli_args
FUZZ_DAG_CLI_ARGS_SRCS = tests/fuzz/fuzz_dag_cli_args.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_BATCH_FILE_TARGET = tests/fuzz/fuzz_dag_batch_file
FUZZ_DAG_BATCH_FILE_SRCS = tests/fuzz/fuzz_dag_batch_file.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_REPLAY_PCAP_READER_TARGET = tests/fuzz/fuzz_dag_replay_pcap_reader
FUZZ_DAG_REPLAY_PCAP_READER_SRCS = tests/fuzz/fuzz_dag_replay_pcap_reader.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_REPLAY_DIFF_TARGET = tests/fuzz/fuzz_dag_replay_diff
FUZZ_DAG_REPLAY_DIFF_SRCS = tests/fuzz/fuzz_dag_replay_diff.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_TCP_REASSEMBLY_TARGET = tests/fuzz/fuzz_dag_tcp_reassembly
FUZZ_DAG_TCP_REASSEMBLY_SRCS = tests/fuzz/fuzz_dag_tcp_reassembly.c tools/dag_tcp_reassembly.c tools/dag_pcap_l4.c tools/dag_replay.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

.PHONY: all clean run fuzz fuzz_core clean-fuzz asan tsan fuzz_tsig fuzz_dag fuzz_tsig_verify dag tools response_cache_test \
	fuzz_dag_hash fuzz_dag_chunked_http fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file \
	fuzz_dag_replay_pcap_reader fuzz_dag_replay_diff fuzz_dag_tcp_reassembly \
	fuzz_dag_all fuzz_dag_test fuzz_karidns fuzz_karidns_test fuzz_all fuzz_test \
	unit-tests test test-all cidr_test tinydns_test asan_test include_test hash_test vulnerability_test \
	coverage coverage-build coverage-run coverage-report coverage-clean

all: $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

$(KARICTL_TARGET): $(KARICTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

$(DAG_TARGET): $(DAG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS) $(WIN_LDFLAGS)

karicheck: tools/karicheck.c dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o dns_utils.o dns_cidr.o dns_tsig_acl.o
	$(CC) $(CFLAGS) tools/karicheck.c dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o dns_utils.o dns_cidr.o dns_tsig_acl.o -o karicheck $(LDFLAGS) -lcrypto

$(OBJS) $(DAG_OBJS) $(KARICTL_OBJS): dns_wire.h dns_config_parser.h dns_zone_parser.h dns_utils.h

.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

dns_server_core.o: dns_server_core.c
	$(CC) $(CFLAGS) -c dns_server_core.c -o dns_server_core.o

dns_catalog_zone.o: dns_catalog_zone.c
	$(CC) $(CFLAGS) -c dns_catalog_zone.c -o dns_catalog_zone.o

dns_dnstap.o: dns_dnstap.c
	$(CC) $(CFLAGS) -c dns_dnstap.c -o dns_dnstap.o

dns_edns_ecs.o: dns_edns_ecs.c
	$(CC) $(CFLAGS) -c dns_edns_ecs.c -o dns_edns_ecs.o

dns_rrl.o: dns_rrl.c
	$(CC) $(CFLAGS) -c dns_rrl.c -o dns_rrl.o

dns_tsig_acl.o: dns_tsig_acl.c
	$(CC) $(CFLAGS) -c dns_tsig_acl.c -o dns_tsig_acl.o

dns_priv_sandbox.o: dns_priv_sandbox.c
	$(CC) $(CFLAGS) -c dns_priv_sandbox.c -o dns_priv_sandbox.o

dns_dynamic_update.o: dns_dynamic_update.c
	$(CC) $(CFLAGS) -c dns_dynamic_update.c -o dns_dynamic_update.o

dns_axfr_ixfr.o: dns_axfr_ixfr.c
	$(CC) $(CFLAGS) -c dns_axfr_ixfr.c -o dns_axfr_ixfr.o

dns_query_engine.o: dns_query_engine.c
	$(CC) $(CFLAGS) -c dns_query_engine.c -o dns_query_engine.o

dns_snapshot_rcu.o: dns_snapshot_rcu.c
	$(CC) $(CFLAGS) -c dns_snapshot_rcu.c -o dns_snapshot_rcu.o

dns_epoch_rcu.o: dns_epoch_rcu.c
	$(CC) $(CFLAGS) -c dns_epoch_rcu.c -o dns_epoch_rcu.o

dns_wire.o: dns_wire.c
	$(CC) $(CFLAGS) -c dns_wire.c -o dns_wire.o

dns_config_parser.o: dns_config_parser.c
	$(CC) $(CFLAGS) -c dns_config_parser.c -o dns_config_parser.o

dns_zone_parser.o: dns_zone_parser.c
	$(CC) $(CFLAGS) -c dns_zone_parser.c -o dns_zone_parser.o

dns_tinydns_parser.o: dns_tinydns_parser.c
	$(CC) $(CFLAGS) -c dns_tinydns_parser.c -o dns_tinydns_parser.o

dns_utils.o: dns_utils.c
	$(CC) $(CFLAGS) -c dns_utils.c -o dns_utils.o

dns_cidr.o: dns_cidr.c
	$(CC) $(CFLAGS) -c dns_cidr.c -o dns_cidr.o

tools/dag.o: tools/dag.c tools/dag_internal.h tools/dag_output_yaml.h tools/dag_batch.h tools/dag_axfr_client.h tools/dag_trace.h tools/dag_tsig_client.h tools/dag_edns_client.h tools/dag_transport.h
	$(CC) $(CFLAGS) -c tools/dag.c -o tools/dag.o

tools/dag_output_yaml.o: tools/dag_output_yaml.c tools/dag_output_yaml.h tools/dag_internal.h
	$(CC) $(CFLAGS) -c tools/dag_output_yaml.c -o tools/dag_output_yaml.o

tools/dag_batch.o: tools/dag_batch.c tools/dag_batch.h tools/dag_internal.h
	$(CC) $(CFLAGS) -c tools/dag_batch.c -o tools/dag_batch.o

tools/dag_axfr_client.o: tools/dag_axfr_client.c tools/dag_axfr_client.h tools/dag_internal.h
	$(CC) $(CFLAGS) -c tools/dag_axfr_client.c -o tools/dag_axfr_client.o

tools/dag_trace.o: tools/dag_trace.c tools/dag_trace.h tools/dag_internal.h tools/dag_output_yaml.h tools/dag_axfr_client.h
	$(CC) $(CFLAGS) -c tools/dag_trace.c -o tools/dag_trace.o

tools/dag_tsig_client.o: tools/dag_tsig_client.c tools/dag_tsig_client.h tools/dag_internal.h
	$(CC) $(CFLAGS) -c tools/dag_tsig_client.c -o tools/dag_tsig_client.o

tools/dag_edns_client.o: tools/dag_edns_client.c tools/dag_edns_client.h tools/dag_internal.h
	$(CC) $(CFLAGS) -c tools/dag_edns_client.c -o tools/dag_edns_client.o

tools/dag_transport.o: tools/dag_transport.c tools/dag_transport.h tools/dag_internal.h
	$(CC) $(CFLAGS) -c tools/dag_transport.c -o tools/dag_transport.o

tools/dag_pcap_l4.o: tools/dag_pcap_l4.c tools/dag_pcap_l4.h
	$(CC) $(CFLAGS) -c tools/dag_pcap_l4.c -o tools/dag_pcap_l4.o

tools/dag_tcp_reassembly.o: tools/dag_tcp_reassembly.c tools/dag_tcp_reassembly.h tools/dag_pcap_l4.h
	$(CC) $(CFLAGS) -c tools/dag_tcp_reassembly.c -o tools/dag_tcp_reassembly.o

tools/dag_replay.o: tools/dag_replay.c tools/dag_replay.h tools/dag_pcap_l4.h tools/dag_tcp_reassembly.h
	$(CC) $(CFLAGS) -c tools/dag_replay.c -o tools/dag_replay.o

tools/karictl.o: tools/karictl.c
	$(CC) $(CFLAGS) -c tools/karictl.c -o tools/karictl.o

TEST_CIDR_SRCS = tests/test_cidr.c dns_cidr.c dns_tsig_acl.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c
TEST_TINYDNS_SRCS = tests/test_tinydns_parser.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_ASAN_SRCS = tests/test_asan_overflow.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_CONF_SRCS = tests/test_conf_include.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_HASH_SRCS = tests/test_hash_table.c
RESPONSE_CACHE_TEST_SRCS = tests/test_response_cache.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
VULN_TEST_SRCS = tests/test_vulnerability_fixes.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c

test_cidr: $(TEST_CIDR_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_CIDR_SRCS) -o test_cidr $(LDFLAGS) -lcrypto

cidr_test: test_cidr
	./test_cidr

test_tinydns_parser: $(TEST_TINYDNS_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_TINYDNS_SRCS) -o test_tinydns_parser $(LDFLAGS) -lcrypto

tinydns_test: test_tinydns_parser
	./test_tinydns_parser

tinydns_timestamp_test: $(TARGET) $(DAG_TARGET) karicheck
	sh tests/run_tinydns_timestamp_test.sh

tinydns_location_test: $(TARGET) $(DAG_TARGET) karicheck
	sh tests/run_tinydns_location_test.sh

bind_ecs_subnet_test: $(TARGET) $(DAG_TARGET) karicheck
	sh tests/run_bind_ecs_subnet_test.sh

extended_axfr_test: $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck
	sh tests/run_extended_axfr_test.sh

test_asan_overflow: $(TEST_ASAN_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_ASAN_SRCS) -o test_asan_overflow $(LDFLAGS) -lcrypto

asan_test: test_asan_overflow
	./test_asan_overflow

test_conf_include: $(TEST_CONF_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_CONF_SRCS) -o test_conf_include $(LDFLAGS) -lcrypto

include_test: test_conf_include
	./test_conf_include

test_hash_table: $(TEST_HASH_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_HASH_SRCS) -o test_hash_table $(LDFLAGS)

hash_test: test_hash_table
	./test_hash_table

test_response_cache: $(RESPONSE_CACHE_TEST_SRCS)
	$(CC) $(CFLAGS) -I. $(RESPONSE_CACHE_TEST_SRCS) -o test_response_cache $(LDFLAGS) -lcrypto -lpthread -lm

response_cache_test: test_response_cache
	./test_response_cache

test_vulnerability_fixes: $(VULN_TEST_SRCS)
	$(CC) $(CFLAGS) -I. $(VULN_TEST_SRCS) -o test_vulnerability_fixes $(LDFLAGS) -lcrypto -lpthread -lm

vulnerability_test: test_vulnerability_fixes
	./test_vulnerability_fixes

unit-tests: cidr_test tinydns_test asan_test include_test hash_test response_cache_test vulnerability_test

test: $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck
	@sh tests/run_all_suite.sh

test-all: test

# --- Code Coverage (Clang Source-Based Instrumentation) ---
LLVM_PROFDATA ?= llvm-profdata
LLVM_COV      ?= llvm-cov

COV_CFLAGS  = -fprofile-instr-generate -fcoverage-mapping -O0 -g -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED -Wall -Wextra -std=c11 -fPIE $(BREW_CFLAGS) $(DARWIN_CFLAGS) $(IDN_CFLAGS)
COV_LDFLAGS = -fprofile-instr-generate -pthread -lm $(BREW_LDFLAGS) $(DARWIN_LDFLAGS) $(HARDEN_LDFLAGS)
COV_DIR     = coverage_raw
COV_HTML_DIR = coverage_html
COV_DATA    = coverage.profdata

coverage-clean:
	rm -rf $(COV_DIR) $(COV_HTML_DIR) $(COV_DATA) default.profraw *.profraw

coverage-build:
	@echo "=== Building KariDNS & Test Suite with Profile Coverage ==="
	$(MAKE) clean
	$(MAKE) CC="clang" CFLAGS="$(COV_CFLAGS)" LDFLAGS="$(COV_LDFLAGS)" all karicheck
	$(MAKE) CC="clang" CFLAGS="$(COV_CFLAGS)" LDFLAGS="$(COV_LDFLAGS)" test_cidr test_tinydns_parser test_asan_overflow test_conf_include test_hash_table test_response_cache test_vulnerability_fixes

coverage-run:
	@echo "=== Executing Test Suite with Instrumentation ==="
	@mkdir -p $(COV_DIR)
	@LLVM_PROFILE_FILE="$(COV_DIR)/karidns_%p_%m.profraw" sh tests/run_all_suite.sh || true

coverage-report:
	@echo "=== Merging Profile Data & Generating Coverage Report ==="
	@command -v $(LLVM_PROFDATA) >/dev/null 2>&1 || { echo "Error: $(LLVM_PROFDATA) not found in PATH."; exit 1; }
	@ls $(COV_DIR)/*.profraw >/dev/null 2>&1 || { echo "Error: No profile data found in $(COV_DIR). Run 'make coverage-run' first."; exit 1; }
	$(LLVM_PROFDATA) merge -sparse $(COV_DIR)/*.profraw -o $(COV_DATA)
	@mkdir -p $(COV_HTML_DIR)
	$(LLVM_COV) show $(TARGET) -instr-profile=$(COV_DATA) -format=html -output-dir=$(COV_HTML_DIR) -ignore-filename-regex="tests/|tools/|scratch/|old_patches/|third_party/" -show-line-counts-or-regions -show-branches=count
	@echo ""
	@echo "=== KariDNS Core Engine Coverage Summary ==="
	$(LLVM_COV) report $(TARGET) -instr-profile=$(COV_DATA) -ignore-filename-regex="tests/|tools/|scratch/|old_patches/|third_party/"
	@echo ""
	@echo "Full HTML coverage report available at: $(COV_HTML_DIR)/index.html"

coverage: coverage-clean coverage-build coverage-run coverage-report

bench_serialize: tests/bench_serialize.c dns_wire.o dns_utils.o dns_zone_parser.o dns_tinydns_parser.o dns_config_parser.o dns_cidr.o dns_tsig_acl.o
	$(CC) $(CFLAGS) tests/bench_serialize.c dns_wire.o dns_utils.o dns_zone_parser.o dns_tinydns_parser.o dns_config_parser.o dns_cidr.o dns_tsig_acl.o -o bench_serialize $(LDFLAGS) -lssl -lcrypto -lz

bench_rrl: tests/bench_rrl.c dns_rrl.o dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o dns_utils.o dns_cidr.o dns_tsig_acl.o
	$(CC) $(CFLAGS) tests/bench_rrl.c dns_rrl.o dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o dns_utils.o dns_cidr.o dns_tsig_acl.o -o bench_rrl $(LDFLAGS) -lssl -lcrypto -lz

clean: clean-fuzz coverage-clean
	rm -f $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck bench_serialize bench_rrl $(OBJS) $(DAG_OBJS) $(KARICTL_OBJS)
	rm -f karidns-asan karidns-tsan *.asan.o *.tsan.o test_asan_overflow test_conf_include test_hash_table test_response_cache test_cidr test_tinydns_parser test_vulnerability_fixes

run: $(TARGET)
	./$(TARGET)

fuzz: $(FUZZ_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TARGET) $(FUZZ_SRCS) $(LDFLAGS) -lcrypto

fuzz_core: $(FUZZ_CORE_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_CORE_TARGET) $(FUZZ_CORE_SRCS) $(LDFLAGS) -lcrypto

fuzz_zone: $(FUZZ_ZONE_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_ZONE_TARGET) $(FUZZ_ZONE_SRCS) $(LDFLAGS) -lcrypto

fuzz_conf: $(FUZZ_CONF_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_CONF_TARGET) $(FUZZ_CONF_SRCS) $(LDFLAGS) -lcrypto

fuzz_tsig: $(FUZZ_TSIG_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TSIG_TARGET) $(FUZZ_TSIG_SRCS) $(LDFLAGS) -lcrypto

fuzz_dag: $(FUZZ_DAG_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_TARGET) $(FUZZ_DAG_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_tsig_verify: $(FUZZ_TSIG_VERIFY_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TSIG_VERIFY_TARGET) $(FUZZ_TSIG_VERIFY_SRCS) $(LDFLAGS) -lcrypto

fuzz_dag_hash: $(FUZZ_DAG_HASH_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_HASH_TARGET) $(FUZZ_DAG_HASH_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_chunked_http: $(FUZZ_DAG_CHUNKED_HTTP_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_CHUNKED_HTTP_TARGET) $(FUZZ_DAG_CHUNKED_HTTP_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_rdata_yaml: $(FUZZ_DAG_RDATA_YAML_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_RDATA_YAML_TARGET) $(FUZZ_DAG_RDATA_YAML_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_axfr_stream: $(FUZZ_DAG_AXFR_STREAM_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_AXFR_STREAM_TARGET) $(FUZZ_DAG_AXFR_STREAM_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_cli_args: $(FUZZ_DAG_CLI_ARGS_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_CLI_ARGS_TARGET) $(FUZZ_DAG_CLI_ARGS_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_batch_file: $(FUZZ_DAG_BATCH_FILE_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_BATCH_FILE_TARGET) $(FUZZ_DAG_BATCH_FILE_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_replay_pcap_reader: $(FUZZ_DAG_REPLAY_PCAP_READER_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_REPLAY_PCAP_READER_TARGET) $(FUZZ_DAG_REPLAY_PCAP_READER_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_replay_diff: $(FUZZ_DAG_REPLAY_DIFF_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_REPLAY_DIFF_TARGET) $(FUZZ_DAG_REPLAY_DIFF_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_tcp_reassembly: $(FUZZ_DAG_TCP_REASSEMBLY_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_TCP_REASSEMBLY_TARGET) $(FUZZ_DAG_TCP_REASSEMBLY_SRCS) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_all: fuzz_dag fuzz_dag_hash fuzz_dag_chunked_http fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file fuzz_dag_replay_pcap_reader fuzz_dag_replay_diff fuzz_dag_tcp_reassembly

fuzz_dag_test: fuzz_dag_all
	@sh tests/run_fuzz_smoke_test.sh dag

fuzz_karidns: fuzz fuzz_core fuzz_zone fuzz_conf fuzz_tsig fuzz_tsig_verify

fuzz_karidns_test: fuzz_karidns
	@sh tests/run_fuzz_smoke_test.sh karidns

fuzz_all: fuzz_karidns fuzz_dag_all

fuzz_test: fuzz_all
	@sh tests/run_fuzz_smoke_test.sh all

clean-fuzz:
	rm -f $(FUZZ_TARGET) $(FUZZ_CORE_TARGET) $(FUZZ_ZONE_TARGET) $(FUZZ_CONF_TARGET) $(FUZZ_TSIG_TARGET) $(FUZZ_DAG_TARGET) $(FUZZ_TSIG_VERIFY_TARGET)
	rm -f $(FUZZ_DAG_HASH_TARGET) $(FUZZ_DAG_CHUNKED_HTTP_TARGET) $(FUZZ_DAG_RDATA_YAML_TARGET) $(FUZZ_DAG_AXFR_STREAM_TARGET) $(FUZZ_DAG_CLI_ARGS_TARGET) $(FUZZ_DAG_BATCH_FILE_TARGET)
	rm -f $(FUZZ_DAG_REPLAY_PCAP_READER_TARGET) $(FUZZ_DAG_REPLAY_DIFF_TARGET) $(FUZZ_DAG_TCP_REASSEMBLY_TARGET)

ASAN_TARGET = karidns-asan
ASAN_CFLAGS = -O1 -Wall -Wextra -std=c11 -D_GNU_SOURCE -DSANITIZER_BUILD -g -fsanitize=address,undefined -fno-omit-frame-pointer -fPIE
ASAN_OBJS = $(SRCS:.c=.asan.o)

asan: $(ASAN_TARGET)

$(ASAN_TARGET): $(ASAN_OBJS)
	$(CC) $(ASAN_CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

.SUFFIXES: .asan.o .c
.c.asan.o:
	$(CC) $(ASAN_CFLAGS) -c $< -o $@

TSAN_TARGET = karidns-tsan
TSAN_CFLAGS = -O1 -Wall -Wextra -std=c11 -D_GNU_SOURCE -DSANITIZER_BUILD -g -fsanitize=thread -fPIE
TSAN_LDFLAGS = -fsanitize=thread -pie
TSAN_OBJS = $(SRCS:.c=.tsan.o)

tsan: $(TSAN_TARGET)

$(TSAN_TARGET): $(TSAN_OBJS)
	$(CC) $(TSAN_CFLAGS) -o $@ $^ $(LDFLAGS) $(TSAN_LDFLAGS) -lcrypto

.SUFFIXES: .tsan.o .c
.c.tsan.o:
	$(CC) $(TSAN_CFLAGS) -c $< -o $@

# --- ASan版ツール群 ---
KARICHECK_ASAN_SRCS = tools/karicheck.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c
karicheck-asan: $(KARICHECK_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(KARICHECK_ASAN_SRCS) -o $@ $(LDFLAGS) -lcrypto

DAG_ASAN_SRCS = tools/dag.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c
dag-asan: $(DAG_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(DAG_ASAN_SRCS) -o $@ $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

KARICTL_ASAN_SRCS = tools/karictl.c
karictl-asan: $(KARICTL_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(KARICTL_ASAN_SRCS) -o $@ -lcrypto -fsanitize=address,undefined

.PHONY: tools-asan
tools-asan: karicheck-asan dag-asan karictl-asan
