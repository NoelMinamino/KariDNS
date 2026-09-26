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
VERSION ?= 0.4.1

CC ?= cc
# CPU tuning. -march=native suits binaries built and run on the same machine;
# distributable packages must be built with MARCH_FLAGS= (baseline ISA), or they
# die with SIGILL on CPUs lacking the build host's extensions (e.g. AVX-512).
MARCH_FLAGS ?= -march=native
CFLAGS += -O3 -flto $(MARCH_FLAGS) -Wall -Wextra -std=c11 -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -DKARIDNS_VERSION=\"$(VERSION)\" $(BREW_CFLAGS) $(DARWIN_CFLAGS) $(IDN_CFLAGS)
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

FUZZ_QUERY_ENGINE_TARGET = tests/fuzz/fuzz_query_engine
FUZZ_QUERY_ENGINE_SRCS = tests/fuzz/fuzz_query_engine.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_rrl.c dns_tsig_acl.c dns_priv_sandbox.c dns_dynamic_update.c dns_axfr_ixfr.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c

FUZZ_XFR_PACKET_TARGET = tests/fuzz/fuzz_xfr_packet
FUZZ_XFR_PACKET_SRCS = tests/fuzz/fuzz_xfr_packet.c dns_axfr_ixfr.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c

FUZZ_DYNAMIC_UPDATE_TARGET = tests/fuzz/fuzz_dynamic_update
FUZZ_DYNAMIC_UPDATE_SRCS = tests/fuzz/fuzz_dynamic_update.c dns_dynamic_update.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_axfr_ixfr.c

FUZZ_ZONE_TARGET = tests/fuzz/fuzz_zone_parser
FUZZ_ZONE_SRCS = tests/fuzz/fuzz_zone_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_wire.c dns_cidr.c

FUZZ_CONF_TARGET = tests/fuzz/fuzz_conf_parser
FUZZ_CONF_SRCS = tests/fuzz/fuzz_conf_parser.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c dns_tsig_acl.c

FUZZ_TSIG_TARGET = tests/fuzz/fuzz_tsig_sign
FUZZ_TSIG_SRCS = tests/fuzz/fuzz_tsig_sign.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_TARGET = tests/fuzz/fuzz_dag_response
FUZZ_DAG_SRCS = tests/fuzz/fuzz_dag_response.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_TSIG_VERIFY_TARGET = tests/fuzz/fuzz_tsig_verify
FUZZ_TSIG_VERIFY_SRCS = tests/fuzz/fuzz_tsig_verify.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_HASH_TARGET = tests/fuzz/fuzz_dag_hash
FUZZ_DAG_HASH_SRCS = tests/fuzz/fuzz_dag_hash.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_CHUNKED_HTTP_TARGET = tests/fuzz/fuzz_dag_chunked_http
FUZZ_DAG_CHUNKED_HTTP_SRCS = tests/fuzz/fuzz_dag_chunked_http.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_RDATA_YAML_TARGET = tests/fuzz/fuzz_dag_rdata_yaml
FUZZ_DAG_RDATA_YAML_SRCS = tests/fuzz/fuzz_dag_rdata_yaml.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_AXFR_STREAM_TARGET = tests/fuzz/fuzz_dag_axfr_stream
FUZZ_DAG_AXFR_STREAM_SRCS = tests/fuzz/fuzz_dag_axfr_stream.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_CLI_ARGS_TARGET = tests/fuzz/fuzz_dag_cli_args
FUZZ_DAG_CLI_ARGS_SRCS = tests/fuzz/fuzz_dag_cli_args.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_BATCH_FILE_TARGET = tests/fuzz/fuzz_dag_batch_file
FUZZ_DAG_BATCH_FILE_SRCS = tests/fuzz/fuzz_dag_batch_file.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_REPLAY_PCAP_READER_TARGET = tests/fuzz/fuzz_dag_replay_pcap_reader
FUZZ_DAG_REPLAY_PCAP_READER_SRCS = tests/fuzz/fuzz_dag_replay_pcap_reader.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_REPLAY_DIFF_TARGET = tests/fuzz/fuzz_dag_replay_diff
FUZZ_DAG_REPLAY_DIFF_SRCS = tests/fuzz/fuzz_dag_replay_diff.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

FUZZ_DAG_TCP_REASSEMBLY_TARGET = tests/fuzz/fuzz_dag_tcp_reassembly
FUZZ_DAG_TCP_REASSEMBLY_SRCS = tests/fuzz/fuzz_dag_tcp_reassembly.c tools/dag_tcp_reassembly.c tools/dag_pcap_l4.c tools/dag_replay.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c

.PHONY: all clean run fuzz fuzz_core fuzz_query_engine fuzz_xfr_packet fuzz_dynamic_update clean-fuzz asan tsan fuzz_tsig fuzz_dag fuzz_tsig_verify dag tools response_cache_test \
	fuzz_dag_hash fuzz_dag_chunked_http fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file \
	fuzz_dag_replay_pcap_reader fuzz_dag_replay_diff fuzz_dag_tcp_reassembly \
	fuzz_dag_all fuzz_dag_test fuzz_karidns fuzz_karidns_test fuzz_all fuzz_test \
	karicheck_matrix_test unit-tests unit-tests-asan unit-tests-portable unit-tests-portable-asan test test-all rfc_vectors_test cidr_test tinydns_test asan_test include_test config_directives_test wire_helpers_test zone_parser_paths_test tinydns_paths_test sig0_sign_test snapshot_rebuild_test dnssec_proofs_test qe_protocol_test dag_format_test dag_reassembly_test hash_test vulnerability_test \
	dnstap_test edns_ecs_test dynamic_update_test axfr_ixfr_test rrl_test query_expanded_test sweep-tests unit-test-bins coverage_sweep_test coverage_sweep_dag_test coverage_sweep_net_test coverage_sweep_tools_test \
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
TEST_CONFDIR_SRCS = tests/test_config_directives.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_WIREHELP_SRCS = tests/test_wire_helpers.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_ZONEPATHS_SRCS = tests/test_zone_parser_paths.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_TINYPATHS_SRCS = tests/test_tinydns_paths.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_SIG0_SRCS = tests/test_sig0_sign.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_SNAPREBUILD_SRCS = tests/test_snapshot_rebuild.c dns_priv_sandbox.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_query_engine.c dns_rrl.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
TEST_HASH_SRCS = tests/test_hash_table.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
TEST_DNSTAP_SRCS = tests/test_dnstap_engine.c dns_dnstap.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c
TEST_EDNS_ECS_SRCS = tests/test_edns_ecs_engine.c dns_edns_ecs.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c
TEST_RFC_VECTORS_SRCS = tests/test_rfc_vectors.c dns_edns_ecs.c dns_rrl.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c
TEST_DYN_UPDATE_SRCS = tests/test_dynamic_update_engine.c dns_dynamic_update.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_axfr_ixfr.c
TEST_AXFR_IXFR_SRCS = tests/test_axfr_ixfr_engine.c dns_axfr_ixfr.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c
TEST_RRL_SRCS = tests/test_rrl_engine.c dns_rrl.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_QUERY_EXP_SRCS = tests/test_query_engine_expanded.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
TEST_DNSSECPROOFS_SRCS = tests/test_dnssec_proofs.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
TEST_QEPROTO_SRCS = tests/test_query_engine_protocol.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
RESPONSE_CACHE_TEST_SRCS = tests/test_response_cache.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
VULN_TEST_SRCS = tests/test_vulnerability_fixes.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c

TEST_CATALOG_SRCS = tests/test_catalog_zone_engine.c dns_catalog_zone.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
TEST_SANDBOX_SRCS = tests/test_snapshot_sandbox_engine.c dns_priv_sandbox.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_query_engine.c dns_rrl.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
TEST_DAGFORMAT_SRCS = tests/test_dag_format.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c dns_config_parser.c dns_tinydns_parser.c dns_tsig_acl.c
TEST_COV_SWEEP_SRCS = tests/test_coverage_sweep.c dns_query_engine.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c dns_utils.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
TEST_COV_SWEEP_NET_SRCS = tests/test_coverage_sweep_net.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c dns_config_parser.c dns_tinydns_parser.c dns_tsig_acl.c
TEST_COV_SWEEP_TOOLS_SRCS = tests/test_coverage_sweep_tools.c tests/test_coverage_sweep_karictl_main.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_COV_SWEEP_DAG_SRCS = tests/test_coverage_sweep_dag.c tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c dns_config_parser.c dns_tinydns_parser.c dns_tsig_acl.c
TEST_DAGREASM_SRCS = tests/test_dag_reassembly.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c
TEST_DAG_TOOLS_SRCS = tests/test_dag_tools.c tools/dag_tcp_reassembly.c tools/dag_pcap_l4.c tools/dag_tsig_client.c tools/dag_replay.c tools/dag_transport.c dns_zone_parser.c dns_config_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_wire.c dns_utils.c
TEST_SERVER_CORE_SRCS = tests/test_server_core.c dns_server_core.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c

FI_WRAP_LDFLAGS  = -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=strdup -Wl,--wrap=strndup -Wl,--wrap=posix_memalign
FI_WRAP_LDFLAGS += -Wl,--wrap=open -Wl,--wrap=openat -Wl,--wrap=fopen -Wl,--wrap=read -Wl,--wrap=write -Wl,--wrap=send -Wl,--wrap=sendto -Wl,--wrap=recv -Wl,--wrap=recvfrom
FI_WRAP_LDFLAGS += -Wl,--wrap=close -Wl,--wrap=pipe -Wl,--wrap=fork -Wl,--wrap=execv -Wl,--wrap=execvp -Wl,--wrap=execve
FI_WRAP_LDFLAGS += -Wl,--wrap=socket -Wl,--wrap=bind -Wl,--wrap=listen -Wl,--wrap=accept -Wl,--wrap=connect -Wl,--wrap=getsockname
FI_WRAP_LDFLAGS += -Wl,--wrap=fcntl -Wl,--wrap=setsockopt -Wl,--wrap=kevent -Wl,--wrap=poll -Wl,--wrap=select
FI_WRAP_LDFLAGS += -Wl,--wrap=rename -Wl,--wrap=mkdir -Wl,--wrap=getaddrinfo -Wl,--wrap=pthread_create
FI_WRAP_LDFLAGS += -Wl,--wrap=time -Wl,--wrap=clock_gettime -Wl,--wrap=gettimeofday
FI_WRAP_SSL_LDFLAGS = -Wl,--wrap=SSL_CTX_new -Wl,--wrap=SSL_connect -Wl,--wrap=SSL_read -Wl,--wrap=SSL_write

FI_COMMON_SRCS = tests/fi/kari_fi.c

TEST_FI_PARSERS_SRCS = tests/test_fi_parsers.c $(FI_COMMON_SRCS) dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c dns_cidr.c dns_tsig_acl.c
TEST_FI_WIRE_SRCS = tests/test_fi_wire.c $(FI_COMMON_SRCS) dns_wire.c dns_utils.c dns_zone_parser.c dns_tinydns_parser.c dns_config_parser.c dns_cidr.c dns_tsig_acl.c
TEST_FI_SNAPSHOT_SRCS = tests/test_fi_snapshot.c $(FI_COMMON_SRCS) dns_priv_sandbox.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_query_engine.c dns_rrl.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c dns_axfr_ixfr.c
TEST_FI_XFR_SRCS = tests/test_fi_xfr.c $(FI_COMMON_SRCS) dns_axfr_ixfr.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_dynamic_update.c
TEST_FI_MISC_SRCS = tests/test_fi_misc.c $(FI_COMMON_SRCS) dns_dynamic_update.c dns_catalog_zone.c dns_dnstap.c dns_edns_ecs.c dns_wire.c dns_utils.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_cidr.c dns_tsig_acl.c dns_snapshot_rcu.c dns_epoch_rcu.c dns_query_engine.c dns_rrl.c dns_priv_sandbox.c dns_axfr_ixfr.c
TEST_FI_DAG_SRCS = tests/test_fi_dag.c $(FI_COMMON_SRCS) tools/dag_output_yaml.c tools/dag_batch.c tools/dag_axfr_client.c tools/dag_trace.c tools/dag_tsig_client.c tools/dag_edns_client.c tools/dag_transport.c tools/dag_replay.c tools/dag_pcap_l4.c tools/dag_tcp_reassembly.c dns_wire.c dns_utils.c dns_zone_parser.c dns_cidr.c dns_config_parser.c dns_tinydns_parser.c dns_tsig_acl.c

test_cidr: $(TEST_CIDR_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_CIDR_SRCS) -o test_cidr $(LDFLAGS) -lcrypto

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

test_config_directives: $(TEST_CONFDIR_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_CONFDIR_SRCS) -o test_config_directives $(LDFLAGS) -lcrypto

config_directives_test: test_config_directives
	./test_config_directives

test_wire_helpers: $(TEST_WIREHELP_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_WIREHELP_SRCS) -o test_wire_helpers $(LDFLAGS) -lcrypto

wire_helpers_test: test_wire_helpers
	./test_wire_helpers

test_zone_parser_paths: $(TEST_ZONEPATHS_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_ZONEPATHS_SRCS) -o test_zone_parser_paths $(LDFLAGS) -lcrypto

zone_parser_paths_test: test_zone_parser_paths
	./test_zone_parser_paths

test_tinydns_paths: $(TEST_TINYPATHS_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_TINYPATHS_SRCS) -o test_tinydns_paths $(LDFLAGS) -lcrypto

tinydns_paths_test: test_tinydns_paths
	./test_tinydns_paths

test_sig0_sign: $(TEST_SIG0_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_SIG0_SRCS) -o test_sig0_sign $(LDFLAGS) -lcrypto

sig0_sign_test: test_sig0_sign
	./test_sig0_sign

test_snapshot_rebuild: $(TEST_SNAPREBUILD_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_SNAPREBUILD_SRCS) -o test_snapshot_rebuild $(LDFLAGS) -lcrypto -lpthread -lm

snapshot_rebuild_test: test_snapshot_rebuild
	./test_snapshot_rebuild

test_dnssec_proofs: $(TEST_DNSSECPROOFS_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_DNSSECPROOFS_SRCS) -o test_dnssec_proofs $(LDFLAGS) -lcrypto -lpthread -lm

dnssec_proofs_test: test_dnssec_proofs
	./test_dnssec_proofs

test_query_engine_protocol: $(TEST_QEPROTO_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_QEPROTO_SRCS) -o test_query_engine_protocol $(LDFLAGS) -lcrypto -lpthread -lm

qe_protocol_test: test_query_engine_protocol
	./test_query_engine_protocol

test_hash_table: $(TEST_HASH_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_HASH_SRCS) -o test_hash_table $(LDFLAGS) -lcrypto -lpthread -lm

hash_test: test_hash_table
	./test_hash_table

test_dnstap_engine: $(TEST_DNSTAP_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_DNSTAP_SRCS) -o test_dnstap_engine $(LDFLAGS) -lcrypto -lpthread -lm

dnstap_test: test_dnstap_engine
	./test_dnstap_engine

test_edns_ecs_engine: $(TEST_EDNS_ECS_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_EDNS_ECS_SRCS) -o test_edns_ecs_engine $(LDFLAGS) -lcrypto -lpthread -lm

edns_ecs_test: test_edns_ecs_engine
	./test_edns_ecs_engine

test_rfc_vectors: $(TEST_RFC_VECTORS_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_RFC_VECTORS_SRCS) -o test_rfc_vectors $(LDFLAGS) -lcrypto -lpthread -lm

rfc_vectors_test: test_rfc_vectors
	./test_rfc_vectors

test_dynamic_update_engine: $(TEST_DYN_UPDATE_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_DYN_UPDATE_SRCS) -o test_dynamic_update_engine $(LDFLAGS) -lcrypto -lpthread -lm

dynamic_update_test: test_dynamic_update_engine
	./test_dynamic_update_engine

test_axfr_ixfr_engine: $(TEST_AXFR_IXFR_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_AXFR_IXFR_SRCS) -o test_axfr_ixfr_engine $(LDFLAGS) -lcrypto -lpthread -lm

axfr_ixfr_test: test_axfr_ixfr_engine
	./test_axfr_ixfr_engine

test_rrl_engine: $(TEST_RRL_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_RRL_SRCS) -o test_rrl_engine $(LDFLAGS) -lcrypto -lpthread -lm

rrl_test: test_rrl_engine
	./test_rrl_engine

test_query_engine_expanded: $(TEST_QUERY_EXP_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_QUERY_EXP_SRCS) -o test_query_engine_expanded $(LDFLAGS) -lcrypto -lpthread -lm

query_expanded_test: test_query_engine_expanded
	./test_query_engine_expanded

test_response_cache: $(RESPONSE_CACHE_TEST_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(RESPONSE_CACHE_TEST_SRCS) -o test_response_cache $(LDFLAGS) -lcrypto -lpthread -lm

response_cache_test: test_response_cache
	./test_response_cache

test_vulnerability_fixes: $(VULN_TEST_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(VULN_TEST_SRCS) -o test_vulnerability_fixes $(LDFLAGS) -lcrypto -lpthread -lm

vulnerability_test: test_vulnerability_fixes
	./test_vulnerability_fixes

test_catalog_zone_engine: $(TEST_CATALOG_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_CATALOG_SRCS) -o test_catalog_zone_engine $(LDFLAGS) -lcrypto -lpthread -lm

catalog_zone_test: test_catalog_zone_engine
	./test_catalog_zone_engine

test_snapshot_sandbox_engine: $(TEST_SANDBOX_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_SANDBOX_SRCS) -o test_snapshot_sandbox_engine $(LDFLAGS) -lcrypto -lpthread -lm

snapshot_sandbox_test: test_snapshot_sandbox_engine
	./test_snapshot_sandbox_engine

test_dag_tools: $(TEST_DAG_TOOLS_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_DAG_TOOLS_SRCS) -o test_dag_tools $(LDFLAGS) -lssl -lcrypto -lpthread -lm -lz $(IDN_LDFLAGS)

dag_tools_test: test_dag_tools
	./test_dag_tools

test_dag_format: $(TEST_DAGFORMAT_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_DAGFORMAT_SRCS) -o test_dag_format $(LDFLAGS) -lssl -lcrypto -lpthread -lm -lz $(IDN_LDFLAGS)

dag_format_test: test_dag_format
	./test_dag_format

test_coverage_sweep: $(TEST_COV_SWEEP_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_COV_SWEEP_SRCS) -o test_coverage_sweep $(LDFLAGS) -lcrypto -lpthread -lm

coverage_sweep_test: test_coverage_sweep
	./test_coverage_sweep

test_coverage_sweep_dag: $(TEST_COV_SWEEP_DAG_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_COV_SWEEP_DAG_SRCS) -o test_coverage_sweep_dag $(LDFLAGS) -lssl -lcrypto -lpthread -lm -lz $(IDN_LDFLAGS)

coverage_sweep_dag_test: test_coverage_sweep_dag
	./test_coverage_sweep_dag

test_coverage_sweep_net: $(TEST_COV_SWEEP_NET_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_COV_SWEEP_NET_SRCS) -o test_coverage_sweep_net $(LDFLAGS) -lssl -lcrypto -lpthread -lm -lz $(IDN_LDFLAGS)

coverage_sweep_net_test: test_coverage_sweep_net
	./test_coverage_sweep_net

test_coverage_sweep_tools: $(TEST_COV_SWEEP_TOOLS_SRCS) tools/karicheck.c tools/karictl.c
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_COV_SWEEP_TOOLS_SRCS) -o test_coverage_sweep_tools $(LDFLAGS) -lcrypto -lpthread -lm

coverage_sweep_tools_test: test_coverage_sweep_tools
	./test_coverage_sweep_tools

test_dag_reassembly: $(TEST_DAGREASM_SRCS)
	$(CC) $(CFLAGS) -I. $(TEST_DAGREASM_SRCS) -o test_dag_reassembly $(LDFLAGS)

dag_reassembly_test: test_dag_reassembly
	./test_dag_reassembly

test_server_core: $(TEST_SERVER_CORE_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_SERVER_CORE_SRCS) -o test_server_core $(LDFLAGS) -lcrypto -lpthread -lm

server_core_test: test_server_core
	./test_server_core

test_fi_parsers: $(TEST_FI_PARSERS_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_FI_PARSERS_SRCS) -o test_fi_parsers $(LDFLAGS) $(FI_WRAP_LDFLAGS) -lcrypto

fi_parsers_test: test_fi_parsers
	./test_fi_parsers

test_fi_wire: $(TEST_FI_WIRE_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_FI_WIRE_SRCS) -o test_fi_wire $(LDFLAGS) $(FI_WRAP_LDFLAGS) -lcrypto

fi_wire_test: test_fi_wire
	./test_fi_wire

test_fi_snapshot: $(TEST_FI_SNAPSHOT_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_FI_SNAPSHOT_SRCS) -o test_fi_snapshot $(LDFLAGS) $(FI_WRAP_LDFLAGS) -lcrypto -lpthread -lm

fi_snapshot_test: test_fi_snapshot
	./test_fi_snapshot

test_fi_xfr: $(TEST_FI_XFR_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_FI_XFR_SRCS) -o test_fi_xfr $(LDFLAGS) $(FI_WRAP_LDFLAGS) -lcrypto -lpthread -lm

fi_xfr_test: test_fi_xfr
	./test_fi_xfr

test_fi_misc: $(TEST_FI_MISC_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_FI_MISC_SRCS) -o test_fi_misc $(LDFLAGS) $(FI_WRAP_LDFLAGS) -lcrypto -lpthread -lm

fi_misc_test: test_fi_misc
	./test_fi_misc

test_fi_dag: $(TEST_FI_DAG_SRCS)
	$(CC) $(CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. $(TEST_FI_DAG_SRCS) -o test_fi_dag $(LDFLAGS) $(FI_WRAP_LDFLAGS) $(FI_WRAP_SSL_LDFLAGS) -lssl -lcrypto -lpthread -lm -lz $(IDN_LDFLAGS)

fi_dag_test: test_fi_dag
	./test_fi_dag

# Binaries behind unit-tests, so they can be built in parallel first
# (`make -j$(nproc) unit-test-bins`); the tests themselves then run one by one.
UT_BINS = test_cidr test_tinydns_parser test_asan_overflow test_conf_include test_config_directives test_wire_helpers test_zone_parser_paths test_tinydns_paths test_sig0_sign test_snapshot_rebuild test_dnssec_proofs test_query_engine_protocol test_dag_format test_dag_reassembly test_hash_table test_dnstap_engine test_edns_ecs_engine test_rfc_vectors test_dynamic_update_engine test_axfr_ixfr_engine test_rrl_engine test_query_engine_expanded test_response_cache test_vulnerability_fixes test_catalog_zone_engine test_snapshot_sandbox_engine test_dag_tools test_server_core test_fi_parsers test_fi_wire test_fi_snapshot test_fi_xfr test_fi_misc test_fi_dag

unit-test-bins: $(UT_BINS)

# The coverage sweeps (engine / dag options / dag network / tools) are long,
# coverage-oriented drivers: `make coverage` runs them through run_all_suite.sh,
# `make sweep-tests` runs them on their own. They are not part of unit-tests.
sweep-tests: coverage_sweep_test coverage_sweep_dag_test coverage_sweep_net_test coverage_sweep_tools_test

unit-tests: cidr_test tinydns_test asan_test include_test config_directives_test wire_helpers_test zone_parser_paths_test tinydns_paths_test sig0_sign_test snapshot_rebuild_test dnssec_proofs_test qe_protocol_test dag_format_test dag_reassembly_test hash_test dnstap_test edns_ecs_test rfc_vectors_test dynamic_update_test axfr_ixfr_test rrl_test query_expanded_test response_cache_test vulnerability_test catalog_zone_test snapshot_sandbox_test dag_tools_test server_core_test fi_parsers_test fi_wire_test fi_snapshot_test fi_xfr_test fi_misc_test fi_dag_test

# --- Unit tests under ASan + UBSan --------------------------------------------
# The plain test_* targets above are built with the production CFLAGS (-O3 -flto),
# so tests such as test_asan_overflow are NOT actually sanitizer-checked by
# "make asan_test". These targets rebuild the same test binaries with
# -fsanitize=address,undefined (UBSan findings are fatal) and run them.
#   make unit-tests-asan                 # leak detection off (default)
#   make unit-tests-asan UT_ASAN_LEAKS=1 # also enable LeakSanitizer
UT_ASAN_LEAKS ?= 0
UT_ASAN_CFLAGS = -O1 -g -Wall -Wextra -std=c11 -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED -DSANITIZER_BUILD -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -fPIE -DKARIDNS_VERSION=\"$(VERSION)\" $(BREW_CFLAGS) $(DARWIN_CFLAGS) $(IDN_CFLAGS)
UT_ASAN_LDFLAGS = -fsanitize=address,undefined -pthread -lm $(BREW_LDFLAGS) $(DARWIN_LDFLAGS)

# Every source is compiled once per variant and the objects are shared by all
# the -asan test binaries (.uta.o: with -DKARIDNS_UNIT_TEST=1, .utn.o: without);
# compiling each binary from source rebuilt ~18 files per binary.
.SUFFIXES: .uta.o .utn.o .c
.c.uta.o:
	$(CC) $(UT_ASAN_CFLAGS) -DKARIDNS_UNIT_TEST=1 -I. -c $< -o $@
.c.utn.o:
	$(CC) $(UT_ASAN_CFLAGS) -I. -c $< -o $@
# test sources that #include a tool's .c file
tests/test_dag_format.uta.o tests/test_coverage_sweep_dag.uta.o tests/test_coverage_sweep_net.uta.o: tools/dag.c
tests/test_coverage_sweep_tools.uta.o: tools/karicheck.c tools/karictl.c
tests/test_coverage_sweep_karictl_main.uta.o: tools/karictl.c

test_cidr-asan: $(TEST_CIDR_SRCS:.c=.uta.o)
	$(CC) $(TEST_CIDR_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_tinydns_parser-asan: $(TEST_TINYDNS_SRCS:.c=.utn.o)
	$(CC) $(TEST_TINYDNS_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_asan_overflow-asan: $(TEST_ASAN_SRCS:.c=.utn.o)
	$(CC) $(TEST_ASAN_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_conf_include-asan: $(TEST_CONF_SRCS:.c=.utn.o)
	$(CC) $(TEST_CONF_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_config_directives-asan: $(TEST_CONFDIR_SRCS:.c=.utn.o)
	$(CC) $(TEST_CONFDIR_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_wire_helpers-asan: $(TEST_WIREHELP_SRCS:.c=.utn.o)
	$(CC) $(TEST_WIREHELP_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_zone_parser_paths-asan: $(TEST_ZONEPATHS_SRCS:.c=.utn.o)
	$(CC) $(TEST_ZONEPATHS_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_tinydns_paths-asan: $(TEST_TINYPATHS_SRCS:.c=.utn.o)
	$(CC) $(TEST_TINYPATHS_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_sig0_sign-asan: $(TEST_SIG0_SRCS:.c=.utn.o)
	$(CC) $(TEST_SIG0_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_snapshot_rebuild-asan: $(TEST_SNAPREBUILD_SRCS:.c=.uta.o)
	$(CC) $(TEST_SNAPREBUILD_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_dnssec_proofs-asan: $(TEST_DNSSECPROOFS_SRCS:.c=.uta.o)
	$(CC) $(TEST_DNSSECPROOFS_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_query_engine_protocol-asan: $(TEST_QEPROTO_SRCS:.c=.uta.o)
	$(CC) $(TEST_QEPROTO_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_hash_table-asan: $(TEST_HASH_SRCS:.c=.uta.o)
	$(CC) $(TEST_HASH_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_dnstap_engine-asan: $(TEST_DNSTAP_SRCS:.c=.uta.o)
	$(CC) $(TEST_DNSTAP_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_edns_ecs_engine-asan: $(TEST_EDNS_ECS_SRCS:.c=.uta.o)
	$(CC) $(TEST_EDNS_ECS_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_rfc_vectors-asan: $(TEST_RFC_VECTORS_SRCS:.c=.uta.o)
	$(CC) $(TEST_RFC_VECTORS_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_dynamic_update_engine-asan: $(TEST_DYN_UPDATE_SRCS:.c=.uta.o)
	$(CC) $(TEST_DYN_UPDATE_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_axfr_ixfr_engine-asan: $(TEST_AXFR_IXFR_SRCS:.c=.uta.o)
	$(CC) $(TEST_AXFR_IXFR_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_rrl_engine-asan: $(TEST_RRL_SRCS:.c=.uta.o)
	$(CC) $(TEST_RRL_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_query_engine_expanded-asan: $(TEST_QUERY_EXP_SRCS:.c=.uta.o)
	$(CC) $(TEST_QUERY_EXP_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_response_cache-asan: $(RESPONSE_CACHE_TEST_SRCS:.c=.uta.o)
	$(CC) $(RESPONSE_CACHE_TEST_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_vulnerability_fixes-asan: $(VULN_TEST_SRCS:.c=.uta.o)
	$(CC) $(VULN_TEST_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_catalog_zone_engine-asan: $(TEST_CATALOG_SRCS:.c=.uta.o)
	$(CC) $(TEST_CATALOG_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_snapshot_sandbox_engine-asan: $(TEST_SANDBOX_SRCS:.c=.uta.o)
	$(CC) $(TEST_SANDBOX_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_dag_tools-asan: $(TEST_DAG_TOOLS_SRCS:.c=.uta.o)
	$(CC) $(TEST_DAG_TOOLS_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lssl -lcrypto   -lz $(IDN_LDFLAGS)

test_dag_format-asan: $(TEST_DAGFORMAT_SRCS:.c=.uta.o)
	$(CC) $(TEST_DAGFORMAT_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lssl -lcrypto   -lz $(IDN_LDFLAGS)

test_coverage_sweep-asan: $(TEST_COV_SWEEP_SRCS:.c=.uta.o)
	$(CC) $(TEST_COV_SWEEP_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_coverage_sweep_dag-asan: $(TEST_COV_SWEEP_DAG_SRCS:.c=.uta.o)
	$(CC) $(TEST_COV_SWEEP_DAG_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lssl -lcrypto   -lz $(IDN_LDFLAGS)

test_coverage_sweep_net-asan: $(TEST_COV_SWEEP_NET_SRCS:.c=.uta.o)
	$(CC) $(TEST_COV_SWEEP_NET_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

test_coverage_sweep_tools-asan: $(TEST_COV_SWEEP_TOOLS_SRCS:.c=.uta.o)
	$(CC) $(TEST_COV_SWEEP_TOOLS_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

test_dag_reassembly-asan: $(TEST_DAGREASM_SRCS:.c=.utn.o)
	$(CC) $(TEST_DAGREASM_SRCS:.c=.utn.o) -o $@ $(UT_ASAN_LDFLAGS)

test_server_core-asan: $(TEST_SERVER_CORE_SRCS:.c=.uta.o)
	$(CC) $(TEST_SERVER_CORE_SRCS:.c=.uta.o) -o $@ $(UT_ASAN_LDFLAGS) -lcrypto

UT_ASAN_BINS = test_cidr-asan test_tinydns_parser-asan test_asan_overflow-asan test_conf_include-asan test_config_directives-asan test_wire_helpers-asan test_zone_parser_paths-asan test_tinydns_paths-asan test_sig0_sign-asan test_snapshot_rebuild-asan test_dnssec_proofs-asan test_query_engine_protocol-asan test_dag_format-asan test_dag_reassembly-asan test_hash_table-asan test_dnstap_engine-asan test_edns_ecs_engine-asan test_rfc_vectors-asan test_dynamic_update_engine-asan test_axfr_ixfr_engine-asan test_rrl_engine-asan test_query_engine_expanded-asan test_response_cache-asan test_vulnerability_fixes-asan test_catalog_zone_engine-asan test_snapshot_sandbox_engine-asan test_dag_tools-asan test_server_core-asan

unit-tests-asan: $(UT_ASAN_BINS)
	@rc=0; for t in $(UT_ASAN_BINS); do \
	  echo "=== $$t"; \
	  ASAN_OPTIONS="detect_leaks=$(UT_ASAN_LEAKS):abort_on_error=0:print_summary=1" \
	  UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" ./$$t || { echo "*** FAILED: $$t"; rc=1; }; \
	done; exit $$rc

# --- Portable subset: unit tests that build and run on Linux/macOS without FreeBSD-only APIs
# (no kqueue / Capsicum). Used by the cross-OS CI jobs; the server-core tests need FreeBSD.
UT_PORTABLE_TESTS = karicheck_matrix_test cidr_test tinydns_test asan_test include_test config_directives_test wire_helpers_test zone_parser_paths_test sig0_sign_test tinydns_paths_test dag_format_test dag_reassembly_test dnstap_test edns_ecs_test rrl_test rfc_vectors_test dag_tools_test
UT_PORTABLE_ASAN_BINS = test_cidr-asan test_tinydns_parser-asan test_asan_overflow-asan test_conf_include-asan test_config_directives-asan test_wire_helpers-asan test_zone_parser_paths-asan test_tinydns_paths-asan test_sig0_sign-asan test_dag_format-asan test_dag_reassembly-asan test_dnstap_engine-asan test_edns_ecs_engine-asan test_rrl_engine-asan test_rfc_vectors-asan test_dag_tools-asan

karicheck_matrix_test: karicheck
	sh tests/run_karicheck_matrix_test.sh

unit-tests-portable: $(UT_PORTABLE_TESTS)

unit-tests-portable-asan: $(UT_PORTABLE_ASAN_BINS)
	@rc=0; for t in $(UT_PORTABLE_ASAN_BINS); do \
	  echo "=== $$t"; \
	  ASAN_OPTIONS="detect_leaks=$(UT_ASAN_LEAKS):abort_on_error=0:print_summary=1" \
	  UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" ./$$t || { echo "*** FAILED: $$t"; rc=1; }; \
	done; exit $$rc

test: $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck
	@sh tests/run_all_suite.sh

test-all: test

# --- Code Coverage (Clang Source-Based Instrumentation) ---
# Prefer the versioned LLVM tools matching the compiler (e.g. llvm-cov19 from the
# llvm19 / llvm19-lite package): FreeBSD 15's base llvm-cov aborts in "show"
# ("Option 'o' registered more than once"). Falls back to the unversioned tools.
LLVM_TOOL_SUFFIX != v=$$(clang --version 2>/dev/null | sed -n 's/.*clang version \([0-9][0-9]*\).*/\1/p' | head -n 1); if [ -n "$$v" ] && command -v llvm-cov$$v >/dev/null 2>&1 && command -v llvm-profdata$$v >/dev/null 2>&1; then echo $$v; fi
LLVM_PROFDATA ?= llvm-profdata$(LLVM_TOOL_SUFFIX)
LLVM_COV      ?= llvm-cov$(LLVM_TOOL_SUFFIX)

# Continuous-mode profiling (LLVM "%c"): the profile file is mmap'ed at process start -- while the process is
# still root -- and counters are updated IN PLACE. Processes that later drop privileges, enter Capsicum or leave
# through _exit() (all karidns backend/worker/router children) still contribute coverage. The default
# write-at-exit mode can never record them: after cap_enter() the profile runtime cannot open its output file,
# which is why dns_query_engine.c / dns_axfr_ixfr.c / dns_snapshot_rcu.c stayed at their unit-test-only numbers
# even though ~70 integration tests exercise them. All processes forked from one instance share one mapping.
# Set COV_CONTINUOUS=0 to fall back to classic mode if the toolchain lacks continuous-mode support.
COV_CONTINUOUS ?= 1
COV_CONT_CFLAGS_1 = -mllvm -runtime-counter-relocation=true
COV_CONT_CFLAGS_0 =
COV_PROFILE_PAT_1 = cov_%c%m.profraw
COV_PROFILE_PAT_0 = karidns_%p_%m.profraw
COV_CFLAGS  = $(COV_CONT_CFLAGS_$(COV_CONTINUOUS)) -Wno-unused-command-line-argument -fprofile-instr-generate -fcoverage-mapping -DKARIDNS_COVERAGE_LINKAGE -O0 -g -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED -Wall -Wextra -std=c11 -fPIE $(BREW_CFLAGS) $(DARWIN_CFLAGS) $(IDN_CFLAGS)
COV_LDFLAGS = -fprofile-instr-generate -pthread -lm $(BREW_LDFLAGS) $(DARWIN_LDFLAGS) $(HARDEN_LDFLAGS)
COV_DIR     = coverage_raw
# Parallel jobs for the coverage build (the test suite itself stays sequential:
# many tests share fixed ports).
COV_JOBS != (sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 2) | head -n 1
# Suites that only exercise ASan/TSan/libFuzzer binaries. Those binaries are not
# coverage-instrumented, so the suites add ~5 minutes and no coverage; the
# regular CI job still runs them.
COV_SUITE_EXCLUDE ?= run_sanitizer_smoke_test,run_stress_test,run_fuzz_smoke_test
COV_HTML_DIR = coverage_html
COV_DATA    = coverage.profdata

COV_FUZZ_DIR = coverage_fuzz
COV_FUZZ_CFLAGS = -fsanitize=fuzzer,address,undefined -fprofile-instr-generate -fcoverage-mapping -DKARIDNS_COVERAGE_LINKAGE -O0 -g -D_GNU_SOURCE -DOPENSSL_SUPPRESS_DEPRECATED -Wall -Wextra -std=c11 -fPIE $(BREW_CFLAGS) $(DARWIN_CFLAGS) $(IDN_CFLAGS)
COV_FUZZ_LDFLAGS = -fsanitize=fuzzer,address,undefined -fprofile-instr-generate $(LDFLAGS)

COV_FUZZ_BINS  = $(COV_FUZZ_DIR)/fuzz_dns_wire $(COV_FUZZ_DIR)/fuzz_dns_server_core
COV_FUZZ_BINS += $(COV_FUZZ_DIR)/fuzz_query_engine $(COV_FUZZ_DIR)/fuzz_xfr_packet $(COV_FUZZ_DIR)/fuzz_dynamic_update
COV_FUZZ_BINS += $(COV_FUZZ_DIR)/fuzz_zone_parser $(COV_FUZZ_DIR)/fuzz_conf_parser
COV_FUZZ_BINS += $(COV_FUZZ_DIR)/fuzz_tsig_sign $(COV_FUZZ_DIR)/fuzz_dag_response
COV_FUZZ_BINS += $(COV_FUZZ_DIR)/fuzz_tsig_verify $(COV_FUZZ_DIR)/fuzz_dag_hash
COV_FUZZ_BINS += $(COV_FUZZ_DIR)/fuzz_dag_chunked_http $(COV_FUZZ_DIR)/fuzz_dag_rdata_yaml
COV_FUZZ_BINS += $(COV_FUZZ_DIR)/fuzz_dag_axfr_stream $(COV_FUZZ_DIR)/fuzz_dag_cli_args
COV_FUZZ_BINS += $(COV_FUZZ_DIR)/fuzz_dag_batch_file $(COV_FUZZ_DIR)/fuzz_dag_replay_pcap_reader
COV_FUZZ_BINS += $(COV_FUZZ_DIR)/fuzz_dag_replay_diff $(COV_FUZZ_DIR)/fuzz_dag_tcp_reassembly

COV_FUZZ_OBJS  = -object=$(COV_FUZZ_DIR)/fuzz_dns_wire -object=$(COV_FUZZ_DIR)/fuzz_dns_server_core
COV_FUZZ_OBJS += -object=$(COV_FUZZ_DIR)/fuzz_query_engine -object=$(COV_FUZZ_DIR)/fuzz_xfr_packet -object=$(COV_FUZZ_DIR)/fuzz_dynamic_update
COV_FUZZ_OBJS += -object=$(COV_FUZZ_DIR)/fuzz_zone_parser -object=$(COV_FUZZ_DIR)/fuzz_conf_parser
COV_FUZZ_OBJS += -object=$(COV_FUZZ_DIR)/fuzz_tsig_sign -object=$(COV_FUZZ_DIR)/fuzz_dag_response
COV_FUZZ_OBJS += -object=$(COV_FUZZ_DIR)/fuzz_tsig_verify -object=$(COV_FUZZ_DIR)/fuzz_dag_hash
COV_FUZZ_OBJS += -object=$(COV_FUZZ_DIR)/fuzz_dag_chunked_http -object=$(COV_FUZZ_DIR)/fuzz_dag_rdata_yaml
COV_FUZZ_OBJS += -object=$(COV_FUZZ_DIR)/fuzz_dag_axfr_stream -object=$(COV_FUZZ_DIR)/fuzz_dag_cli_args
COV_FUZZ_OBJS += -object=$(COV_FUZZ_DIR)/fuzz_dag_batch_file -object=$(COV_FUZZ_DIR)/fuzz_dag_replay_pcap_reader
COV_FUZZ_OBJS += -object=$(COV_FUZZ_DIR)/fuzz_dag_replay_diff -object=$(COV_FUZZ_DIR)/fuzz_dag_tcp_reassembly

$(COV_FUZZ_DIR)/fuzz_dns_wire: $(FUZZ_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto

$(COV_FUZZ_DIR)/fuzz_dns_server_core: $(FUZZ_CORE_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_CORE_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto -lpthread -lm

$(COV_FUZZ_DIR)/fuzz_query_engine: $(FUZZ_QUERY_ENGINE_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_QUERY_ENGINE_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto -lpthread -lm

$(COV_FUZZ_DIR)/fuzz_xfr_packet: $(FUZZ_XFR_PACKET_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_XFR_PACKET_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto -lpthread -lm

$(COV_FUZZ_DIR)/fuzz_dynamic_update: $(FUZZ_DYNAMIC_UPDATE_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DYNAMIC_UPDATE_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto -lpthread -lm

$(COV_FUZZ_DIR)/fuzz_zone_parser: $(FUZZ_ZONE_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_ZONE_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto

$(COV_FUZZ_DIR)/fuzz_conf_parser: $(FUZZ_CONF_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_CONF_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto

$(COV_FUZZ_DIR)/fuzz_tsig_sign: $(FUZZ_TSIG_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_TSIG_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto

$(COV_FUZZ_DIR)/fuzz_dag_response: $(FUZZ_DAG_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_tsig_verify: $(FUZZ_TSIG_VERIFY_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_TSIG_VERIFY_SRCS) $(COV_FUZZ_LDFLAGS) -lcrypto

$(COV_FUZZ_DIR)/fuzz_dag_hash: $(FUZZ_DAG_HASH_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_HASH_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_dag_chunked_http: $(FUZZ_DAG_CHUNKED_HTTP_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_CHUNKED_HTTP_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_dag_rdata_yaml: $(FUZZ_DAG_RDATA_YAML_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_RDATA_YAML_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_dag_axfr_stream: $(FUZZ_DAG_AXFR_STREAM_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_AXFR_STREAM_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_dag_cli_args: $(FUZZ_DAG_CLI_ARGS_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_CLI_ARGS_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_dag_batch_file: $(FUZZ_DAG_BATCH_FILE_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_BATCH_FILE_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_dag_replay_pcap_reader: $(FUZZ_DAG_REPLAY_PCAP_READER_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_REPLAY_PCAP_READER_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_dag_replay_diff: $(FUZZ_DAG_REPLAY_DIFF_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_REPLAY_DIFF_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

$(COV_FUZZ_DIR)/fuzz_dag_tcp_reassembly: $(FUZZ_DAG_TCP_REASSEMBLY_SRCS)
	@mkdir -p $(COV_FUZZ_DIR)
	$(CC) $(COV_FUZZ_CFLAGS) -o $@ $(FUZZ_DAG_TCP_REASSEMBLY_SRCS) $(COV_FUZZ_LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

coverage-fuzz-build: $(COV_FUZZ_BINS)

coverage-fuzz-run:
	@mkdir -p $(COV_DIR)
	@sh tests/coverage_fuzz_run.sh $(COV_DIR)

coverage-fuzz: coverage-fuzz-build coverage-fuzz-run

COV_BIN_OBJS  = -object=$(TARGET) -object=$(DAG_TARGET) -object=$(KARICTL_TARGET) -object=karicheck
COV_BIN_OBJS += -object=test_cidr -object=test_tinydns_parser -object=test_asan_overflow -object=test_conf_include
COV_BIN_OBJS += -object=test_config_directives -object=test_wire_helpers -object=test_zone_parser_paths -object=test_tinydns_paths
COV_BIN_OBJS += -object=test_sig0_sign -object=test_snapshot_rebuild -object=test_dnssec_proofs -object=test_dag_format
COV_BIN_OBJS += -object=test_dag_reassembly -object=test_query_engine_protocol -object=test_hash_table -object=test_dnstap_engine
COV_BIN_OBJS += -object=test_edns_ecs_engine -object=test_rfc_vectors -object=test_dynamic_update_engine -object=test_axfr_ixfr_engine
COV_BIN_OBJS += -object=test_rrl_engine -object=test_query_engine_expanded -object=test_response_cache -object=test_vulnerability_fixes
COV_BIN_OBJS += -object=test_catalog_zone_engine -object=test_snapshot_sandbox_engine -object=test_dag_tools -object=test_server_core
COV_BIN_OBJS += -object=test_fi_parsers -object=test_fi_wire -object=test_fi_snapshot -object=test_fi_xfr -object=test_fi_misc -object=test_fi_dag
COV_BIN_OBJS += -object=test_coverage_sweep -object=test_coverage_sweep_dag -object=test_coverage_sweep_net -object=test_coverage_sweep_tools
COV_BIN_OBJS += $(COV_FUZZ_OBJS)

coverage-clean:
	rm -rf $(COV_DIR) $(COV_HTML_DIR) $(COV_DATA) $(COV_FUZZ_DIR) default.profraw *.profraw

coverage-build:
	@echo "=== Building KariDNS & Test Suite with Profile Coverage ==="
	$(MAKE) clean
	$(MAKE) -j$(COV_JOBS) CC="clang" CFLAGS="$(COV_CFLAGS)" LDFLAGS="$(COV_LDFLAGS)" all karicheck
	$(MAKE) -j$(COV_JOBS) CC="clang" CFLAGS="$(COV_CFLAGS)" LDFLAGS="$(COV_LDFLAGS)" test_cidr test_tinydns_parser test_asan_overflow test_conf_include test_config_directives test_wire_helpers test_zone_parser_paths test_tinydns_paths test_sig0_sign test_snapshot_rebuild test_dnssec_proofs test_query_engine_protocol test_dag_format test_dag_reassembly test_hash_table test_dnstap_engine test_edns_ecs_engine test_rfc_vectors test_dynamic_update_engine test_axfr_ixfr_engine test_rrl_engine test_query_engine_expanded test_response_cache test_vulnerability_fixes test_catalog_zone_engine test_snapshot_sandbox_engine test_dag_tools test_server_core test_fi_parsers test_fi_wire test_fi_snapshot test_fi_xfr test_fi_misc test_fi_dag test_coverage_sweep test_coverage_sweep_dag test_coverage_sweep_net test_coverage_sweep_tools
	$(MAKE) -j$(COV_JOBS) coverage-fuzz-build
	@# ASan builds some integration tests use (built here in parallel, instead of
	@# one by one in the middle of the suite)
	$(MAKE) -j$(COV_JOBS) asan tools-asan fuzz_dag

coverage-run:
	@echo "=== Executing Test Suite with Instrumentation ==="
	@mkdir -p $(COV_DIR)
	@chmod 1777 $(COV_DIR)
	@LLVM_PROFILE_FILE="$$(pwd)/$(COV_DIR)/$(COV_PROFILE_PAT_$(COV_CONTINUOUS))" sh tests/run_all_suite.sh --exclude "$(COV_SUITE_EXCLUDE)" || true
	@$(MAKE) coverage-fuzz-run || true
	@echo "Profile files in $(COV_DIR): $$(ls $(COV_DIR) | wc -l | tr -d ' ') (continuous mode: one file per instrumented binary)"

coverage-report:
	@echo "=== Merging Profile Data & Generating Coverage Report ==="
	@command -v $(LLVM_PROFDATA) >/dev/null 2>&1 || { echo "Error: $(LLVM_PROFDATA) not found in PATH."; exit 1; }
	@ls $(COV_DIR)/*.profraw >/dev/null 2>&1 || { echo "Error: No profile data found in $(COV_DIR). Run 'make coverage-run' first."; exit 1; }
	@sh tests/coverage_merge.sh "$(LLVM_PROFDATA)" $(COV_DIR) $(COV_DATA)
	@mkdir -p $(COV_HTML_DIR)
	$(LLVM_COV) show $(TARGET) $(COV_BIN_OBJS) -instr-profile=$(COV_DATA) -format=html -output-dir=$(COV_HTML_DIR) -ignore-filename-regex="tests/|scratch/|old_patches/|third_party/" -show-line-counts-or-regions -show-branches=count
	@echo ""
	@echo "=== KariDNS & dag Integrated Engine Coverage Summary ==="
	$(LLVM_COV) report $(TARGET) $(COV_BIN_OBJS) -instr-profile=$(COV_DATA) -ignore-filename-regex="tests/|scratch/|old_patches/|third_party/"
	@echo ""
	@echo "Full HTML coverage report available at: $(COV_HTML_DIR)/index.html"
	@if [ -f tests/coverage_gate.pl ]; then perl tests/coverage_gate.pl --llvm-cov=$(LLVM_COV) --profdata=$(COV_DATA) || true; fi

coverage: coverage-clean coverage-build coverage-run coverage-report

bench_serialize: tests/bench_serialize.c dns_wire.o dns_utils.o dns_zone_parser.o dns_tinydns_parser.o dns_config_parser.o dns_cidr.o dns_tsig_acl.o
	$(CC) $(CFLAGS) tests/bench_serialize.c dns_wire.o dns_utils.o dns_zone_parser.o dns_tinydns_parser.o dns_config_parser.o dns_cidr.o dns_tsig_acl.o -o bench_serialize $(LDFLAGS) -lssl -lcrypto -lz

bench_rrl: tests/bench_rrl.c dns_rrl.o dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o dns_utils.o dns_cidr.o dns_tsig_acl.o
	$(CC) $(CFLAGS) tests/bench_rrl.c dns_rrl.o dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o dns_utils.o dns_cidr.o dns_tsig_acl.o -o bench_rrl $(LDFLAGS) -lssl -lcrypto -lz

clean: clean-fuzz coverage-clean
	rm -f $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck bench_serialize bench_rrl $(OBJS) $(DAG_OBJS) $(KARICTL_OBJS)
	rm -f karidns-asan karidns-tsan *.asan.o *.tsan.o test_asan_overflow test_conf_include test_config_directives test_wire_helpers test_zone_parser_paths test_tinydns_paths test_sig0_sign test_snapshot_rebuild test_dnssec_proofs test_query_engine_protocol test_dag_format test_dag_reassembly test_hash_table test_dnstap_engine test_edns_ecs_engine test_rfc_vectors test_dynamic_update_engine test_axfr_ixfr_engine test_rrl_engine test_query_engine_expanded test_response_cache test_cidr test_tinydns_parser test_vulnerability_fixes test_catalog_zone_engine test_snapshot_sandbox_engine test_dag_tools test_server_core test_fi_parsers test_fi_wire test_fi_snapshot test_fi_xfr test_fi_misc test_fi_dag test_coverage_sweep test_coverage_sweep_dag test_coverage_sweep_net test_coverage_sweep_tools
	rm -f $(UT_ASAN_BINS)
	rm -f *.uta.o *.utn.o tests/*.uta.o tests/*.utn.o tools/*.uta.o tools/*.utn.o
	rm -f tests/fi/kari_fi_preload.so

run: $(TARGET)
	./$(TARGET)

# Fuzz sources are compiled once (fuzzer-no-link instrumentation) and the objects
# shared by every fuzzer; only the link step adds libFuzzer (-fsanitize=fuzzer).
FUZZ_OBJ_CFLAGS = -O1 -g -fsanitize=fuzzer-no-link,address,undefined -fPIE
.SUFFIXES: .fz.o .c
.c.fz.o:
	$(CC) $(FUZZ_OBJ_CFLAGS) -c $< -o $@

fuzz: $(FUZZ_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TARGET) $(FUZZ_SRCS:.c=.fz.o) $(LDFLAGS) -lcrypto

fuzz_core: $(FUZZ_CORE_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_CORE_TARGET) $(FUZZ_CORE_SRCS:.c=.fz.o) $(LDFLAGS) -lcrypto

fuzz_zone: $(FUZZ_ZONE_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_ZONE_TARGET) $(FUZZ_ZONE_SRCS:.c=.fz.o) $(LDFLAGS) -lcrypto

fuzz_conf: $(FUZZ_CONF_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_CONF_TARGET) $(FUZZ_CONF_SRCS:.c=.fz.o) $(LDFLAGS) -lcrypto

fuzz_tsig: $(FUZZ_TSIG_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TSIG_TARGET) $(FUZZ_TSIG_SRCS:.c=.fz.o) $(LDFLAGS) -lcrypto

fuzz_dag: $(FUZZ_DAG_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_TARGET) $(FUZZ_DAG_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_tsig_verify: $(FUZZ_TSIG_VERIFY_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TSIG_VERIFY_TARGET) $(FUZZ_TSIG_VERIFY_SRCS:.c=.fz.o) $(LDFLAGS) -lcrypto

fuzz_dag_hash: $(FUZZ_DAG_HASH_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_HASH_TARGET) $(FUZZ_DAG_HASH_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_chunked_http: $(FUZZ_DAG_CHUNKED_HTTP_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_CHUNKED_HTTP_TARGET) $(FUZZ_DAG_CHUNKED_HTTP_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_rdata_yaml: $(FUZZ_DAG_RDATA_YAML_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_RDATA_YAML_TARGET) $(FUZZ_DAG_RDATA_YAML_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_axfr_stream: $(FUZZ_DAG_AXFR_STREAM_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_AXFR_STREAM_TARGET) $(FUZZ_DAG_AXFR_STREAM_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_cli_args: $(FUZZ_DAG_CLI_ARGS_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_CLI_ARGS_TARGET) $(FUZZ_DAG_CLI_ARGS_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_batch_file: $(FUZZ_DAG_BATCH_FILE_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_BATCH_FILE_TARGET) $(FUZZ_DAG_BATCH_FILE_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_replay_pcap_reader: $(FUZZ_DAG_REPLAY_PCAP_READER_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_REPLAY_PCAP_READER_TARGET) $(FUZZ_DAG_REPLAY_PCAP_READER_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_replay_diff: $(FUZZ_DAG_REPLAY_DIFF_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_REPLAY_DIFF_TARGET) $(FUZZ_DAG_REPLAY_DIFF_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

fuzz_dag_tcp_reassembly: $(FUZZ_DAG_TCP_REASSEMBLY_SRCS:.c=.fz.o)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_TCP_REASSEMBLY_TARGET) $(FUZZ_DAG_TCP_REASSEMBLY_SRCS:.c=.fz.o) $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

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
	rm -f *.fz.o tests/fuzz/*.fz.o tools/*.fz.o
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
