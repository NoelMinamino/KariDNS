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
VERSION ?= 0.1.0

CC ?= cc
CFLAGS += -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -DKARIDNS_VERSION=\"$(VERSION)\" $(BREW_CFLAGS) $(DARWIN_CFLAGS) $(IDN_CFLAGS)
LDFLAGS = -pthread -lm $(BREW_LDFLAGS) $(DARWIN_LDFLAGS) $(HARDEN_LDFLAGS)


TARGET = karidns
SRCS = dns_server_core.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c
OBJS = $(SRCS:.c=.o)

DAG_TARGET = dag
DAG_SRCS = tools/dag.c dns_wire.c dns_utils.c dns_zone_parser.c

DAG_OBJS = $(DAG_SRCS:.c=.o)

KARICTL_TARGET = karictl
KARICTL_SRCS = tools/karictl.c
KARICTL_OBJS = $(KARICTL_SRCS:.c=.o)

FUZZ_TARGET = tests/fuzz/fuzz_dns_wire
FUZZ_SRCS = tests/fuzz/fuzz_dns_wire.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_CORE_TARGET = tests/fuzz/fuzz_dns_server_core
FUZZ_CORE_SRCS = tests/fuzz/fuzz_dns_server_core.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c

FUZZ_ZONE_TARGET = tests/fuzz/fuzz_zone_parser
FUZZ_ZONE_SRCS = tests/fuzz/fuzz_zone_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c dns_wire.c

FUZZ_CONF_TARGET = tests/fuzz/fuzz_conf_parser
FUZZ_CONF_SRCS = tests/fuzz/fuzz_conf_parser.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c

FUZZ_TSIG_TARGET = tests/fuzz/fuzz_tsig_sign
FUZZ_TSIG_SRCS = tests/fuzz/fuzz_tsig_sign.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_DAG_TARGET = tests/fuzz/fuzz_dag_response
FUZZ_DAG_SRCS = tests/fuzz/fuzz_dag_response.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_TSIG_VERIFY_TARGET = tests/fuzz/fuzz_tsig_verify
FUZZ_TSIG_VERIFY_SRCS = tests/fuzz/fuzz_tsig_verify.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_DAG_HASH_TARGET = tests/fuzz/fuzz_dag_hash
FUZZ_DAG_HASH_SRCS = tests/fuzz/fuzz_dag_hash.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_DAG_CHUNKED_HTTP_TARGET = tests/fuzz/fuzz_dag_chunked_http
FUZZ_DAG_CHUNKED_HTTP_SRCS = tests/fuzz/fuzz_dag_chunked_http.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_DAG_RDATA_YAML_TARGET = tests/fuzz/fuzz_dag_rdata_yaml
FUZZ_DAG_RDATA_YAML_SRCS = tests/fuzz/fuzz_dag_rdata_yaml.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_DAG_AXFR_STREAM_TARGET = tests/fuzz/fuzz_dag_axfr_stream
FUZZ_DAG_AXFR_STREAM_SRCS = tests/fuzz/fuzz_dag_axfr_stream.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_DAG_CLI_ARGS_TARGET = tests/fuzz/fuzz_dag_cli_args
FUZZ_DAG_CLI_ARGS_SRCS = tests/fuzz/fuzz_dag_cli_args.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_DAG_BATCH_FILE_TARGET = tests/fuzz/fuzz_dag_batch_file
FUZZ_DAG_BATCH_FILE_SRCS = tests/fuzz/fuzz_dag_batch_file.c dns_wire.c dns_utils.c dns_zone_parser.c

.PHONY: all clean run fuzz fuzz_core clean-fuzz asan tsan fuzz_tsig fuzz_dag fuzz_tsig_verify dag tools \
	fuzz_dag_hash fuzz_dag_chunked_http fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file \
	fuzz_dag_all fuzz_dag_test fuzz_karidns fuzz_karidns_test fuzz_all fuzz_test

all: $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

$(KARICTL_TARGET): $(KARICTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

$(DAG_TARGET): $(DAG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS) $(WIN_LDFLAGS)

karicheck: tools/karicheck.c dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o dns_utils.o
	$(CC) $(CFLAGS) tools/karicheck.c dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o dns_utils.o -o karicheck $(LDFLAGS) -lcrypto

$(OBJS) $(DAG_OBJS) $(KARICTL_OBJS): dns_wire.h dns_config_parser.h dns_zone_parser.h dns_utils.h

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tinydns_test: tests/test_tinydns_parser.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c
	clang -fsanitize=address,undefined -O1 -g tests/test_tinydns_parser.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c -lcrypto -o test_tinydns_parser
	./test_tinydns_parser

tinydns_timestamp_test: $(TARGET) $(DAG_TARGET) karicheck
	sh tests/run_tinydns_timestamp_test.sh

tinydns_location_test: $(TARGET) $(DAG_TARGET) karicheck
	sh tests/run_tinydns_location_test.sh

bind_ecs_subnet_test: $(TARGET) $(DAG_TARGET) karicheck
	sh tests/run_bind_ecs_subnet_test.sh

asan_test: tests/test_asan_overflow.c dns_config_parser.o dns_zone_parser.o dns_tinydns_parser.o dns_wire.o
	clang -fsanitize=address,undefined -O1 -g tests/test_asan_overflow.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c -lcrypto -o test_asan_overflow
	./test_asan_overflow

include_test: tests/test_conf_include.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c
	clang -fsanitize=address,undefined -O1 -g tests/test_conf_include.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_tinydns_parser.c dns_utils.c -lcrypto -o test_conf_include
	./test_conf_include

hash_test: tests/test_hash_table.c
	clang -fsanitize=address,undefined -O1 -g tests/test_hash_table.c -o test_hash_table
	./test_hash_table

clean: clean-fuzz
	rm -f $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) $(OBJS) $(DAG_OBJS) $(KARICTL_OBJS)
	rm -f karidns-asan karidns-tsan *.asan.o *.tsan.o test_asan_overflow test_conf_include test_hash_table

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

fuzz_dag_all: fuzz_dag fuzz_dag_hash fuzz_dag_chunked_http fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file

fuzz_dag_test: fuzz_dag_all
	@for target in fuzz_dag_response fuzz_dag_hash fuzz_dag_chunked_http fuzz_dag_rdata_yaml fuzz_dag_axfr_stream fuzz_dag_cli_args fuzz_dag_batch_file; do \
		corpus="tests/fuzz/corpus_$$target"; \
		[ -d "$$corpus" ] || corpus="tests/fuzz/corpus"; \
		count=$$(ls -1 "$$corpus" 2>/dev/null | wc -l); \
		echo "Checking $$target (corpus files: $$count)"; \
		[ "$$count" -gt 0 ] || { echo "Error: corpus $$corpus is empty!"; exit 1; }; \
		./tests/fuzz/$$target -runs=1 "$$corpus" || exit 1; \
	done

fuzz_karidns: fuzz fuzz_core fuzz_zone fuzz_conf fuzz_tsig fuzz_tsig_verify

fuzz_karidns_test: fuzz_karidns
	@for target in fuzz_dns_wire fuzz_dns_server_core fuzz_zone_parser fuzz_conf_parser fuzz_tsig_sign fuzz_tsig_verify; do \
		corpus="tests/fuzz/corpus_$$target"; \
		[ -d "$$corpus" ] || corpus="tests/fuzz/corpus"; \
		count=$$(ls -1 "$$corpus" 2>/dev/null | wc -l); \
		echo "Checking $$target (corpus files: $$count)"; \
		[ "$$count" -gt 0 ] || { echo "Error: corpus $$corpus is empty!"; exit 1; }; \
		./tests/fuzz/$$target -runs=1 "$$corpus" || exit 1; \
	done

fuzz_all: fuzz_karidns fuzz_dag_all

fuzz_test: fuzz_karidns_test fuzz_dag_test

clean-fuzz:
	rm -f $(FUZZ_TARGET) $(FUZZ_CORE_TARGET) $(FUZZ_ZONE_TARGET) $(FUZZ_CONF_TARGET) $(FUZZ_TSIG_TARGET) $(FUZZ_DAG_TARGET) $(FUZZ_TSIG_VERIFY_TARGET) \
		$(FUZZ_DAG_HASH_TARGET) $(FUZZ_DAG_CHUNKED_HTTP_TARGET) $(FUZZ_DAG_RDATA_YAML_TARGET) $(FUZZ_DAG_AXFR_STREAM_TARGET) $(FUZZ_DAG_CLI_ARGS_TARGET) $(FUZZ_DAG_BATCH_FILE_TARGET)

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
KARICHECK_ASAN_SRCS = tools/karicheck.c dns_config_parser.c dns_zone_parser.c dns_tinydns_parser.c dns_wire.c dns_utils.c
karicheck-asan: $(KARICHECK_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(KARICHECK_ASAN_SRCS) -o $@ $(LDFLAGS) -lcrypto

DAG_ASAN_SRCS = tools/dag.c dns_wire.c dns_utils.c dns_zone_parser.c
dag-asan: $(DAG_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(DAG_ASAN_SRCS) -o $@ $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS)

KARICTL_ASAN_SRCS = tools/karictl.c
karictl-asan: $(KARICTL_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(KARICTL_ASAN_SRCS) -o $@ -lcrypto -fsanitize=address,undefined

.PHONY: tools-asan
tools-asan: karicheck-asan dag-asan karictl-asan
