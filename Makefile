# Makefile for karidns & dag (FreeBSD, Linux, macOS)

UNAME_S != uname -s 2>/dev/null || echo Unknown

# OS-specific flags
DARWIN_CFLAGS  != [ "`uname -s 2>/dev/null`" = "Darwin" ] && echo "-I`brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl`/include" || echo "-I/usr/local/include"
DARWIN_LDFLAGS != [ "`uname -s 2>/dev/null`" = "Darwin" ] && echo "-L`brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl`/lib" || echo "-L/usr/local/lib"

# Hardening LDFLAGS (macOS & Windows ld do not support ELF -z options)
HARDEN_LDFLAGS != case "`uname -s 2>/dev/null`" in Darwin) echo "-pie" ;; MINGW*|MSYS*|CYGWIN*) echo "" ;; *) echo "-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack" ;; esac

# libidn2 detection (portable for BSD make & GNU make)
IDN_CFLAGS != (pkg-config --cflags libidn2 2>/dev/null || (pkg info -e libidn2 >/dev/null 2>&1 && echo "-DHAVE_LIBIDN2") || ([ -f /usr/include/idn2.h ] || [ -f /usr/local/include/idn2.h ] && echo "-DHAVE_LIBIDN2")) || true
IDN_LDFLAGS != (pkg-config --libs libidn2 2>/dev/null || (pkg info -e libidn2 >/dev/null 2>&1 && echo "-L/usr/local/lib -lidn2") || ([ -f /usr/lib/libidn2.so ] || [ -f /usr/local/lib/libidn2.so ] || [ -f /usr/lib64/libidn2.so ] && echo "-lidn2")) || true

# Windows / MinGW detection (static single-binary build)
WIN_LDFLAGS != case "`uname -s 2>/dev/null`" in MINGW*|MSYS*|CYGWIN*) echo "-static -lws2_32 -liphlpapi -lcrypt32" ;; *) echo "" ;; esac

CC ?= cc
CFLAGS += -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE $(DARWIN_CFLAGS) $(IDN_CFLAGS)
LDFLAGS = -pthread -lm $(DARWIN_LDFLAGS) $(HARDEN_LDFLAGS)


TARGET = karidns
SRCS = dns_server_core.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_utils.c
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
FUZZ_CORE_SRCS = tests/fuzz/fuzz_dns_server_core.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_utils.c

FUZZ_ZONE_TARGET = tests/fuzz/fuzz_zone_parser
FUZZ_ZONE_SRCS = tests/fuzz/fuzz_zone_parser.c dns_zone_parser.c dns_utils.c dns_wire.c

FUZZ_CONF_TARGET = tests/fuzz/fuzz_conf_parser
FUZZ_CONF_SRCS = tests/fuzz/fuzz_conf_parser.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_utils.c

FUZZ_TSIG_TARGET = tests/fuzz/fuzz_tsig_sign
FUZZ_TSIG_SRCS = tests/fuzz/fuzz_tsig_sign.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_DAG_TARGET = tests/fuzz/fuzz_dag_response
FUZZ_DAG_SRCS = tests/fuzz/fuzz_dag_response.c dns_wire.c dns_utils.c dns_zone_parser.c

FUZZ_TSIG_VERIFY_TARGET = tests/fuzz/fuzz_tsig_verify
FUZZ_TSIG_VERIFY_SRCS = tests/fuzz/fuzz_tsig_verify.c dns_wire.c dns_utils.c dns_zone_parser.c

.PHONY: all clean run fuzz fuzz_core clean-fuzz asan tsan fuzz_tsig fuzz_dag fuzz_tsig_verify dag tools

all: $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

$(KARICTL_TARGET): $(KARICTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

$(DAG_TARGET): $(DAG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lssl -lcrypto -lz $(IDN_LDFLAGS) $(WIN_LDFLAGS)

karicheck: tools/karicheck.c dns_config_parser.o dns_zone_parser.o dns_wire.o dns_utils.o
	$(CC) $(CFLAGS) tools/karicheck.c dns_config_parser.o dns_zone_parser.o dns_wire.o dns_utils.o -o karicheck $(LDFLAGS) -lcrypto

$(OBJS) $(DAG_OBJS) $(KARICTL_OBJS): dns_wire.h dns_config_parser.h dns_zone_parser.h dns_utils.h

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

asan_test: tests/test_asan_overflow.c dns_config_parser.o dns_zone_parser.o dns_wire.o
	clang -fsanitize=address,undefined -O1 -g tests/test_asan_overflow.c dns_config_parser.c dns_zone_parser.c dns_wire.c dns_utils.c -lcrypto -o test_asan_overflow
	./test_asan_overflow

include_test: tests/test_conf_include.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_utils.c
	clang -fsanitize=address,undefined -O1 -g tests/test_conf_include.c dns_config_parser.c dns_wire.c dns_zone_parser.c dns_utils.c -lcrypto -o test_conf_include
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
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TARGET) $(FUZZ_SRCS) $(LDFLAGS)

fuzz_core: $(FUZZ_CORE_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_CORE_TARGET) $(FUZZ_CORE_SRCS) $(LDFLAGS)

fuzz_zone: $(FUZZ_ZONE_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_ZONE_TARGET) $(FUZZ_ZONE_SRCS) $(LDFLAGS)

fuzz_conf: $(FUZZ_CONF_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_CONF_TARGET) $(FUZZ_CONF_SRCS) $(LDFLAGS)

fuzz_tsig: $(FUZZ_TSIG_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TSIG_TARGET) $(FUZZ_TSIG_SRCS) $(LDFLAGS)

fuzz_dag: $(FUZZ_DAG_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_DAG_TARGET) $(FUZZ_DAG_SRCS) $(LDFLAGS) -lssl -lz $(IDN_LDFLAGS)

fuzz_tsig_verify: $(FUZZ_TSIG_VERIFY_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -fPIE -o $(FUZZ_TSIG_VERIFY_TARGET) $(FUZZ_TSIG_VERIFY_SRCS) $(LDFLAGS)

clean-fuzz:
	rm -f $(FUZZ_TARGET) $(FUZZ_CORE_TARGET) $(FUZZ_ZONE_TARGET) $(FUZZ_CONF_TARGET) $(FUZZ_TSIG_TARGET) $(FUZZ_DAG_TARGET) $(FUZZ_TSIG_VERIFY_TARGET)

ASAN_TARGET = karidns-asan
ASAN_CFLAGS = -O1 -Wall -Wextra -std=c11 -D_GNU_SOURCE -DSANITIZER_BUILD -g -fsanitize=address,undefined -fno-omit-frame-pointer -fPIE
ASAN_OBJS = $(SRCS:.c=.asan.o)

asan: $(ASAN_TARGET)

$(ASAN_TARGET): $(ASAN_OBJS)
	$(CC) $(ASAN_CFLAGS) -o $@ $^ $(LDFLAGS)

.SUFFIXES: .asan.o .c
.c.asan.o:
	$(CC) $(ASAN_CFLAGS) -c $< -o $@

TSAN_TARGET = karidns-tsan
TSAN_CFLAGS = -O1 -Wall -Wextra -std=c11 -D_GNU_SOURCE -DSANITIZER_BUILD -g -fsanitize=thread -fPIE
TSAN_LDFLAGS = -fsanitize=thread -pie
TSAN_OBJS = $(SRCS:.c=.tsan.o)

tsan: $(TSAN_TARGET)

$(TSAN_TARGET): $(TSAN_OBJS)
	$(CC) $(TSAN_CFLAGS) -o $@ $^ $(LDFLAGS) $(TSAN_LDFLAGS)

.SUFFIXES: .tsan.o .c
.c.tsan.o:
	$(CC) $(TSAN_CFLAGS) -c $< -o $@

# --- ASan版ツール群 ---
KARICHECK_ASAN_SRCS = tools/karicheck.c dns_config_parser.c dns_zone_parser.c dns_wire.c dns_utils.c
karicheck-asan: $(KARICHECK_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(KARICHECK_ASAN_SRCS) -o $@ $(LDFLAGS)

DAG_ASAN_SRCS = tools/dag.c dns_wire.c dns_utils.c dns_zone_parser.c
dag-asan: $(DAG_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(DAG_ASAN_SRCS) -o $@ $(LDFLAGS) -lssl -lz $(IDN_LDFLAGS)

KARICTL_ASAN_SRCS = tools/karictl.c
karictl-asan: $(KARICTL_ASAN_SRCS)
	$(CC) $(ASAN_CFLAGS) $(KARICTL_ASAN_SRCS) -o $@ -lcrypto -fsanitize=address,undefined

.PHONY: tools-asan
tools-asan: karicheck-asan dag-asan karictl-asan
