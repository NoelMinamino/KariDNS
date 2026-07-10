# Makefile for karidns (FreeBSD)

CC = cc
CFLAGS = -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDFLAGS = -pthread -lcrypto

TARGET = karidns
SRCS = dns_server_core.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_utils.c
OBJS = $(SRCS:.c=.o)

DAG_TARGET = dag
DAG_SRCS = tools/dag.c dns_wire.c dns_utils.c

DAG_OBJS = $(DAG_SRCS:.c=.o)

KARICTL_TARGET = karictl
KARICTL_SRCS = tools/karictl.c
KARICTL_OBJS = $(KARICTL_SRCS:.c=.o)

FUZZ_TARGET = tests/fuzz/fuzz_dns_wire
FUZZ_SRCS = tests/fuzz/fuzz_dns_wire.c dns_wire.c dns_utils.c

FUZZ_CORE_TARGET = tests/fuzz/fuzz_dns_server_core
FUZZ_CORE_SRCS = tests/fuzz/fuzz_dns_server_core.c dns_wire.c dns_config_parser.c dns_zone_parser.c dns_utils.c

FUZZ_ZONE_TARGET = tests/fuzz/fuzz_zone_parser
FUZZ_ZONE_SRCS = tests/fuzz/fuzz_zone_parser.c dns_zone_parser.c dns_utils.c

FUZZ_CONF_TARGET = tests/fuzz/fuzz_conf_parser
FUZZ_CONF_SRCS = tests/fuzz/fuzz_conf_parser.c dns_config_parser.c dns_utils.c

.PHONY: all clean run fuzz fuzz_core clean-fuzz asan tsan

all: $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) karicheck

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(KARICTL_TARGET): $(KARICTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(DAG_TARGET): $(DAG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lz

karicheck: tools/karicheck.c dns_config_parser.o dns_zone_parser.o dns_wire.o dns_utils.o
	$(CC) $(CFLAGS) tools/karicheck.c dns_config_parser.o dns_zone_parser.o dns_wire.o dns_utils.o -o karicheck $(LDFLAGS) -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

asan_test: tests/test_asan_overflow.c dns_config_parser.o dns_zone_parser.o dns_wire.o
	clang -fsanitize=address,undefined -O1 -g tests/test_asan_overflow.c dns_config_parser.c dns_zone_parser.c dns_wire.c dns_utils.c -lcrypto -o test_asan_overflow
	./test_asan_overflow

clean: clean-fuzz
	rm -f $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) $(OBJS) $(DAG_OBJS) $(KARICTL_OBJS)
	rm -f karidns-asan karidns-tsan *.asan.o *.tsan.o

run: $(TARGET)
	./$(TARGET)

fuzz: $(FUZZ_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -o $(FUZZ_TARGET) $(FUZZ_SRCS) $(LDFLAGS)

fuzz_core: $(FUZZ_CORE_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -o $(FUZZ_CORE_TARGET) $(FUZZ_CORE_SRCS) $(LDFLAGS)

fuzz_zone: $(FUZZ_ZONE_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -o $(FUZZ_ZONE_TARGET) $(FUZZ_ZONE_SRCS) $(LDFLAGS)

fuzz_conf: $(FUZZ_CONF_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -o $(FUZZ_CONF_TARGET) $(FUZZ_CONF_SRCS) $(LDFLAGS)

clean-fuzz:
	rm -f $(FUZZ_TARGET) $(FUZZ_CORE_TARGET) $(FUZZ_ZONE_TARGET) $(FUZZ_CONF_TARGET)

ASAN_TARGET = karidns-asan
ASAN_CFLAGS = -O1 -Wall -Wextra -std=c11 -D_GNU_SOURCE -DSANITIZER_BUILD -g -fsanitize=address,undefined -fno-omit-frame-pointer
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
