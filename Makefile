# Makefile for karidns (FreeBSD)

CC = cc
CFLAGS = -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDFLAGS = -pthread -lcrypto

TARGET = karidns
SRCS = dns_server_core.c dns_wire.c
OBJS = $(SRCS:.c=.o)

DAG_TARGET = dag
DAG_SRCS = tools/dag.c dns_wire.c

DAG_OBJS = $(DAG_SRCS:.c=.o)

KARICTL_TARGET = karictl
KARICTL_SRCS = tools/karictl.c
KARICTL_OBJS = $(KARICTL_SRCS:.c=.o)

FUZZ_TARGET = tests/fuzz/fuzz_dns_wire
FUZZ_SRCS = tests/fuzz/fuzz_dns_wire.c dns_wire.c

FUZZ_CORE_TARGET = tests/fuzz/fuzz_dns_server_core
FUZZ_CORE_SRCS = tests/fuzz/fuzz_dns_server_core.c dns_wire.c

.PHONY: all clean run fuzz fuzz_core clean-fuzz

all: $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(KARICTL_TARGET): $(KARICTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(DAG_TARGET): $(DAG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lz

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean: clean-fuzz
	rm -f $(TARGET) $(DAG_TARGET) $(KARICTL_TARGET) $(OBJS) $(DAG_OBJS) $(KARICTL_OBJS)

run: $(TARGET)
	./$(TARGET)

fuzz: $(FUZZ_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -o $(FUZZ_TARGET) $(FUZZ_SRCS) $(LDFLAGS)

fuzz_core: $(FUZZ_CORE_SRCS)
	$(CC) -O1 -g -fsanitize=fuzzer,address,undefined -o $(FUZZ_CORE_TARGET) $(FUZZ_CORE_SRCS) $(LDFLAGS)

clean-fuzz:
	rm -f $(FUZZ_TARGET) $(FUZZ_CORE_TARGET)
