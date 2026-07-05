# Makefile for karidns (FreeBSD)

CC = cc
CFLAGS = -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDFLAGS = -pthread -lcrypto

TARGET = karidns
SRCS = dns_server_core.c dns_wire.c
OBJS = $(SRCS:.c=.o)

DOG_TARGET = dog
DOG_SRCS = tools/dog.c dns_wire.c
DOG_OBJS = $(DOG_SRCS:.c=.o)

.PHONY: all clean run

all: $(TARGET) $(DOG_TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(DOG_TARGET): $(DOG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(DOG_TARGET) $(OBJS) $(DOG_OBJS)

run: $(TARGET)
	./$(TARGET)
