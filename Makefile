# Makefile for my_dns (FreeBSD)

CC = cc
CFLAGS = -O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDFLAGS = -pthread -lcrypto

TARGET = karidns
SRCS = dns_server_core.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

run: $(TARGET)
	./$(TARGET)
