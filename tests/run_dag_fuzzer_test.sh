#!/bin/sh
set -e

echo "[+] Building fuzz_dag_response with ASan..."
cc -fsanitize=fuzzer,address -O1 -g tests/fuzz/fuzz_dag_response.c dns_wire.o dns_utils.o dns_zone_parser.o -I. -o tests/fuzz/fuzz_dag_response -pthread -lssl -lcrypto -lm -lz

echo "[+] Running fuzz_dag_response on corpus..."
./tests/fuzz/fuzz_dag_response tests/fuzz/corpus/dag_long_rdata.bin

echo "[+] Done. No ASan errors means pass."
