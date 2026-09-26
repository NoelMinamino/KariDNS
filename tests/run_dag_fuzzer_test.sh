#!/bin/sh
set -e

[ -x tests/fuzz/fuzz_dag_response ] || {
    echo "[+] Building fuzz_dag_response with ASan..."
    # the Makefile rule links every dag module the harness needs (the old
    # hand-written command missed dag_transport.c etc. and failed to link)
    make fuzz_dag
}

echo "[+] Running fuzz_dag_response on corpus..."
./tests/fuzz/fuzz_dag_response tests/fuzz/corpus/dag_long_rdata.bin

echo "[+] Done. No ASan errors means pass."
