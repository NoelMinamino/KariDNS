#!/bin/sh
# ci_portrange.sh: in a CI VM (as root), start the kernel's ephemeral port range (net.inet.ip.portrange.first and .hifirst) at 60000, above
# every port a test binds (the suite's windows end at 56999, tests/run_all_suite.sh; the fixed and PID-derived ports of the scripts stay below
# 57000).  With FreeBSD's default (10000 .. 65535) a client's source port can be the port of a test server on the same address: the kernel
# hands it out beside the server's SO_REUSEADDR + SO_REUSEPORT_LB listeners, the SYN reaches the client itself, and the client reads back
# its own query (CI flake row 85: dig +tcp got "flags: rd ad; ANSWER: 0", 1 in 1281 .. 55000 TCP queries on pc101).  A server on port 53
# cannot meet this (below the range).  Only for the throwaway CI VMs: the dev hosts keep their settings (run_all_suite.sh warns there).
set -eu
FIRST=60000
sysctl net.inet.ip.portrange.first="$FIRST" net.inet.ip.portrange.hifirst="$FIRST"
echo "ci_portrange.sh: ephemeral ports $(sysctl -n net.inet.ip.portrange.first) .. $(sysctl -n net.inet.ip.portrange.last), high $(sysctl -n net.inet.ip.portrange.hifirst) .. $(sysctl -n net.inet.ip.portrange.hilast)"
