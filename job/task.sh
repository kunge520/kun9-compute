#!/usr/bin/env bash
# Does the sizing differ per run? The first job reported nproc=2, the next one nproc=4.
set +e
echo "== runner sizing sample =="
date -u '+at %FT%TZ'
echo "nproc        = $(nproc)"
echo "cpuinfo      = $(grep -c ^processor /proc/cpuinfo) logical, $(grep -m1 'model name' /proc/cpuinfo | cut -f2- -d:)"
lscpu | grep -E '^(CPU\(s\)|Thread|Core|Socket|Model name)'
echo "cgroup limit = cpu:$(cat /sys/fs/cgroup/cpu.max 2>/dev/null)  memory:$(cat /sys/fs/cgroup/memory.max 2>/dev/null)"
echo "mem          = $(awk '/MemTotal/{printf "%.2f GiB", $2/1048576}' /proc/meminfo)"
echo "disk avail   = $(df -h / | awk 'NR==2{print $4" free of "$2}')"
echo
echo "== a real 30-second cpu burn on all cores (what 1 free minute actually buys) =="
end=$((SECONDS+30))
for i in $(seq 1 $(nproc)); do ( while [ $SECONDS -lt $end ]; do :; done ) & done
wait
echo "burned 30s x $(nproc) cores; load now: $(cat /proc/loadavg)"
# submitted 2026-10-05 13:16:03Zee8ed4
