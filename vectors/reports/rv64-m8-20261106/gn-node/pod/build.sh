#!/bin/bash
# m8-gn-node build: zig (driver + receiver) then the jobs addon (a25 base), first free build lock.
# usage: build.sh <name> [zig|addon|both]
set -u
N=$1; W=${2:-both}; S=m8-gn-node; R=/workspace/m3/runs/$S; B=/workspace/m3/build/$S
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global TMPDIR=/workspace/m3/tmp
cd /workspace/m3/src/$S
run_locked(){ while true; do for i in 1 2 3; do flock -E 75 -n /workspace/m3/locks/build.$i.lock "$@"; rc=$?; [ $rc -ne 75 ] && return $rc; done; sleep 30; done; }
if [ $W != addon ]; then run_locked bash -c "python3 scripts/rv64_m3_pod.py build --stream $S --only zig > $R/$N-zig.log 2>&1"; echo zig EXIT=$? >> $R/$N.status; fi
if [ $W != zig ]; then run_locked bash -c "env PATH=/usr/local/cuda/bin:\$PATH python3 scripts/rv64_m8_jobs_addon_build.py --base /workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so --out $B/jobs-addon-$N > $R/$N-addon.log 2>&1"; echo addon EXIT=$? >> $R/$N.status; fi
echo DONE >> $R/$N.status
