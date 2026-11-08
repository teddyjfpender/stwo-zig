#!/bin/bash
# m8-gn-node piece harness on recorded real nodes. usage: harness.sh <records-dir> <tree.json> <addon-build> <out-log>
set -u
REC=$1; TREE=$2; AB=$3; OUT=$4
S=/workspace/m3/src/m8-gn-node
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global TMPDIR=/workspace/m3/tmp
cd $S/src/integrations/riscv_cuda
run_locked(){ while true; do for i in 1 2 3; do flock -E 75 -n /workspace/m3/locks/build.$i.lock "$@"; rc=$?; [ $rc -ne 75 ] && return $rc; done; sleep 20; done; }
Z="/workspace/zig/zig build test-rv64-jobs-outer -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha --cache-dir $S/.zig-cache -j8"
run_locked bash -c "$Z > $OUT.compile 2>&1"; echo compile EXIT=$? >> $OUT.status
if [ $AB = none ]; then env STWO_RV64_M8_GN_NODE_RECORDS=$REC STWO_RV64_M8_GN_NODE_TREE=$TREE bash -c "$Z > $OUT 2>&1"; echo harness EXIT=$? >> $OUT.status; echo DONE >> $OUT.status; exit 0; fi
env STWO_RV64_M8_GN_NODE_RECORDS=$REC STWO_RV64_M8_GN_NODE_TREE=$TREE \
    STWO_RV64_M8_GPU_BASE=/workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so \
    STWO_RV64_M8_JOBS_LIBRARY=/workspace/m3/build/m8-gn-node/jobs-addon-$AB/libstwo-rv64-jobs.so \
    LD_LIBRARY_PATH=/workspace/m3/build/m7-combined-residency/cuda/native:/usr/local/cuda/lib64 CUDA_VISIBLE_DEVICES=0 \
    flock -w 3600 /workspace/m3/locks/gpu.lock bash -c "$Z > $OUT 2>&1"; echo harness EXIT=$? >> $OUT.status
echo DONE >> $OUT.status
