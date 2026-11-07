#!/bin/bash
cd /workspace/m3/src/m9-stream-commit-review
export CUDA_VISIBLE_DEVICES=0
nvidia-smi --query-gpu=name,clocks.sm,clocks.mem,power.draw,temperature.gpu --format=csv,noheader
# re-run headline rows
SC_LOW=11 ./sc_bench bench 24 304 16 5 0
SC_LOW=11 SC_OFFSET=7 ./sc_bench bench 24 304 16 5 0
SC_LOW=11 ./sc_bench bench 24 304 32 5 0
./sc_bench bench 21 32 32 7 0
# recursion default chunk 2^26 = 4 columns at log 24 (outer_trace_commit.zig)
SC_LOW=11 ./sc_bench bench 24 304 4 5 0
SC_LOW=11 SC_OFFSET=7 ./sc_bench bench 24 304 4 5 0
# partial trees with production non-final calls: arm 1 fused final, arm 2 LDE-input final
for A in 1 2; do SC_ARM=$A SC_LOW=11 ./sc_bench bench 24 304 32 5 10 108; done
SC_ARM=2 ./sc_bench bench 24 304 32 5 0 108
SC_ARM=2 ./sc_bench bench 24 304 32 5 0 0
for L in 23 22 21 20 18; do for A in 1 2; do SC_ARM=$A ./sc_bench bench $L 64 32 7 10 108; done; done
# fused arm with queries, now timed symmetrically
./sc_bench bench 21 32 32 7 10 108
./sc_bench bench 20 32 32 7 10 108
