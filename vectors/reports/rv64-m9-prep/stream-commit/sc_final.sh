#!/bin/bash
cd /workspace/m3/src/m9-stream-commit
export CUDA_VISIBLE_DEVICES=0
nvidia-smi --query-gpu=name,clocks.sm,clocks.mem,power.draw,temperature.gpu --format=csv,noheader
./sc_bench parity | tail -1
# log 24 widest recursion tree: chunk policy (production 2^27 = 8 cols, fullstack 2^28 = 16 cols), alignment, fused splits
SC_LOW=11 ./sc_bench bench 24 304 8 3 0
SC_LOW=11 SC_OFFSET=7 ./sc_bench bench 24 304 16 3 0
SC_LOW=11 ./sc_bench bench 24 304 16 3 0
SC_LOW=11 ./sc_bench bench 24 304 16 3 10 108
SC_LOW=13 ./sc_bench bench 24 304 16 3 0
SC_LOW=10 ./sc_bench bench 24 304 16 3 0
SC_LOW=11 ./sc_bench bench 24 304 32 3 0
for c in 16 45 114; do SC_LOW=11 ./sc_bench bench 24 $c 16 3 0; done
SC_LOW=10 ./sc_bench bench 23 16 16 3 0
SC_LOW=10 ./sc_bench bench 22 32 32 3 0
for l in 21 20 19 18 16; do ./sc_bench bench $l 32 32 5 0; ./sc_bench bench $l 32 32 5 10 108; done
