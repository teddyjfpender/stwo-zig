#!/bin/bash
cd /workspace/m3/src/m9-stream-commit
export CUDA_VISIBLE_DEVICES=0
./sc_bench occupancy
./sc_bench parity | tail -7
for L in 13 12 11 10; do SC_LOW=$L ./sc_bench bench 24 64 16 3 0; done
for L in 12 11 10; do SC_LOW=$L ./sc_bench bench 23 32 16 3 0; done
for L in 11 10; do SC_LOW=$L ./sc_bench bench 22 32 32 3 0; done
