#!/bin/bash
cd /workspace/m3/src/m9-stream-commit-review
export CUDA_VISIBLE_DEVICES=0
./sc_bench parity
SC_NEGATIVE=1 ./sc_bench parity | tail -1
