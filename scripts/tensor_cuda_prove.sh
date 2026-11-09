#!/usr/bin/env bash
# Prove toy / MLP / decoder-stack shapes on CPU and on the CUDA backend and
# require identical proof digests; prints prove times and the CUDA transfer /
# launch counters. Run after scripts/tensor_cuda_build.sh.
#   scripts/tensor_cuda_prove.sh [small|medium]
# medium stays within 2^20-element tensors / 1024 tokens.
set -euo pipefail
SIZE="${1:-small}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
B="${TENSOR_BENCH:-$ROOT/src/tensor/zig-out/bin/tensor-bench}"
THREADS="${THREADS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu)}"
if [[ "$SIZE" == small ]]; then
  CASES=("product 14 $THREADS" "mlp 6 10 12 $THREADS" "layer 6 9 11 3 $THREADS" "model t=6 d=9 f=11 h=3 kv=1 layers=2 e=2 fe=10 v=12 threads=$THREADS")
else
  CASES=("product 20 $THREADS" "mlp 10 12 14 $THREADS" "layer 10 12 14 5 $THREADS" "model t=10 d=12 f=14 h=5 kv=3 layers=4 e=3 fe=12 v=15 threads=$THREADS")
fi
export TENSOR_TEST_SALT=1  # fixed request salts: model digests are comparable
fail=0
for c in "${CASES[@]}"; do
  cpu="$($B $c | tail -1)"
  dev="$($B $c --cuda | tail -1)"
  dc="$(echo "$cpu" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("proof_digest"))')"
  dd="$(echo "$dev" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("proof_digest"))')"
  tc="$(echo "$cpu" | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d.get("prove_s") or d.get("prove_requests_s"))')"
  td="$(echo "$dev" | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d.get("prove_s") or d.get("prove_requests_s"), json.dumps(d.get("cuda")))')"
  if [[ "$dc" == "$dd" && "$dc" != None ]]; then st=SAME; else st=DIFFERENT; fail=1; fi
  echo "$st  [$c]  cpu ${tc}s  cuda ${td}  digest $dc / $dd"
done
exit $fail
