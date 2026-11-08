#!/bin/bash
# fold-v3: extra fresh-process root-only reps against an existing derive (same receiver binary that derived the table).
set -u
FORMAT=${FORMAT:-old}; TAG=${TAG:-r4}; REPS=${REPS:-5}
S=/workspace/m3/scratch/m6-fold-v3/$FORMAT-$TAG; O=$S/reverify; mkdir -p $O
R=${RECEIVER:-/workspace/m3/build/m6-fold-v3/zig-out/bin/rv64-word16-ethereum-recursion-receiver}
P=conjectured128_b2_q108_p20_fold4; FIX=12884901888; HOST=34359738368
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE
if [ $FORMAT = canon ]; then RUNS=/workspace/m3/runs/m5-integrate; RT=b1-canon; export STWO_RV64_OUTER_PROFILE=m5_outer_canonical_r1_b2_q108_p20_fold4_v1; else RUNS=/workspace/m3/runs/integrate; RT=scale; fi
ROOT=$(python3 -c "import json;print(json.load(open(\"$S/out/derive-both.json\"))[\"table_root\"])")
cd /workspace/m3/src/m6-fold-v3; sha256sum $R
for rep in $(seq 1 $REPS); do for b in 26235156 24628607; do
  l=$(cut -d" " -f1 /proc/loadavg); t0=$(date +%s.%N)
  $R --security-profile $P verify-root-candidate $S/$b-request.json $RUNS/$b-2gpu-$RT/case/batch/trial-0/$b/proof $S/tables/vk-both.json $FIX $HOST --table-root $ROOT > $O/$b-r$rep.json 2>$O/$b-r$rep.stderr; rc=$?
  t1=$(date +%s.%N); echo "$b r$rep exit=$rc wall=$(python3 -c "print(round($t1-$t0,3))") load=$l internal=$(python3 -c "import json;print(json.load(open(\"$O/$b-r$rep.json\"))[\"verify_per_block_ns\"]/1e9)" 2>/dev/null)"
done; done
