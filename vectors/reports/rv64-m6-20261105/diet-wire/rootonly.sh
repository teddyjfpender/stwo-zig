#!/bin/bash
# diet-wire: root-only receiver (fold-v3/rootverify entry) on named-profile proofs: derive-vk-tables, verify-root-candidate, --audit.
#   bash rootonly.sh TAG PROFILE
set -u
TAG=$1; export STWO_RV64_OUTER_PROFILE=$2
SRC=/workspace/m3/src/m6-diet-wire; RUNS=/workspace/m3/runs/m6-diet-wire; S=/workspace/m3/scratch/m6-diet-wire/ro-$TAG; mkdir -p $S/tables $S/out
R=/workspace/m3/build/m6-diet-wire/zig-out/bin/rv64-word16-ethereum-recursion-receiver
P=conjectured128_b2_q108_p20_fold4; FIX=12884901888; HOST=34359738368
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE STWO_RV64_FOLD_CLASS_CACHE
cd $SRC
proof() { ls -d $RUNS/$1-2gpu-$TAG/case/batch/trial-0/$1/proof; }
step() { name=$1; shift; t0=$(date +%s.%N); "$@" > $S/out/$name.json 2> $S/out/$name.stderr; rc=$?; t1=$(date +%s.%N)
  echo "$name exit=$rc wall=$(python3 -c "print(round($t1-$t0,2))") load=$(cut -d' ' -f1 /proc/loadavg) $(grep -m1 -oE 'error: [A-Za-z0-9_]+' $S/out/$name.stderr)"; }
for b in 26235156 24628607; do
  python3 $RUNS/req.py $RUNS/$b-2gpu-$TAG/request.json $S/$b-request.json $S/capture-$b
  step derive-$b $R --security-profile $P derive-vk-tables $S/$b-request.json $(proof $b) $S/tables/vk-$b.json $FIX $HOST --source-commit $(cat .m3-commit)
  step verify-$b $R --security-profile $P verify-root-candidate $S/$b-request.json $(proof $b) $S/tables/vk-$b.json $FIX $HOST
  step audit-$b $R --security-profile $P verify-root-candidate $S/$b-request.json $(proof $b) $S/tables/vk-$b.json $FIX $HOST --audit
  rm -rf $S/capture-$b
done
echo ROOTONLY_DONE
