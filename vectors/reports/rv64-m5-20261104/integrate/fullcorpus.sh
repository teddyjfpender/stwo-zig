#!/bin/bash
# M5 integrate (b): profiles' negative corpus v3 in the full-tree (m3 / --audit-equivalent) format against the
# merged receiver on the canonical-profile proofs of both dev blocks (CPU only, no GPU lock).
set -u
TAG=${1:-b1-canon}
SRC=/workspace/m3/src/m5-integrate; RUNS=/workspace/m3/runs/m5-integrate
S=/workspace/m3/scratch/m5-integrate/$TAG-full; mkdir -p $S
R=${RECEIVER:-/workspace/m3/build/m5-integrate/receiver-v2/bin/rv64-word16-ethereum-recursion-receiver}
export STWO_RV64_OUTER_PROFILE=${STWO_RV64_OUTER_PROFILE:-m5_outer_canonical_r1_b2_q108_p20_fold4_v1}
cd $SRC
sha256sum $R; echo "outer profile: $STWO_RV64_OUTER_PROFILE"
for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
echo "== profiles corpus v3 m3 $b $(date +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
python3 scripts/rv64_m5_negative_corpus.py run --format m3 --run $RUNS/$b-2gpu-$TAG --donor $RUNS/$o-2gpu-$TAG --receiver $R \
  --out $S/pc-full-corpus-$b.json --jobs 4 --work $S/work > $S/pc-full-corpus-$b.log 2>&1
echo "exit=$? $(tail -1 $S/pc-full-corpus-$b.log | cut -c1-600)"
done
rm -rf $S/work
echo FULLCORPUS_DONE
