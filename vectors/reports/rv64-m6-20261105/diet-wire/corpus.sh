#!/bin/bash
# diet-wire: profiles' negative corpus (full-tree m3 format) + root-only/--audit attempt on named-profile proofs. CPU only.
#   bash corpus.sh TAG PROFILE   (TAG = run tag, e.g. k3-p1)
set -u
TAG=$1; export STWO_RV64_OUTER_PROFILE=$2
SRC=/workspace/m3/src/m6-diet-wire; RUNS=/workspace/m3/runs/m6-diet-wire; S=/workspace/m3/scratch/m6-diet-wire/$TAG; mkdir -p $S
R=/workspace/m3/build/m6-diet-wire/zig-out/bin/rv64-word16-ethereum-recursion-receiver
cd $SRC; sha256sum $R; echo "outer profile: $STWO_RV64_OUTER_PROFILE"
for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
  echo "== corpus m3 $b $(date +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
  python3 scripts/rv64_m5_negative_corpus.py run --format m3 --run $RUNS/$b-2gpu-$TAG --donor $RUNS/$o-2gpu-$TAG --receiver $R \
    --out $S/corpus-$b.json --jobs 4 --work $S/work > $S/corpus-$b.log 2>&1
  echo "exit=$? $(tail -1 $S/corpus-$b.log | cut -c1-500)"
done
rm -rf $S/work
echo CORPUS_DONE
