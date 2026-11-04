#!/bin/bash
# DW-R2 condition: k=3 proof under a k=2 receiver policy and reverse (full-tree receiver, fresh process, CPU only).
set -u
SRC=/workspace/m3/src/m6-profiles; R=/workspace/m3/runs/m6-diet-wire; O=/workspace/m3/runs/m6-profiles
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE STWO_RV64_OUTER_PROFILE
for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
  for pol in 3 2; do alt=$([ $pol = 3 ] && echo 2 || echo 3)
    if [ $pol = 3 ]; then export STWO_RV64_FOLD_ARITY=3; else unset STWO_RV64_FOLD_ARITY; fi
    echo "== $b policy k=$pol (alt proof k=$alt) load=$(cut -d' ' -f1 /proc/loadavg) $(date +%T)"
    python3 -I $SRC/scripts/rv64_m5_negative_corpus.py run --format m5-audit \
      --run $R/$b-2gpu-k$pol-ab1 --donor $R/$o-2gpu-k$pol-ab1 --alt-format-run $R/$b-2gpu-k$alt-ab1 \
      --cases C00-control,DW07-cross-outer-format --jobs 2 --work /workspace/m3/scratch/m6-profiles/corpus-k \
      --out $O/$b-corpus-v4-dw07-policy-k$pol.json > $O/$b-dw07-k$pol.log 2>&1
    echo "exit=$? $(tail -1 $O/$b-dw07-k$pol.log)"
  done
done
rm -rf /workspace/m3/scratch/m6-profiles/corpus-k
echo DW07_DONE
