#!/bin/bash
# profiles corpus v4 vs native-format v2-strict (full-tree receiver of native-format, fresh CPU process per case).
# usage: RUN156=<v2s run dir 26235156> RUN607=<v2s run dir 24628607> bash corpus_nv2.sh
set -u
SRC=/workspace/m3/src/m6-profiles; O=/workspace/m3/runs/m6-profiles; M5=/workspace/m3/runs/integrate
S=/workspace/m3/scratch/m6-profiles/nv2; mkdir -p $S
cp /workspace/m3/build/m6-native-format/zig-out/bin/rv64-word16-ethereum-recursion-receiver $S/receiver; sha256sum $S/receiver
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE STWO_RV64_OUTER_PROFILE STWO_RV64_FOLD_ARITY
declare -A RUN=([26235156]=$RUN156 [24628607]=$RUN607)
for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
  echo "== $b v2 policy, full corpus + NV03 (alt = M5 default proof) load=$(cut -d' ' -f1 /proc/loadavg) $(date +%T)"
  STWO_RV64_NATIVE_VERSION=m6-native-v2-strict python3 -I $SRC/scripts/rv64_m5_negative_corpus.py run --format m5-audit \
    --run ${RUN[$b]} --donor ${RUN[$o]} --alt-format-run $M5/$b-2gpu-scale --receiver $S/receiver \
    --jobs 3 --work /workspace/m3/scratch/m6-profiles/corpus-nv2 --out $O/$b-corpus-v4-native-v2s.json > $O/$b-nv2.log 2>&1
  echo "exit=$? $(tail -1 $O/$b-nv2.log)"
  echo "== $b v1 (default) policy, NV03 reverse (alt = v2s proof) $(date +%T)"
  python3 -I $SRC/scripts/rv64_m5_negative_corpus.py run --format m5-audit \
    --run $M5/$b-2gpu-scale --donor $M5/$o-2gpu-scale --alt-format-run ${RUN[$b]} --receiver $S/receiver \
    --cases C00-control,NV03-cross-native-version --jobs 2 --work /workspace/m3/scratch/m6-profiles/corpus-nv2 \
    --out $O/$b-corpus-v4-native-v1-policy.json > $O/$b-nv1.log 2>&1
  echo "exit=$? $(tail -1 $O/$b-nv1.log)"
done
rm -rf /workspace/m3/scratch/m6-profiles/corpus-nv2
echo NV2_DONE
