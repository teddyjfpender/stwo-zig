set -u
SRC=/workspace/m3/src/m6-profiles; O=/workspace/m3/runs/m6-profiles; S=/workspace/m3/scratch/m6-profiles/nv2
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE STWO_RV64_OUTER_PROFILE STWO_RV64_FOLD_ARITY
df -h /workspace | tail -1
STWO_RV64_NATIVE_VERSION=m6-native-v2-strict python3 -I $SRC/scripts/rv64_m5_negative_corpus.py run --format m5-audit \
  --run /workspace/m3/runs/m6-native-format/24628607-2gpu-v2s-r6 --donor /workspace/m3/runs/m6-native-format/26235156-2gpu-v2s-r5 \
  --alt-format-run /workspace/m3/runs/integrate/24628607-2gpu-scale --receiver $S/receiver \
  --jobs 1 --work /workspace/m3/scratch/m6-profiles/corpus-nv2 --out $O/24628607-corpus-v4-native-v2s.json > $O/24628607-nv2.log 2>&1
echo "exit=$? $(tail -1 $O/24628607-nv2.log)"
rm -rf /workspace/m3/scratch/m6-profiles/corpus-nv2
