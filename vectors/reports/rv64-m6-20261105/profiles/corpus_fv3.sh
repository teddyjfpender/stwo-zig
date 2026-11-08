#!/bin/bash
# profiles corpus v4 (format m6-root) against fold-v3's standalone root-only receiver. CPU only, fresh process per case.
set -u
SRC=/workspace/m3/src/m6-profiles
S=/workspace/m3/scratch/m6-profiles/fv3; mkdir -p $S
cp /workspace/m3/build/m6-fold-v3/zig-out/bin/rv64-word16-ethereum-recursion-receiver $S/receiver
cp /workspace/m3/scratch/m6-fold-v3/old-r2/tables/vk-2*.json $S/
for b in 26235156 24628607; do cp /workspace/m3/scratch/m6-fold-v3/old-r2/out/derive-$b.json $S/derive-$b.json; done
sha256sum $S/receiver
root() { python3 -c "import json;print(json.load(open('$S/derive-$1.json'))['table_root'])"; }
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE STWO_RV64_OUTER_PROFILE
OUT=$SRC/vectors/reports/rv64-m6-20261105/profiles
for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
  echo "== $b load=$(cut -d' ' -f1 /proc/loadavg) $(date +%T)"
  python3 -I $SRC/scripts/rv64_m5_negative_corpus.py run --format m6-root \
    --run /workspace/m3/runs/integrate/$b-2gpu-scale --donor /workspace/m3/runs/integrate/$o-2gpu-scale \
    --root-donor /workspace/m3/runs/integrate/$o-2gpu-scale \
    --receiver $S/receiver --table-root $(root $b) --donor-table-root $(root $o) \
    --receiver-argv "[\"{receiver}\",\"--security-profile\",\"{profile}\",\"verify-root-candidate\",\"{request}\",\"{proof}\",\"$S/vk-$b.json\",\"{fixed}\",\"{host}\",\"--table-root\",\"{table_root}\"]" \
    --jobs 3 --work /workspace/m3/scratch/m6-profiles/corpus --out /workspace/m3/runs/m6-profiles/$b-corpus-v4-fold-v3-receiver.json \
    > /workspace/m3/runs/m6-profiles/$b-corpus.log 2>&1
  echo "exit=$? $(tail -1 /workspace/m3/runs/m6-profiles/$b-corpus.log)"
done
rm -rf /workspace/m3/scratch/m6-profiles/corpus
echo CORPUS_DONE
