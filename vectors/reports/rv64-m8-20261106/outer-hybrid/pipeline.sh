#!/bin/bash
# outer-hybrid measurement pipeline (pod). usage: pipeline.sh <source-commit> <tag> [NATIVE_ENV ...]
#   build -> addon -> gates (default, outer x2 blocks, composed x2 if native env given)
#   -> prepare + interleaved 3+3 (+ ownership profile pair) per block per candidate preset.
# Never wraps the gate/runner in gpu.lock (the harness takes it).
set -u
SC=$1; T=$2; shift 2; NATIVE=("$@")
S=m8-integrate
SRC=/workspace/m3/src/$S
R=/workspace/m3/runs/$S/oh-$T
B=/workspace/m3/build/$S
ADDON=$B/jobs-addon-oh-$T/libstwo-rv64-jobs.so
FS=$B/assets-2/libstwo-rv64-outer-fs-ops.so
BASE=/workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global TMPDIR=/workspace/m3/tmp
mkdir -p $R; L=$R/pipeline.log
log(){ echo "$* $(date -u +%FT%TZ)" >> $L; }
quiet(){ while pgrep -f rv64_m7_integration_stack.py >/dev/null || tmux ls 2>/dev/null | grep -v '^oh-' | grep -qi meas || nvidia-smi --query-compute-apps=pid --format=csv,noheader | grep -q .; do log WAIT quiet; sleep 150; done; }
cd $SRC
STAGE=${STAGE:-all}
if [ "$STAGE" = all ] || [ "$STAGE" = build ]; then
  log STEP build
  flock -w 7200 /workspace/m3/locks/build.1.lock python3 scripts/rv64_m3_pod.py build --stream $S --only zig > $R/build.log 2>&1 || { log build FAIL; exit 1; }
  log STEP addon
  flock -w 7200 /workspace/m3/locks/build.2.lock env PATH=/usr/local/cuda/bin:$PATH python3 scripts/rv64_m8_jobs_addon_build.py --base $BASE --out $(dirname $ADDON) > $R/addon.log 2>&1 || { log addon FAIL; exit 1; }
  sha256sum $ADDON $FS $B/zig-out/bin/rv64-word16-ethereum-gpu-combined $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver >> $L
fi
HY="--env STWO_RV64_M8_OUTER_JOBS=1 --env STWO_RV64_M8_JOBS_LIBRARY=$ADDON --env STWO_RV64_M8_OUTER_FS_LIBRARY=$FS --env STWO_RV64_M8_JOBS_PINNED_BYTES=2365587456"
NE=""; for kv in "${NATIVE[@]}"; do NE="$NE --env $kv"; done
if [ "$STAGE" = all ] || [ "$STAGE" = gate ]; then
  quiet; log STEP gate-d
  bash scripts/rv64_gate.sh --stream $S --out $R/gate-d --source-commit $SC > $R/gate-d.log 2>&1; log gate-d EXIT $?
  for BL in 26235156 24628607; do
    quiet; log STEP gate-h-$BL
    bash scripts/rv64_gate.sh --stream $S --out $R/gate-h-$BL --block $BL --source-commit $SC $HY > $R/gate-h-$BL.log 2>&1; log gate-h-$BL EXIT $?
    if [ ${#NATIVE[@]} -gt 0 ]; then
      quiet; log STEP gate-c-$BL
      bash scripts/rv64_gate.sh --stream $S --out $R/gate-c-$BL --block $BL --source-commit $SC $HY $NE > $R/gate-c-$BL.log 2>&1; log gate-c-$BL EXIT $?
    fi
  done
fi
if [ "$STAGE" = all ] || [ "$STAGE" = measure ]; then
  python3 vectors/reports/rv64-m8-20261106/outer-hybrid/make_presets.py design/riscv-proving-stack/m7-handoff/integration-stack-preset.json $R $ADDON $FS "${NATIVE[@]}" >> $L
  for P in ${ARMS:-outer composed}; do
    [ -f $R/preset-$P.json ] || continue
    for BL in ${BLOCKS:-24628607 26235156}; do
      python3 scripts/rv64_m7_integration_stack.py prepare --source-root $SRC --source-commit $SC \
        --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
        --library $BASE --sparse /workspace/m3/build/m7-rc-sparse/libstwo-rc-sparse.so --observer /workspace/m3/build/m7-rc-sparse/libstwo-process-memory-v3.so \
        --process-budget-guard /workspace/m3/build/m7-rc-sparse/gpu-budget-guard --native-hooks-commit $SC --device-hooks-commit $SC \
        --preset $R/preset-$P.json --block $BL --out $R/manifest-$P-$BL.json >> $L 2>&1 || { log prepare-$P-$BL FAIL; continue; }
      quiet; log STEP measure-$P-$BL
      python3 scripts/rv64_m7_integration_stack.py run --manifest $R/manifest-$P-$BL.json --out $R/exp-$P-$BL --ownership-profile-pair > $R/exp-$P-$BL.log 2>&1
      log measure-$P-$BL EXIT $?
    done
  done
fi
log DONE
