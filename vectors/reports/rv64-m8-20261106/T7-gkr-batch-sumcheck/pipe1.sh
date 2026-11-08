#!/bin/bash
# T7 pipeline 1 (pod, tmux t7-pipe1): wait for disk -> compose image -> wait for GPUs ->
# gate default (flag unset, 26235156) -> gates flag on (26235156, 24628607) -> canonical 3+3 A/B on 24628607.
set -u
S=m8-opt-T7-gkr-batch-sumcheck; R=/workspace/m3/runs/$S; SRC=/workspace/m3/src/$S; B=/workspace/m3/build/$S
IMG=$B/img1; RT=$IMG/runtime.json; C=${C:?commit}; ST=$R/pipe1.status; FLAG=STWO_RV64_M8_GKR_BATCH_PAR
T7=$SRC/vectors/reports/rv64-m8-20261106/T7-gkr-batch-sumcheck
log() { echo "$(date -u +%FT%TZ) $*" >> $ST; }
log start commit=$C
if [ ! -f $RT ]; then
  log waiting-for-disk
  until [ "$(df --output=avail -B1G /workspace | tail -1 | tr -d ' ')" -ge "${MIN_FREE_GB:-5}" ]; do sleep 60; done
  log disk-ok $(df --output=avail -B1G /workspace | tail -1)
  flock /workspace/m3/locks/build.1.lock python3 $T7/compose_image.py $SRC $IMG > $R/img1.log 2>&1
  rc=$?; log img1 rc=$rc $(tail -1 $R/img1.log); [ $rc -eq 0 ] || exit 1
fi
log waiting-for-gpus
while true; do
  u=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | sort -n | tail -1)
  [ "$u" -lt 2048 ] && break; sleep 30
done
log gpus-free
cd $SRC
bash scripts/rv64_gate.sh --stream $S --out $R/gate-1-default-26235156 --source-commit $C --runtime $RT > $R/gate-1-default-26235156.log 2>&1
rc=$?; log gate-default-26235156 rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
for blk in 26235156 24628607; do
  bash scripts/rv64_gate.sh --stream $S --block $blk --out $R/gate-1-on-$blk --source-commit $C --runtime $RT --env $FLAG=1 > $R/gate-1-on-$blk.log 2>&1
  rc=$?; log gate-on-$blk rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
done
get() { python3 -c "import json,sys;print(json.load(open('$RT'))['assets'][sys.argv[1]])" $1; }
python3 scripts/rv64_m7_integration_stack.py prepare --source-root $SRC --source-commit $C \
  --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
  --library $(get library) --sparse $(get sparse) --observer $(get observer) --process-budget-guard $(get process_budget_guard) \
  --native-hooks-commit c72b51646 --device-hooks-commit c72b51646 \
  --preset $T7/ab-preset.json --block 24628607 --out $R/ab-24628607-manifest.json > $R/ab-prepare.log 2>&1; log prepare rc=$?
python3 scripts/rv64_m7_integration_stack.py run --manifest $R/ab-24628607-manifest.json --out $R/ab-24628607 > $R/ab-24628607.log 2>&1
log ab-24628607 rc=$?
log DONE
