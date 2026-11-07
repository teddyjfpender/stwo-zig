#!/bin/bash
# T10 pipeline 2 (after pipe1's three gate PASSes): canonical 3+3 A/B on 24628607 with the same-memory-model preset
# (both arms = canonical baseline env; only STWO_RV64_M8_CAPTURE_RECORDER differs). Drivers = the gate build (code unchanged).
# The runner's quiet gate refuses a service while other streams compile (nvcc/cicc/ptxas/zig) or the pod is loaded, so each
# attempt first waits for no compilers, then runs into a fresh out dir; up to ATTEMPTS attempts.
# Usage (pod, tmux): C=<commit> [ATTEMPTS=12] bash pipe2.sh
S=m8-opt-T10-narrow-capture-recorder; R=/workspace/m3/runs/$S; SRC=/workspace/m3/src/$S; B=/workspace/m3/build/$S
C=${C:?commit}; ST=$R/pipe2.status; RT=$SRC/design/riscv-proving-stack/m7-handoff/p0-runtime.json; ATTEMPTS=${ATTEMPTS:-12}
log() { echo "$(date -u +%FT%TZ) $*" >> $ST; }
log start commit=$C
cd $SRC
get() { python3 -c "import json,sys;print(json.load(open('$RT'))['assets'][sys.argv[1]])" $1; }
python3 scripts/rv64_m7_integration_stack.py prepare --source-root $SRC --source-commit $C \
  --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
  --library $(get library) --sparse $(get sparse) --observer $(get observer) --process-budget-guard $(get process_budget_guard) \
  --native-hooks-commit c72b51646 --device-hooks-commit c72b51646 \
  --preset $SRC/vectors/reports/rv64-m8-20261106/opt-T10-narrow-capture-recorder/ab-preset.json --block 24628607 \
  --out $R/ab2-manifest.json > $R/ab2-prepare.log 2>&1; log prepare rc=$?
# Host load is informational for the runner (quiet_resource=cgroup); only wait out compilers it lists as blocking.
quiet() { ! pgrep -x 'nvcc|cicc|ptxas|zig|nsys' > /dev/null; }
for k in $(seq 1 $ATTEMPTS); do
  n=0; until quiet; do sleep 20; n=$((n+1)); done
  log attempt-$k quiet-after=$((n*20))s
  OUT=$R/ab2-24628607-a$k
  python3 scripts/rv64_m7_integration_stack.py run --manifest $R/ab2-manifest.json --out $OUT > $OUT.log 2>&1
  rc=$?; log ab2-24628607-a$k rc=$rc
  [ $rc -eq 0 ] && break
  grep -q "integration service failed" $OUT.log || break
done
log DONE
