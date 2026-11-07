#!/bin/bash
# m-runtime pipeline 1 (pod, tmux; never inside gpu.lock - the harness takes it per service):
# gates on the new default runtime -> T1+T10 3+3 on 24628607 -> T1+T10 3+3 on 26235159 (--allow-block) -> T2 isolation 3+3.
set -u
S=m8-m-runtime; R=/workspace/m3/runs/$S; SRC=/workspace/m3/src/$S; B=/workspace/m3/build/$S
C=${C:?commit}; ST=$R/${PIPE:-pipe1}.status; P=$SRC/vectors/reports/rv64-m8-20261106
STEPS=${STEPS:-"gate-def-26235156 gate-def-24628607 gate-on-24628607 ab-24628607 ab-26235159 t2-24628607"}
log() { echo "$(date -u +%FT%TZ) $*" >> $ST; }
ON="--env STWO_RV64_M8_CAPTURE_LOCAL_LEDGER=1 --env STWO_RV64_M8_CAPTURE_INFLIGHT=16 --env STWO_RV64_M8_CAPTURE_RECORDER=1"
cd $SRC
log start commit=$C steps="$STEPS"
gate() { name=$1; shift; [ -e $R/$name/gate.json ] && grep -q '"PASS"' $R/$name/gate.json && { log $name already-pass; return 0; }
  bash scripts/rv64_gate.sh --stream $S --out $R/$name --source-commit $C "$@" > $R/$name.log 2>&1; rc=$?; log $name rc=$rc; return $rc; }
ab() { name=$1; preset=$2; block=$3; shift 3
  python3 scripts/rv64_m7_integration_stack.py prepare --source-root $SRC --source-commit $C \
    --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
    --native-hooks-commit c72b51646 --device-hooks-commit c72b51646 --preset $preset --block $block $PREP \
    --out $R/$name-manifest.json > $R/$name-prepare.log 2>&1; log $name prepare rc=$?
  for a in $(seq ${FIRST_ATTEMPT:-1} ${LAST_ATTEMPT:-3}); do
    if [ -n "${QUIET_WAIT:-}" ]; then
      # Quiet window: hold all three build locks (every pod build/test runs under one of them) for the
      # timed services only, so running builds drain and new ones queue; then wait for no compiler/
      # receiver/GPU process. The GPU itself is still taken per service by the harness (never wrapped).
      flock -w 14400 /workspace/m3/locks/build.1.lock flock -w 14400 /workspace/m3/locks/build.2.lock \
        flock -w 14400 /workspace/m3/locks/build.3.lock bash -c "echo \$(date -u +%FT%TZ) $name-$a build-locks held >> $ST; \
        python3 $P/m-runtime/quiet_window.py --timeout 1800 >> $ST 2>&1 || exit 75; \
        exec python3 scripts/rv64_m7_integration_stack.py run --manifest $R/$name-manifest.json --out $R/$name-$a $* --timing-only" \
        > $R/$name-$a.log 2>&1; rc=$?
      [ $rc -eq 0 ] && { python3 scripts/rv64_m7_integration_stack.py run --manifest $R/$name-manifest.json --out $R/$name-$a $* --receivers-only >> $R/$name-$a.log 2>&1; rc=$?; }
    else
    python3 scripts/rv64_m7_integration_stack.py run --manifest $R/$name-manifest.json --out $R/$name-$a "$@" > $R/$name-$a.log 2>&1; rc=$?
    fi
    log $name-$a rc=$rc; [ $rc -eq 0 ] && return 0
    [ $rc -eq 75 ] || grep -q "quiet admission timed out" $R/$name-$a/*.log 2>/dev/null || return $rc
  done; return 1; }
for step in $STEPS; do case $step in
  gate-def-26235156) gate $step --block 26235156 || { log STOP; exit 1; } ;;
  gate-def-24628607) gate $step --block 24628607 || { log STOP; exit 1; } ;;
  gate-on-24628607) gate $step --block 24628607 $ON || { log STOP; exit 1; } ;;
  ab-24628607) PREP="" ab $step $P/m-runtime/ab-preset-t1t10.json 24628607 ;;
  ab-26235159) PREP="--allow-block 26235159" ab $step $P/m-runtime/ab-preset-t1t10-26235159.json 26235159 --fresh-receivers reference ;;
  t2-24628607) PREP="" ab $step $P/opt-combined/ab-preset-t2-off.json 24628607 ;;
esac; done
log DONE
