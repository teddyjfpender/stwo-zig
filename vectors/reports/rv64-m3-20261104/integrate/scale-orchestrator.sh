#!/bin/bash
# Ordered scale-up: one block at a time, increasing instruction count, each proven once.
# Producer runs serially under the GPU lock; each block's fresh receiver runs in the
# background (CPU only, nice 10, 8 workers) while the next block is produced.
# Stops at the first producer failure or the first receiver rejection.
cd /workspace/m3/src/integrate
R=/workspace/m3/runs/integrate
TAG=${TAG:-scale}
ENVS=${ENVS:-}
for b in "$@"; do
  for f in $R/recv-*.done; do [ -e "$f" ] || continue; if ! grep -q '"accepted"' "$f" ; then :; fi; done
  if ls $R/recv-*.rejected >/dev/null 2>&1; then echo "STOP: receiver rejection $(ls $R/recv-*.rejected)"; exit 2; fi
  echo "PROVE $b start $(date -u +%T)"
  python3 scripts/rv64_m3_pod.py prove $b --gpus 2 --stream integrate --tag $TAG --allow-scale-up $ENVS > $R/prove-$b-$TAG.log 2>&1
  rc=$?
  echo "PROVE $b rc=$rc end $(date -u +%T)"
  if [ $rc -ne 0 ]; then echo "STOP: producer failure on $b"; tail -20 $R/prove-$b-$TAG.log; exit 1; fi
  run=$R/$b-2gpu-$TAG
  ( python3 scripts/rv64_m3_pod.py receive $b --run $run --workers 8 --host-bytes $((96<<30)) > $R/recv-$b-$TAG.log 2>&1;
    if python3 -c "import json,sys; r=json.load(open('$run/receipt.json')); sys.exit(0 if r.get('accepted') else 1)"; then touch $R/recv-$b.accepted; else touch $R/recv-$b.rejected; fi ) &
done
echo "WAIT receivers $(date -u +%T)"; wait
ls $R/recv-*.rejected 2>/dev/null && { echo "STOP: rejection"; exit 2; }
echo "SCALE DONE $(date -u +%T)"
