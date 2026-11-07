#!/bin/bash
# gpu_idle_run.sh SCRIPT LOG [WAIT_S]: wait (outside the lock) until no compute app is on any GPU and no
# request-level harness / A-B / quiet-window process of another stream is alive, then take gpu.lock,
# re-check, and run SCRIPT (<= 270 s).
script="$1"; log="$2"; wait_s="${3:-1800}"; t0=$(date +%s)
busy() {
  [ "$(nvidia-smi --query-compute-apps=pid --format=csv,noheader | wc -l)" != "0" ] && return 0
  pgrep -f "^python3 [^ ]*(quiet_window|rv64_m7_integration_stack)" >/dev/null && return 0
  return 1
}
while busy; do
  [ $(( $(date +%s) - t0 )) -gt "$wait_s" ] && { echo "SKIP: GPU/harness busy for ${wait_s}s"; exit 75; }
  sleep 20
done
exec flock -w 3600 /workspace/m3/locks/gpu.lock bash -c '
  apps=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader | wc -l)
  if [ "$apps" != "0" ]; then echo "SKIP: foreign compute app on GPU"; exit 75; fi
  echo "START $(date -u +%FT%TZ)"; timeout 270 "$0" > "$1" 2>&1; echo EXIT=$? "END $(date -u +%FT%TZ)"
' "$script" "$log"
