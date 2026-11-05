#!/bin/bash
# rsssample.sh TAGSUBSTR OUT : sample the m6-sched service's RSS components every 0.2 s until it exits
OUT=$2
for i in $(seq 1 3000); do
  PID=$(pgrep -f "combined-serve /workspace/m3/runs/m6-sched/.*$1" | head -1)
  [ -n "$PID" ] && break; sleep 0.2
done
echo "pid $PID" > $OUT
while kill -0 $PID 2>/dev/null; do
  echo "$(date +%s.%N) $(grep -E 'VmRSS|RssAnon|RssFile|RssShmem' /proc/$PID/status 2>/dev/null | awk '{printf "%s %s ", $1, $2}')" >> $OUT
  sleep 0.2
done
