#!/bin/bash
# sched M6 config comparison (pod). Each daemon run takes the GPU lock itself.
set -u
cd /workspace/m3/src/m6-sched
TAG=$1; shift
D="python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream m6-sched --build-stream m6-sched --repeat 1"
STORE=${STORE:-fresh}; N=0
for cfg in "$@"; do
  X=()
  case $cfg in
    m5)       E=(--env STWO_RV64_RECURSION_SCHED=m5 --env STWO_RV64_RECURSION_STREAM=0) ;;
    crit)     E=(--env STWO_RV64_RECURSION_SCHED=critical --env STWO_RV64_RECURSION_STREAM=0) ;;
    stream)   E=(--env STWO_RV64_RECURSION_SCHED=critical --env STWO_RV64_RECURSION_STREAM=1) ;;
    stream8)  E=(--env STWO_RV64_RECURSION_SCHED=critical --env STWO_RV64_RECURSION_STREAM=1 --env STWO_RV64_RECURSION_STREAM_PREP=8) ;;
    default)  E=() ;;
    m5s)      E=(--env STWO_RV64_RECURSION_STREAM=0) ;;
    pa3)      E=(--env STWO_RV64_RECURSION_PREP_AHEAD=3) ;;
    sp8)      E=(--env STWO_RV64_RECURSION_STREAM_PREP=8) ;;
    lazy)     E=(); X=(--loading lazy) ;;
    s1)       E=(--env STWO_RV64_RECURSION_STREAM=1) ;;
    c2)       E=(--env STWO_RV64_RECURSION_STREAM=1 --env STWO_RV64_RECURSION_LANES_PER_DEVICE=2 --env STWO_RV64_RECURSION_PREP_AHEAD=8) ;;
    c2l2)     E=(--env STWO_RV64_RECURSION_STREAM=1 --env STWO_RV64_RECURSION_LANES_PER_DEVICE=2 --env STWO_RV64_RECURSION_LEAVES_PER_DEVICE=2 --env STWO_RV64_RECURSION_PREP_AHEAD=8) ;;
  esac
  echo "CFG $cfg start $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
  $D --tag $TAG-$cfg-$((N++)) --store $STORE --warm "${E[@]}" "${X[@]}" --receive none
  echo "CFG $cfg exit $? $(date -u +%T)"
  STORE=reuse
done
echo ALL_DONE
