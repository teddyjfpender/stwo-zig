#!/bin/bash
# ab.sh BIN TAG REPS "blocks" INFLIGHT [K=V...]: parity (digest) once per block/arm, then interleaved off/on timing reps
cd /workspace/m3/runs/m8-opt-T10-narrow-capture-recorder
B=$1; T=$2; R=$3; BLK=$4; I=$5; shift 5
for b in $BLK; do for arm in 0 1; do
python3 t10cap.py $B $b $I 8 $T-par-a$arm STWO_RV64_M8_CAPTURE_RECORDER=$arm STWO_RV64_M8_CAPTURE_RECORDER_DIGEST=1 "$@" >> $T.par.log 2>&1
done; done
echo PARDONE >> $T.par.log
for r in $(seq 1 $R); do for b in $BLK; do for arm in 0 1; do
python3 t10cap.py $B $b $I 8 $T-a$arm-r$r STWO_RV64_M8_CAPTURE_RECORDER=$arm STWO_RV64_T10_PROFILE=1 "$@" >> $T.log 2>&1
done; done; done; echo DONE >> $T.log
