#!/bin/bash
# DW07/P-arity: fresh cache-disabled receivers under a mismatched outer profile / fold arity must reject; CTRL must accept.
R=/workspace/m3/build/m6-diet-wire/zig-out/bin/rv64-word16-ethereum-recursion-receiver; RUNS=/workspace/m3/runs/m6-diet-wire
S=/workspace/m3/scratch/m6-diet-wire; mkdir -p $S
cd /workspace/m3/src/m6-diet-wire
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE STWO_RV64_FOLD_CLASS_CACHE
case_() { name=$1 run=$2 prof=$3 extra=$4
  src=$(ls -d $RUNS/$run/receiver-*/receiver-request.json | head -1); req=$S/cross-$name.json; rm -rf $S/cross-cap-$name
  python3 $RUNS/req.py $src $req $S/cross-cap-$name
  proof=$(ls -d $RUNS/$run/case/batch/trial-0/*/proof)
  out=$(env STWO_RV64_OUTER_PROFILE=$prof $extra $R --security-profile conjectured128_b2_q108_p20_fold4 verify-recursion-candidate $req $proof 12884901888 34359738368 2>&1); rc=$?
  echo "$name run=$run profile=$prof $extra exit=$rc :: $(echo "$out" | grep -m1 -oE 'error: [A-Za-z0-9_]+|"accepted": ?(true|false)')"; rm -rf $S/cross-cap-$name; }
case_ CTRL 26235156-2gpu-k4c-p1 m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 ""
case_ DW07a 26235156-2gpu-k4c-p1 r1_b2_q108_p20_fold4 ""
case_ DW07b 26235156-2gpu-k4c-p1 m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1 ""
case_ DW07c 26235156-2gpu-k3-p1 m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 ""
case_ DW07d 26235156-2gpu-k3-ab1 m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1 ""
case_ DW07e 26235156-2gpu-k3-p1 r1_b2_q108_p20_fold4 STWO_RV64_FOLD_ARITY=3
case_ DWA1 26235156-2gpu-k4c-p1 m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 STWO_RV64_FOLD_ARITY=2
echo CROSS_DONE
