#!/bin/bash
# rootverify: derive tables then root-only verify both dev blocks (CPU only).
set -u
R=${R:-/workspace/m3/build/m5-rootverify/zig-out/bin/rv64-word16-ethereum-recursion-receiver}
S=/workspace/m3/scratch/m5-rootverify; mkdir -p $S/tables $S/out
SRC=/workspace/m3/src/m5-rootverify
COMMIT=$(cat $SRC/.m3-commit)
P=conjectured128_b2_q108_p20_fold4
FIX=12884901888; HOST=34359738368
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false
unset STWO_ZIG_RV64_SETUP_CACHE
cd $SRC
proof() { ls -d /workspace/m3/runs/m5-rootverify/$1-2gpu-m4base/case/batch/trial-0/$1/proof; }
req() { python3 - "$1" <<'PY'
import json,sys
b=sys.argv[1]
r=json.load(open(f"/workspace/m3/runs/m5-rootverify/{b}-2gpu-m4base/request.json"))
r["workers"]=16; r["output_directory"]=f"/workspace/m3/scratch/m5-rootverify/capture-{b}"
json.dump(r,open(f"/workspace/m3/scratch/m5-rootverify/{b}-request.json","w"),indent=1)
PY
}
step() { name=$1; shift; echo "== $name load=$(cut -d' ' -f1 /proc/loadavg) $(date +%T)"; t0=$(date +%s.%N); "$@" > $S/out/$name.json 2> $S/out/$name.stderr; rc=$?; t1=$(date +%s.%N); echo "exit=$rc wall=$(python3 -c "print(round($t1-$t0,3))") load_end=$(cut -d' ' -f1 /proc/loadavg)"; [ $rc = 0 ] || tail -3 $S/out/$name.stderr; }
req 26235156; req 24628607
MODE=${1:-all}
if [ "$MODE" = all ] || [ "$MODE" = derive ]; then
step derive-26235156 $R --security-profile $P derive-vk-tables $S/26235156-request.json $(proof 26235156) $S/tables/vk-26235156.json $FIX $HOST --source-commit $COMMIT
step derive-24628607 $R --security-profile $P derive-vk-tables $S/24628607-request.json $(proof 24628607) $S/tables/vk-24628607.json $FIX $HOST --source-commit $COMMIT
step derive-both $R --security-profile $P derive-vk-tables $S/24628607-request.json $(proof 24628607) $S/tables/vk-both.json $FIX $HOST --merge $S/tables/vk-26235156.json
fi
if [ "$MODE" = all ] || [ "$MODE" = verify ]; then
for rep in 1 2; do for b in 26235156 24628607; do
step verify-$b-r$rep $R --security-profile $P verify-root-candidate $S/$b-request.json $(proof $b) $S/tables/vk-both.json $FIX $HOST
done; done
for b in 26235156 24628607; do
step audit-$b $R --security-profile $P verify-root-candidate $S/$b-request.json $(proof $b) $S/tables/vk-both.json $FIX $HOST --audit
done
fi
echo DONE
