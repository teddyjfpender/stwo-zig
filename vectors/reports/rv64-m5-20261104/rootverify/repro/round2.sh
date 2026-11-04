#!/bin/bash
set -u
S=/workspace/m3/scratch/m5-rootverify; RUNS=/workspace/m3/runs/m5-rootverify; SRC=/workspace/m3/src/m5-rootverify
R=/workspace/m3/build/m5-rootverify/zig-out/bin/rv64-word16-ethereum-recursion-receiver
mkdir -p $S/old && mv $S/tables/*.json $S/old/ 2>/dev/null; mkdir -p $RUNS/round1 && mv $RUNS/corpus-2*.json $RUNS/corpus-2*.log $RUNS/go-*.log $RUNS/receipts $RUNS/round1/ 2>/dev/null
cd $SRC
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false
P=$(ls -d $RUNS/24628607-2gpu-m4base/case/batch/trial-0/24628607/proof)
echo "== stale-table check"; $R --security-profile conjectured128_b2_q108_p20_fold4 verify-root-candidate $S/24628607-request.json $P $S/old/vk-both.json 12884901888 34359738368 > $S/out/stale.json 2> $S/out/stale.stderr; echo "exit=$? $(grep -m1 error: $S/out/stale.stderr)"
$S/rv_go.sh all > $RUNS/go-all.log 2>&1
for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
python3 scripts/rv64_m5_rootverify_corpus.py run --run $RUNS/$b-2gpu-m4base --donor $RUNS/$o-2gpu-m4base --table $S/tables/vk-both.json --donor-table $S/tables/vk-$o.json --receiver $R --out $RUNS/corpus-$b.json --jobs 4 > $RUNS/corpus-$b.log 2>&1
python3 $S/pc/rv64_m5_negative_corpus.py run --format m5-root --run $RUNS/$b-2gpu-m4base --donor $RUNS/$o-2gpu-m4base --receiver $R --out $RUNS/profiles-v3-m5root-$b.json --jobs 4 --work $S/pcwork --receiver-argv "[\"{receiver}\", \"--security-profile\", \"{profile}\", \"verify-root-candidate\", \"{request}\", \"{proof}\", \"$S/tables/vk-both.json\", \"{fixed}\", \"{host}\"]" > $RUNS/profiles-v3-m5root-$b.log 2>&1
done
echo ALLDONE
