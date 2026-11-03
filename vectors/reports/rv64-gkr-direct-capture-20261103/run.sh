#!/bin/bash
# usage: run.sh BIN OUT PREFIX_COUNT JOBS RESOURCES   (JOBS "-" = in-process direct capture)
B=$1; OUT=$2; N=$3; J=$4; RES=$5
cd ~/Coding/ge-cache/directgkr/runs
rm -rf $OUT
env STWO_ZIG_PROFILE_OM_DOMAIN=1 STWO_ZIG_GKR_TREE_METRICS=1 ~/Coding/ge-ops/bin/memguard run --gb ${GB:-22} --label directgkr-$OUT -- /usr/bin/time -l $B produce-candidate request.json $J $OUT $N $RES > $OUT.log 2>&1
echo "rc=$?" >> $OUT.log
(cd $OUT && shasum -a 256 bundle.json *.bin | sort -k2) > $OUT.sha256 2>/dev/null
if [ "$N" = 0 ]; then VM=verify-candidate; else VM=verify-prefix-candidate; fi
~/Coding/ge-ops/bin/memguard run --gb 8 --label directgkr-$OUT-verify -- /usr/bin/time -l $B $VM request.json $OUT 12884901888 > $OUT.fresh.json 2> $OUT.fresh.time
echo "vrc=$?" >> $OUT.log
echo done > $OUT.done
