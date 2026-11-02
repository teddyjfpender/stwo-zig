#!/bin/bash
# usage: run.sh BIN OUT PREFIX_COUNT [GB] [extra env]
B=$1; OUT=$2; N=$3; GB=${4:-24}
J=~/Coding/ge-cache/gkrperf/native/jobs
cd ~/Coding/ge-cache/keccakdeep/runs
rm -rf $OUT
env STWO_ZIG_PROFILE_OM_DOMAIN=1 $EXTRA_ENV ~/Coding/ge-ops/bin/memguard run --gb $GB --label keccakdeep-$OUT -- /usr/bin/time -l $B --security-profile ${PROFILE:-conjectured128_b2_q108_p20_fold4} produce-candidate request.json $J $OUT $N resources.json > $OUT.log 2>&1
echo "rc=$?" >> $OUT.log
(cd $OUT && shasum -a 256 bundle.json cells.bin *.bin 2>/dev/null) > $OUT.sha256
