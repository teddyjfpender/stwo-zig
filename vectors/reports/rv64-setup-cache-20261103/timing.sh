#!/bin/bash
# AC timing batch (after the gates). Quiet host, one job at a time.
B=~/Coding/ge-cache/setupcache/new5/bin/rv64-word16-ethereum-gkr
MAIN=~/Coding/ge-cache/fullblock/bin/bin/rv64-word16-ethereum-gkr
T=~/Coding/ge-cache/setupcache/timing; rm -rf $T; mkdir -p $T
cd ~/Coding/ge-cache/setupcache/runs
S=$T/timing.txt; echo "START $(date)" > $S; pmset -g batt | head -1 >> $S
v() { # label bin env...
  l=$1; b=$2; shift 2
  env "$@" ~/Coding/ge-ops/bin/memguard run --gb 8 --label setupcache-tv-$l -- $b verify-candidate request.json fbw 12884901888 > $T/v-$l.json 2> $T/v-$l.err
  echo "verify $l rc=$? $(python3 -c "import json;v=json.load(open('$T/v-$l.json'));print('accepted',v['accepted'],'load_and_setup_s=%.3f verify_s=%.3f'%(v['load_and_setup_ns']/1e9,v['verify_ns']/1e9))")" >> $S
}
v main1 $MAIN X=1; v main2 $MAIN X=1
v new-nodir $B X=1
v new-nodir-noidonly $B STWO_ZIG_RV64_SETUP_IDENTITY_ONLY_CPU=0
rm -rf $T/vc; v new-cold $B STWO_ZIG_RV64_SETUP_CACHE=$T/vc
v new-warm1 $B STWO_ZIG_RV64_SETUP_CACHE=$T/vc; v new-warm2 $B STWO_ZIG_RV64_SETUP_CACHE=$T/vc
# producer setup through block_to_inputs (inputs-candidate), cold then 3 warm
python3 -I ~/Coding/ge-wt/setupcache/scripts/rv64_block_to_inputs.py --bin $B --blocks ~/Coding/ge-wt/setupcache/vectors/reports/rv64-setup-cache-20261103/blocks.json --resources resources.json --out $T/b2i --setup-cache $T/pc --repeat 4 >> $S 2>&1
python3 -I ~/Coding/ge-wt/setupcache/scripts/rv64_block_to_inputs.py --bin $B --blocks ~/Coding/ge-wt/setupcache/vectors/reports/rv64-setup-cache-20261103/blocks.json --resources resources.json --out $T/b2i-nodir >> $S 2>&1
STWO_ZIG_RV64_SETUP_IDENTITY_ONLY_CPU=0 python3 -I ~/Coding/ge-wt/setupcache/scripts/rv64_block_to_inputs.py --bin $B --blocks ~/Coding/ge-wt/setupcache/vectors/reports/rv64-setup-cache-20261103/blocks.json --resources resources.json --out $T/b2i-noidonly >> $S 2>&1
echo "DONE $(date)" >> $S; pmset -g batt | head -1 >> $S
