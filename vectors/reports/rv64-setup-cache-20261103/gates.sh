#!/bin/bash
# Final gates for codex/rv64-setup-cache (binary: $B).
B=${B:-~/Coding/ge-cache/setupcache/new5/bin/rv64-word16-ethereum-gkr}
R=~/Coding/ge-wt/setupcache/vectors/reports/rv64-setup-cache-20261103/run.sh
cd ~/Coding/ge-cache/setupcache/runs
S=gates.txt; echo "START $(date) bin=$(shasum -a 256 $B | cut -c1-16)" > $S
pmset -g batt | head -1 >> $S
rm -rf gP gV gFP gFV p4c p4w fbc fbw
export GB=${GB:-18}
VERIFY_ENV=STWO_ZIG_RV64_SETUP_CACHE=$PWD/gV $R $B p4c 4 STWO_ZIG_RV64_SETUP_CACHE=$PWD/gP >> $S 2>&1
VERIFY_ENV=STWO_ZIG_RV64_SETUP_CACHE=$PWD/gP $R $B p4w 4 STWO_ZIG_RV64_SETUP_CACHE=$PWD/gP >> $S 2>&1
VERIFY_ENV=STWO_ZIG_RV64_SETUP_CACHE=$PWD/gFV $R $B fbc 0 STWO_ZIG_RV64_SETUP_CACHE=$PWD/gFP >> $S 2>&1
VERIFY_ENV=STWO_ZIG_RV64_SETUP_CACHE=$PWD/gFP $R $B fbw 0 STWO_ZIG_RV64_SETUP_CACHE=$PWD/gFP >> $S 2>&1
for o in p4c p4w; do diff <(sort -k2 $o.sha256) <(sort -k2 ~/Coding/ge-wt/setupcache/vectors/reports/rv64-gkr-memory-20261102/proof-files.sha256) >/dev/null && echo "$o bytes IDENTICAL to main" || echo "$o bytes DIFFER"; done >> $S
for o in fbc fbw; do diff <(sort -k2 $o.sha256) <(sort -k2 ~/Coding/ge-cache/gkrmem/runs/fbmain.sha256) >/dev/null && echo "$o bytes IDENTICAL to main" || echo "$o bytes DIFFER"; done >> $S
grep -H -E "^rc=|^vrc=" p4c.log p4w.log fbc.log fbw.log >> $S
# warm verifier-written cache on the warm bundles
for pair in "p4w verify-prefix-candidate gV" "fbw verify-candidate gFV"; do set -- $pair
  STWO_ZIG_RV64_SETUP_CACHE=$PWD/$3 ~/Coding/ge-ops/bin/memguard run --gb 8 --label setupcache-g-$1-vw -- $B $2 request.json $1 12884901888 > $1.fresh-vwarm.json 2>$1.fresh-vwarm.err; echo "$1 fresh receiver warm ($3) rc=$? $(python3 -c "import json;v=json.load(open('$1.fresh-vwarm.json'));print('accepted',v['accepted'],'load_and_setup_s=%.3f'%(v['load_and_setup_ns']/1e9),'disk_hits',v['setup_cache']['disk_hits'])" 2>&1)" >> $S; done
# tamper: verifier VK byte, prover bulk byte (copies)
rm -rf tV tP; cp -R gFV tV; cp -R gFP tP
f=$(ls tV/*.rv64-setup | head -1); python3 -c "
import sys;p=sys.argv[1];b=bytearray(open(p,'rb').read());b[256+40]^=1;open(p,'wb').write(b)" $f
STWO_ZIG_RV64_SETUP_CACHE=$PWD/tV ~/Coding/ge-ops/bin/memguard run --gb 8 --label setupcache-g-tamperV -- $B verify-candidate request.json fbw 12884901888 > tamperV.json 2> tamperV.err; echo "tampered VK byte, fresh receiver rc=$? $(tail -1 tamperV.err)" >> $S
f=$(ls -S tP/*.rv64-setup | head -1); python3 -c "
import sys;p=sys.argv[1];b=bytearray(open(p,'rb').read());b[len(b)//2]^=1;open(p,'wb').write(b)" $f
STWO_ZIG_RV64_SETUP_CACHE=$PWD/tP ~/Coding/ge-ops/bin/memguard run --gb 10 --label setupcache-g-tamperP -- $B inputs-candidate request.json ~/Coding/ge-cache/gkrperf/native/jobs 0 resources.json > tamperP.json 2> tamperP.err; echo "tampered bulk byte, prover rc=$? $(tail -1 tamperP.err)" >> $S
echo "DONE $(date)" >> $S
