#!/bin/bash
# usage: run.sh BIN OUT PREFIX_COUNT [ENV=VAL ...]
# Same driver as ../rv64-gkr-memory-20261102/run.sh, run in $RUNS (default
# ~/Coding/ge-cache/setupcache/runs, holding request.json/resources.json copied
# from ~/Coding/ge-cache/gkrmem/runs). Prover env: trailing ENV=VAL args.
# Fresh-receiver env: $VERIFY_ENV (e.g. STWO_ZIG_RV64_SETUP_CACHE=/dir).
B=$1; OUT=$2; N=$3; shift 3
J=~/Coding/ge-cache/gkrperf/native/jobs
cd ${RUNS:-~/Coding/ge-cache/setupcache/runs}
rm -rf $OUT
env STWO_ZIG_PROFILE_OM_DOMAIN=1 STWO_ZIG_GKR_TREE_METRICS=1 "$@" ~/Coding/ge-ops/bin/memguard run --gb ${GB:-22} --label setupcache-$OUT -- /usr/bin/time -l $B produce-candidate request.json $J $OUT $N resources.json > $OUT.log 2>&1
echo "rc=$?" >> $OUT.log
(cd $OUT && shasum -a 256 bundle.json *.bin | sort -k2) > $OUT.sha256 2>/dev/null
if [ "$N" = 0 ]; then VM=verify-candidate; else VM=verify-prefix-candidate; fi
env $VERIFY_ENV ~/Coding/ge-ops/bin/memguard run --gb 8 --label setupcache-$OUT-verify -- /usr/bin/time -l $B $VM request.json $OUT 12884901888 > $OUT.fresh.json 2> $OUT.fresh.time
echo "vrc=$?" >> $OUT.log
python3 - $OUT <<'PY'
import json,sys,re
o=sys.argv[1]; r=json.load(open(f'{o}/report.json'))
log=open(f'{o}.log').read()
rss=re.search(r'(\d+)\s+maximum resident',log); fp=re.search(r'(\d+)\s+peak memory footprint',log)
b=r.get('block_to_inputs',{})
print(o,'setup_s=%.3f'%(r['setup_ns']/1e9),'prove_s=%.2f'%(r['prove_ns']/1e9),'maxrss=%.3fGB'%(int(rss.group(1))/1e9),'footprint=%.3fGB'%(int(fp.group(1))/1e9),'t_first_s=%.3f'%(b.get('t_first_ns',0)/1e9),'t_all_s=%.3f'%(b.get('t_all_ns',0)/1e9))
try:
  v=json.load(open(f'{o}.fresh.json')); print(' fresh accepted=%s load_and_setup_s=%.3f verify_s=%.3f'%(v['accepted'],v['load_and_setup_ns']/1e9,v['verify_ns']/1e9), v.get('setup_cache'))
except Exception as e: print(' fresh: unreadable', e)
PY
echo done > $OUT.done
