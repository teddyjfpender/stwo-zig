#!/bin/bash
# usage: run.sh BIN OUT PREFIX_COUNT [ENV=VAL ...]
B=$1; OUT=$2; N=$3; shift 3
J=~/Coding/ge-cache/gkrperf/native/jobs
cd ~/Coding/ge-cache/gkrmem/runs
rm -rf $OUT
env STWO_ZIG_PROFILE_OM_DOMAIN=1 STWO_ZIG_GKR_TREE_METRICS=1 "$@" ~/Coding/ge-ops/bin/memguard run --gb ${GB:-22} --label gkrmem-$OUT -- /usr/bin/time -l $B produce-candidate request.json $J $OUT $N resources.json > $OUT.log 2>&1
echo "rc=$?" >> $OUT.log
(cd $OUT && shasum -a 256 bundle.json *.bin | sort -k2) > $OUT.sha256 2>/dev/null
if [ "$N" = 0 ]; then VM=verify-candidate; else VM=verify-prefix-candidate; fi
~/Coding/ge-ops/bin/memguard run --gb 8 --label gkrmem-$OUT-verify -- /usr/bin/time -l $B $VM request.json $OUT 12884901888 > $OUT.fresh.json 2> $OUT.fresh.time
echo "vrc=$?" >> $OUT.log
python3 - $OUT <<'PY'
import json,sys,re
o=sys.argv[1]; r=json.load(open(f'{o}/report.json'))
log=open(f'{o}.log').read()
rss=re.search(r'(\d+)\s+maximum resident',log); fp=re.search(r'(\d+)\s+peak memory footprint',log)
print(o,'prove_s=%.2f'%(r['prove_ns']/1e9),'maxrss=%.3fGB'%(int(rss.group(1))/1e9),'footprint=%.3fGB'%(int(fp.group(1))/1e9))
for i,w in enumerate(r['workers']):
  if 'numerical_requested_peak_bytes' in w: print(' w%d num=%.3f incl=%.3f admit=%.3f gkr_s=%.2f numer_s=%.2f'%(i,w['numerical_requested_peak_bytes']/1e9,w.get('gkr_peak_including_final_binding_bytes',0)/1e9,w['admitted_gkr_peak_bytes']/1e9,w['gkr_ns']/1e9,w['numerical_ns']/1e9), w.get('resolved_tree_policy'))
PY
echo done > $OUT.done
