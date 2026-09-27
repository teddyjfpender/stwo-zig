#!/usr/bin/env python3
import hashlib,json,re,statistics
from pathlib import Path
p=Path(__file__).resolve().parent
runs=[]
for name in ['parallel-1','serial-1','serial-2','parallel-2']:
 text=(p/(name+'.log')).read_text()
 assert 'BLAKE3_EXTENSION_PARENT verified=true leaf_queries=70 parent_queries=70 pow_bits=26' in text
 assert ('steps succeeded' in text or 'All 9 tests passed' in text)
 line=re.search(r'BLAKE3_EXTENSION_PARENT_TIMING ([^\n]+)',text)[1]
 fields=dict(x.split('=') for x in line.split())
 assert fields['workers']=='16' and fields['optimize']=='ReleaseFast'
 ns={k:int(v) for k,v in fields.items() if k.endswith('_ns')}
 assert sum(v for k,v in ns.items() if k!='total_ns')==ns['total_ns']
 stages=json.loads(re.search(r'BLAKE3_PARENT_STAGE_PROFILE ([^\n]+)',text)[1])
 runs.append({'name':name,'total_seconds':ns['total_ns']/1e9,'proving_seconds':ns['proving_ns']/1e9,'lookup_setup_seconds':next(x['seconds'] for x in stages['stages'] if x['id']=='parent.main_setup'),'proof_blake3':re.search(r'BLAKE3_PARENT_ARTIFACT_HASH (\w+)',text)[1]})
assert len({r['proof_blake3'] for r in runs})==1
medians={arm:{k:statistics.median(r[k] for r in runs if r['name'].startswith(arm)) for k in ['total_seconds','proving_seconds','lookup_setup_seconds']} for arm in ['serial','parallel']}
summary={'runs':runs,'medians':medians,'total_speedup':medians['serial']['total_seconds']/medians['parallel']['total_seconds'],'total_reduction_percent':100*(1-medians['parallel']['total_seconds']/medians['serial']['total_seconds']),'lookup_speedup':medians['serial']['lookup_setup_seconds']/medians['parallel']['lookup_setup_seconds'],'same_proof_bytes':True,'security_parameters_changed':False,'samples_per_arm':2,'warmups':0}
(p/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
