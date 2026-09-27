import json, os, subprocess
from pathlib import Path
p=Path(__file__).resolve().parent
records=json.loads((p/'metal-results.json').read_text())
for r in records:
 if 'ecdsa' not in r['case']:continue
 prefix=p/('metal-ecdsa-quotient-'+r['arm'])
 c=r['command'][:]
 for k,v in [('--samples','1'),('--report-out',str(prefix.with_suffix('.json'))),('--proof-out',str(prefix.with_suffix('.b3proof')))]:c[c.index(k)+1]=v
 e=os.environ.copy();e.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_EXECUTION_PROFILE='1',STWO_ZIG_METAL_QUOTIENT_PROFILE='1')
 for k in ['STWO_ZIG_DETACH_STREAMING_LDE','STWO_ZIG_DETACH_STREAMING_COEFFICIENTS','STWO_RISCV_SMALL_COMMIT_BATCH']:e.pop(k,None)
 if r['arm']=='control':e['STWO_ZIG_DETACH_STREAMING_LDE']='1'
 with prefix.with_suffix('.log').open('w') as f:subprocess.run(c,env=e,stdout=f,stderr=subprocess.STDOUT,check=True)
 report=json.loads(prefix.with_suffix('.json').read_text());assert report['proof_sha256']==r['proof_sha256']
 assert report['verified_in_process']
