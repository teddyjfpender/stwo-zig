import json,os,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent
root=p.parents[2]
records=json.loads((root/'autoresearch/notes/2026-09-23-streaming-lde-arenas/metal-results.json').read_text())
for r in records:
 if r['arm']!='candidate' or not any(x in r['case'] for x in ['ecdsa','sha256-2048']):continue
 prefix=p/(r['case']+'-parity')
 c=r['command'][:];c[0]=str(p/'candidate-products/bin/stwo-zig-riscv-metal')
 for k,v in [('--samples','1'),('--report-out',str(prefix.with_suffix('.json'))),('--proof-out',str(prefix.with_suffix('.b3proof')))]:c[c.index(k)+1]=v
 e=os.environ.copy();e.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_EXECUTION_PROFILE='1',STWO_ZIG_METAL_QUOTIENT_PROFILE='1',STWO_ZIG_METAL_QUOTIENT_PARITY='1')
 for k in ['STWO_ZIG_METAL_DIRECT_FLAT_QUOTIENT','STWO_ZIG_DETACH_STREAMING_LDE','STWO_ZIG_DETACH_STREAMING_COEFFICIENTS','STWO_RISCV_SMALL_COMMIT_BATCH']:e.pop(k,None)
 with prefix.with_suffix('.log').open('w') as f:subprocess.run(c,env=e,stdout=f,stderr=subprocess.STDOUT,check=True)
 report=json.loads(prefix.with_suffix('.json').read_text());assert report['proof_sha256']==r['proof_sha256'];assert report['verified_in_process']
 log=prefix.with_suffix('.log').read_text();assert 'METAL_QUOTIENT_PARITY=exact' in log
 print(r['case'],'CPU quotient parity exact; proof unchanged',flush=True)
