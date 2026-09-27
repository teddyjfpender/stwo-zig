"""Resolve the ECDSA composition-stage discrepancy against frozen prior binary."""
import hashlib,json,os,statistics,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
OUT=HERE/'ecdsa-recheck';OUT.mkdir(exist_ok=True)
original=next(x for x in json.loads((ROOT/'autoresearch/notes/2026-09-23-compact-range-provider/suite-metal/results.json').read_text()) if x['case']=='metal-ecdsa_secp256k1-32')
results=[]
for arm in ['previous','bulk','scalar','previous_again']:
 product=(HERE.parent/'2026-09-23-blake3-prefix-reuse' if arm.startswith('previous') else HERE)/'candidate-products/bin/stwo-zig-riscv-metal'
 cmd=original['command'][:];cmd[0]=str(product)
 prefix=OUT/arm
 for flag,value in [('--samples','3'),('--report-out',str(prefix.with_suffix('.json'))),('--proof-out',str(prefix.with_suffix('.b3proof')))]:cmd[cmd.index(flag)+1]=value
 env=os.environ.copy();env.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_EXECUTION_PROFILE='1')
 env.pop('STWO_ZIG_REPLAY_BOUNDED_MERKLE_TAIL',None);env.pop('STWO_ZIG_SCALAR_TAIL_UPDATES',None)
 if arm=='scalar':env['STWO_ZIG_SCALAR_TAIL_UPDATES']='1'
 with prefix.with_suffix('.log').open('w') as f:subprocess.run(cmd,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 r=json.loads(prefix.with_suffix('.json').read_text());assert r['proof_sha256']==original['proof_sha256']
 profiles=[json.loads(l.split(' ',1)[1]) for l in prefix.with_suffix('.log').read_text().splitlines() if l.startswith('BLAKE3_EXECUTION_STAGE_PROFILE ')]
 composition=statistics.median(next(x['seconds'] for x in next(s['children'] for s in p['stages'] if s['id']=='execution.core') if x['id']=='composition_evaluation') for p in profiles)
 results.append(dict(arm=arm,command=cmd,binary_sha256=hashlib.sha256(product.read_bytes()).hexdigest(),total=r['median_seconds'],composition=composition,proof_sha256=r['proof_sha256']))
 (OUT/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(arm,r['median_seconds'],composition,flush=True)
