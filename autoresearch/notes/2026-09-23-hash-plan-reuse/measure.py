"""Frozen-control/candidate comparison, canonical inputs and proof-byte gate."""
import argparse,hashlib,json,os,statistics,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--backend',choices=['cpu','metal'],default='cpu');args=parser.parse_args()
backend=args.backend
baseline=ROOT/f'autoresearch/notes/2026-09-23-compact-range-provider/suite-{backend}/results.json'
records=json.loads(baseline.read_text());results=[]
for case in [f'{backend}-ecdsa_secp256k1-32',f'{backend}-sha256-128',f'{backend}-sha256-2048',f'{backend}-keccak-128']:
 r=next(r for r in records if r['case']==case)
 for arm in ['control','candidate']:
  prefix=HERE/f'{case}-{arm}';cmd=r['command'][:]
  if arm=='control':cmd[0]=str(ROOT/f'autoresearch/notes/2026-09-23-sampled-scheduling/candidate-products/bin/stwo-zig-riscv-{backend}')
  for key,value in [('--samples','3'),('--report-out',str(prefix.with_suffix('.json'))),('--proof-out',str(prefix.with_suffix('.b3proof')))]:cmd[cmd.index(key)+1]=value
  env=os.environ.copy();env.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_EXECUTION_PROFILE='1')
  env.pop('STWO_ZIG_EXPERIMENTAL_PARALLEL_BARYCENTRIC_WEIGHTS',None)
  env.pop('STWO_RISCV_SERIAL_HASH_INTERACTIONS',None)
  with prefix.with_suffix('.log').open('w') as f:subprocess.run(cmd,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
  report=json.loads(prefix.with_suffix('.json').read_text())
  assert report['proof_sha256']==r['proof_sha256'],'Proof bytes changed'
  verify=[cmd[0],'ecdsa-csp-verify' if 'ecdsa' in case else 'verify','--artifact',str(prefix.with_suffix('.b3proof')),'--elf',cmd[cmd.index('--elf')+1],'--input',cmd[cmd.index('--input')+1],'--expect-statement-digest',report['statement_blake3']]
  if 'ecdsa' not in case:verify+=['--protocol','secure']
  with prefix.with_suffix('.verify.json').open('w') as f:subprocess.run(verify,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
  profiles=[json.loads(line.split(' ',1)[1]) for line in prefix.with_suffix('.log').read_text().splitlines() if line.startswith('BLAKE3_EXECUTION_STAGE_PROFILE ')]
  assert len(profiles)==3
  record=dict(case=case,arm=arm,command=cmd,binary_sha256=hashlib.sha256(Path(cmd[0]).read_bytes()).hexdigest(),total_seconds=report['median_seconds'],hash_interaction_seconds=statistics.median(next(s['seconds'] for s in p['stages'] if s['id']=='execution.hash_interaction') for p in profiles),sampled_seconds=statistics.median(next(s['seconds'] for s in next(t['children'] for t in p['stages'] if t['id']=='execution.core') if s['id']=='sampled_value_evaluation') for p in profiles),witness_seconds=statistics.median(t['witness_ns']/1e9 for t in report['timings']),admission_seconds=statistics.median(t['admission_ns']/1e9 for t in report['timings']),proof_sha256=report['proof_sha256'],verified=True,parameters=report['pcs_config'],profiles=profiles)
  results.append(record);(HERE/f'{backend}-results.json').write_text(json.dumps(results,indent=2)+'\n')
  print(case,arm,record['total_seconds'],record['witness_seconds'],record['admission_seconds'],flush=True)
