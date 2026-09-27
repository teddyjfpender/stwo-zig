"""Frozen-control/candidate comparison, canonical inputs and proof-byte gate."""
import argparse,hashlib,json,os,statistics,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--backend',choices=['cpu','metal'],default='metal');args=parser.parse_args()
backend=args.backend
baseline=ROOT/f'autoresearch/notes/2026-09-23-compact-range-provider/suite-{backend}/results.json'
records=json.loads(baseline.read_text());results=[]
for case in [f'{backend}-ecdsa_secp256k1-32',f'{backend}-sha256-128',f'{backend}-sha256-2048',f'{backend}-keccak-128']:
 r=next(r for r in records if r['case']==case)
 expected_report=json.loads((ROOT/f'autoresearch/notes/2026-09-24-overlapped-metal-stream-leaves/{case}-candidate-first.json').read_text())
 for arm in ['control-first','candidate-first','candidate-last','control-last']:
  prefix=HERE/f'{case}-{arm}';cmd=r['command'][:]
  product=HERE/'candidate-products' if arm.startswith('candidate') else ROOT/'autoresearch/notes/2026-09-24-overlapped-metal-stream-leaves/candidate-products'
  cmd[0]=str(product/f'bin/stwo-zig-riscv-{backend}')
  for key,value in [('--samples','3'),('--report-out',str(prefix.with_suffix('.json'))),('--proof-out',str(prefix.with_suffix('.b3proof')))]:cmd[cmd.index(key)+1]=value
  env=os.environ.copy();env.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_EXECUTION_PROFILE='1')
  env.pop('STWO_ZIG_EXPERIMENTAL_PARALLEL_BARYCENTRIC_WEIGHTS',None)
  env.pop('STWO_RISCV_SERIAL_HASH_INTERACTIONS',None)
  env.pop('STWO_RISCV_SMALL_COMMIT_BATCH',None)
  env.pop('STWO_ZIG_DETACH_STREAMING_COEFFICIENTS',None)
  env.pop('STWO_ZIG_DETACH_STREAMING_LDE',None)
  env.pop('STWO_ZIG_REPLAY_BOUNDED_MERKLE_TAIL',None)
  env.pop('STWO_ZIG_SCALAR_TAIL_UPDATES',None)
  env.pop('STWO_ZIG_SERIAL_COLUMN_PROJECTION',None)
  env.pop('STWO_RISCV_CPU_HASH_INTERACTIONS',None)
  env.pop('STWO_RISCV_CPU_HASH_COMPOSITION',None)
  env.pop('STWO_ZIG_METAL_STREAM_LEAVES',None)
  env.pop('STWO_ZIG_CPU_STREAM_LEAVES',None)
  env.pop('STWO_ZIG_SYNC_STREAM_LEAVES',None)

  with prefix.with_suffix('.log').open('w') as f:subprocess.run(cmd,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
  report=json.loads(prefix.with_suffix('.json').read_text())
  if arm.startswith('control'):assert report['proof_sha256']==r['proof_sha256'],'Control proof changed'
  for key in ('elf_sha256','input_sha256','output_sha256','pcs_config'):assert report[key]==expected_report[key], f'Changed {key}'
  prior=[x for x in results if x['case']==case and x['arm'].split('-')[0]==arm.split('-')[0]]
  if prior:assert report['proof_sha256']==prior[0]['proof_sha256'],'Nondeterministic proof'
  verify=[cmd[0],'ecdsa-csp-verify' if 'ecdsa' in case else 'verify','--artifact',str(prefix.with_suffix('.b3proof')),'--elf',cmd[cmd.index('--elf')+1],'--input',cmd[cmd.index('--input')+1],'--expect-statement-digest',report['statement_blake3']]
  if 'ecdsa' not in case:verify+=['--protocol','secure']
  with prefix.with_suffix('.verify.json').open('w') as f:subprocess.run(verify,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
  profiles=[json.loads(line.split(' ',1)[1]) for line in prefix.with_suffix('.log').read_text().splitlines() if line.startswith('BLAKE3_EXECUTION_STAGE_PROFILE ')]
  assert len(profiles)==3
  device_lines=[line for line in prefix.with_suffix('.log').read_text().splitlines() if line.startswith('METAL_FRAMEWORK_INTERACTION ')]
  if backend=='metal':
   assert device_lines, 'Device interactions must stay enabled in both arms'
   composition_lines=[line for line in prefix.with_suffix('.log').read_text().splitlines() if 'METAL_FRAMEWORK_COMPOSITION ' in line]
   assert composition_lines, 'Device composition must stay enabled in both arms'
   stream_lines=[line for line in prefix.with_suffix('.log').read_text().splitlines() if line.startswith('METAL_STREAM_LEAVES ')]
   assert stream_lines, 'GPU streaming leaves must stay enabled in both arms'
   expected='overlap=true'
   assert all(expected in line for line in stream_lines), 'Unexpected overlap route'
  record=dict(case=case,arm=arm,command=cmd,binary_sha256=hashlib.sha256(Path(cmd[0]).read_bytes()).hexdigest(),total_seconds=report['median_seconds'],hash_interaction_seconds=statistics.median(next(s['seconds'] for s in p['stages'] if s['id']=='execution.hash_interaction') for p in profiles),composition_seconds=statistics.median(next(s['seconds'] for s in next(t['children'] for t in p['stages'] if t['id']=='execution.core') if s['id']=='composition_evaluation') for p in profiles),sampled_seconds=statistics.median(next(s['seconds'] for s in next(t['children'] for t in p['stages'] if t['id']=='execution.core') if s['id']=='sampled_value_evaluation') for p in profiles),witness_seconds=statistics.median(t['witness_ns']/1e9 for t in report['timings']),admission_seconds=statistics.median(t['admission_ns']/1e9 for t in report['timings']),proof_sha256=report['proof_sha256'],verified=True,parameters=report['pcs_config'],device_counts=report['proof_device_counts'],resources=report['resources'],profiles=profiles)
  results.append(record);(HERE/f'{backend}-results.json').write_text(json.dumps(results,indent=2)+'\n')
  print(case,arm,record['total_seconds'],record['witness_seconds'],record['admission_seconds'],flush=True)
