"""Matched ECDSA architectural comparison; old/new protocols verify with their own CLI."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from scripts.riscv_csp_benchmark_lib.contract import validate_manifest,MANIFEST
HERE=Path(__file__).resolve().parent
OUT=HERE/'ecdsa-pairs'
OUT.mkdir(exist_ok=False)
_,cases,_=validate_manifest(MANIFEST)
case=next(c for c in cases if c.target=='ecdsa_secp256k1')
elf=ROOT/'vectors/riscv_csp/guests/ecdsa_secp256k1_precompile_odd.elf'
records=[]
for backend in ['cpu','metal']:
 for i,arm in enumerate(['baseline','candidate','candidate','baseline']):
  name=f'{backend}-{i}-{arm}'
  prefix=ROOT/'autoresearch/notes/2026-09-23-blake3-csp-regression/baseline-products' if arm=='baseline' else ROOT/'zig-out'
  cli=prefix/'bin'/f'stwo-zig-riscv-{backend}'
  proof=OUT/f'{name}.b3proof'; report=OUT/f'{name}.json'
  env=os.environ.copy()
  for key in ['STWO_RISCV_EXECUTION_PROFILE','STWO_RISCV_SERIAL_PARENT_LOOKUPS','STWO_RISCV_NO_EXECUTION_COEFFICIENT_CACHE','STWO_RISCV_METAL_AOT_BUNDLE']:env.pop(key,None)
  env['STWO_ZIG_WORKERS']=env['STWO_ZIG_MERKLE_WORKERS']='16'
  env['STWO_RISCV_EXECUTION_PROFILE']='1'
  if backend=='metal':env['STWO_RISCV_METAL_AOT_BUNDLE']=str(prefix/'share/stwo-zig/metal/core')
  cmd=[str(cli),'ecdsa-csp-bench','--elf',str(elf),'--input',str(case.input_path),'--proof-out',str(proof),'--report-out',str(report),'--warmups','0','--samples','1','--workers','16','--host-byte-budget','38654705664']
  with (OUT/f'{name}.log').open('w') as log:subprocess.run(cmd,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
  r=json.loads(report.read_text())
  assert r['pcs_config']['pow_bits']==26 and r['pcs_config']['fri_config']['n_queries']==70
  assert r['proof_suite']=='blake3' and r['verified_samples']==1 and r['total_steps']==1828
  assert r['input_sha256']==case.input_sha256 and r['elf_sha256']==hashlib.sha256(elf.read_bytes()).hexdigest()
  assert r['output_sha256']==hashlib.sha256(bytes.fromhex(case.expected_digest)).hexdigest()
  verify=[str(cli),'ecdsa-csp-verify','--artifact',str(proof),'--elf',str(elf),'--input',str(case.input_path),'--expect-statement-digest',r['statement_blake3']]
  with (OUT/f'{name}-verify.json').open('w') as log:subprocess.run(verify,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
  records.append(dict(backend=backend,arm=arm,command=cmd,verify=verify,seconds=r['median_seconds'],proof_sha256=r['proof_sha256'],binary_sha256=hashlib.sha256(cli.read_bytes()).hexdigest(),verified=True))
  (OUT/'results.json').write_text(json.dumps(records,indent=2)+'\n')
  print(name,r['median_seconds'],flush=True)
