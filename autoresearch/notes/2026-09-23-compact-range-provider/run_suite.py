"""Source-pinned diagnostic; does not claim clean-source CSP suite admission."""
import argparse,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from scripts.riscv_csp_benchmark_lib.contract import validate_manifest,MANIFEST
parser=argparse.ArgumentParser()
parser.add_argument('--backend',choices=['cpu','metal'],required=True)
parser.add_argument('--samples',type=int,default=3)
args=parser.parse_args()
assert args.samples > 0
p=Path(__file__).resolve().parent/f'suite-{args.backend}'
p.mkdir(exist_ok=False)
_,cases,negative_cases=validate_manifest(MANIFEST)
from scripts.riscv_csp_benchmark_lib.precompile import validate_manifest as validate_precompile
from scripts.riscv_csp_benchmark_lib.full_width import artifact_sections
validate_precompile()
cases=[*cases,*negative_cases]
results=[]
for backend in [args.backend]:
 for case in cases:
  negative=hasattr(case,'name')
  name=f'{backend}-{case.name}' if negative else f'{backend}-{case.target}-{case.input_size}'
  accelerated=case.target=='ecdsa_secp256k1' and not negative
  elf=ROOT/'vectors/riscv_csp/guests/ecdsa_secp256k1_precompile_odd.elf' if accelerated else case.guest_path
  report=p/f'{name}.json';proof=p/f'{name}.b3proof'
  env=os.environ.copy()
  for key in ['STWO_RISCV_EXECUTION_PROFILE','STWO_RISCV_SERIAL_PARENT_LOOKUPS','STWO_RISCV_NO_EXECUTION_COEFFICIENT_CACHE','STWO_RISCV_METAL_AOT_BUNDLE']:env.pop(key,None)
  env['STWO_ZIG_WORKERS']=env['STWO_ZIG_MERKLE_WORKERS']='16'
  cli=str(ROOT/f'zig-out/bin/stwo-zig-riscv-{backend}')
  cmd=[cli,'ecdsa-csp-bench' if accelerated else 'bench','--elf',str(elf),'--input',str(case.input_path),'--proof-out',str(proof),'--report-out',str(report),'--warmups','0','--samples',str(1 if negative else args.samples)]
  if accelerated:cmd+=['--workers','16','--host-byte-budget','38654705664']
  else:cmd+=['--backend',backend,'--protocol','secure']
  record={'case':name,'negative':negative,'command':cmd,'canonical_input_sha256':case.input_sha256,'expected_output':case.expected_digest,'result_class':'source_pinned_dirty_diagnostic'}
  with (p/f'{name}.log').open('w') as log:
   process=subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   while process.poll() is None:
    rss=subprocess.run(['ps','-o','rss=','-p',str(process.pid)],capture_output=True,text=True).stdout.strip()
    if rss and int(rss)*1024>40*1024**3:
     record['failure']='physical_rss_limit_40_GiB';os.killpg(process.pid,signal.SIGTERM)
     try:process.wait(timeout=10)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
     break
    time.sleep(2)
   record['exit_code']=process.wait()
  if record['exit_code']==0:
   r=json.loads(report.read_text())
   assert r['pcs_config']['pow_bits']==26 and r['pcs_config']['fri_config']['n_queries']==70
   assert r['proof_suite']=='blake3' and r['verified_samples']==(1 if negative else args.samples)
   assert r['input_sha256']==case.input_sha256
   assert r['elf_sha256']==hashlib.sha256(elf.read_bytes()).hexdigest()
   assert r['output_sha256']==hashlib.sha256(bytes.fromhex(case.expected_digest)).hexdigest()
   assert r['total_steps']==(1828 if accelerated else case.expected_cycles)
   magic,elf_hash,input_hash,stark=artifact_sections(proof.read_bytes())
   assert elf_hash==r['elf_sha256'] and input_hash==r['input_sha256']
   assert all(sample['dispatches']>0 for sample in r['proof_device_counts']) if backend=='metal' else all(sample['dispatches']==0 and sample['cpu_fallbacks']==0 for sample in r['proof_device_counts'])
   verify=[cli,'ecdsa-csp-verify' if accelerated else 'verify','--artifact',str(proof),'--elf',str(elf),'--input',str(case.input_path),'--expect-statement-digest',r['statement_blake3']]
   if not accelerated:verify+=['--protocol','secure']
   with (p/f'{name}-verify.json').open('w') as out:subprocess.run(verify,cwd=ROOT,env=env,stdout=out,stderr=subprocess.STDOUT,check=True)
   record.update(total_seconds=r['median_seconds'],samples=r['verified_samples'],all_timings=r['timings'],device=r['proof_device_counts'],binary_sha256=hashlib.sha256(Path(cli).read_bytes()).hexdigest(),implementation_dirty=r['implementation_dirty'],artifact_magic=magic,stark_bytes=len(stark),timing=r['timings'][0],physical_peak_bytes=r['resources']['after_verified_samples']['lifetime_max_phys_footprint_bytes'],proof_sha256=r['proof_sha256'],independent_verified=True)
  results.append(record);(p/'results.json').write_text(json.dumps(results,indent=2)+'\n')
  print(name,record.get('total_seconds',record['exit_code']),flush=True)
assert len(results)==17 and all(r.get('independent_verified') for r in results)
