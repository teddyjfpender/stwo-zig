"""Size a deterministic SHA-256 guest proof, not an official CSP workload."""
import hashlib,json,os,struct,subprocess,sys,time
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R));sys.path.insert(0,str(R/'scripts'))
from scripts.riscv_cli_admission import resolve
from zig_serial_build import build_lock
size=int(sys.argv[1]); stem=f'sha256-{size}'+('-'+sys.argv[2] if len(sys.argv)>2 else ''); message=bytes(32)
if not 0 <= size <= 4096: raise SystemExit('This guest admits iteration counts from 0 through 4096.')
if any((H/f'{stem}.{ext}').exists() for ext in ('report.json','proof.json','fixture.json')):
 raise SystemExit('Retained run exists; provide a new run label as the second argument.')
for _ in range(size): message=hashlib.sha256(message).digest()
p=H/f'{stem}.input';p.write_bytes(struct.pack('<I',size))
cli=R/'zig-out/bin/stwo-zig-riscv-cpu';elf=H/'guest-stwo/target/riscv32im-unknown-none-elf/release/sha256-chain-guest'
# The guest ELF and inputs are retained independently of the official CSP manifest.
expected={'size':size,'input_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'expected_digest':message.hex(),'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),'cli_sha256':hashlib.sha256(cli.read_bytes()).hexdigest(),'power':subprocess.check_output(['pmset','-g','batt'],text=True)}
(H/f'{stem}.fixture.json').write_text(json.dumps(expected,indent=2)+'\n')
env=os.environ.copy();env['STWO_ZIG_WORKERS']='16';env['STWO_ZIG_MERKLE_WORKERS']='16'
cmd=[str(cli),'--proof-suite','blake3','bench','--elf',str(elf),'--input',str(p),'--backend','cpu','--protocol','secure','--warmups','0','--samples','1','--profiled','--report-out',str(H/f'{stem}.report.json'),'--proof-out',str(H/f'{stem}.proof.json')]
cmd.extend(resolve(cli,backend='cpu').arguments)
with build_lock(label='large-guest-calibration'):
 with (H/f'{stem}.log').open('w') as f:
  start=time.monotonic();res=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=300)
 expected.update(exit_code=res.returncode,wall_seconds=time.monotonic()-start)
 if res.returncode == 0:
  report=json.loads((H/f'{stem}.report.json').read_text())
  assert report['verified_in_process'] and report['verified_samples']==1
  assert report['input_sha256']==expected['input_sha256'] and report['elf_sha256']==expected['elf_sha256']
  assert report['output_len']==32 and report['output_sha256']==hashlib.sha256(message).hexdigest()
  assert report['pcs_config']['pow_bits']==26 and report['pcs_config']['fri_config']['n_queries']==70
  expected['qualified']=True
  expected['total_seconds']=report['median_seconds']
  expected['proving_seconds']=sum(report['timings'][0][k] for k in ('execution_ns','witness_ns','proving_ns'))/1e9
  expected['steps']=report['total_steps']

 (H/f'{stem}.fixture.json').write_text(json.dumps(expected,indent=2)+'\n')
 print(json.dumps(expected),flush=True)
 raise SystemExit(res.returncode)
