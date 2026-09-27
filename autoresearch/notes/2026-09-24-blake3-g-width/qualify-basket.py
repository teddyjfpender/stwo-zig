"""One retained default-route proof per canonical positive CSP case; not a timing study."""
import hashlib,json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
records=json.loads((ROOT/'autoresearch/notes/2026-09-23-compact-range-provider/suite-metal/results.json').read_text())
out=HERE/'default-basket';out.mkdir(exist_ok=True)
results=[]
for r in records:
 if r.get('negative'):continue
 case=r['case'];prefix=out/case;cmd=r['command'][:];cmd[0]=str(HERE/'candidate-products/bin/stwo-zig-riscv-metal')
 for key,value in [('--samples','1'),('--report-out',str(prefix.with_suffix('.json'))),('--proof-out',str(prefix.with_suffix('.b3proof')))]:cmd[cmd.index(key)+1]=value
 env=os.environ.copy();env.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_EXECUTION_PROFILE='1')
 for key in ['STWO_ZIG_SYNC_STREAM_LEAVES','STWO_ZIG_METAL_STREAM_LEAVES','STWO_ZIG_CPU_STREAM_LEAVES','STWO_RISCV_CPU_HASH_INTERACTIONS','STWO_RISCV_CPU_HASH_COMPOSITION']:env.pop(key,None)
 with prefix.with_suffix('.log').open('w') as f:subprocess.run(cmd,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 report=json.loads(prefix.with_suffix('.json').read_text())
 old=json.loads(Path(r['command'][r['command'].index('--report-out')+1]).read_text())
 for key in ('elf_sha256','input_sha256','output_sha256','pcs_config'):assert report[key]==old[key], f'Changed {key}'
 assert report['pcs_config']['pow_bits']==26 and report['pcs_config']['fri_config']['n_queries']==70
 assert 'METAL_STREAM_LEAVES ' in prefix.with_suffix('.log').read_text()
 verify=[cmd[0],'ecdsa-csp-verify' if 'ecdsa' in case else 'verify','--artifact',str(prefix.with_suffix('.b3proof')),'--elf',cmd[cmd.index('--elf')+1],'--input',cmd[cmd.index('--input')+1],'--expect-statement-digest',report['statement_blake3']]
 if 'ecdsa' not in case:verify+=['--protocol','secure']
 with prefix.with_suffix('.verify.json').open('w') as f:subprocess.run(verify,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 results.append(dict(case=case,command=cmd,verify_command=verify,proof_sha256=report['proof_sha256'],binary_sha256=hashlib.sha256(Path(cmd[0]).read_bytes()).hexdigest(),verified=True))
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(case,'verified canonical inputs/output',flush=True)
assert len(results)==16
