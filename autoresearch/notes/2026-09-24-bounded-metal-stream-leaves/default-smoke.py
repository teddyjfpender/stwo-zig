import hashlib,json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
records=json.loads((ROOT/'autoresearch/notes/2026-09-23-compact-range-provider/suite-metal/results.json').read_text())
r=next(r for r in records if r['case']=='metal-ecdsa_secp256k1-32')
cmd=r['command'][:];cmd[0]=str(HERE/'retained-products/bin/stwo-zig-riscv-metal')
for key,value in [('--samples','1'),('--report-out',str(HERE/'default-smoke.json')),('--proof-out',str(HERE/'default-smoke.b3proof'))]:cmd[cmd.index(key)+1]=value
env=os.environ.copy();env.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_EXECUTION_PROFILE='1')
env.pop('STWO_ZIG_METAL_STREAM_LEAVES',None);env.pop('STWO_ZIG_CPU_STREAM_LEAVES',None);env.pop('STWO_RISCV_CPU_HASH_INTERACTIONS',None);env.pop('STWO_RISCV_CPU_HASH_COMPOSITION',None)
(HERE/'default-smoke-command.json').write_text(json.dumps(dict(command=cmd,environment_overrides={k:v for k,v in env.items() if k.startswith('STWO_')}),indent=2)+'\n')
with (HERE/'default-smoke.log').open('w') as f:subprocess.run(cmd,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
assert 'METAL_STREAM_LEAVES ' in (HERE/'default-smoke.log').read_text(), 'Streaming leaves did not dispatch'
assert 'METAL_FRAMEWORK_COMPOSITION components=8' in (HERE/'default-smoke.log').read_text(), 'Composition did not dispatch'
report=json.loads((HERE/'default-smoke.json').read_text());assert report['proof_sha256']==r['proof_sha256']
verify=[cmd[0],'ecdsa-csp-verify','--artifact',str(HERE/'default-smoke.b3proof'),'--elf',cmd[cmd.index('--elf')+1],'--input',cmd[cmd.index('--input')+1],'--expect-statement-digest',report['statement_blake3']]
with (HERE/'default-smoke.verify.json').open('w') as f:subprocess.run(verify,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
print('Parity smoke passed, unchanged proof',report['proof_sha256'])
