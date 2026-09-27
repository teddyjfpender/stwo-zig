import hashlib,json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
records=json.loads((HERE.parent/'suite-cpu/results.json').read_text())
env=os.environ.copy()
env.update(STWO_RISCV_EXECUTION_PROFILE='1',STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16')
profiles=[]
for name in ['cpu-sha256-128','cpu-keccak-128']:
 r=next(r for r in records if r['case']==name)
 cmd=r['command'][:]
 for key,value in [('--samples','1'),('--report-out',str(HERE/f'{name}.json')),('--proof-out',str(HERE/f'{name}.b3proof'))]:cmd[cmd.index(key)+1]=value
 with (HERE/f'{name}.log').open('w') as f:subprocess.run(cmd,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 report=json.loads((HERE/f'{name}.json').read_text())
 assert report['proof_sha256']==r['proof_sha256'], 'Profiling changed proof bytes'
 verify=[cmd[0],'verify','--artifact',str(HERE/f'{name}.b3proof'),'--elf',cmd[cmd.index('--elf')+1],'--input',cmd[cmd.index('--input')+1],'--expect-statement-digest',report['statement_blake3'],'--protocol','secure']
 with (HERE/f'{name}-verify.json').open('w') as f:subprocess.run(verify,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 stages=[json.loads(line.split(' ',1)[1]) for line in (HERE/f'{name}.log').read_text().splitlines() if line.startswith('BLAKE3_EXECUTION_STAGE_PROFILE ')]
 assert len(stages)==1
 profiles.append(dict(case=name,binary_sha256=hashlib.sha256(Path(cmd[0]).read_bytes()).hexdigest(),command=cmd,proof_unchanged=True,fresh_verified=True,profile=stages[0]))
 print(name,json.dumps(stages[0]),flush=True)
 (HERE/'base-profiles.json').write_text(json.dumps(profiles,indent=2)+'\n')
