from pathlib import Path
import json,subprocess,sys,os,shutil
active=Path.cwd();sys.path.insert(0,str(active))
from scripts.riscv_csp_ab_benchmark_lib import workspace
out=Path('/tmp/pr198-csp-clean-evidence-v1');out.mkdir(exist_ok=False)
root=Path('/tmp/pr198-csp-clean-source-v1');prefix=Path('/tmp/pr198-csp-clean-products-v1')
print('Isolated snapshot: started',flush=True)
snapshot=workspace.materialize_ephemeral_current(active,root)
(out/'snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
print('Isolated snapshot: passed',flush=True)
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')}
commands=[]
def run(name,args):
 print(name+': started',flush=True)
 with (out/(name+'.log')).open('w') as stream:r=subprocess.run(args,cwd=root,env=env,stdout=stream,stderr=subprocess.STDOUT)
 commands.append({'name':name,'argv':args,'exit_code':r.returncode})
 (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 if r.returncode:raise RuntimeError(name+' failed; inspect '+str(out/(name+'.log')))
 assert not workspace.worktree_status(root)['dirty']
 print(name+': passed',flush=True)
run('build',[sys.executable,'scripts/zig_serial_build.py','stwo-zig-riscv-cpu','stwo-riscv-metal','riscv-trace-dump','-Doptimize=ReleaseFast','--prefix',str(prefix),'--summary','all'])
for backend in ('cpu','metal'):
 run(backend,[sys.executable,'scripts/riscv_csp_benchmark.py','--backend',backend,'--cli',str(prefix/'bin'/('stwo-zig-riscv-'+backend)),'--trace-cli',str(prefix/'bin/riscv-trace-dump'),'--report-out',str(out/(backend+'.json')),'--workers','16','--warmups','1','--samples','10'])
assert workspace.source_content(root)['sha256']==snapshot['source_content_sha256']
shutil.copyfile('/tmp/pr198-csp-clean-suite-v1.py',out/'run.py')
print('Complete current CSP suite finished.',flush=True)
