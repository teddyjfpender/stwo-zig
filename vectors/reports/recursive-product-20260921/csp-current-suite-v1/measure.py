from pathlib import Path
import json,subprocess,sys,os,shutil
root=Path('/tmp/pr198-csp-clean-source-v1').resolve();out=Path('/tmp/pr198-csp-clean-evidence-v1');old=Path('/tmp/pr198-csp-clean-products-v1');prefix=root/'zig-out'
shutil.copytree(old,prefix)
shutil.copyfile(out/'cpu.log',out/'cpu-external-path-report-failure.log')
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')}
commands=json.loads((out/'commands.json').read_text())
for backend in ('cpu','metal'):
 args=[sys.executable,'scripts/riscv_csp_benchmark.py','--backend',backend,'--cli',str(prefix/'bin'/('stwo-zig-riscv-'+backend)),'--trace-cli',str(prefix/'bin/riscv-trace-dump'),'--report-out',str(out/(backend+'.json')),'--workers','16','--warmups','1','--samples','10']
 print(backend+': started',flush=True)
 with (out/(backend+'.log')).open('w') as stream:r=subprocess.run(args,cwd=root,env=env,stdout=stream,stderr=subprocess.STDOUT)
 commands.append({'name':backend+'-internal-install','argv':args,'exit_code':r.returncode});(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 if r.returncode:raise RuntimeError(backend+' failed')
 assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
 print(backend+': passed',flush=True)
shutil.copyfile('/tmp/pr198-csp-clean-measure-v2.py',out/'measure.py')
print('Both full CSP reports completed.',flush=True)
