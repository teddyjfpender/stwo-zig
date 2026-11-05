import json,os,pathlib,subprocess,sys,time
root=pathlib.Path('/workspace/m3/src/m7-integrate')
base=pathlib.Path('/workspace/m3/runs/m7-integrate')
control=base/'p1-inter-reuse-preflight-20261106-01'
sys.path.insert(0,str(root/'scripts'))
import rv64_m7_integration_stack as stack
while not (control/'exit').exists(): time.sleep(5)
if (control/'exit').read_text().strip()!='0': raise SystemExit('preflight failed; no GPU run')
before=json.loads((base/'p1-small-20261106-01/artifact.json').read_text())
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'prepare','--source-root',str(root),'--source-commit',(root/'.m3-commit').read_text().strip(),'--block','26235156','--preset',str(root/'vectors/reports/rv64-m8-20261106/p1/inter-reuse-v1-preset.json'),'--out',str(control/'smoke-artifact.json'),'--native-hooks-commit',before['native_hooks_commit'],'--device-hooks-commit',before['device_hooks_commit']]
for key,value in before['assets'].items(): argv+=['--'+key.replace('_','-'),value]
env=stack.clean_environment(os.environ)
subprocess.run(argv,cwd=root,env=env,check=True)
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'run','--manifest',str(control/'smoke-artifact.json'),'--out',str(base/'p1-inter-reuse-small-20261106-01'),'--smoke','--smoke-seeds','17','--smoke-request-timeout','120']
rc=subprocess.run(argv,cwd=root,env=env).returncode
(control/'smoke.exit').write_text(str(rc)+'\n')
sys.exit(rc)
