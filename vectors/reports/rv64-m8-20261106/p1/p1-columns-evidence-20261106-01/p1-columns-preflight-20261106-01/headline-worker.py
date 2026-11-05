import json,os,pathlib,shutil,subprocess,sys,time
root=pathlib.Path('/workspace/m3/src/m7-integrate')
base=pathlib.Path('/workspace/m3/runs/m7-integrate')
control=base/'p1-columns-preflight-20261106-01'
sys.path.insert(0,str(root/'scripts'))
import rv64_m7_integration_stack as stack
while not (control/'smoke.exit').exists(): time.sleep(5)
if (control/'smoke.exit').read_text().strip()!='0': raise SystemExit('smoke failed; no headline timing')
smoke=json.loads((base/'p1-columns-small-20261106-01/experiment.json').read_text())
assert smoke.get('status')=='SMOKE_BYTE_PARITY_AND_FRESH_ACCEPTED'
if shutil.disk_usage('/workspace').free < 1_800_000_000: raise SystemExit('less than 1.8GB free; preserve smoke and stop before headline')
before=json.loads((control/'smoke-artifact.json').read_text())
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'prepare','--source-root',str(root),'--source-commit',before['source_commit'],'--block','24628607','--preset',str(root/'vectors/reports/rv64-m8-20261106/p1/columns-v1-preset.json'),'--out',str(control/'headline-artifact.json'),'--native-hooks-commit',before['native_hooks_commit'],'--device-hooks-commit',before['device_hooks_commit']]
for key,value in before['assets'].items(): argv+=['--'+key.replace('_','-'),value]
env=stack.clean_environment(os.environ)
subprocess.run(argv,cwd=root,env=env,check=True)
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'run','--manifest',str(control/'headline-artifact.json'),'--out',str(base/'p1-columns-headline-20261106-01'),'--ownership-profile-pair']
rc=subprocess.run(argv,cwd=root,env=env).returncode
(control/'headline.exit').write_text(str(rc)+'\n')
sys.exit(rc)
