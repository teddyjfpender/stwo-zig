from pathlib import Path
import os,json,time,subprocess,sys
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'))
import rv64_m7_integration_stack as S
base=Path('/workspace/m3/runs/m7-integrate')
control=base/'p1-outer-chunks-smoke-controller-20261106-01'
out=base/'p1-outer-chunks-headline-controller-20261106-01'
while not (control/'exit').exists():time.sleep(5)
assert (control/'exit').read_text().strip()=='0','smoke failed; headline not launched'
smoke=json.loads((base/'p1-outer-chunks-small-20261106-01/experiment.json').read_text())
assert smoke['status']=='SMOKE_BYTE_PARITY_AND_FRESH_ACCEPTED'
m=json.loads((control/'artifact.json').read_text());S.validate_manifest(m)
m['block']=24628607;m['created_utc_ns']=time.time_ns()
S.write(out/'artifact.json',m)
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'run','--manifest',str(out/'artifact.json'),'--out',str(base/'p1-outer-chunks-headline-20261106-01')]
with (out/'headline.log').open('w') as log:r=subprocess.run(argv,cwd=root,env=S.clean_environment(os.environ),stdout=log,stderr=subprocess.STDOUT)
(out/'exit').write_text(str(r.returncode)+'\n')
if r.returncode:raise RuntimeError('headline failed; preserve completed services for validation')
