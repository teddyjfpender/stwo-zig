from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent
steps=[('test_barycentric.py',[],'test-barycentric-final.log'),('build_local.py',[],'build-final.log')]
for script,args,log in steps:
 print('Starting '+script,flush=True)
 with (H/log).open('w') as out: subprocess.run([sys.executable,str(H/script),*args],stdout=out,stderr=subprocess.STDOUT,check=True)
for size in (1,16,32,64):
 print('Proving batch '+str(size),flush=True)
 subprocess.run([sys.executable,str(H/'run.py'),'local','batch-'+str(size),'prove','compact-opening'],check=True)
