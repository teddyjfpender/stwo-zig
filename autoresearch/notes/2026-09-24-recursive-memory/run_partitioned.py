from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent
for size in (64,16,32,1):
 print('Proving partitioned batch '+str(size),flush=True)
 subprocess.run([sys.executable,str(H/'run.py'),'local','batch-'+str(size),'prove','partitioned'],check=True)
