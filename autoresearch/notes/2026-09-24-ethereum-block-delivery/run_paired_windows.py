from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent
for index in (0,1,15,63):
 print(f'Proving paired-memory block leaf {index}',flush=True)
 subprocess.run([sys.executable,str(H/'run_leaf_paired_window.py'),'--index',str(index)],check=True)
