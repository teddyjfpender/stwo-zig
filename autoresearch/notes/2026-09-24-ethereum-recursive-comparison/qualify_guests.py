from pathlib import Path
import subprocess,sys,json
H=Path(__file__).resolve().parent
cases=['batch-1','batch-2','batch-4','batch-8','batch-16','bad-type','bad-parity','zero-r','high-s','bad-rlp']
for side in ['local','peer']:
 for case in cases:
  subprocess.run([sys.executable,str(H/'run.py'),side,case,'execute','qualification'],check=True,stdout=subprocess.DEVNULL)
  print(side,case,'passed',flush=True)
(H/'guest-qualification.json').write_text(json.dumps({'execution_only':True,'cases':cases,'both_backends_passed':True,'negative_proof_claim':False},indent=2)+'\n')
