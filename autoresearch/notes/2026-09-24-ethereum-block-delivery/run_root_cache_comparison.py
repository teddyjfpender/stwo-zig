from pathlib import Path
import subprocess,sys
h=Path(__file__).resolve().parent
for flags in (['--uncached'],[]):
 subprocess.run([sys.executable,str(h/'run_leaf_root_cache.py'),*flags],check=True)
assert (h/'leaf-root-cache-window-0-32768-262144.proof').read_bytes()==(h/'leaf-root-cache-window-0-32768-262144-uncached.proof').read_bytes()
print('Same-binary cache comparison proofs are byte-identical')
