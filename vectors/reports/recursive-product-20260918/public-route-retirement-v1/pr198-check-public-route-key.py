from pathlib import Path
import sys,subprocess,hashlib,json
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from zig_serial_build import build_lock
manifest=Path('/tmp/pr198-public-route-key-setup-manifest.json'); output=Path('/tmp/pr198-public-route-derived-key-v1')
binary=root/'src/integrations/riscv_cpu/zig-out/bin/recursive-segment-v2-leaf-key-setup'
with build_lock(label='public-route-key-setup-check'):
 with Path('/tmp/pr198-public-route-key-setup-v1.log').open('w') as log:
  subprocess.run([str(binary),str(manifest),hashlib.sha256(manifest.read_bytes()).hexdigest(),str(output)],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
expected=json.loads((root/'vectors/reports/recursive-product-20260918/larger-memory-ladder-qualified-v1/admissions/1.json').read_text())['leaves'][0]['key']['sha256']
actual=hashlib.sha256((output/'child-0-key.json').read_bytes()).hexdigest();assert actual==expected,(actual,expected)
receipt=json.loads((output/'setup.json').read_text());assert receipt['outer_proofs_created']==0
out=root/'vectors/reports/recursive-product-20260918/public-route-retirement-v1/key-setup-check.json';out.write_text(json.dumps({'passed':True,'key_sha256':actual,'expected_key_sha256':expected,'outer_proofs_created':0,'receipt':receipt},indent=2)+'\n')
print('Canonical native key setup reproduced independently pinned key:',actual)
