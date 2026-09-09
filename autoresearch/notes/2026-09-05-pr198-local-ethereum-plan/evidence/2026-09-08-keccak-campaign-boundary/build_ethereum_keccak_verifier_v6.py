from pathlib import Path
import subprocess,json,hashlib,time
repo=Path.cwd();source=repo/'.git/local-ethereum/prepared-leaf-metal-source-v7';product=repo/'.git/local-ethereum/fixed-program-native-verifier-v6';product.mkdir()
manifest=source/'manifest.json';encoded=manifest.read_bytes();authority=json.loads(encoded)
def check():
 for entry in authority['files']:
  data=(source/'source'/entry['path']).read_bytes()
  if len(data)!=entry['bytes'] or hashlib.sha256(data).hexdigest()!=entry['sha256']:raise SystemExit('Frozen source changed: '+entry['path'])
def ident(p):
 d=p.read_bytes();return {'path':str(p),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
check();command=['python3',str(repo/'scripts/zig_serial_build.py'),'--cwd',str(source/'source/src/integrations/riscv_cpu'),'build-ethereum-full-leaf-bundle-verifier','-Doptimize=ReleaseSafe','-Dethereum-proof-strip=true','--prefix',str(product),'--summary','all'];(product/'build-plan.json').write_text(json.dumps({'command':command,'source_manifest':ident(manifest)},indent=2)+'\n');start=time.monotonic_ns()
with (product/'build.log').open('wb') as log:result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
check();receipt={'schema':'stwo.ethereum.frozen-product.v1','source_manifest':ident(manifest),'build_log':ident(product/'build.log'),'exit_code':result.returncode,'elapsed_ns_including_lock_wait':time.monotonic_ns()-start,'optimization':'ReleaseSafe','source_scope':'Built only from immutable complete source copy; all source files rehashed before and after build'}
exe=product/'bin/ethereum-full-leaf-bundle-verify-v1'
if result.returncode==0:receipt['executable']=ident(exe)
(product/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt));raise SystemExit(result.returncode)
