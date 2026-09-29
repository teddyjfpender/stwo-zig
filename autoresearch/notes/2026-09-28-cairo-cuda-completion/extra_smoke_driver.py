"""Bounded hardware correctness checks using the exact built Cairo archive."""
import datetime,json,subprocess,sys,time
from pathlib import Path
root=Path('/workspace/stwo-zig');sys.path.insert(0,str(root/'scripts'))
from cuda_device_smoke import compile_command,sha256_file
out=Path('/workspace/cairo-extra-smokes');out.mkdir(exist_ok=True)
archive=root/'zig-out/lib/libstwo_cuda_kernels.a'
names=('native_ec_op_composite_smoke','native_composition_split_smoke','native_pedersen_module_globals_smoke','native_platform_snapshot_smoke')
results=[]
for name in names:
 source=root/'tests/cuda'/(name+'.cpp');binary=out/name
 compile_result=subprocess.run(compile_command(Path('/usr/bin/g++'),source,binary,archive,Path('/usr/local/cuda')),capture_output=True,text=True,timeout=90)
 (out/(name+'.compile.log')).write_text(compile_result.stdout+compile_result.stderr)
 receipt={'name':name,'compile_exit_code':compile_result.returncode,'source_sha256':sha256_file(source),'archive_sha256':sha256_file(archive)}
 if compile_result.returncode==0:
  start=time.monotonic_ns()
  try:
   run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=90,cwd=root)
   (out/(name+'.run.log')).write_text(run.stdout+run.stderr)
   receipt.update(exit_code=run.returncode,diagnostic_wall_ns=time.monotonic_ns()-start,executable_sha256=sha256_file(binary),stdout=run.stdout,stderr=run.stderr)
  except subprocess.TimeoutExpired:receipt['timeout_seconds']=90
 results.append(receipt)
 (out/'receipt.json').write_text(json.dumps({'schema':'stwo-cairo-cuda-component-correctness-v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'tests':results},indent=2)+'\n')
 print(json.dumps(receipt),flush=True)
raise SystemExit(0 if all(r.get('exit_code')==0 for r in results) else 1)
