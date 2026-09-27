from pathlib import Path
import subprocess,sys,time,json,hashlib
h=Path(__file__).resolve().parent;r=h.parents[2];sys.path.insert(0,str(r/'scripts'))
from zig_serial_build import build_lock
for variant in ('native','fast-memory'):
 with build_lock(label='ethereum-evm-'+variant):
  paths=[h/'block-execute-hints',h/f'ethereum-block-evm-{variant}.elf',h/'fixture/stwo-runner-input-evm-hints.bin',h/'fixture/expected-output.bin']
  stem='evm-'+variant+'-execution'
  cmd=['/usr/bin/time','-l',*[str(p) for p in paths],str(h/(stem+'.json')),'262144']
  identity={str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths};start=time.monotonic()
  with (h/(stem+'.log')).open('x') as log: result=subprocess.run(cmd,cwd=r,stdout=log,stderr=subprocess.STDOUT)
  (h/(stem+'-invocation.json')).write_text(json.dumps(dict(command=cmd,exit_code=result.returncode,wall_seconds=time.monotonic()-start,sha256=identity),indent=2)+'\n')
  if result.returncode:sys.exit(result.returncode)
