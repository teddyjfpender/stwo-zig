from pathlib import Path
import subprocess,sys,json,time,hashlib
h=Path(__file__).resolve().parent;r=h.parents[2];sys.path.insert(0,str(r/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='real-block-evm-recovery-leaf'):
 location=json.loads((h/'evm-recovery-locations.json').read_text())
 paths=[h/'block-leaf-evm-recursive',h/'ethereum-block-evm-final.elf',h/'fixture/stwo-runner-input-evm-hints.bin']
 target=location['proof_target_segment'];stem='evm-first-recovery-recursive'
 cmd=['/usr/bin/time','-l',*[str(p) for p in paths],'32768',str(h/(stem+'.proof')),str(h/(stem+'.json')),str(target),'32768','recursive']
 identity={str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths};start=time.monotonic()
 with (h/(stem+'.log')).open('x') as log:result=subprocess.run(cmd,cwd=r,stdout=log,stderr=subprocess.STDOUT)
 (h/(stem+'-invocation.json')).write_text(json.dumps(dict(command=cmd,exit_code=result.returncode,wall_seconds=time.monotonic()-start,sha256=identity),indent=2)+'\n')
 if result.returncode:sys.exit(result.returncode)
 report=json.loads((h/(stem+'.json')).read_text());assert report['segment_verified'] and report['recovery_calls']>=1 and report['queries']==70 and report['pow_bits']==26
 assert report['global_first_cycle']<=location['first_evm_call']['global_cycle']<report['global_first_cycle']+report['cycles']
