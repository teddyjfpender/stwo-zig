from pathlib import Path
import subprocess,sys,time,json,hashlib
h=Path(__file__).resolve().parent;r=h.parents[2];sys.path.insert(0,str(r/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='evm-software-hint-collection'):
 paths=[h/'block-execute-hints',h/'ethereum-block-evm-collector.elf',h/'fixture/stwo-runner-input.bin',h/'fixture/expected-output.bin']
 cmd=['/usr/bin/time','-l',*[str(p) for p in paths],str(h/'evm-collector.json'),'262144','collect-evm-hints',str(h/'evm-collector-output.bin')]
 identity={str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths};start=time.monotonic()
 with (h/'evm-collector.log').open('x') as log: result=subprocess.run(cmd,cwd=r,stdout=log,stderr=subprocess.STDOUT)
 (h/'evm-collector-invocation.json').write_text(json.dumps(dict(command=cmd,exit_code=result.returncode,wall_seconds=time.monotonic()-start,sha256=identity),indent=2)+'\n')
 if result.returncode:sys.exit(result.returncode)
 output=(h/'evm-collector-output.bin').read_bytes();assert output[:43]==(h/'fixture/expected-output.bin').read_bytes();footer=output[43:];assert footer[:8]==b'STWECR01'
 count=int.from_bytes(footer[8:12],'little');assert len(footer)==12+(count+7)//8
 base=(h/'fixture/stwo-runner-input.bin').read_bytes();assert len(base)==4+int.from_bytes(base[:4],'little')
 with (h/'fixture/stwo-runner-input-evm-hints.bin').open('xb') as f:f.write(base+footer)
 (h/'evm-hint-manifest.json').write_text(json.dumps(dict(count=count,successful=sum((footer[12+i//8]>>(i%8))&1 for i in range(count)),canonical_ssz_sha256=hashlib.sha256(base[4:]).hexdigest(),augmented_input_sha256=hashlib.sha256(base+footer).hexdigest(),hints_are_untrusted=True),indent=2)+'\n')
