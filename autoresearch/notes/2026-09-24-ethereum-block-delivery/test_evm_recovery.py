from pathlib import Path
import subprocess,sys,os
h=Path(__file__).resolve().parent;r=h.parents[2];sys.path.insert(0,str(r/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='evm-recovery-host-tests'):
 subprocess.run(['cargo','test','--offline','--manifest-path',str(h/'evm-recovery-tests/Cargo.toml')],cwd=r,check=True)
