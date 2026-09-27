from pathlib import Path
import subprocess,sys,os
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='zisk-guest-peer-cpu-build'):
 env=os.environ.copy();env['PROTOC']='/tmp/stwo-zisk-guest-e2e-20260924/protoc/bin/protoc';env['CARGO_TARGET_DIR']='/tmp/stwo-zisk-guest-e2e-20260924/target';env['CMAKE_BUILD_PARALLEL_LEVEL']='4';env['NUM_JOBS']='4';env['CPATH']=str(H.parent/'2026-09-24-zisk-component-suite/dependencies')+(':'+env['CPATH'] if env.get('CPATH') else '')
 subprocess.run(['cargo','build','--release','--locked','-j','4'],cwd=H/'peer-host',env=env,check=True)
