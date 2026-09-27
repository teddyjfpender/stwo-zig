from pathlib import Path
import sys,subprocess
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
label=sys.argv[1];z='/opt/homebrew/opt/zig@0.15/bin/zig'
with build_lock(label='system-stage-build'):
 for name,root in [('system','src/frontends/riscv/zisk_system_benchmark.zig'),('protocol','src/prover/zisk_protocol_benchmark.zig'),('primitive','src/frontends/riscv/zisk_primitive_benchmark.zig')]:
  subprocess.run([z,'build-lib','-dynamic','-OReleaseFast','-mcpu=native','--dep','stwo_core','-Mroot='+root,'-Mstwo_core=src/core/mod.zig','-femit-bin='+str(H/(label+'-'+name+'.dylib'))],cwd=R,check=True)
