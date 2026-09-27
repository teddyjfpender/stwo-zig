from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='system-stage-qualification'):
 subprocess.run(['/opt/homebrew/opt/zig@0.15/bin/zig','test','-OReleaseSafe','--dep','stwo_core','-Mroot=src/frontends/riscv/zisk_system_benchmark.zig','-Mstwo_core=src/core/mod.zig'],cwd=R,check=True)
