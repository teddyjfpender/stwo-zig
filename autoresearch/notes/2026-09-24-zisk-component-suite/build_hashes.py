from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent;ROOT=H.parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from zig_serial_build import build_lock
p=Path('/tmp/stwo-recursion-peer-research-20260921/pil2-proofman/pil2-stark/src');z='/opt/homebrew/opt/zig@0.15/bin/zig'
with build_lock(label='zisk-hashes-build'):
 subprocess.run([z,'c++','-O3','-std=c++17','-mcpu=native','-dynamiclib','-fPIC','-I'+str(p/'goldilocks/src'),'-I'+str(p/'starkpil/recursion_trace/gate_bands'),'-I/opt/homebrew/opt/gmp/include','-I/opt/homebrew/opt/libomp/include',str(H/'peer.cpp'),'-o',str(H/'peer.dylib')],check=True)
 subprocess.run([z,'build-lib','-dynamic','-OReleaseFast','-mcpu=native','--dep','stwo_core','-Mroot=src/frontends/riscv/zisk_component_benchmark.zig','-Mstwo_core=src/core/mod.zig','-femit-bin='+str(H/'local.dylib')],check=True,cwd=ROOT)
