from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'scripts'))
from zig_serial_build import build_lock
z='/opt/homebrew/opt/zig@0.15/bin/zig';p='/tmp/stwo-recursion-peer-research-20260921/pil2-proofman/pil2-stark/src/goldilocks/src';n=str(Path(__file__).resolve().parent)
with build_lock(label='zisk-more-build'):
 subprocess.run([z,'c++','-O3','-std=c++17','-mcpu=native','-dynamiclib','-fPIC','-I'+p,'-I/opt/homebrew/opt/gmp/include','-I/opt/homebrew/opt/libomp/include',n+'/peer_more.cpp',p+'/goldilocks_base_field.cpp',p+'/goldilocks_cubic_extension.cpp',p+'/blake3_goldilocks.cpp','-L/opt/homebrew/opt/gmp/lib','-lgmp','-L/opt/homebrew/opt/libomp/lib','-lomp','-o',n+'/peer_more.dylib'],check=True)
 subprocess.run([z,'build-lib','-dynamic','-OReleaseFast','-mcpu=native','--dep','stwo_core','-Mroot=src/frontends/riscv/zisk_more_benchmark.zig','-Mstwo_core=src/core/mod.zig','-femit-bin='+n+'/local_more.dylib'],check=True,cwd=ROOT)
