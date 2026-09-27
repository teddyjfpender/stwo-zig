from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent;ROOT=H.parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from zig_serial_build import build_lock
p=Path('/tmp/stwo-recursion-peer-research-20260921/pil2-proofman/pil2-stark/src');g=p/'goldilocks/src';z='/opt/homebrew/opt/zig@0.15/bin/zig'
includes=sorted({str(f.parent) for f in p.rglob('*.hpp')} | {str(p/'bn128/src'),str(H/'dependencies')})
with build_lock(label='zisk-protocol-build'):
 subprocess.run([z,'c++','-O3','-std=c++17','-mcpu=native','-dynamiclib','-fPIC',*['-I'+i for i in includes],'-I/opt/homebrew/opt/gmp/include','-I/opt/homebrew/opt/libomp/include',str(H/'peer_protocol.cpp'),str(p/'starkpil/transcript/transcriptGL.cpp'),*[str(g/s) for s in ['goldilocks_base_field.cpp','blake3_goldilocks.cpp','poseidon_goldilocks.cpp','poseidon2_goldilocks.cpp']],'-L/opt/homebrew/opt/gmp/lib','-lgmp','-L/opt/homebrew/opt/libomp/lib','-lomp','-o',str(H/'peer_protocol.dylib')],check=True)
 subprocess.run([z,'build-lib','-dynamic','-OReleaseFast','-mcpu=native','--dep','stwo_core','-Mroot=src/prover/zisk_protocol_benchmark.zig','-Mstwo_core=src/core/mod.zig','-femit-bin='+str(H/'local_protocol.dylib')],cwd=ROOT,check=True)
