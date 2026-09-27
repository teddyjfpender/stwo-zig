from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
z='/opt/homebrew/opt/zig@0.15/bin/zig';p=Path('/tmp/stwo-recursion-peer-research-20260921/pil2-proofman/pil2-stark/src/goldilocks/src');label='before'; output=H/(sys.argv[1] if len(sys.argv)>1 else 'local.dylib')
with build_lock(label='pipeline-build'):
 if True:subprocess.run([z,'c++','-O3','-std=c++17','-mcpu=native','-dynamiclib','-fPIC','-I'+str(p),'-I/opt/homebrew/opt/gmp/include','-I/opt/homebrew/opt/libomp/include',str(H/'peer.cpp'),*[str(p/f) for f in ['goldilocks_base_field.cpp','blake3_goldilocks.cpp']],'-L/opt/homebrew/opt/gmp/lib','-lgmp','-L/opt/homebrew/opt/libomp/lib','-lomp','-o',str(H/'peer.dylib')],check=True)
 subprocess.run([z,'build-lib','-dynamic','-OReleaseFast','-mcpu=native','--dep','stwo_core','--dep','stwo_prover_engine','-Mroot=src/frontends/riscv/zisk_matched_commitment_benchmark.zig','-Mstwo_core=src/core/mod.zig','--dep','stwo_core','--dep','stwo_backend_contracts','--dep','stwo_prover_api','-Mstwo_prover_engine=src/prover/mod.zig','--dep','stwo_core','-Mstwo_backend_contracts=src/backend/mod.zig','--dep','stwo_core','-Mstwo_prover_api=src/prover_api/mod.zig','-femit-bin='+str(output)],check=True,cwd=R)
