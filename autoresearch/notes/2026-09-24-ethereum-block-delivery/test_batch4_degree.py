from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
z='/opt/homebrew/opt/zig@0.15/bin/zig'
with build_lock(label='ethereum-auth-build'):
 subprocess.run([z,'test','--test-filter','compression committed proof','-OReleaseFast','-lc','-mcpu=native','--dep','stwo_core','--dep','stwo_prover_engine','--dep','stwo_cpu_backend','--dep','interop_postcard','--dep','stwo_prover_api','-Mroot=src/frontends/riscv/blake3_wide_batch_test_root.zig','-Mstwo_core=src/core/mod.zig','--dep','stwo_core','--dep','stwo_backend_contracts','--dep','stwo_prover_api','-Mstwo_prover_engine=src/prover/mod.zig','--dep','stwo_core','-Mstwo_backend_contracts=src/backend/mod.zig','--dep','stwo_core','-Mstwo_prover_api=src/prover_api/mod.zig','--dep','stwo_core','--dep','stwo_prover_engine','--dep','stwo_backend_contracts','-Mstwo_cpu_backend=src/backends/cpu_scalar/mod.zig','--dep','stwo_core','--dep','stwo_proof_wire','-Minterop_postcard=src/interop/postcard.zig','--dep','stwo_core','-Mstwo_proof_wire=src/interop/proof_wire/mod.zig'],check=True,cwd=R)
