from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
z='/opt/homebrew/opt/zig@0.15/bin/zig'
with build_lock(label='large-roster-qualification'):
 subprocess.run([z,'test','-OReleaseSafe','-mcpu=native','--dep','stwo_core','--dep','stwo_prover_engine','-Mroot=src/frontends/riscv/large_roster_test_root.zig','-Mstwo_core=src/core/mod.zig','--dep','stwo_core','--dep','stwo_backend_contracts','--dep','stwo_prover_api','-Mstwo_prover_engine=src/prover/mod.zig','--dep','stwo_core','-Mstwo_backend_contracts=src/backend/mod.zig','--dep','stwo_core','-Mstwo_prover_api=src/prover_api/mod.zig'],check=True,cwd=R)
