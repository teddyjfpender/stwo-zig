from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent;R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='ethereum-real-block-fixture'):
 subprocess.run(['cargo','build','--locked','--release','-j','2'],cwd=R/'autoresearch/benchmarks/guest_runtime/projection',check=True)
 subprocess.run([str(R/'autoresearch/benchmarks/guest_runtime/projection/target/release/stwo-ethereum-input-projection'),str(H/'mainnet_24628607_66_7_zec_reth.bin'),str(H/'fixture')],check=True)
