from pathlib import Path
import os,sys,subprocess
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='ethereum-auth-guests'):
 subprocess.run(['cargo','build','--release','--locked'],cwd=H/'guest-stwo',check=True)

 import shutil
 shutil.copy2(H/'guest-stwo/target/riscv32im-unknown-none-elf/release/eth-auth-stwo',H/'eth-auth-stwo-expanded.elf')
