from pathlib import Path
import os,sys,subprocess
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='zisk-large-sha-guest-build'):
 env=os.environ.copy();env['CARGO_ENCODED_RUSTFLAGS']='\x1f'.join(['--cfg','zisk_guest','-C','link-arg=-T/tmp/stwo-recursion-peer-research-20260921/zisk/ziskbuild/zisk_linker_script.ld'])
 subprocess.run(['cargo','+stwo-zisk-peer-4','build','--release','--target','riscv64ima-zisk-zkvm-elf','-j','4'],cwd=H/'guest-zisk',env=env,check=True)
