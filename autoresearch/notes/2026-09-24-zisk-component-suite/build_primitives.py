from pathlib import Path
import subprocess,sys,os
H=Path(__file__).resolve().parent;ROOT=H.parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='zisk-primitives-build'):
 subprocess.run(['cargo','build','--release','--offline','--manifest-path',str(H/'rust-peer/Cargo.toml')],env={**os.environ,'RUSTFLAGS':'-C target-cpu=native'},check=True)
 subprocess.run(['/opt/homebrew/opt/zig@0.15/bin/zig','build-lib','-dynamic','-OReleaseFast','-mcpu=native','--dep','stwo_core','-Mroot=src/frontends/riscv/zisk_primitive_benchmark.zig','-Mstwo_core=src/core/mod.zig','-femit-bin='+str(H/'local_primitives.dylib')],cwd=ROOT,check=True)
