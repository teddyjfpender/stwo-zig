from pathlib import Path
import subprocess,sys,os,shutil,json,hashlib
h=Path(__file__).resolve().parent;r=h.parents[2];sys.path.insert(0,str(r/'scripts'))
from zig_serial_build import build_lock
g=r/'autoresearch/benchmarks/guest_runtime/ethereum'
with build_lock(label='evm-fast-memory-guest'):
 out=h/'ethereum-block-evm-final.elf'
 if out.exists():raise FileExistsError(out)
 env=os.environ.copy();env['RUSTFLAGS']='-C link-arg=-Tlinker.ld'
 subprocess.run(['cargo','+nightly-2026-08-08','build','--locked','--offline','-j','2','--release','--target','riscv32i-stwo.json','-Z','json-target-spec','-Z','build-std=core,alloc','-Z','build-std-features=compiler-builtins-mem'],cwd=g,env=env,check=True)
 shutil.copy2(g/'target/riscv32i-stwo/release/stwo-ethereum-guest',out)
 files=[*g.glob('src/*.rs'),g/'Cargo.toml',g/'Cargo.lock',g.parent/'fast_memory_v1.rs',out]
 (h/'evm-final-build-manifest.json').write_text(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},indent=2)+'\n')
