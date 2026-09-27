from pathlib import Path
import subprocess,sys,os,shutil,hashlib,json
h=Path(__file__).resolve().parent;r=h.parents[2];sys.path.insert(0,str(r/'scripts'))
from zig_serial_build import build_lock
g=r/'autoresearch/benchmarks/guest_runtime/ethereum'
with build_lock(label='evm-recovery-guests'):
 env=os.environ.copy();env['RUSTFLAGS']='-C link-arg=-Tlinker.ld'
 for mode,flags in [('collector',['--features','collect-evm-hints']),('native',[])]:
  out=h/f'ethereum-block-evm-{mode}.elf'
  if out.exists():raise FileExistsError(out)
  subprocess.run(['cargo','+nightly-2026-08-08','build','--locked','--offline','-j','2','--release','--target','riscv32i-stwo.json','-Z','json-target-spec','-Z','build-std=core,alloc','-Z','build-std-features=compiler-builtins-mem',*flags],cwd=g,env=env,check=True)
  shutil.copy2(g/'target/riscv32i-stwo/release/stwo-ethereum-guest',out)
 files=[*g.glob('src/*.rs'),g/'Cargo.toml',g/'Cargo.lock',h/'ethereum-block-evm-collector.elf',h/'ethereum-block-evm-native.elf']
 (h/'evm-guest-build-manifest.json').write_text(json.dumps({str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},indent=2)+'\n')
