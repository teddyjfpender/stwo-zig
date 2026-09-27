from pathlib import Path
import subprocess,sys,os,shutil,hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='ethereum-block-host-and-guest'):
 host=R/'autoresearch/benchmarks/guest_runtime/host_validation'
 subprocess.run(['cargo','build','--locked','--release','-j','2'],cwd=host,check=True)
 subprocess.run([str(host/'target/release/stwo-ethereum-host-validation'),str(H/'fixture/canonical-input.ssz'),str(H/'fixture/expected-output.bin')],check=True)
 guest=R/'autoresearch/benchmarks/guest_runtime/ethereum'
 env=os.environ.copy();env['RUSTFLAGS']='-C link-arg=-Tlinker.ld'
 subprocess.run(['cargo','+nightly-2026-08-08','build','--locked','-j','2','--release','--target','riscv32i-stwo.json','-Z','json-target-spec','-Z','build-std=core,alloc','-Z','build-std-features=compiler-builtins-mem'],cwd=guest,env=env,check=True)
 shutil.copy2(guest/'target/riscv32i-stwo/release/stwo-ethereum-guest',H/'ethereum-block.elf')
 paths=[H/'ethereum-block.elf',H/'fixture/canonical-input.ssz',H/'fixture/stwo-runner-input.bin',H/'fixture/expected-output.bin']
 (H/'block-artifacts.json').write_text(json.dumps({str(p.relative_to(H)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths},indent=2)+'\n')
