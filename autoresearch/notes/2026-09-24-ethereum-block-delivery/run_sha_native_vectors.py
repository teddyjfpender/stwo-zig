"""Build and execute native RV32 SHA SDK vectors against hashlib SHA-256."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from zig_serial_build import build_lock

runtime = ROOT / 'autoresearch/benchmarks/guest_runtime'
crate = runtime / 'sha256_precompile_tests'
out = HERE / 'sha-native-vectors-v1'
out.mkdir(exist_ok=False)
lengths = [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1024]
message = bytes((i * 71 + 9) & 255 for i in range(1032))
(out / 'input.bin').write_bytes(b'')
(out / 'expected.bin').write_bytes(b''.join(hashlib.sha256(message[offset:offset + length]).digest()
                                          for offset in range(4) for length in lengths))
record = {'proof_verified': False, 'execution_verified': False, 'vectors': 44,
          'expected_compressions': 4 * sum((length + 9 + 63) // 64 for length in lengths)}
with build_lock(label='native-sha-sdk-vectors'):
    env = os.environ.copy()
    env['RUSTFLAGS'] = '-C link-arg=-T' + str(runtime / 'ethereum/linker.ld')
    command = ['cargo', '+nightly-2026-08-08', 'build', '--locked', '--offline', '-j', '2',
               '--release', '--features', 'sha256-precompile', '--bin', 'sha-native-vectors',
               '--target', str(runtime / 'ethereum/riscv32i-stwo.json'), '-Z', 'json-target-spec',
               '-Z', 'build-std=core', '-Z', 'build-std-features=compiler-builtins-mem']
    record['build_command'] = command
    with (out / 'build.log').open('x') as log:
        subprocess.run(command, cwd=crate, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    elf = out / 'guest.elf'
    shutil.copy2(crate / 'target/riscv32i-stwo/release/sha-native-vectors', elf)
    command = [str(HERE / 'block-execute-sha'), str(elf), str(out / 'input.bin'),
               str(out / 'expected.bin'), str(out / 'execution.json'), '262144']
    record['execution_command'] = command
    with (out / 'execution.log').open('x') as log:
        subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    result = json.loads((out / 'execution.json').read_text())
    if result['sha256_compression_calls'] != record['expected_compressions']:
        raise ValueError('native compression count differs from padding specification')
    record['execution_verified'] = True
    sources = [crate / 'Cargo.toml', crate / 'Cargo.lock', crate / 'src/lib.rs',
               crate / 'src/native_vectors.rs', runtime / 'sha256_precompile_v1.rs',
               runtime / 'ethereum_admission_v1.rs', runtime / 'ethereum/linker.ld',
               runtime / 'ethereum/riscv32i-stwo.json', elf, out / 'expected.bin', HERE / 'block-execute-sha']
    record['sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
