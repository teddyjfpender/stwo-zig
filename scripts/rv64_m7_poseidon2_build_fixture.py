#!/usr/bin/env python3
"""Build only the CPU synthetic Poseidon fixture under the shared pod lock."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--binary', required=True)
p.add_argument('--receipt', required=True)
p.add_argument('--lock', default='/workspace/m3/locks/build.3.lock')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
modules = [
    ('stwo_core', 'src/core/mod.zig', []),
    ('stwo_backend_contracts', 'src/backend/mod.zig', ['stwo_core']),
    ('stwo_prover_api', 'src/prover_api/mod.zig', ['stwo_core']),
    ('stwo_prover_engine', 'src/prover/mod.zig', ['stwo_core','stwo_backend_contracts','stwo_prover_api']),
    ('stwo_cpu_backend', 'src/backends/cpu_scalar/mod.zig', ['stwo_core','stwo_backend_contracts','stwo_prover_api','stwo_prover_engine']),
    ('stwo_proof_wire', 'src/interop/proof_wire/mod.zig', ['stwo_core']),
]
command = ['/workspace/zig/zig', 'build-exe', '-OReleaseSafe']
for name, _, _ in modules:
    command += ['--dep', name]
command += ['-Mroot=src/tests/native/prover/poseidon2_stark_fixture_main.zig']
for name, path, dependencies in modules:
    command += ['-OReleaseSafe']
    for dependency in dependencies:
        command += ['--dep', dependency]
    command += ['-M'+name+'='+path]
command += ['-femit-bin='+a.binary]
env = os.environ.copy()
env.update(ZIG_GLOBAL_CACHE_DIR='/workspace/m3/cache/zig-global', TMPDIR='/workspace/m3/tmp')
source_paths = sorted({p for prefix in ['src/core','src/prover','src/prover_api','src/backend','src/backends/cpu_scalar','src/interop/proof_wire']
                       for p in (root/prefix).rglob('*.zig')} | set((root/'src/tests/native/prover').glob('poseidon2_stark*.zig')))
def fingerprint():
    h = hashlib.sha256()
    for path in source_paths:
        h.update(str(path.relative_to(root)).encode()+b'\0'+hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()
with open(a.lock, 'a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    before = fingerprint()
    result = subprocess.run(command, cwd=root, env=env)
    after = fingerprint()
receipt = {'scope':'synthetic boolean AIR only','command':command,'exit_code':result.returncode,
           'source_fingerprint_before':before,'source_fingerprint_after':after,'sources_unchanged':before==after}
if result.returncode == 0:
    receipt['binary_sha256'] = hashlib.sha256(Path(a.binary).read_bytes()).hexdigest()
Path(a.receipt).write_text(json.dumps(receipt,indent=2)+'\n')
raise SystemExit(result.returncode or (1 if before!=after else 0))
