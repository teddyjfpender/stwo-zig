"""Bounded canonical NVIDIA build and official-verifier qualification."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import signal
import shutil
from pathlib import Path
import subprocess
import sys
import tarfile
import time

root = Path('/workspace/stwo-zig')
zig = '/opt/zig/zig-x86_64-linux-0.15.2/zig'
identity = json.loads(Path('/workspace/snapshot.json').read_text())
# Bind incremental fixes to the actual source snapshot being compiled, rather
# than reusing the original archive's source identity after an update.
digest = hashlib.sha256()
with tarfile.open('/workspace/source.tar.gz', 'r:gz') as archive:
    names = sorted(member.name for member in archive if member.isfile())
for name in names:
    path = root / name
    payload = path.read_bytes()
    encoded = name.encode()
    digest.update(len(encoded).to_bytes(8, 'little'))
    digest.update(encoded)
    digest.update(len(payload).to_bytes(8, 'little'))
    digest.update(payload)
if digest.hexdigest() != identity['dirty_content_sha256']:
    raise RuntimeError('compiled sources differ from the authenticated snapshot')
Path('/workspace/compiled-snapshot.json').write_text(json.dumps(identity, indent=2) + '\n')
env = dict(os.environ, STWO_CUDA_ARCHIVE_CACHE='/workspace/cuda-archive-cache',
           LD_LIBRARY_PATH='/usr/local/cuda/lib64:' + os.environ.get('LD_LIBRARY_PATH', ''))
if Path('/workspace/native-cubins/manifest.json').exists() and os.environ.get('STWO_CUDA_DISABLE_CUBIN_IMPORT') != '1':
    env['STWO_CUDA_AOT_CUBIN_IMPORT_ROOT'] = '/workspace/native-cubins'
flags = ['-Doptimize=ReleaseFast', '-Dimplementation-commit=' + identity['implementation_commit'],
         '-Dimplementation-tree=' + identity['implementation_tree'], '-Dimplementation-dirty=true',
         '-Dimplementation-dirty-content-sha256=' + identity['dirty_content_sha256']]

def run(label, command, timeout=900, cwd=root, extra_env=None):
    print('START ' + label, flush=True)
    started = time.monotonic()
    with Path('/workspace/' + label + '.log').open('w') as log:
        process = subprocess.Popen(command, cwd=cwd, env=extra_env or env,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        result = process
    print(f'END {label}: exit={result.returncode} seconds={time.monotonic()-started:.3f}', flush=True)
    if result.returncode:
        print('\n'.join(Path('/workspace/' + label + '.log').read_text().splitlines()[-60:]), flush=True)
        raise RuntimeError(label + ' failed')

cuda_flags = ['-Dcuda-nvcc=/usr/local/cuda/bin/nvcc', '-Dcuda-host-cxx=/usr/bin/g++',
              '-Dcuda-host-runtime=/usr/lib/x86_64-linux-gnu/libstdc++.so.6',
              '-Dcuda-host-unwind-runtime=/usr/lib/x86_64-linux-gnu/libgcc_s.so.1',
              '-Dcuda-ar=/usr/bin/ar', '-Dcuda-home=/usr/local/cuda',
              '-Dcuda-library-dir=/usr/local/cuda/lib64', '-Dcuda-arch=sm_90',
              '-Dcuda-build-jobs=12', '-j2', '--summary', 'all']

verifier = root / 'tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier'
cached_verifier = Path('/workspace/cached-official-verifier')
cached_identity = identity.get('cached_official_verifier')
reuse_verifier = cached_identity is not None and cached_verifier.is_file()
if reuse_verifier:
    if hashlib.file_digest(cached_verifier.open('rb'), 'sha256').hexdigest() != cached_identity['binary_sha256']:
        raise RuntimeError('cached official verifier differs from its snapshot identity')
    verifier_source = hashlib.sha256()
    for name in names:
        if not name.startswith('tools/stwo-cairo-official-verifier-rs/'):
            continue
        encoded = name.encode()
        payload = (root / name).read_bytes()
        verifier_source.update(len(encoded).to_bytes(8, 'little')); verifier_source.update(encoded)
        verifier_source.update(len(payload).to_bytes(8, 'little')); verifier_source.update(payload)
    if verifier_source.hexdigest() != cached_identity['source_sha256']:
        raise RuntimeError('cached official verifier was built from different project sources')
    verifier.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(cached_verifier, verifier)
    verifier.chmod(0o755)
    print('REUSE: authenticated pinned Linux official verifier', flush=True)

with ThreadPoolExecutor(max_workers=2) as jobs:
    cuda = jobs.submit(run, 'cuda-build', [zig, 'build', 'stwo-cairo-cuda', *flags, *cuda_flags])
    rust = None if reuse_verifier else jobs.submit(run, 'official-verifier-build', ['/root/.cargo/bin/cargo',
                       '+nightly-2026-01-15', 'build', '--release', '--locked'],
                       cwd=root / 'tools/stwo-cairo-official-verifier-rs')
    cuda.result()
    if rust is not None:
        rust.result()
run('preprocessed-build', [zig, 'build', 'cairo-preprocessed-export', *flags, '-j2'])
preprocessed_path = Path('/workspace/canonical.stwzppc')
if preprocessed_path.exists():
    if hashlib.file_digest(preprocessed_path.open('rb'), 'sha256').hexdigest() != '4d4fda06dfa3bca19554510a158f6c50abad06a74d29c17885ed4cbb88ada34d':
        raise RuntimeError('retained canonical preprocessed coefficients differ from pinned local export')
    print('REUSE: authenticated canonical preprocessed coefficients', flush=True)
else:
    run('preprocessed-export', [str(root / 'zig-out/bin/cairo-preprocessed-export'),
                               str(preprocessed_path), 'canonical'])
prover = root / 'zig-out/bin/stwo-cairo-cuda'
run_output = Path('/workspace/qualified-runs') / (identity['dirty_content_sha256'][:16] + '-' + str(time.time_ns()))
run_output.mkdir(parents=True, exist_ok=False)
print('OUTPUT: ' + str(run_output), flush=True)
tiny_proof = run_output / 'tiny-proof.json'
tiny_backend = run_output / 'tiny-backend.json'
tiny_verification = run_output / 'tiny-verification.json'
failure_path = str(run_output / 'tiny.unverified.bin')
proof_env = dict(env, STWO_CAIRO_CUDA_ARTIFACT_DIR=str(root / 'vectors/cairo'),
                 STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS='/workspace/canonical.stwzppc',
                 STWO_CAIRO_CUDA_PREPROCESSED_VARIANT='canonical',
                 STWO_CAIRO_CUDA_FAILURE_TRANSPORT=failure_path)
if os.environ.get('STWO_CUDA_SOURCE_DIAGNOSTIC') == '1':
    source_diagnostics = Path('/workspace/source-diagnostics-' + identity['dirty_content_sha256'][:16])
    source_diagnostics.mkdir(exist_ok=False)
    proof_env['STWO_CAIRO_CUDA_SOURCE_DIAGNOSTIC'] = str(source_diagnostics)
run('tiny-proof', [str(prover), 'prove', '--backend', 'cuda', '--input',
                   str(root / 'vectors/cairo/official/all_opcodes.prover_input.cpi'),
                   '--output', str(tiny_proof), '--report-out',
                   str(tiny_backend), '--repeat', '1'], extra_env=proof_env, timeout=180)
run('tiny-official-verification', [str(verifier), 'verify', '--proof', str(tiny_proof),
                                  '--channel', 'blake2s', '--proof-format', 'json',
                                  '--result', str(tiny_verification)], timeout=60)
sys.path.insert(0, str(root / 'scripts'))
from benchmark_cairo_cuda import check_receipts, sha
check_receipts(json.loads(tiny_backend.read_text()),
               json.loads(tiny_verification.read_text()),
               tiny_proof, input_sha256=sha(root / 'vectors/cairo/official/all_opcodes.prover_input.cpi'),
               executable_sha256=sha(prover))
run('sn-pie-suite', [sys.executable, str(root / 'scripts/benchmark_cairo_cuda.py'),
                    '--prover', str(prover), '--verifier', str(verifier), '--input-dir', '/workspace/inputs',
                    '--artifact-dir', str(root / 'vectors/cairo'), '--preprocessed', '/workspace/canonical.stwzppc',
                    '--out', str(run_output / 'sn-pie-suite'), '--timeout', '240'], timeout=1100)
print('COMPLETE: canonical NVIDIA suite accepted by official Rust verifier', flush=True)
