"""Profile only the already qualified v7/v8 comparison products."""

import os
from pathlib import Path
import subprocess

root = Path('/workspace/stwo-zig')
out = Path('/workspace/hopper-v8-experiments')
env = dict(os.environ,
           STWO_CAIRO_CUDA_ARTIFACT_DIR=str(root / 'vectors/cairo'),
           STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS='/workspace/canonical.stwzppc',
           STWO_CAIRO_CUDA_PREPROCESSED_VARIANT='canonical',
           LD_LIBRARY_PATH='/usr/local/cuda/lib64:' + os.environ.get('LD_LIBRARY_PATH', ''))

for label, number, binary in (
    ('baseline', 1, Path('/workspace/candidate-v7.bin')),
    ('candidate', 1, root / 'zig-out/bin/stwo-cairo-cuda'),
    ('candidate', 3, root / 'zig-out/bin/stwo-cairo-cuda'),
):
    prefix = f'profile-{label}-pie-{number}'
    proof = out / (prefix + '.proof.json')
    report = out / (prefix + '.backend.json')
    profile = out / (prefix + '.nsys-rep')
    command = [
        'python3', str(root / 'autoresearch/cli/stwo-prof'),
        'cuda', 'systems', '--output', str(profile), '--timeout', '180', '--',
        str(binary), 'prove', '--backend', 'cuda', '--input',
        f'/workspace/inputs/sn-pie-{number}.cpi', '--output', str(proof),
        '--report-out', str(report), '--repeat', '1',
    ]
    with (out / (prefix + '.log')).open('w') as log:
        subprocess.run(command, cwd=root, env=env, stdout=log,
                       stderr=subprocess.STDOUT, check=True, timeout=240)
    with (out / (prefix + '-stats.log')).open('w') as log:
        subprocess.run([
            'nsys', 'stats', '--report',
            'cuda_gpu_kern_sum,cuda_api_sum,cuda_gpu_mem_time_sum',
            '--format', 'csv', str(profile),
        ], cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                       check=True, timeout=180)
    print(prefix, 'complete', flush=True)
