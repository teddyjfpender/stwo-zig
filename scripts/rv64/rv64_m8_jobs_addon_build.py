#!/usr/bin/env python3
"""Build libstwo-rv64-jobs.so, the M8 job-runtime CUDA addon.

Compiles every .cu under src/backends/cuda/native/rv64/jobs/ and links the
objects against a frozen base image (libstwo-rv64-native.so) without copying
or rebuilding it, following the libstwo-rv64-outer-fs-ops.so precedent
(vectors/reports/rv64-m7-20261105/outer-fs-ops/build.json). Writes build.json
with argv, toolkit version and SHA-256 of sources, objects, addon and base.

Run on the pod under one build lock, e.g.
  flock /workspace/m3/locks/build.2.lock python3 scripts/rv64/rv64_m8_jobs_addon_build.py \\
      --base /workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so \\
      --out /workspace/m3/build/m8-runtime/jobs-addon
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / 'src/backends/cuda/native'
SOURCES = NATIVE / 'rv64/jobs'
ADDON = 'libstwo-rv64-jobs.so'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def commands(base, out, sources, nvcc='nvcc', arch='120'):
    compile_argv, objects = [], []
    for source in sources:
        obj = out / (source.stem + '.o')
        objects.append(obj)
        compile_argv.append([nvcc, '-O3', '-std=c++17', '-lineinfo', '-gencode', f'arch=compute_{arch},code=sm_{arch}',
                             '-Xcompiler=-fPIC,-pthread', f'-I{NATIVE}', '-c', str(source), '-o', str(obj)])
    link_argv = [nvcc, '-shared', '-Xcompiler=-fPIC,-pthread', *map(str, objects), f'-L{base.parent}',
                 '-Xlinker=--no-as-needed', f'-l:{base.name}', f'-Xlinker=-rpath,{base.parent}', '-o', str(out / ADDON)]
    return compile_argv, link_argv, objects


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--base', required=True, type=Path, help='frozen libstwo-rv64-native.so to link against')
    p.add_argument('--out', required=True, type=Path, help='new output directory (never a frozen image path)')
    p.add_argument('--nvcc', default='nvcc')
    p.add_argument('--arch', default='120')
    args = p.parse_args(argv)
    base = args.base.resolve()
    if not base.is_file():
        p.error(f'missing base image {base}')
    out = args.out.resolve()
    if out == base.parent or (out / base.name).exists():
        p.error('output directory must not hold the base image')
    out.mkdir(parents=True, exist_ok=True)
    sources = sorted(SOURCES.glob('*.cu'))
    if not sources:
        p.error(f'no addon sources under {SOURCES}')
    compile_argv, link_argv, objects = commands(base, out, sources, args.nvcc, args.arch)
    for step in compile_argv + [link_argv]:
        print(' '.join(step), flush=True)
        subprocess.run(step, check=True)
    headers = sorted(SOURCES.glob('*.h')) + sorted(SOURCES.glob('*.cuh'))
    receipt = {
        'schema': 'rv64-m8-jobs-addon-build/v1',
        'scope': 'Additive M8 job-runtime addon; frozen base image unchanged and not copied',
        'nvcc_version': subprocess.run([args.nvcc, '--version'], capture_output=True, text=True).stdout,
        'compile_argv': compile_argv,
        'link_argv': link_argv,
        'source_sha256': {str(s.relative_to(ROOT)): sha(s) for s in sources + headers + [Path(__file__)]},
        'artifacts': {str(f): {'bytes': f.stat().st_size, 'sha256': sha(f)} for f in objects + [out / ADDON]},
        'base': {'path': str(base), 'bytes': base.stat().st_size, 'sha256': sha(base)},
    }
    (out / 'build.json').write_text(json.dumps(receipt, indent=1) + '\n')
    print(out / ADDON)
    return 0


if __name__ == '__main__':
    sys.exit(main())
