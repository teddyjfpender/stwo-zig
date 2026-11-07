#!/usr/bin/env python3
"""k-merkle image: the shared opt-combined image (lib 25d0e62f) with only the named native TUs recompiled.

Reuses the final link command of /workspace/m3/build/m8-opt-combined/img/build.json (P1 native relink +
T5 relink, see opt-combined/compose_image.py) and swaps the objects of the given sources
(paths relative to src/backends/cuda/native, e.g. rv64/trace.cu), compiled with the same flags as
scripts/rv64_m8_native_relink.py. Every other object must keep its recorded SHA-256.

usage: compose_image.py <src-root> <out-dir> <tu> [<tu> ...]
"""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path('/workspace/m3/build/m8-opt-combined')


def main():
    root, out, tus = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3:]
    assert tus, __doc__
    sys.path.insert(0, str(root / 'scripts'))
    import rv64_cuda_native_library_build as N
    import rv64_m7_integration_stack as S
    src = root / 'src/backends/cuda/native'
    nvcc = '/usr/local/cuda/bin/nvcc'
    flags = ['-O3', '-std=c++17', '-lineinfo', '-gencode', 'arch=compute_120,code=sm_120',
             '-Xcompiler=-fPIC,-pthread', '-I' + str(src)]
    version = subprocess.check_output([nvcc, '--version'], text=True)
    (out / 'objects').mkdir(parents=True, exist_ok=True)
    (out / 'native').mkdir(parents=True, exist_ok=True)
    N.configure_object_store(Path('/workspace/m3/cache/cuda-objects'), [(str(root), '@ROOT'), (str(out / 'objects'), '@BUILD')])
    base = json.loads((BASE / 'img/build.json').read_text())
    argv = list(base['link_command'])
    started = time.monotonic()
    steps = []
    for tu in tus:
        name = tu.replace('/', '-', 1) + '.o'
        old = str(BASE / 'nr/objects' / name)
        assert argv.count(old) == 1, old
        obj = out / 'objects' / name
        t = time.monotonic()
        hit = N.compile_native(nvcc, version, flags, src / tu, obj, out / (name + '.log'), 2400)
        steps.append({'source': tu, 'cached': hit, 'seconds': round(time.monotonic() - t, 1),
                      'sha256': S.sha(obj), 'base_sha256': S.sha(old)})
        argv[argv.index(old)] = str(obj)
    library = out / 'native/libstwo-rv64-native.so'
    argv[argv.index('-o') + 1] = str(library)
    # The caller already holds one build lock (img1.sh: flock build.2) for the
    # compiles; the link runs under that same lock. Taking build.1 here as
    # well queued the link behind other streams' Zig builds for > 1 h.
    with (out / 'link.log').open('w') as log:
        t = time.monotonic()
        code = subprocess.run(argv, env=dict(os.environ, TMPDIR='/workspace/m3/tmp'), stdout=log, stderr=subprocess.STDOUT).returncode
        link_seconds = round(time.monotonic() - t, 1)
    assert code == 0, 'link failed; see ' + str(out / 'link.log')
    lib = ctypes.CDLL(str(library))
    required = json.loads((src / 'rv64/required_symbols.json').read_text())['symbols'] + ['stwo_blake2s_merkle_layers_on']
    missing = [n for n in required if not hasattr(lib, n)]
    assert not missing, missing
    lib_sha = S.sha(library)
    runtime = json.loads((BASE / 'img/runtime.json').read_text())
    runtime['scope'] = 'k-merkle image: opt-combined (25d0e62f) relinked with recompiled ' + ', '.join(tus)
    runtime['assets']['library'] = str(library)
    runtime['asset_sha256']['library'] = lib_sha
    (out / 'runtime.json').write_text(json.dumps(runtime, indent=2) + '\n')
    receipt = {'schema': 'rv64-m8-k-merkle-image/v1', 'label': 'M', 'base_build': str(BASE / 'img/build.json'),
               'base_library_sha256': base['library_sha256'], 'steps': steps, 'link_seconds': link_seconds,
               'library': str(library), 'library_sha256': lib_sha, 'library_bytes': library.stat().st_size,
               'required_exports_checked': len(required), 'seconds': round(time.monotonic() - started, 1)}
    (out / 'image.json').write_text(json.dumps(receipt, indent=1) + '\n')
    print(json.dumps({k: receipt[k] for k in ('library_sha256', 'library_bytes', 'seconds')}))


if __name__ == '__main__':
    main()
