#!/usr/bin/env python3
"""Rebuild the RV64 native CUDA image the way the accepted P1 images were built.

The accepted node-peaks image (pause-builds.json native, sha 604d88af) is
produced by recompiling the hand-written native sources
(src/backends/cuda/native/**) and relinking them against the frozen AOT
objects of a prior link (link-inputs.json). The resident image builder
(rv64_cuda_resident_image_build.py) links a different object set and its
image fails at service start with `error: Unexpected` [M], so M8 memory
uses this recipe. The frozen objects are never written: native objects are
compiled into OUT/objects, and every link-input path outside the native
directory must keep its recorded SHA-256.

  python3 scripts/rv64_m8_native_relink.py --base-link-inputs LINK.json --out DIR
"""
import argparse
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rv64_cuda_native_library_build as N  # noqa: E402
import rv64_m3_pod as P  # noqa: E402
import rv64_m7_integration_stack as S  # noqa: E402

ROOT = HERE.parent
NATIVE = Path('/workspace/m3/build/m7-integrate/cuda/native')
OBSERVER_SYMBOLS = ['stwo_exec_context_allocation_observer_begin_v1', 'stwo_exec_context_allocation_observer_next_v1',
                    'stwo_exec_context_allocation_observer_end_v1', 'stwo_exec_context_allocation_observer_bind_v1',
                    'stwo_exec_context_allocation_observer_capability_v1']


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--base-link-inputs', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    out = args.out.resolve()
    (out / 'objects').mkdir(parents=True, exist_ok=False)
    src = ROOT / 'src/backends/cuda/native'
    nvcc = '/usr/local/cuda/bin/nvcc'
    flags = ['-O3', '-std=c++17', '-lineinfo', '-gencode', 'arch=compute_120,code=sm_120',
             '-Xcompiler=-fPIC,-pthread', '-I' + str(src)]
    version = subprocess.check_output([nvcc, '--version'], text=True)
    N.configure_object_store(Path('/workspace/m3/cache/cuda-objects'), [(str(ROOT), '@ROOT'), (str(out / 'objects'), '@BUILD')])
    base = json.loads(args.base_link_inputs.read_text())
    receipt = {'schema': 'rv64-m8-native-relink/v1', 'base_link_inputs': str(args.base_link_inputs),
               'base_link_inputs_sha256': S.sha(args.base_link_inputs), 'source_root': str(ROOT),
               'source_sha256_count': 0, 'steps': []}
    source_map = S.source_hashes(ROOT)
    receipt['source_sha256_count'] = len(source_map)
    argv = list(base['argv'])
    for index, name in enumerate(argv):
        path = Path(name)
        if path.parent != NATIVE or not path.name.endswith('.cu.o'):
            if name in base['objects_sha256']:
                assert S.sha(path) == base['objects_sha256'][name], 'frozen AOT object changed: ' + name
            continue
        relative = path.name[:-2].replace('-', '/', 1)
        source = src / relative
        assert source.is_file(), source
        obj = out / 'objects' / path.name
        started = time.monotonic()
        hit = N.compile_native(nvcc, version, flags, source, obj, out / (path.name + '.log'), 2400)
        receipt['steps'].append({'source': relative, 'cached': hit, 'seconds': round(time.monotonic() - started, 2),
                                 'sha256': S.sha(obj), 'base_sha256': base['objects_sha256'].get(name)})
        argv[index] = str(obj)
    library = out / 'libstwo-rv64-native.so'
    argv[argv.index('-o') + 1] = str(library)
    receipt['argv'] = argv
    S.write(out / 'relink.json', receipt)
    with open('/workspace/m3/locks/build.1.lock', 'a') as lock:  # link and Zig link never compete for host RAM
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX)
        with (out / 'link.log').open('w') as log:
            started = time.monotonic()
            code = subprocess.run(argv, env=dict(os.environ, TMPDIR='/workspace/m3/tmp'), stdout=log, stderr=subprocess.STDOUT).returncode
            receipt['link_seconds'] = round(time.monotonic() - started, 1)
    receipt['link_exit_code'] = code
    if code:
        S.write(out / 'relink.json', receipt)
        raise SystemExit('link failed; see ' + str(out / 'link.log'))
    lib = C.CDLL(str(library))
    required = json.loads((src / 'rv64/required_symbols.json').read_text())['symbols'] + OBSERVER_SYMBOLS
    missing = [n for n in required if not hasattr(lib, n)]
    assert not missing, missing
    assert lib.stwo_exec_context_allocation_observer_capability_v1() == 1
    receipt.update(library=str(library), library_sha256=S.sha(library), required_exports_checked=len(required),
                   changed_objects=[s['source'] for s in receipt['steps'] if s['sha256'] != s['base_sha256']],
                   stack_admission=P.stack_admission(library, 12544))
    assert S.source_hashes(ROOT) == source_map, 'source changed during build'
    receipt['status'] = 'NATIVE_RELINK_PASS'
    S.write(out / 'relink.json', receipt)
    print(json.dumps({k: receipt[k] for k in ('status', 'library_sha256', 'changed_objects', 'link_seconds')}))


if __name__ == '__main__':
    main()
