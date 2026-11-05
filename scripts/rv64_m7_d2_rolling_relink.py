#!/usr/bin/env python3
"""Relink one experimental PCS TU against an exact frozen M6/cap128 image roster."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import time
import rv64_cuda_native_library_build as N
import rv64_cuda_private_host_symbols as PrivateHost


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('source-root', 'base-build', 'object-store', 'output'):
        p.add_argument('--' + key, required=True, type=Path)
    p.add_argument('--source-equivalent-host-dispatch', action='store_true', help='allow only the source-pinned core host dispatcher with identical dependencies')
    args = p.parse_args()
    root, out = args.source_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    baseline = json.loads(args.base_build.read_text())
    objects = []
    replaced = []
    cache = None
    equivalent = []
    for name, digest in baseline['objects'].items():
        if Path(name).name == 'rv64-pcs_native.cu.o':
            objects.append(None)
            replaced.append(len(objects) - 1)
            continue
        obj = Path(name)
        if not obj.is_file():
            if cache is None:
                cache = {}
                for stamp in args.object_store.glob('*/*/stamp.json'):
                    record = json.loads(stamp.read_text())
                    cache[record['object_sha256']] = stamp.parent / 'object.o'
            obj = cache.get(digest)
            if obj is None:
                # Dispatcher objects can predate the shared object store.
                # Sibling builds are read-only and accepted only by exact SHA.
                obj = next((candidate for candidate in args.base_build.parents[3].glob('*/cuda/aot-objects/' + Path(name).name) if N.sha(candidate) == digest), None)
        if obj is None or not obj.is_file() or N.sha(obj) != digest:
            obj = None
            if args.source_equivalent_host_dispatch and Path(name).name.startswith('core_composition_dispatch-'):
                base_cuda = args.base_build.parent.parent
                image = json.loads((base_cuda / 'image-build.json').read_text())
                source = base_cuda / 'core_composition_dispatch.cu'
                if image['source_sha256'].get(str(source)) != N.sha(source):
                    raise RuntimeError('frozen core dispatcher source changed')
                for candidate in args.base_build.parents[3].glob('*/cuda/aot-objects/' + Path(name).name):
                    stamp = candidate.with_suffix('.json')
                    if not stamp.is_file():
                        continue
                    record = json.loads(stamp.read_text())
                    candidate_cuda = candidate.parent.parent
                    checked = {}
                    for dependency, expected in record['dependencies'].items():
                        target = Path(dependency)
                        if target.is_relative_to(candidate_cuda):
                            target = base_cuda / target.relative_to(candidate_cuda)
                        elif '/src/' in str(target) and '/src/backends/cuda/native/' in str(target):
                            target = root / 'src/backends/cuda/native' / str(target).split('/src/backends/cuda/native/', 1)[1]
                        if not target.is_file() or N.sha(target) != expected:
                            break
                        checked[str(target)] = expected
                    else:
                        if N.sha(candidate) != record['object_sha256']:
                            continue
                        obj = candidate
                        equivalent.append({'original': name, 'original_sha256': digest, 'replacement': str(obj), 'replacement_sha256': N.sha(obj), 'frozen_source_sha256': N.sha(source), 'identical_dependency_sha256': checked})
                        break
            if obj is None:
                raise RuntimeError('missing frozen object or SHA mismatch: ' + name)
        objects.append(obj)
    if len(replaced) != 1:
        raise RuntimeError('expected exactly one frozen PCS object')
    native = root / 'src/backends/cuda/native'
    nvcc = '/usr/local/cuda/bin/nvcc'
    flags = ['-O3', '-std=c++17', '-lineinfo', '-gencode', 'arch=compute_120,code=sm_120', '-Xcompiler=-fPIC,-pthread', '-I' + str(native)]
    version = subprocess.check_output([nvcc, '--version'], text=True)
    obj = out / 'rv64-pcs_native.cu.o'
    started = time.monotonic()
    N.compile_native(nvcc, version, flags, native / 'rv64/pcs_native.cu', obj, out / 'compile.log', 180)
    selected, localization = PrivateHost.localize(obj, out / 'localized-host-objects')
    objects[replaced[0]] = selected
    pending = out / '.libstwo-rv64-native.pending.so'
    command = [nvcc, '-shared', '-Xcompiler=-pthread', '-Xlinker=-Bsymbolic', '-rdc=true', '-gencode', 'arch=compute_120,code=sm_120', *map(str, objects), '-o', str(pending)]
    with (out / 'link.log').open('w') as log:
        N.run_checked(command, log, 180)
    loaded = ctypes.CDLL(str(pending))
    missing = [name for name in baseline['required_exports'] if not hasattr(loaded, name)]
    if missing:
        raise RuntimeError('candidate missing baseline ABI: ' + repr(missing))
    output = out / 'libstwo-rv64-native.so'
    os.replace(pending, output)
    receipt = {'schema': 'rv64-m7-d2-rolling-relink/v1', 'scope': 'frozen numerical object roster; one PCS TU replaced, optional source-identical host dispatcher explicitly recorded; GPU qualification separate', 'author': 'OpenAI Codex', 'seconds': time.monotonic() - started, 'base_build': str(args.base_build), 'base_build_sha256': N.sha(args.base_build), 'base_library_sha256': baseline['library_sha256'], 'library_sha256': N.sha(output), 'objects': {str(obj): N.sha(obj) for obj in objects}, 'localization': localization, 'source_equivalent_host_dispatch': equivalent, 'source_sha256': {str(native / name): N.sha(native / name) for name in ('rv64/pcs_native.cu', 'rv64/pcs_pipeline.cuh', 'rv64/gkr.h', 'transform/lde.cu')}, 'required_exports_pass': True, 'gpu_qualified': False}
    (out / 'relink.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'library': str(output), 'sha256': receipt['library_sha256'], 'seconds': receipt['seconds']}))


if __name__ == '__main__':
    main()
