#!/usr/bin/env python3
"""T2 image: the m7-combined-residency composition (m7-integrate objects + the
same four replaced objects), with the four replacements recompiled from THIS
tree (their frozen objects are no longer on disk). Only circuit_fill_chain.cu
differs from the integrate tree. usage: compose_image.py <src-root> <out-dir>"""
from pathlib import Path
import ctypes, hashlib, json, os, subprocess, sys, time
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
root, out = Path(sys.argv[1]), Path(sys.argv[2])
native = root / 'src/backends/cuda/native'
out.mkdir(parents=True, exist_ok=True)
base = Path('/workspace/m3/build/m7-integrate/cuda/native')
j = json.loads((base / 'build.json').read_text())
assert j['library_sha256'] == '11e622367774e1b8b0c525a5d46dfeb75c96bfa185f1863d546ef69dd22fdda4'
nvcc = '/usr/local/cuda/bin/nvcc'
flags = ['-O3', '-std=c++17', '-lineinfo', '-gencode', 'arch=compute_120,code=sm_120', '-Xcompiler=-fPIC,-pthread', f'-I{native}']
sources = {'rv64-pcs_native.cu.o': 'rv64/pcs_native.cu', 'rv64-fused_blake2s.cu.o': 'rv64/fused_blake2s.cu',
           'rv64-circuit_fill_chain.cu.o': 'rv64/circuit_fill_chain.cu', 'runtime-context.cu.o': 'runtime/context.cu'}
started = time.monotonic()
replacements = {}
for name, rel in sources.items():
    obj = out / name
    subprocess.run([nvcc, *flags, '-c', str(native / rel), '-o', str(obj)], check=True)
    replacements[name] = {'source': rel, 'source_sha256': sha(native / rel), 'object': str(obj), 'object_sha256': sha(obj)}
localized = {r['original']: r for r in j['localized_private_host_helpers']}
objects, used = [], []
for p, h in j['objects'].items():
    name = Path(p).name
    if name in replacements:
        objects.append(replacements[name]['object']); used.append(name); continue
    if p in localized:
        r = localized[p]; p = r['localized']; assert sha(p) == r['localized_sha256'], p
    objects.append(p)
assert sorted(used) == sorted(replacements), used
lib, pending = out / 'libstwo-rv64-native.so', out / '.pending.so'
cmd = [nvcc, '-shared', '-Xcompiler=-pthread', '-Xlinker=-Bsymbolic', '-rdc=true', '-gencode', 'arch=compute_120,code=sm_120', *objects, '-o', str(pending)]
subprocess.run(cmd, check=True)
image = ctypes.CDLL(str(pending))
for name in ['stwo_exec_context_arena_snapshot_v1', 'stwo_rv64_gpu_session_controller', 'stwo_rv64_gpu_session_cleanup', 'stwo_rv64_gpu_session_trim_unused',
             'stwo_assignment_graph_create_v1', 'stwo_circuit_blake_sample_prefill_on', 'stwo_circuit_assignment_chain_run_on', 'stwo_circuit_assignment_wide_level_on']:
    assert hasattr(image, name), name
os.replace(pending, lib)
receipt = {'schema': 'rv64-m8-T2-image/v1', 'label': 'M', 'seconds': round(time.monotonic() - started, 1), 'baseline_library_sha256': j['library_sha256'],
           'replacements': replacements, 'library_sha256': sha(lib), 'link_command_objects': len(objects),
           'note': 'm7-combined-residency composition; the 4 replaced objects recompiled from this tree; only circuit_fill_chain.cu differs from integrate'}
(out / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
frozen = json.loads((root / 'design/riscv-proving-stack/m7-handoff/p0-runtime.json').read_text())
runtime = dict(frozen, scope='T2 image (assignment chain flow, default off) + frozen sparse/observer/guard addons')
runtime['assets'] = dict(frozen['assets'], library=str(lib))
runtime['asset_sha256'] = dict(frozen['asset_sha256'], library=receipt['library_sha256'])
(out / 'runtime.json').write_text(json.dumps(runtime, indent=2) + '\n')
print(receipt['library_sha256'], receipt['seconds'])
