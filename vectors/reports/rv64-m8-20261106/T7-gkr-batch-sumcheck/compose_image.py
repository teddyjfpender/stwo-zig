#!/usr/bin/env python3
"""T7 image: the frozen m7-combined-residency link command (same 949 objects,
same order), with
  - rv64-batch.cu.o recompiled from THIS tree (the only T7 product change:
    batch.cu + batch_transition.cuh + the new round.cuh helpers it alone uses;
    STWO_RV64_M8_GKR_BATCH_PAR default off), and
  - the four replacement objects whose frozen files are gone (pcs_native,
    runtime/context, fused_blake2s, circuit_fill_chain) recompiled from this
    tree, as T2's compose_image.py does.
Every other link object is sha256-checked against the frozen receipt.
usage: compose_image.py <src-root> <out-dir>"""
from pathlib import Path
import ctypes, hashlib, json, os, subprocess, sys, time
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
root, out = Path(sys.argv[1]), Path(sys.argv[2])
native = root / 'src/backends/cuda/native'
out.mkdir(parents=True, exist_ok=True)
frozen = json.loads(Path('/workspace/m3/build/m7-combined-residency/cuda/native/build.json').read_text())
assert frozen['library_sha256'] == 'a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45'
nvcc = '/usr/local/cuda/bin/nvcc'
flags = ['-O3', '-std=c++17', '-lineinfo', '-gencode', 'arch=compute_120,code=sm_120', '-Xcompiler=-fPIC,-pthread', f'-I{native}']
recompile = {  # frozen link path -> source in this tree
    '/workspace/m3/build/m7-owner-cleanup/rv64-pcs_native.cu.o': 'rv64/pcs_native.cu',
    '/workspace/m3/build/m7-admission/cuda/native/runtime-context.cu.o': 'runtime/context.cu',
    '/workspace/m3/build/m7-blake-prefill/cuda/native/rv64-fused_blake2s.cu.o': 'rv64/fused_blake2s.cu',
    '/workspace/m3/build/m7-assignment-graphs/circuit_fill_chain.o': 'rv64/circuit_fill_chain.cu',
    '/workspace/m3/build/m7-integrate/cuda/native/rv64-batch.cu.o': 'rv64/batch.cu',
}
started = time.monotonic()
cmd, replacements, checked = [], {}, 0
for arg in frozen['link_command']:
    if arg.endswith('.pending.so'):
        cmd.append(str(out / '.pending.so')); continue
    if not arg.endswith('.o'):
        cmd.append(arg); continue
    if arg in recompile:
        rel = recompile[arg]
        obj = out / (rel.replace('/', '-') + '.o')
        subprocess.run([nvcc, *flags, '-c', str(native / rel), '-o', str(obj)], check=True)
        replacements[arg] = {'source': rel, 'source_sha256': sha(native / rel), 'object': str(obj), 'object_sha256': sha(obj)}
        cmd.append(str(obj)); continue
    want = frozen['all_link_objects_sha256'].get(arg)
    assert want and sha(arg) == want, arg
    checked += 1
    cmd.append(arg)
assert sorted(replacements) == sorted(recompile), replacements.keys()
pending, lib = out / '.pending.so', out / 'libstwo-rv64-native.so'
subprocess.run(cmd, check=True)
image = ctypes.CDLL(str(pending))
for name in ['stwo_exec_context_arena_snapshot_v1', 'stwo_rv64_gpu_session_controller', 'stwo_assignment_graph_create_v1',
             'stwo_circuit_assignment_chain_run_on', 'stwo_rv64_batch_init_on', 'stwo_rv64_batch_round_on',
             'stwo_rv64_batch_tail_on', 'stwo_rv64_batch_mask_on', 'stwo_rv64_batch_sum_on', 'stwo_rv64_batch_fold_on']:
    assert hasattr(image, name), name
os.replace(pending, lib)
receipt = {'schema': 'rv64-m8-T7-image/v1', 'label': 'M', 'seconds': round(time.monotonic() - started, 1),
           'baseline_library_sha256': frozen['library_sha256'], 'replacements': replacements,
           'frozen_objects_sha_checked': checked, 'library_sha256': sha(lib),
           'note': 'frozen m7-combined-residency link command; rv64/batch.cu from this tree (T7 flag default off) + the 4 missing frozen replacements recompiled'}
(out / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
rt = json.loads((root / 'design/riscv-proving-stack/m7-handoff/p0-runtime.json').read_text())
runtime = dict(rt, scope='T7 image (STWO_RV64_M8_GKR_BATCH_PAR default off) + frozen sparse/observer/guard addons')
runtime['assets'] = dict(rt['assets'], library=str(lib))
runtime['asset_sha256'] = dict(rt['asset_sha256'], library=receipt['library_sha256'])
(out / 'runtime.json').write_text(json.dumps(runtime, indent=2) + '\n')
for r in replacements.values():  # keep only the receipt; objects are reproducible
    Path(r['object']).unlink()
print(receipt['library_sha256'], receipt['seconds'])
