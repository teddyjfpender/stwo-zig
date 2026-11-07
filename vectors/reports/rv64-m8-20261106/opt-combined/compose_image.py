#!/usr/bin/env python3
"""M8 opt-combined image: T2..T9 kernel objects + T5 register-scheduled AOT shards in ONE image.

Recipe (the union of the T2/T4/T6/T7/T8/T9 compose scripts and T5's relink):
  1. Start from the frozen m7-combined-residency link line (build.json, 958 items).
  2. Recompile from THIS tree every link object whose source an opt branch changed
     (plus the four frozen objects whose build dirs are gone, as every T* image did),
     and write a derived base receipt with those objects swapped in.
  3. Run scripts/rv64_m8_aot_register_relink.py (T5) on the derived receipt with T5's
     plan-img1.json: it adds the `_t5` kernels and the flag-gated dispatcher and links.
Every other object is byte-for-byte the frozen one. All opt kernels are flag-selected at
run time, so flags off this image runs the frozen kernels except T3/T4 (default-on kill
switches; see the receipt README).

usage: compose_image.py <src-root> <out-dir> [--jobs N]
"""
import argparse
import concurrent.futures
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

BASE = Path('/workspace/m3/build/m7-combined-residency/cuda/native/build.json')
BASE_LIBRARY_SHA = 'a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45'
# link-object basename -> source under src/backends/cuda/native (who changed it)
SOURCES = {
    'rv64-pcs_native.cu.o': 'rv64/pcs_native.cu',            # frozen object gone (unchanged source)
    'runtime-context.cu.o': 'runtime/context.cu',            # frozen object gone (unchanged source)
    'rv64-fused_blake2s.cu.o': 'rv64/fused_blake2s.cu',      # frozen object gone (unchanged source)
    'circuit_fill_chain.o': 'rv64/circuit_fill_chain.cu',    # T2 (frozen object also gone)
    'rv64-deep.cu.o': 'rv64/deep.cu',                        # T3
    'rv64-samples.cu.o': 'rv64/samples.cu',                  # T3
    'transform-lde.cu.o': 'transform/lde.cu',                # T4 (n2b_smem.cuh)
    'transform-n2b.cu.o': 'transform/n2b.cu',                # T4
    'transform-b2n_retained.cu.o': 'transform/b2n_retained.cu',  # T4
    'commitment-merkle.cu.o': 'commitment/merkle.cu',        # T6
    'rv64-batch.cu.o': 'rv64/batch.cu',                      # T7
    'rv64-global.cu.o': 'rv64/global.cu',                    # T8
    'rv64-binding.cu.o': 'rv64/binding.cu',                  # T8
    'rv64-keccak_witness.cu.o': 'rv64/keccak_witness.cu',    # T9
    'rv64-bridge_witness.cu.o': 'rv64/bridge_witness.cu',    # T9
    'circuit-base_witness.cu.o': 'circuit/base_witness.cu',  # T9
}
EXPORTS = ['stwo_exec_context_arena_snapshot_v1', 'stwo_rv64_gpu_session_controller', 'stwo_assignment_graph_create_v1',
           'stwo_circuit_assignment_chain_run_on', 'stwo_rv64_keccak_witness_on', 'stwo_rv64_bridge_witness_on',
           'stwo_circuit_base_witness_on', 'stwo_blake2s_merkle_layers_on', 'stwo_rv64_batch_round_on',
           'stwo_rv64_global_pairs_on', 'stwo_rv64_prefix_scan_on', 'stwo_rv64_composition_role_on',
           'stwo_rv64_truth_composition_role_on']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('root', type=Path)
    ap.add_argument('out', type=Path)
    ap.add_argument('--jobs', type=int, default=6)
    args = ap.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    native = root / 'src/backends/cuda/native'
    (out / 'rebuilt').mkdir(parents=True, exist_ok=True)
    base = json.loads(BASE.read_text())
    assert base['library_sha256'] == BASE_LIBRARY_SHA
    link = list(base['link_command'])
    nvcc = '/usr/local/cuda/bin/nvcc'
    flags = ['-O3', '-std=c++17', '-lineinfo', '-gencode', 'arch=compute_120,code=sm_120', '-Xcompiler=-fPIC,-pthread', f'-I{native}']
    started = time.monotonic()
    slots = {Path(x).name: i for i, x in enumerate(link) if x.endswith('.o')}
    assert set(SOURCES) <= set(slots), sorted(set(SOURCES) - set(slots))

    def build(name):
        source, target = native / SOURCES[name], out / 'rebuilt' / name
        key_file, key = target.with_suffix('.key'), ' '.join([sha(source), *flags])
        if not (target.is_file() and key_file.is_file() and key_file.read_text() == key):
            subprocess.run([nvcc, *flags, '-c', str(source), '-o', str(target)], check=True)
            key_file.write_text(key)
        return name, {'original': link[slots[name]], 'original_sha256': base['all_link_objects_sha256'].get(link[slots[name]]),
                      'source': SOURCES[name], 'source_sha256': sha(source), 'object': str(target), 'object_sha256': sha(target)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        replacements = dict(pool.map(build, sorted(SOURCES)))
    derived = dict(base)
    for name, r in replacements.items():
        link[slots[name]] = r['object']
    derived['link_command'] = link
    derived['all_link_objects_sha256'] = dict(base['all_link_objects_sha256'], **{r['object']: r['object_sha256'] for r in replacements.values()})
    derived['opt_combined_replacements'] = replacements
    derived_path = out / 'base-link.json'
    derived_path.write_text(json.dumps(derived, indent=1) + '\n')
    compile_seconds = round(time.monotonic() - started, 1)
    # T5 relink on the derived line: nothing is missing any more, so it only adds the _t5 modules + dispatcher.
    subprocess.run([sys.executable, str(root / 'scripts/rv64_m8_aot_register_relink.py'), '--source-root', str(root),
                    '--base-link', str(derived_path), '--base-runtime', str(root / 'design/riscv-proving-stack/m7-handoff/p0-runtime.json'),
                    '--plan', str(root / 'vectors/reports/rv64-m8-20261106/opt-T5-aot-constraint-regs/plan-img1.json'),
                    '--out', str(out / 'img'), '--jobs', '4', '--rss-cap-gb', '40'], check=True)
    relink = json.loads((out / 'img/build.json').read_text())
    image = ctypes.CDLL(relink['library'])
    missing = [n for n in EXPORTS if not hasattr(image, n)]
    assert not missing, missing
    runtime = json.loads((out / 'img/runtime.json').read_text())
    runtime['scope'] = ('M8 opt-combined image: T2/T3/T4/T6/T7/T8/T9 objects recompiled + T5 register-scheduled AOT shards, '
                        'all on m7-combined-residency; ' + runtime.get('scope', ''))
    (out / 'img/runtime.json').write_text(json.dumps(runtime, indent=2) + '\n')
    receipt = {'schema': 'rv64-m8-opt-combined-image/v1', 'label': 'M', 'base_link_receipt': str(BASE), 'base_library_sha256': BASE_LIBRARY_SHA,
               'replacements': replacements, 'replacement_compile_seconds': compile_seconds,
               't5_relink_receipt': str(out / 'img/build.json'), 't5_modules': [m.get('symbol', m.get('source')) for m in relink['modules']],
               'library': relink['library'], 'library_sha256': relink['library_sha256'],
               'library_bytes': Path(relink['library']).stat().st_size, 'seconds': round(time.monotonic() - started, 1)}
    (out / 'build.json').write_text(json.dumps(receipt, indent=1) + '\n')
    print(json.dumps({'library': receipt['library'], 'sha256': receipt['library_sha256'], 'bytes': receipt['library_bytes'], 'seconds': receipt['seconds']}))


if __name__ == '__main__':
    main()
