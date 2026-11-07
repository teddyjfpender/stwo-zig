#!/usr/bin/env python3
"""M8 opt-combined image: ONE coherent CUDA image from THIS tree + T5 register-scheduled AOT shards.

Why not the T* recipe (relink the frozen m7-combined-residency link line with a few objects
recompiled): that line is no longer reproducible [M, 2026-11-07]. 4 of its objects are gone
and 6 more (commitment-progressive, rv64-composition_finalize, rv64-binding, rv64-global,
rv64-circuit_interaction, core_composition_dispatch) were overwritten by later m7-integrate
builds. Also runtime/context.cu and rv64/pcs_native.cu changed after the frozen build
(0eeaad6fd, 898a38bfe, b68e02081, 5a93c2449), so "recompile the missing four from the tree"
mixes revisions: that image fails service start with `error: Unexpected` even with every
flag off (attempt 1, lib afe02a0c…).

Recipe:
  1. (separately) `scripts/rv64_m3_pod.py build --stream m8-opt-combined --only cuda`: the
     harness's full source build of this tree (catalogues-v3, shared object store), i.e. what
     PROTOCOL-M8 prescribes for a CUDA change. Every T2/T3/T4/T6/T7/T8/T9 kernel is in it.
  2. this script: T5's relink (`scripts/rv64_m8_aot_register_relink.py`) on THAT build's own
     link line (receipt converted to the relink's base-link schema), adding the `_t5`
     kernels and the flag-gated dispatcher.
All opt kernels are run-time flag-selected (T3/T4: default-on kill switches).

usage: compose_image.py <src-root> <build-dir>   (build-dir = /workspace/m3/build/m8-opt-combined)
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

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
    ap.add_argument('build', type=Path)
    args = ap.parse_args()
    root, build = args.root.resolve(), args.build.resolve()
    started = time.monotonic()
    source = json.loads((build / 'cuda/native/build.json').read_text())
    objects = list(source['objects'])  # post-localization, in link order (rv64_cuda_native_library_build.py)
    plain = build / 'cuda/native/libstwo-rv64-native.so'
    assert sha(plain) == source['library_sha256']
    link = ['/usr/local/cuda/bin/nvcc', '-shared', '-Xcompiler=-pthread', '-Xlinker=-Bsymbolic', '-rdc=true', '-gencode',
            'arch=compute_120,code=sm_120', *objects, '-o', str(plain)]
    derived = {'schema': 'rv64-m8-opt-combined-base-link/v1', 'library_sha256': source['library_sha256'], 'link_command': link,
               'all_link_objects_sha256': dict(source['objects']), 'source_build_receipt': str(build / 'cuda/native/build.json')}
    derived_path = build / 'base-link.json'
    derived_path.write_text(json.dumps(derived, indent=1) + '\n')
    subprocess.run([sys.executable, str(root / 'scripts/rv64_m8_aot_register_relink.py'), '--source-root', str(root),
                    '--base-link', str(derived_path), '--base-runtime', str(root / 'design/riscv-proving-stack/m7-handoff/p0-runtime.json'),
                    '--plan', str(root / 'vectors/reports/rv64-m8-20261106/opt-T5-aot-constraint-regs/plan-img1.json'),
                    '--core-parts', str(build / 'cuda/core-parts'), '--include', str(build / 'cuda'),
                    '--out', str(build / 'img'), '--jobs', '4', '--rss-cap-gb', '40'], check=True)
    relink = json.loads((build / 'img/build.json').read_text())
    image = ctypes.CDLL(relink['library'])
    missing = [n for n in EXPORTS if not hasattr(image, n)]
    assert not missing, missing
    runtime = json.loads((build / 'img/runtime.json').read_text())
    runtime['scope'] = ('M8 opt-combined image: full source build of the merged tree (T2/T3/T4/T6/T7/T8/T9 kernels, flag-selected) '
                        '+ T5 register-scheduled AOT shards behind STWO_RV64_M8_AOT_REGISTER_SCHEDULE; frozen sparse/observer/guard addons')
    (build / 'img/runtime.json').write_text(json.dumps(runtime, indent=2) + '\n')
    receipt = {'schema': 'rv64-m8-opt-combined-image/v1', 'label': 'M', 'source_build_receipt': str(build / 'cuda/native/build.json'),
               'source_library_sha256': source['library_sha256'], 'source_objects': len(objects),
               't5_relink_receipt': str(build / 'img/build.json'), 't5_modules': [m.get('symbol', m.get('source')) for m in relink['modules']],
               'library': relink['library'], 'library_sha256': relink['library_sha256'],
               'library_bytes': Path(relink['library']).stat().st_size, 'seconds': round(time.monotonic() - started, 1)}
    (build / 'opt-combined-image.json').write_text(json.dumps(receipt, indent=1) + '\n')
    print(json.dumps({'library': receipt['library'], 'sha256': receipt['library_sha256'], 'bytes': receipt['library_bytes'], 'seconds': receipt['seconds']}))


if __name__ == '__main__':
    main()
