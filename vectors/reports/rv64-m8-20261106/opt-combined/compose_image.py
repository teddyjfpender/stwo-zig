#!/usr/bin/env python3
"""M8 opt-combined image: the accepted P1 native-relink recipe on THIS tree + T5 register-scheduled AOT shards.

Two recipes do NOT give a startable image of the merged tree [M, 2026-11-07, runs/m8-opt-combined]:
  * the T* recipe (relink the frozen m7-combined-residency line with a few objects recompiled):
    that line is not reproducible (4 objects gone, 6 overwritten by later m7-integrate builds),
    and runtime/context.cu + rv64/pcs_native.cu changed after it; attempt 1 (lib afe02a0c)
    fails service start with `error: Unexpected`, every flag off;
  * the resident image builder (`rv64_m3_pod.py build --only cuda`, lib 61ff9412 plain /
    663c8a5b with T5): same `error: Unexpected` (the known integrate-head defect reported by
    m8-memory in M8-INTERFACES.md, 04:40).
Recipe (as m8-memory's np3 image, sha 604d88af, which starts):
  1. scripts/rv64_m8_native_relink.py (m8-memory, 3bb987887): recompile every hand-written
     native TU (48, so every T2/T3/T4/T6/T7/T8/T9 kernel) from THIS tree and relink them with
     the SHA-checked frozen AOT objects of the P1 node-peaks link
     (runs/m7-integrate/p1-node-peaks-native-20261106-03/link-inputs.json);
  2. T5's relink (scripts/rv64_m8_aot_register_relink.py) on THAT argv, adding the `_t5`
     kernels and the flag-gated composition dispatcher.
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
    link_inputs = Path('/workspace/m3/runs/m7-integrate/p1-node-peaks-native-20261106-03/link-inputs.json')
    subprocess.run([sys.executable, str(root / 'scripts/rv64_m8_native_relink.py'), '--base-link-inputs', str(link_inputs),
                    '--out', str(build / 'nr')], check=True)
    relinked = json.loads((build / 'nr/relink.json').read_text())
    assert relinked['status'] == 'NATIVE_RELINK_PASS'
    base = json.loads(link_inputs.read_text())
    link = list(relinked['argv'])
    shas = {item: (sha(item) if item.endswith('.o') else None) for item in link if item.endswith('.o')}
    derived = {'schema': 'rv64-m8-opt-combined-base-link/v1', 'library_sha256': relinked['library_sha256'], 'link_command': link,
               'all_link_objects_sha256': shas, 'native_relink_receipt': str(build / 'nr/relink.json'),
               'link_inputs': str(link_inputs), 'link_inputs_frozen_objects': len(base['objects_sha256'])}
    derived_path = build / 'base-link.json'
    derived_path.write_text(json.dumps(derived, indent=1) + '\n')
    subprocess.run([sys.executable, str(root / 'scripts/rv64_m8_aot_register_relink.py'), '--source-root', str(root),
                    '--base-link', str(derived_path), '--base-runtime', str(root / 'design/riscv-proving-stack/m7-handoff/p0-runtime.json'),
                    '--plan', str(root / 'vectors/reports/rv64-m8-20261106/opt-T5-aot-constraint-regs/plan-img1.json'),
                    '--out', str(build / 'img'), '--jobs', '4', '--rss-cap-gb', '40'], check=True)
    relink = json.loads((build / 'img/build.json').read_text())
    image = ctypes.CDLL(relink['library'])
    missing = [n for n in EXPORTS if not hasattr(image, n)]
    assert not missing, missing
    runtime = json.loads((build / 'img/runtime.json').read_text())
    runtime['scope'] = ('M8 opt-combined image: P1 native relink of the merged tree (T2/T3/T4/T6/T7/T8/T9 kernels, flag-selected) '
                        '+ T5 register-scheduled AOT shards behind STWO_RV64_M8_AOT_REGISTER_SCHEDULE; frozen sparse/observer/guard addons')
    (build / 'img/runtime.json').write_text(json.dumps(runtime, indent=2) + '\n')
    receipt = {'schema': 'rv64-m8-opt-combined-image/v1', 'label': 'M', 'native_relink_receipt': str(build / 'nr/relink.json'),
               'native_relink_library_sha256': relinked['library_sha256'], 'changed_native_objects': relinked['changed_objects'],
               't5_relink_receipt': str(build / 'img/build.json'), 't5_modules': [m.get('symbol', m.get('source')) for m in relink['modules']],
               'library': relink['library'], 'library_sha256': relink['library_sha256'],
               'library_bytes': Path(relink['library']).stat().st_size, 'seconds': round(time.monotonic() - started, 1)}
    (build / 'opt-combined-image.json').write_text(json.dumps(receipt, indent=1) + '\n')
    # Pod disk: keep one image. The T5 link consumed nr/objects; the plain relinked .so is recorded by sha in nr/relink.json.
    (build / 'nr/libstwo-rv64-native.so').unlink(missing_ok=True)
    print(json.dumps({'library': receipt['library'], 'sha256': receipt['library_sha256'], 'bytes': receipt['library_bytes'], 'seconds': receipt['seconds']}))


if __name__ == '__main__':
    main()
