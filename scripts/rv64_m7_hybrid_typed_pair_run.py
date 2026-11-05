#!/usr/bin/env python3
"""Qualify a real hybrid two-child typed fold; synthetic admitted leaf class."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time
import rv64_m7_hybrid_fixture_run as F


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--library', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--build-receipt', type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True, exist_ok=True)
    build = json.loads(args.build_receipt.read_text())
    if not build['passed'] or build['binary_sha256'] != F.sha(args.binary) or build['source_files_sha256'] != F.source_hashes(root):
        raise RuntimeError('Typed-pair build/source mismatch')
    receipt = dict(schema='rv64-m7-hybrid-typed-pair/v1', ethereum_request=False,
                   native_execution_admission=False, synthetic_echo_leaf_class=True,
                   production_profile_promoted=False, binary_sha256=F.sha(args.binary),
                   library_sha256=F.sha(args.library), build_receipt_sha256=F.sha(args.build_receipt),
                   source_files_sha256=build['source_files_sha256'], tests=[])
    env = os.environ.copy()
    env['STWO_RV64_OUTER_PROFILE'] = 'm7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1'
    for k in tuple(env):
        if k.startswith('STWO_RV64_GPU'):
            env.pop(k)

    def run(label, argv, gpu=False, reject=False):
        lock = open('/workspace/m3/locks/gpu.lock', 'a') if gpu else None
        try:
            if lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
            started = time.monotonic()
            child_env = env.copy()
            if not gpu:
                child_env['CUDA_VISIBLE_DEVICES'] = ''
            with open(args.out / (label + '.log'), 'w') as log:
                result = subprocess.run([str(args.binary), *map(str, argv)], cwd=root, env=child_env,
                                        stdout=log, stderr=subprocess.STDOUT)
            passed = result.returncode != 0 if reject else result.returncode == 0
            receipt['tests'].append(dict(label=label, argv=list(map(str, argv)), gpu_access=gpu,
                                        expected_rejection=reject, exit_code=result.returncode,
                                        wall_s=time.monotonic() - started, passed=passed))
            receipt['passed'] = all(x['passed'] for x in receipt['tests'])
            (args.out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
            print(json.dumps(receipt['tests'][-1]), flush=True)
            if not passed:
                raise RuntimeError((args.out / (label + '.log')).read_text()[-12000:])
        finally:
            if lock:
                fcntl.flock(lock, fcntl.LOCK_UN)
                lock.close()

    run('prove', ['--prove', args.library, args.out], gpu=True)
    run('derive', ['--derive', args.out])
    key_pin = F.sha(args.out / 'derived-key.json')
    receipt['source_derived_key_sha256'] = key_pin
    for name in ('left.hom31', 'right.hom31'):
        path = args.out / name
        receipt[name] = dict(bytes=path.stat().st_size, sha256=F.sha(path))
        path.unlink()
    receipt['leaf_proofs_deleted_before_fresh_receiver'] = True
    root_proof = args.out / 'root.hom31'
    receipt['root_bytes'] = root_proof.stat().st_size
    receipt['root_sha256'] = F.sha(root_proof)
    run('root-only-verify', ['--verify', args.out, key_pin])
    bad_pin = ('0' if key_pin[0] != '0' else '1') + key_pin[1:]
    run('bad-key-pin', ['--verify', args.out, bad_pin], reject=True)
    saved = root_proof.read_bytes()
    damaged = bytearray(saved)
    damaged[len(damaged) // 2] ^= 1
    root_proof.write_bytes(damaged)
    try:
        run('tampered-root', ['--verify', args.out, key_pin], reject=True)
    finally:
        root_proof.write_bytes(saved)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
