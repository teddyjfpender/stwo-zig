#!/usr/bin/env python3
"""Build and freshly verify real scoped P2-row STARKs, never Ethereum metrics."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import rv64_m7_hybrid_fixture_run as F


def sources(root):
    out = F.source_hashes(root)
    out.update({str(p.relative_to(root)): F.sha(p) for p in (root / 'build_support').rglob('*.zig')})
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--prefix', type=Path, required=True)
    p.add_argument('--lock', default='/workspace/m3/locks/build.1.lock')
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True, exist_ok=True)
    receipt = dict(schema='rv64-m7-dedicated-poseidon-row-stark/v1', ethereum_request=False,
                   production_profile_promoted=False, general_five_roster_prover=False,
                   public_port_adapter=True, degree=8, rows=16, main_columns=716,
                   fixed_columns=74, constraints=725, queries=24, pow_bits=0,
                   gpu_access=False, tests=[])
    env = os.environ.copy()
    env.update(CUDA_VISIBLE_DEVICES='', STWO_RV64_GPU_PCS_HELPER='/bin/false',
               ZIG_GLOBAL_CACHE_DIR='/workspace/m3/cache/zig-global')
    before = sources(root)
    digest = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
    argv = ['/workspace/zig/zig', 'build', 'rv64-poseidon-row-fixture', '-Doptimize=ReleaseSafe', '-j8',
            '--prefix', str(args.prefix), '--summary', 'all',
            '-Dimplementation-commit=' + (root / '.m3-commit-full').read_text().strip(),
            '-Dimplementation-tree=' + (root / '.m3-tree').read_text().strip(),
            '-Dimplementation-dirty=true', '-Dimplementation-dirty-content-sha256=' + digest]
    with open(args.lock, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        started = time.monotonic()
        with open(args.out / 'build.log', 'w') as log:
            result = subprocess.run(argv, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
        receipt.update(build_argv=argv, build_exit_code=result.returncode,
                       build_wall_s=time.monotonic() - started,
                       source_files_sha256=before, sources_unchanged=before == sources(root))
    binary = args.prefix / 'bin/rv64-poseidon-row-fixture'
    if result.returncode or not receipt['sources_unchanged']:
        receipt['passed'] = False
        (args.out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print((args.out / 'build.log').read_text()[-12000:], flush=True)
        return 1
    receipt['binary_sha256'] = F.sha(binary)

    def run(label, argv, reject=False, producer_reject=False):
        started = time.monotonic()
        with open(args.out / (label + '.log'), 'w') as log:
            result = subprocess.run([str(binary), *map(str, argv)], cwd=root, env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
        log_text = (args.out / (label + '.log')).read_text()
        expected_errors = ('OodsNotMatching', 'UntrustedPoseidonFixedCommitment', 'MerkleVerificationError', 'MerkleVerificationFailed', 'RootMismatch')
        typed_rejection = result.returncode == 1 and any('P2_DEDICATED_ROW_REJECT ' + err in log_text for err in expected_errors)
        if producer_reject:
            typed_rejection = result.returncode == 1 and 'P2_DEDICATED_ROW_PRODUCER_REJECT ConstraintsNotSatisfied' in log_text
        passed = typed_rejection if (reject or producer_reject) else result.returncode == 0
        receipt['tests'].append(dict(label=label, argv=list(map(str, argv)),
                                    expected_rejection=reject or producer_reject, rejection_stage='producer' if producer_reject else 'receiver' if reject else None, exit_code=result.returncode,
                                    wall_s=time.monotonic() - started, passed=passed))
        receipt['passed'] = all(x['passed'] for x in receipt['tests'])
        (args.out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt['tests'][-1]), flush=True)
        return passed

    proof = args.out / 'valid.binary'
    if not run('produce-valid', ['--produce', 'none', proof]):
        return 1
    receipt.update(proof_bytes=proof.stat().st_size, proof_sha256=F.sha(proof))
    if not run('fresh-receiver', ['--verify', proof]):
        return 1
    if not run('wrong-public-output', ['--verify-wrong-public', proof], reject=True):
        return 1
    mutations = ('x2', 'x5', 'port_address', 'port_extension', 'fixed_id')
    for mutation in mutations:
        path = args.out / ('invalid-trace-' + mutation + '.binary')
        if not run('produce-' + mutation, ['--produce', mutation, path], producer_reject=True):
            return 1
    for mutation in (*mutations, 'fixed_root'):
        path = args.out / ('tampered-' + mutation + '.binary')
        if not run('tamper-' + mutation, ['--tamper-proof', mutation, proof, path]):
            return 1
        if not run('fresh-reject-' + mutation, ['--verify', path], reject=True):
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
