#!/usr/bin/env python3
"""CPU-only frontier custody and exact Poseidon2 prototype census; no promotion."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import rv64_m7_hybrid_fixture_run as F


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--lock', default='/workspace/m3/locks/build.1.lock')
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True, exist_ok=True)
    receipt = dict(schema='rv64-m7-inner-prototype-gate/v1', ethereum_request=False,
                   production_profile_promoted=False, gpus=0, tests=[])
    env = os.environ.copy()
    env.update(CUDA_VISIBLE_DEVICES='', ZIG_GLOBAL_CACHE_DIR='/workspace/m3/cache/zig-global')
    jobs = [('frontier', root / 'src/integrations/riscv_cuda', 'test-rv64-gkr-plan'),
            ('poseidon2-width16', root, 'test-riscv64-poseidon2-circuit')]
    with open(args.lock, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = F.source_hashes(root)
        before.update({str(p.relative_to(root)): F.sha(p) for p in (root/'build_support').rglob('*.zig')})
        receipt['source_files_sha256'] = before
        for name, cwd, step in jobs:
            argv = ['/workspace/zig/zig', 'build', step, '-Doptimize=ReleaseSafe', '-j8', '--summary', 'all']
            if cwd == root:
                digest = hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest()
                argv += ['-Dimplementation-commit='+(root/'.m3-commit-full').read_text().strip(), '-Dimplementation-tree='+(root/'.m3-tree').read_text().strip(), '-Dimplementation-dirty=true', '-Dimplementation-dirty-content-sha256='+digest]
            started = time.monotonic()
            with open(args.out / (name+'.log'), 'w') as log:
                result = subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
            receipt['tests'].append(dict(name=name,argv=argv,exit_code=result.returncode,wall_s=time.monotonic()-started))
            after = F.source_hashes(root)
            after.update({str(p.relative_to(root)): F.sha(p) for p in (root/'build_support').rglob('*.zig')})
            receipt['sources_unchanged'] = before == after
            receipt['passed'] = receipt['sources_unchanged'] and all(x['exit_code']==0 for x in receipt['tests'])
            (args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
            print(json.dumps(receipt['tests'][-1]),flush=True)
            if not receipt['passed']:
                print((args.out/(name+'.log')).read_text()[-12000:],flush=True)
                return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
