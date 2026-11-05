#!/usr/bin/env python3
"""Fresh CPU acceptance with another receiver, preserving the original receipt."""
import argparse
import hashlib
import json
from pathlib import Path

import rv64_m4_resident as R


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('runs', nargs='+', type=Path)
    p.add_argument('--receiver', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    result = {'schema': 'rv64-m7-supplemental-fresh-receiver/v1',
              'scope': 'Supplemental CPU-only acceptance; original run metadata stays unchanged. No verifier timing comparison.',
              'receiver': str(args.receiver), 'receiver_sha256': sha(args.receiver), 'runs': []}
    for run in args.runs:
        original = {f: sha(run / f) for f in ['receipt.json', 'plan.json']}
        plan = json.loads((run / 'plan.json').read_text())
        receipt = json.loads((run / 'receipt.json').read_text())
        if plan.get('store', {}).get('directory'):
            raise RuntimeError('supplemental gate requires a store-free source run')
        plan['assets']['recursive_receiver'] = str(args.receiver)
        verdicts = []
        for request in receipt['requests']:
            if request['trial'] != 0:
                continue
            verdict = R.receive_one(plan, request['block'], Path(request['proof']), args.out, 16)
            verdict.update(trial=0, store_present_during_receive=False)
            verdicts.append(verdict)
            if not verdict['accepted']:
                raise RuntimeError('supplemental fresh receiver rejected ' + str(request['block']))
        if original != {f: sha(run / f) for f in original}:
            raise RuntimeError('original receipt/plan mutated')
        result['runs'].append({'run': str(run), 'original_sha256': original, 'receivers': verdicts})
        (args.out / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
