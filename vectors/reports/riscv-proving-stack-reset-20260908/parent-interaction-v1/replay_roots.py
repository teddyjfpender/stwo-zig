"""Paired cold-process root replays with fresh hostile-input verification.

Run from the repository root, after freezing the binaries named below.
Each receipt retains the exact command, environment and executable pins.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import statistics
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', required=True, choices=('cpu', 'metal'))
    parser.add_argument('--pairs', type=int, default=3, choices=range(1, 4))
    parser.add_argument('--label', default='v2')
    args = parser.parse_args()
    repo = Path.cwd()
    report = Path(__file__).resolve().parent
    old = report.parent / 'provider-resident-v1'
    frozen = repo / '.git/local-riscv-proving-stack'
    baseline = frozen / ('small-detached-recursion-v1/air-fusion-final-cpu-prove' if args.backend == 'cpu' else 'provider-resident-v1/parent-prove-metal')
    candidate = frozen / f'parent-interaction-v1/parent-prove-{args.backend}-{args.label}'
    assert baseline.is_file() and candidate.is_file()
    template = json.loads((old / 'root-metal-timing-command.json').read_text())
    records = []
    for pair in range(args.pairs):
        for arm in (('baseline', 'candidate') if pair % 2 == 0 else ('candidate', 'baseline')):
            producer = baseline if arm == 'baseline' else candidate
            output = report / f'root-{args.backend}-{args.label}-{pair + 1}-{arm}'
            assert not output.exists() and not output.with_suffix('.json').exists()
            argv = list(template['argv'])
            replacements = {'--producer': str(producer), '--producer-sha256': sha(producer), '--bundle': str(output), '--output': str(output.with_suffix('.json'))}
            for key, value in replacements.items():
                argv[argv.index(key) + 1] = value
            aot_options = ('--metal-aot-bundle', '--metal-aot-manifest-sha256', '--metal-aot-profile')
            if args.backend == 'cpu':
                for key in aot_options:
                    index = argv.index(key)
                    del argv[index:index + 2]
            elif arm == 'candidate':
                bundle = frozen / 'native-tables-aot-m4-v1'
                argv[argv.index('--metal-aot-bundle') + 1] = str(bundle)
                argv[argv.index('--metal-aot-manifest-sha256') + 1] = sha(bundle / 'stwo_zig_core.manifest.json')
            env = template['environment']
            output.with_name(output.name + '-command.json').write_text(json.dumps({'argv': argv, 'environment': env}, indent=2) + '\n')
            with output.with_suffix('.log').open('x') as log:
                result = subprocess.run(argv, env=dict(os.environ, **env), stdout=log, stderr=subprocess.STDOUT)
            assert result.returncode == 0, output.with_suffix('.log').read_text()[-3000:]
            receipt = json.loads(output.with_suffix('.json').read_text())
            assert receipt['passed'] and receipt['producer']['exited_before_verification']
            artifacts = {name: sha(output / name) for name in ('proof.bin', 'key.json', 'claims.json')}
            assert all(digest == sha(old / 'root-metal-timing' / name) for name, digest in artifacts.items())
            lifecycle = receipt['producer']['lifecycle']
            entry = {'pair': pair + 1, 'arm': arm, 'receipt': str(output.with_suffix('.json').relative_to(repo)), 'receipt_sha256': sha(output.with_suffix('.json')), 'request_ns': lifecycle['request_ns'], 'preparation_ns': lifecycle['preparation_ns'], 'proof_ns': lifecycle['proof_ns'], 'fresh_cases': len(receipt['cases']), 'artifact_sha256': artifacts}
            records.append(entry)
            (report / f'root-{args.backend}-{args.label}-paired.json').write_text(json.dumps({'scope': 'Cold process requests, alternating order; same retained children and independently pinned verifier/key. Candidate Metal also has equivalent regenerated AOT names and unused native-table kernels.', 'records': records}, indent=2) + '\n')
            print(args.backend, pair + 1, arm, f"{lifecycle['request_ns'] / 1e9:.6f}s", 'freshly verified, identical artifacts', flush=True)
    print('request medians', {arm: statistics.median(e['request_ns'] for e in records if e['arm'] == arm) / 1e9 for arm in ('baseline', 'candidate')}, flush=True)


if __name__ == '__main__':
    main()
