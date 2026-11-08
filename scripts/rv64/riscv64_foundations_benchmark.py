#!/usr/bin/env python3
"""Paired ReleaseFast execution kernels; no proving or RV32 performance claim."""
import argparse
import hashlib
import json
import platform
import random
import statistics
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, default=ROOT / 'vectors/reports/rv64-foundations-20261030/baseline-source.json')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=7, choices=range(3, 32))
    args = parser.parse_args()
    snapshot = json.loads(args.baseline.read_text())
    if snapshot['schema'] != 'rv64-execution-source-snapshot-v0':
        raise ValueError('Invalid baseline source snapshot')
    benchmark = ROOT / 'src/frontends/riscv/rv64/benchmark.zig'
    if snapshot['files']['benchmark.zig'] != benchmark.read_text():
        raise ValueError('Benchmark harness must be identical in both arms')
    report = {'schema': 'rv64-foundations-paired-execution-v1', 'proof_supported': False,
              'host': platform.platform(), 'optimize': 'ReleaseFast',
              'baseline_snapshot_sha256': sha(args.baseline),
              'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in sorted(benchmark.parent.glob('*.zig'))},
              'conditions': 'local host, randomized paired order, no quiet-host or proving qualification',
              'rows': []}
    with tempfile.TemporaryDirectory(prefix='rv64-foundations-') as temporary:
        directory = Path(temporary)
        for name, text in snapshot['files'].items():
            if Path(name).name != name or not name.endswith('.zig'):
                raise ValueError('Baseline files must be flat Zig source names')
            if hashlib.sha256(text.encode()).hexdigest() != snapshot['sha256'][name]:
                raise ValueError('Baseline source checksum mismatch')
            (directory / name).write_text(text)
        binaries = {'baseline': directory / 'baseline', 'candidate': directory / 'candidate'}
        for arm, source in [('baseline', directory / 'benchmark.zig'), ('candidate', benchmark)]:
            subprocess.run(['zig', 'build-exe', str(source), '-O', 'ReleaseFast',
                            f'-femit-bin={binaries[arm]}'], cwd=ROOT, check=True)
        report['binary_sha256'] = {arm: sha(binary) for arm, binary in binaries.items()}
        rng = random.Random(0x52563634)
        for workload in ('execution', 'memory', 'bulk'):
            samples = {'baseline': [], 'candidate': []}
            checksums, operations = set(), set()
            for _ in range(args.samples):
                order = list(binaries)
                rng.shuffle(order)
                for arm in order:
                    sample = json.loads(subprocess.check_output([str(binaries[arm]), workload]))
                    samples[arm].append(sample['elapsed_ns'])
                    checksums.add(sample['checksum'])
                    operations.add(sample['operations'])
            if len(checksums) != 1 or len(operations) != 1:
                raise ValueError('Kernel final state or operation counts disagree')
            before, after = (statistics.median(samples[arm]) for arm in ('baseline', 'candidate'))
            report['rows'].append({'workload': workload, 'operations': operations.pop(),
                                   'checksum': checksums.pop(), 'samples_ns': samples,
                                   'baseline_median_ns': before, 'candidate_median_ns': after,
                                   'speedup': before / after})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps([{k: v for k, v in row.items() if k != 'samples_ns'} for row in report['rows']], indent=2))


if __name__ == '__main__':
    main()
