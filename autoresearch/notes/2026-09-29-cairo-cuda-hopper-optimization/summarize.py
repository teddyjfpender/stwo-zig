"""Summarize verified comparisons; timing exclusions must be explicit arguments."""
import argparse
import json
from pathlib import Path
from statistics import median

parser = argparse.ArgumentParser()
parser.add_argument('comparison', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--exclude-block', type=int, action='append', default=[])
args = parser.parse_args()
doc = json.loads(args.comparison.read_text())
assert doc['complete']
results = doc['results']
assert all(r['status'] == 'verified' for r in results)
summary = {'gpu': doc['gpu'], 'security': doc['security'],
           'scope': doc['scope'], 'products': doc['products'],
           'excluded_timing_blocks': args.exclude_block, 'results': []}
for number in range(1, 5):
    name = f'SN PIE {number}'
    all_trials = [r for r in results if r['benchmark'] == name]
    assert len({r['proof_sha256'] for r in all_trials}) == 1
    item = {'benchmark': name, 'proof_sha256': all_trials[0]['proof_sha256']}
    for product in ['baseline', 'candidate']:
        trials = [r for r in all_trials if r['product'] == product
                  and r['block'] not in args.exclude_block]
        assert len(trials) >= 2
        item[product] = {
            'proof_s': median(r['backend_trial']['proof_execute_and_decode_ns'] / 1e9 for r in trials),
            'adapted_publication_s': median(r['backend_trial']['adapted_input_until_publication_ns'] / 1e9 for r in trials),
            'process_wall_s': median(r['process_wall_ns'] / 1e9 for r in trials),
            'teardown_s': median(r['runtime_teardown_ns'] / 1e9 for r in trials),
            'gpu_peak_gb': max(r['highest_sampled_device_used_bytes'] / 1e9 for r in trials),
            'arena_gb': max(r['backend_trial']['planned_arena_bytes'] / 1e9 for r in trials),
            'host_peak_gb': max(r['host_peak_rss_bytes'] / 1e9 for r in trials),
            'trials': len(trials)}
    warm = next(w for w in doc['warm'] if w['benchmark'] == name)['trials'][1:]
    assert len(warm) == 2
    assert all(bytes(r['proof_sha256']).hex() == item['proof_sha256'] for r in warm)
    item['warm_proof_s'] = median(r['proof_execute_and_decode_ns'] / 1e9 for r in warm)
    item['warm_adapted_publication_s'] = median(r['adapted_input_until_publication_ns'] / 1e9 for r in warm)
    summary['results'].append(item)
args.output.write_text(json.dumps(summary, indent=2) + '\n')
