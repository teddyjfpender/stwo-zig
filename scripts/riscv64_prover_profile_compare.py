#!/usr/bin/env python3
"""Compare complete, identically secured CSP proofs and export total/stage costs."""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def identity(case):
    return case['target'], case['size'], case['negative'], case['input_sha256']


def flatten(stages):
    result = {}
    for stage in stages:
        name, seconds = stage['id'], stage['seconds']
        if not isinstance(seconds, (int, float)) or not 0 <= seconds < float('inf'):
            raise ValueError('Invalid stage duration')
        result[name] = result.get(name, 0) + seconds
        for child, duration in flatten(stage.get('children') or []).items():
            result[child] = result.get(child, 0) + duration
    return result


def compare(baseline, candidate):
    if not all(report.get('complete') and report.get('whole_guest_proof') for report in (baseline, candidate)):
        raise ValueError('Both reports must contain complete verified proofs')
    old = {identity(case): case for case in baseline['cases']}
    new = {identity(case): case for case in candidate['cases']}
    if len(old) != len(baseline['cases']) or len(new) != len(candidate['cases']) or old.keys() != new.keys():
        raise ValueError('Case coverage differs or contains duplicates')
    rows = []
    for key, after in new.items():
        before = old[key]
        a, b = before['prover'], after['prover']
        if any(case['status'] != 'verified_full_execution' or not case.get('independent_statement_binding') or
               not case['fresh_process'].get('verified') or not case['fresh_process'].get('whole_guest_proof') for case in (before, after)):
            raise ValueError('Every case needs independent expected-state binding and fresh verification')
        if before['elf_sha256'] != after['elf_sha256'] or before['expected_output'] != after['expected_output']:
            raise ValueError('Guest program or expected output differs')
        controls = ('instructions', 'rows', 'main_columns', 'interaction_columns', 'pow_bits', 'fri_queries', 'workers', 'build_mode')
        if any(a[field] != b[field] for field in controls):
            raise ValueError('Workload geometry or security changed')
        if before['artifact_sha256'] != after['artifact_sha256']:
            raise ValueError('Statement, claim or proof bytes changed')
        before_wall = before['prover_process_ns'] / 1e9
        after_wall = after['prover_process_ns'] / 1e9
        if min(before_wall, after_wall, a['prove_ns'], b['prove_ns']) <= 0:
            raise ValueError('Invalid total duration')
        stages = flatten((b.get('stage_profile') or {}).get('stages', []))
        previous_stages = flatten((a.get('stage_profile') or {}).get('stages', []))
        rows.append(dict(target=key[0], size=key[1], negative=key[2], instructions=b['instructions'],
                         before_total_s=before_wall, after_total_s=after_wall,
                         total_speedup=before_wall / after_wall, before_prove_s=a['prove_ns'] / 1e9,
                         after_prove_s=b['prove_ns'] / 1e9, before_witness_s=a['witness_ns'] / 1e9,
                         after_witness_s=b['witness_ns'] / 1e9,
                         before_peak_gib=a['peak_caller_bytes'] / 2**30,
                         peak_gib=b['peak_caller_bytes'] / 2**30,
                         interaction_s=stages.get('interaction_generation'),
                         composition_s=stages.get('composition_evaluation'),
                         cpu_fft_s=stages.get('cpu_coset_fft'), cpu_rows_s=stages.get('cpu_constraint_rows'),
                         proof_bytes=b['proof_bytes'], proof_sha256=after['artifact_sha256']['proof.bin']))
        # Missing instrumentation is unknown, never an apparent zero-cost phase.
        for name in ('fixed_commit', 'main_commit', 'interaction_generation',
                     'interaction_commit', 'composition_evaluation',
                     'cpu_coset_fft', 'cpu_constraint_rows'):
            rows[-1]['before_' + name + '_s'] = previous_stages.get(name)
            rows[-1]['after_' + name + '_s'] = stages.get(name)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--csv', type=Path, required=True)
    args = parser.parse_args()
    rows = compare(json.loads(args.baseline.read_text()), json.loads(args.candidate.read_text()))
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = dict(schema='rv64-prover-performance-comparison-v1', complete=True,
                  baseline_report_sha256=digest(args.baseline), candidate_report_sha256=digest(args.candidate),
                  exact_artifact_parity=True,
                  measurement='One complete local run per case per version; total time includes capture, setup, witness, proving, codec, verification and process overhead. Stage totals are inclusive; nested stages must not be summed with their parents.',
                  rows=rows)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    with args.csv.open('w', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    main()
