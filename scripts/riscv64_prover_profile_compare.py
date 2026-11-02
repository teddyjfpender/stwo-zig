#!/usr/bin/env python3
"""Compare verified CSP evidence; this report reader is not a proof verifier.

Byte parity qualifies transcript-preserving optimizations. Semantic parity also
admits changed proof geometry, requiring every public statement field to match,
fresh verification of the pinned claims, and identical explicit PCS security.
"""
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


def checked_security(case):
    config = case.get('pcs_config')
    if (not isinstance(config, dict) or
            set(config) != {'pow_bits', 'fri_config', 'lifting_log_size'}):
        raise ValueError('Semantic parity requires explicit complete PCS security configuration')
    fri = config['fri_config']
    keys = {'log_blowup_factor', 'log_last_layer_degree_bound', 'n_queries', 'fold_step'}
    if (type(config['pow_bits']) is not int or not 0 <= config['pow_bits'] <= 256 or
            not isinstance(fri, dict) or set(fri) != keys or
            any(type(fri[key]) is not int for key in keys) or
            not 1 <= fri['log_blowup_factor'] <= 16 or
            not 0 <= fri['log_last_layer_degree_bound'] <= 10 or
            fri['n_queries'] <= 0 or not 1 <= fri['fold_step'] <= 31 or
            (config['lifting_log_size'] is not None and
             (type(config['lifting_log_size']) is not int or not 0 <= config['lifting_log_size'] <= 31))):
        raise ValueError('Invalid PCS security configuration')
    if (case['prover'].get('pcs_config') != config or
            case['fresh_process'].get('pcs_config') != config or
            case['prover']['pow_bits'] != config['pow_bits'] or
            case['prover']['fri_queries'] != fri['n_queries']):
        raise ValueError('Producer and fresh receiver security configurations differ')
    return config


def compare(baseline, candidate, parity='bytes'):
    if parity not in ('bytes', 'semantic'):
        raise ValueError('Unknown parity gate')
    if not all(report.get('complete') is True and report.get('whole_guest_proof') is True for report in (baseline, candidate)):
        raise ValueError('Both reports must contain complete verified proofs')
    timing_fields = ('host', 'memory_limit_bytes', 'profile_stages')
    timing_comparable = all(field in baseline and field in candidate and
                            baseline[field] == candidate[field] for field in timing_fields)
    old = {identity(case): case for case in baseline['cases']}
    new = {identity(case): case for case in candidate['cases']}
    if not old or not new or len(old) != len(baseline['cases']) or len(new) != len(candidate['cases']) or old.keys() != new.keys():
        raise ValueError('Case coverage differs or contains duplicates')
    rows = []
    for key, after in new.items():
        before = old[key]
        a, b = before['prover'], after['prover']
        if any(case['status'] != 'verified_full_execution' or case.get('independent_statement_binding') is not True or
               case['fresh_process'].get('verified') is not True or case['fresh_process'].get('whole_guest_proof') is not True for case in (before, after)):
            raise ValueError('Every case needs independent expected-state binding and fresh verification')
        if before['elf_sha256'] != after['elf_sha256'] or before['expected_output'] != after['expected_output']:
            raise ValueError('Guest program or expected output differs')
        controls = ('instructions', 'pow_bits', 'fri_queries', 'workers', 'build_mode')
        if parity == 'bytes':
            controls += ('rows', 'main_columns', 'interaction_columns')
        if any(a[field] != b[field] for field in controls):
            raise ValueError('Workload geometry or security changed')
        if parity == 'bytes' and before['artifact_sha256'] != after['artifact_sha256']:
            raise ValueError('Statement, claim or proof bytes changed')
        if parity == 'semantic':
            for case in (before, after):
                value = case.get('semantic_statement_sha256')
                if (not isinstance(value, str) or len(value) != 64 or
                        any(char not in '0123456789abcdef' for char in value) or
                        case.get('fresh_claim_verification') is not True):
                    raise ValueError('Semantic parity requires a pinned statement and fresh claim verification')
                checked_security(case)
            if before['semantic_statement_sha256'] != after['semantic_statement_sha256']:
                raise ValueError('Public execution statement semantics changed')
            if before['pcs_config'] != after['pcs_config']:
                raise ValueError('Proof security configuration changed')
        before_wall = before['prover_process_ns'] / 1e9
        after_wall = after['prover_process_ns'] / 1e9
        if min(before_wall, after_wall, a['prove_ns'], b['prove_ns']) <= 0:
            raise ValueError('Invalid total duration')
        stages = flatten((b.get('stage_profile') or {}).get('stages', []))
        previous_stages = flatten((a.get('stage_profile') or {}).get('stages', []))
        rows.append(dict(target=key[0], size=key[1], negative=key[2], instructions=b['instructions'],
                         before_total_s=before_wall, after_total_s=after_wall,
                         total_speedup=before_wall / after_wall if timing_comparable else None,
                         timing_metadata_match=timing_comparable, before_prove_s=a['prove_ns'] / 1e9,
                         after_prove_s=b['prove_ns'] / 1e9, before_witness_s=a['witness_ns'] / 1e9,
                         after_witness_s=b['witness_ns'] / 1e9,
                         before_peak_gib=a['peak_caller_bytes'] / 2**30,
                         peak_gib=b['peak_caller_bytes'] / 2**30,
                         interaction_s=stages.get('interaction_generation'),
                         composition_s=stages.get('composition_evaluation'),
                         cpu_fft_s=stages.get('cpu_coset_fft'), cpu_rows_s=stages.get('cpu_constraint_rows'),
                         proof_bytes=b['proof_bytes'], proof_sha256=after['artifact_sha256']['proof.bin']))
        rows[-1].update(parity_gate=parity,
                        exact_artifact_parity=before['artifact_sha256'] == after['artifact_sha256'])
        for field in ('rows', 'main_columns', 'interaction_columns', 'oods_samples',
                      'queried_base_values', 'authenticated_hashes'):
            rows[-1]['before_' + field] = a.get(field)
            rows[-1]['after_' + field] = b.get(field)
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
    parser.add_argument('--parity', choices=('bytes', 'semantic'), default='bytes')
    args = parser.parse_args()
    rows = compare(json.loads(args.baseline.read_text()), json.loads(args.candidate.read_text()), args.parity)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = dict(schema='rv64-prover-performance-comparison-v1', complete=True,
                  baseline_report_sha256=digest(args.baseline), candidate_report_sha256=digest(args.candidate),
                  parity_gate=args.parity,
                  exact_artifact_parity=all(row['exact_artifact_parity'] for row in rows),
                  measurement='One complete local run per case per version; total time includes capture, setup, witness, proving, codec, verification and process overhead. Stage totals are inclusive; nested stages must not be summed with their parents.',
                  rows=rows)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    with args.csv.open('w', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    main()
