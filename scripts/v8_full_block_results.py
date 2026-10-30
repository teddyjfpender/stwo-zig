#!/usr/bin/env python3
"""Collect a live complete-block campaign without treating publication as proof.

Parent proof time, original-bundle time and whole-run time have distinct columns.
Per-window budget peaks from native reports are cumulative, not isolated peaks.
Missing measurements remain empty. The observer never changes proving artifacts.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from v8_full_block_prove import validate_result

_proof_hashes = {}


def proof_hash(path: Path):
    stat = path.stat()
    identity = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    previous = _proof_hashes.get(path)
    if previous is None or previous[0] != identity:
        previous = (identity, hashlib.sha256(path.read_bytes()).hexdigest())
        _proof_hashes[path] = previous
    return previous[1]


def read(path: Path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def seconds(value):
    return None if value is None else value / 1e9


def publish_csv(path: Path, rows: list[dict]):
    if not rows:
        return
    fields = list(dict.fromkeys(key for row in rows for key in row))
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def stage_measurements(report, *, source, family, index=None, prefix=''):
    """Keep every recorded duration/byte counter without inventing partitions.

    Nested whole times include their child stages and must not be summed with
    them. Byte counters retain their original names: some are cumulative peaks,
    others retained storage, rather than isolated per-operation device peaks.
    """
    rows = []
    for key, value in report.items():
        name = f'{prefix}.{key}' if prefix else key
        if isinstance(value, dict):
            rows.extend(stage_measurements(value, source=source, family=family,
                                           index=index, prefix=name))
        elif type(value) is int and (key.endswith('_ns') or key.endswith('_bytes')):
            rows.append(dict(family=family, index=index, source=source,
                             measurement=name, value=value,
                             unit='ns' if key.endswith('_ns') else 'bytes'))
    return rows


def collect(attempt: Path):
    plan = json.loads((attempt / 'selected-plan.json').read_text())
    invocation = read(attempt / 'invocation.json') or {}
    proof = attempt / 'proof'
    analysis = attempt / 'analysis'
    analysis.mkdir(exist_ok=True)
    verified = False
    report = read(proof / 'report.json')
    audit_error = None
    if report is not None and (proof / 'benchmark-report.json').exists():
        try:
            validate_result(proof, plan, resume_allowed=invocation.get('resume_requested', False), native_cohort_cycles=invocation.get('native_cohort_cycles'), immutable_admission_cache=invocation.get('immutable_admission_cache', False))
            verified = True
        except (ValueError, KeyError, TypeError, OSError) as error:
            audit_error = str(error)
    rows = []
    stages = []
    for index, window in enumerate(plan['windows']):
        original = read(proof / f'window-{index}-original.json')
        parent = read(proof / f'node-{index}.recursion.json')
        root_path = proof / f'node-{index}.proof'
        row = dict(window_index=index, window_id=window['id'], kind=window['kind'], skip_cycles=window['skip_cycles'], cycles=window['cycles'], native_rows=window['counts']['core_rows'], keccak_calls=window['counts']['keccak_calls'], recovery_calls=window['counts']['recovery_calls'], sha_calls=window['counts']['sha_calls'], original_report_present=original is not None, root_published=root_path.exists(), full_block_verified=verified, workers=invocation.get('workers'), queries=70, pow_bits=26)
        if original is not None:
            stages.extend(stage_measurements(original, source=f'window-{index}-original.json', family='window_original', index=index))
            row['original_bundle_whole_s'] = seconds(original.get('whole_ns'))
            if window['kind'] == 'native':
                row.update(original_core_sum_s=seconds(original.get('local_core_proof_ns')), execution_s=seconds(original.get('execution_ns')), native_witness_s=seconds(original.get('native_witness_ns')), original_fresh_bundle_verification_s=seconds(original.get('fresh_bundle_verify_ns')), cumulative_parent_budget_peak_bytes=original.get('charged_peak_bytes'))
            else:
                row.update(original_core_sum_s=seconds(original.get('original', {}).get('core_ns')), source_preparation_s=seconds(original.get('preparation_ns')), execution_s=seconds(original.get('preparation', {}).get('execution_ns')), native_witness_s=seconds(original.get('preparation', {}).get('native_ns')), caller_witness_s=seconds(original.get('preparation', {}).get('caller_ns')), original_fresh_bundle_verification_s=seconds(original.get('fresh_verification_ns')))
        if parent is not None:
            stages.extend(stage_measurements(parent, source=f'node-{index}.recursion.json', family='window_parent', index=index))
            for name in ('fixed_compile', 'fixed_commit', 'witness', 'plan', 'proof', 'encode', 'whole'):
                row[f'root_parent_{name}_s'] = seconds(parent.get(name + '_ns'))
            row['root_parent_retained_rows_bytes'] = parent.get('retained_rows_bytes')
        if root_path.exists():
            row['root_bytes'] = root_path.stat().st_size
            row['root_sha256'] = proof_hash(root_path)
        rows.append(row)
    publish_csv(analysis / 'windows.csv', rows)
    folds = []
    for path in sorted(proof.glob('node-*.timing.json'), key=lambda path: int(path.name.split('-')[1].split('.')[0])):
        timing = read(path)
        if timing is None:
            continue
        index = timing['index']
        parent = read(proof / f'node-{index}.proving.json') or {}
        resumed = read(proof / f'node-{index}.resume.json') if invocation.get('resume_requested') and invocation.get('immutable_admission_cache') else None
        stages.extend(stage_measurements(timing, source=path.name, family='fold_whole', index=index))
        stages.extend(stage_measurements(parent, source=f'node-{index}.proving.json', family='fold_parent', index=index))
        row = dict(node_index=index, children=json.dumps(timing['children']), fold_whole_s=seconds(timing.get('fold_ns')), full_block_verified=verified)
        row['production_timing_scope'] = 'historical_production' if resumed is not None else 'recorded_production'
        row['resumed_from_saved_proof'] = resumed is not None
        row['current_resume_verification_s'] = seconds(resumed.get('verification_ns')) if resumed is not None else None
        if resumed is not None:
            stages.extend(stage_measurements(resumed, source=f'node-{index}.resume.json', family='fold_resume_verification', index=index))
        for name in ('fixed_compile', 'fixed_commit', 'key_admission', 'witness', 'plan', 'proof', 'encode', 'whole'):
            row[f'parent_{name}_s'] = seconds(parent.get(name + '_ns'))
        row['parent_retained_rows_bytes'] = parent.get('retained_rows_bytes')
        folds.append(row)
    publish_csv(analysis / 'folds.csv', folds)
    if report is not None:
        stages.extend(stage_measurements(report, source='report.json', family='complete_run'))
    benchmark = read(proof / 'benchmark-report.json')
    if benchmark is not None:
        # The nested pipeline is already exported from its authoritative report.
        # Keep outer loading/whole timing as a distinct boundary, not another
        # copy of every pipeline duration.
        outer = {key: value for key, value in benchmark.items() if key != 'pipeline'}
        stages.extend(stage_measurements(outer, source='benchmark-report.json', family='benchmark'))
    publish_csv(analysis / 'stages.csv', stages)
    state = dict(schema='stwo-b8-full-block-analysis-v1', full_block_verified=verified, artifact_audit_error=audit_error, windows=len(rows), published_window_roots=sum(row['root_published'] for row in rows), completed_folds=len(folds), progress=read(proof / 'progress.json'), report=report, timing_notes=['Original bundle and parent-recursion durations are different boundaries.', 'Native charged peaks are cumulative parent-budget peaks, not per-window peaks.', 'Published files alone do not establish a verified full-block proof.', 'Resumed invocation time excludes earlier completed proving.'])
    (analysis / 'summary.json').write_text(json.dumps(state, indent=2) + '\n')
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('attempt', type=Path)
    parser.add_argument('--watch-pid', type=int)
    args = parser.parse_args()
    previous = None
    while True:
        state = collect(args.attempt)
        progress = state.get('progress') or {}
        identity = (progress.get('phase'), progress.get('completed'), state['full_block_verified'])
        if identity != previous:
            with (args.attempt / 'analysis/progress-observations.jsonl').open('a') as stream:
                stream.write(json.dumps(dict(observed_unix_ns=time.time_ns(), progress=progress, full_block_verified=state['full_block_verified'])) + '\n')
            previous = identity
        if args.watch_pid is None:
            break
        try:
            os.kill(args.watch_pid, 0)
        except ProcessLookupError:
            collect(args.attempt)
            break
        rss = subprocess.run(['ps', '-o', 'rss=', '-p', str(args.watch_pid)], capture_output=True, text=True, check=False).stdout.strip()
        if rss.isdigit():
            with (args.attempt / 'analysis/host-rss.csv').open('a', newline='') as stream:
                csv.writer(stream).writerow([time.time_ns(), progress.get('phase'), progress.get('completed'), int(rss) * 1024])
        time.sleep(5)


if __name__ == '__main__':
    main()
