#!/usr/bin/env python3
"""Read immutable paired CUDA experiment artifacts; never run or modify proofs.

Each --pair NAME=DIR contains cpu/ and gpu/ runner outputs plus cpu-nvml.csv
and gpu-nvml.csv. Missing/failed runs remain explicit null records. Stage rows
are inclusive/exclusive views, not additive to request or GPU callback totals.
"""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path


def load(path):
    return json.loads(path.read_text()) if path.is_file() else None


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def csv_write(path, rows):
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def stage_rows(stages, prefix='', occurrence=''):
    for i, stage in enumerate(stages or []):
        children = stage.get('children') or []
        seconds = stage['seconds']
        child_sum = sum(c['seconds'] for c in children)
        if seconds < 0 or child_sum > seconds + 1e-6:
            raise ValueError('stage containment violated')
        name = prefix + stage['id']
        ordinal = occurrence + str(i)
        yield {'stage': name, 'occurrence': ordinal, 'inclusive_seconds': seconds,
               'exclusive_seconds': max(0, seconds-child_sum), 'leaf': not children}
        yield from stage_rows(children, name+'/', ordinal+'.')


def numeric_leaves(value, prefix=''):
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        name = prefix+key
        if isinstance(item, dict):
            yield from numeric_leaves(item, name+'.')
        elif key.endswith('_ns') and isinstance(item, (int, float)):
            yield name, item


def read_run(name, mode, base):
    directory = base/mode
    invocation = load(directory/'invocation.json') or {}
    report = load(directory/'report.json')
    device = load(directory/'gpu/cuda-deep-receipt.json')
    log_path = directory/'qualification.log'
    log = log_path.read_text(errors='replace') if log_path.exists() else ''
    passed = invocation.get('returncode') == 0 and invocation.get('report_checked') is True
    proofs = sorted(directory.glob('original-*.postcard'))
    if (directory/'root.proof').exists():
        proofs.append(directory/'root.proof')
    roster = [{'file': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in proofs]
    if passed and not roster:
        raise ValueError('successful run has no saved proof artifact')
    roster_hash = hashlib.sha256(json.dumps(roster, sort_keys=True, separators=(',', ':')).encode()).hexdigest() if roster else None
    memory = re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', log)
    nvml = base/(mode+'-nvml.csv')
    samples = []
    if nvml.exists():
        with nvml.open() as file:
            for sample in csv.DictReader(file):
                sample = {k.strip(): v.strip() for k,v in sample.items()}
                used = sample.get('memory.used [MiB]', '').split(' ')[0]
                if used.isdigit():
                    samples.append(int(used)*1024*1024)
    status = 'passed' if passed else ('interrupted' if invocation.get('returncode') in (130,-2) else ('failed' if invocation else 'missing'))
    row = {'pair': name, 'mode': mode, 'status': status,
           'returncode': invocation.get('returncode'), 'binary_sha256': invocation.get('binary_sha256'),
           'build_manifest_sha256': invocation.get('build_manifest_sha256'),
           'capture_sha256': invocation.get('capture_sha256'), 'proof_roster_sha256': roster_hash,
           'proof_files': len(roster), 'proof_bytes': sum(p['bytes'] for p in roster),
           'host_rss_bytes': int(memory[1])*1024 if memory else None,
           'sampled_device_peak_bytes': max(samples) if samples else None, 'nvml_samples': len(samples),
           'command_wall_ns': invocation.get('finished_unix_ns',0)-invocation.get('started_unix_ns',0) if invocation.get('finished_unix_ns') else None}
    diagnostic = load(base/'diagnostic-environment.json')
    row['diagnostic_only'] = bool(diagnostic and diagnostic.get('diagnostic_only'))
    row['diagnostic_environment'] = json.dumps(diagnostic.get('environment'),sort_keys=True) if diagnostic else None
    manifest_path = base/'build.json'
    manifest = load(manifest_path)
    if manifest:
        if invocation and (sha(manifest_path) != invocation.get('build_manifest_sha256') or manifest.get('binary_sha256') != invocation.get('binary_sha256')):
            raise ValueError('pair build manifest does not match invoked binary provenance')
        command = manifest.get('command') or []
        row.update({'source_sha256':manifest.get('source_sha256'),
                    'gpu_archive_sha256':manifest.get('gpu_archive_sha256'),
                    'zig_binary_sha256':manifest.get('zig_binary_sha256'),
                    'optimization':next((x[2:] for x in command if x.startswith('-O')),None),
                    'cpu_target_flag':next((x for x in command if x.startswith('-mcpu=')),None),
                    'compile_wall_ns':manifest.get('finished_unix_ns',0)-manifest.get('started_unix_ns',0)})
    phases = []
    if report:
        row['whole_request_ns'] = report.get('whole_request_ns', report.get('whole_ns'))
        row['charged_peak_bytes'] = (report.get('stats') or {}).get('charged_peak_bytes', report.get('tracked_peak_bytes', report.get('charged_peak_bytes')))
        row['root_kind'] = report.get('root_kind')
        row['shared_epoch_prefix'] = report.get('shared_epoch_prefix')
        row['materialized_parent_polynomials'] = report.get('materialized_parent_polynomials')
        for path, ns in numeric_leaves(report):
            phases.append({'pair': name, 'mode': mode, 'scope': 'report', 'stage': path, 'inclusive_seconds': ns/1e9, 'exclusive_seconds': None, 'leaf': None, 'occurrence': ''})
    if device:
        if passed and (device.get('gpu_selected') != (mode == 'gpu') or not device.get('complete_helper_succeeded') or device.get('fallback_allowed') is not False):
            raise ValueError('successful run has inconsistent CUDA selection receipt')
        for key, value in device['stats'].items():
            row['cuda_'+key] = value
        row['context_startup_ns'] = device.get('context_startup_ns')
    calls_file = directory/'gpu/cuda-deep-calls.jsonl'
    calls = [{'pair': name, 'mode': mode, 'stage': 'deep', **json.loads(line)} for line in calls_file.read_text().splitlines() if line] if calls_file.exists() else []
    if device and len(calls) != device['stats']['calls']:
        raise ValueError('callback count differs from receipt')
    composition = load(directory/'gpu/cuda-composition-receipt.json')
    composition_file = directory/'gpu/cuda-composition-calls.jsonl'
    composition_calls = [{'pair':name, 'mode':mode, 'stage':'composition', **json.loads(line)}
                         for line in composition_file.read_text().splitlines() if line] if composition_file.exists() else []
    for call in composition_calls:
        delta = call.pop('delta', {})
        for key, value in delta.items():
            if key in call and call[key] != value:
                raise ValueError('composition callback summary conflicts with its delta')
            call[key] = value
    if passed and report and (report.get('external_composition_executor') is True or invocation.get('cuda_composition') is True) and not composition:
        raise ValueError('successful selected composition run has no device receipt')
    if composition:
        if passed and (mode != 'gpu' or not composition.get('complete_helper_succeeded') or
                       composition.get('fallback_allowed') is not False or composition.get('resident_proof') is not False or
                       not report or report.get('external_composition_executor') is not True or
                       composition['stats']['calls'] != report.get('recursive_proof_count')):
            raise ValueError('composition coverage does not match selected recursive proof stage')
        if len(composition_calls) != composition['stats']['calls']:
            raise ValueError('composition callback count differs from receipt')
        for key, value in composition['stats'].items():
            row['cuda_composition_'+key] = value
        row['cuda_composition_context_startup_ns'] = composition.get('context_startup_ns')
    calls.extend(composition_calls)
    profile = load(directory/'native-stage-profile.json')
    profiles = [('native', profile)] if profile else []
    for i, line in enumerate(log.splitlines()):
        if 'BLAKE3_PARENT_STAGE_PROFILE ' in line:
            profiles.append(('root:'+str(i), json.loads(line.split('BLAKE3_PARENT_STAGE_PROFILE ',1)[1])))
    for scope, profile in profiles:
        for stage in stage_rows(profile['stages']):
            phases.append({'pair': name, 'mode': mode, 'scope': scope, **stage})
    return row, calls, phases, roster, report


def collect(pairs, output):
    output.mkdir(parents=True, exist_ok=True)
    runs, calls, phases, index = [], [], [], []
    for name, base in pairs:
        results = [read_run(name, mode, base) for mode in ('cpu','gpu')]
        for row, call, phase, _, _ in results:
            runs.append(row); calls.extend(call); phases.extend(phase)
        cpu, gpu = results
        successful = all(r[0]['status'] == 'passed' for r in results)
        same_contract = None
        if successful:
            keys = ('elf_sha256','incoming_sha256','outgoing_sha256','window','cycles','skip_cycles','segment_cycles','worker_count','native_layout_mode','resident_memory','sparse_window_initialization','query_count','pow_bits','root_kind','shared_epoch_prefix','materialized_parent_polynomials')
            same_contract = all(cpu[4].get(k) == gpu[4].get(k) for k in keys)
        index.append({'name': name, 'directory': str(base.resolve()), 'both_passed': successful,
                      'same_binary': cpu[0]['binary_sha256'] == gpu[0]['binary_sha256'] if successful else None,
                      'same_public_contract': same_contract,
                      'all_proof_bytes_equal': cpu[3] == gpu[3] if successful else None,
                      'cpu_proofs': cpu[3], 'gpu_proofs': gpu[3]})
    csv_write(output/'runs.csv', runs)
    csv_write(output/'gpu-calls.csv', calls)
    csv_write(output/'stages.csv', phases)
    (output/'index.json').write_text(json.dumps({'schema':'stwo-v7-cuda-paired-campaign-v1',
        'timing_note':'Single pairs are observations, not speedup confidence intervals. Nested inclusive stage times must not be summed; device buffer peaks differ from NVML process/device usage. Source window theorem does not prove skipped prefix or full Ethereum block.',
        'pairs':index},indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair',action='append',required=True,metavar='NAME=DIR')
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    collect([(name,Path(path)) for name,path in (p.split('=',1) for p in args.pair)],args.output)


if __name__ == '__main__':
    main()
