#!/usr/bin/env python3
"""Six CPU-only full-receiver negatives against the accepted coalesced headline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

import rv64_m4_resident as R


def fingerprint(path):
    out = {}
    for file in sorted(path.rglob('*')):
        if file.is_file():
            with file.open('rb') as f:
                out[str(file.relative_to(path))] = hashlib.file_digest(f, 'sha256').hexdigest()
    return out


def replace(path, data):
    temporary = path.with_name(path.name + '.tamper-tmp')
    temporary.write_bytes(data)
    os.replace(temporary, path)  # Never write through an original hard link.


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', required=True, type=Path)
    p.add_argument('--receiver', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--cases', nargs='+', help='Optional subset, preserving complete per-case evidence')
    p.add_argument('--coherent-root', action='store_true', help='Corrupt the top fold and exported root together')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    receipt = json.loads((args.run / 'receipt.json').read_text())
    original_plan = json.loads((args.run / 'plan.json').read_text())
    request = next(row for row in receipt['requests'] if row['trial'] == 0)
    if request['block'] != 24628607 or request['leaves'] != 14:
        raise RuntimeError('expected actual fourteen-leaf headline proof')
    if not any(v['accepted'] and v['proof'] == request['proof'] for v in receipt['receivers']):
        raise RuntimeError('fixture lacks fresh CPU acceptance')
    if original_plan.get('store', {}).get('directory'):
        raise RuntimeError('store must be absent')
    original = Path(request['proof'])
    before = fingerprint(original)
    result = {'schema': 'rv64-m7-coalesced-head-tamper/v1', 'author': 'OpenAI Codex',
              'run': str(args.run), 'proof': str(original), 'original_fingerprints': before,
              'scope': 'Six fresh cache-disabled/GPU-disabled full receiver processes. Hard-linked fixtures; mutated files atomically replaced. No performance claim.',
              'cases': []}
    cases = ['truth_first_id', 'truth_calls_coverage', 'omitted_truth', 'wrong_native_profile',
             'coherent_native_truth_corruption', 'recursive_root_corruption']
    if args.cases and any(case not in cases for case in args.cases):
        raise RuntimeError('unknown tamper case')
    chosen = [case for case in cases if not args.cases or case in args.cases]
    result['expected_cases'] = chosen
    result['coherent_root'] = args.coherent_root
    for case in chosen:
        directory = args.out / case
        directory.mkdir()
        proof = directory / 'proof'
        shutil.copytree(original, proof, copy_function=os.link)
        plan = json.loads(json.dumps(original_plan))
        plan['assets']['recursive_receiver'] = str(args.receiver)
        bundle = json.loads((proof / 'bundle.json').read_text())
        merged = next(i for i, value in enumerate(bundle['truths']) if value['declaration']['family'] == 'add')
        details = {}
        if case == 'truth_first_id':
            bundle['truths'][merged]['declaration']['first_id'] += 1
        elif case == 'truth_calls_coverage':
            bundle['truths'][merged]['declaration']['calls'] -= 1
        elif case == 'omitted_truth':
            index = len(bundle['truths']) - 1
            bundle['truths'].pop()
            (proof / f'truth-{index}.bin').unlink()
        elif case == 'wrong_native_profile':
            plan['profile'] = 'conjectured128_b2_q108_p20_fold4'
        elif case == 'coherent_native_truth_corruption':
            file = proof / f'truth-{merged}.bin'
            data = bytearray(file.read_bytes())
            offset = len(data) // 2
            data[offset] ^= 1
            replace(file, data)
            bundle['truths'][merged]['proof']['sha256'] = list(hashlib.sha256(data).digest())
            details.update(offset=offset, coherent_bundle_hash=True, native_truth=merged)
        else:
            file = proof / 'recursion-om31/root.proof'
            data = bytearray(file.read_bytes())
            offset = len(data) // 2
            data[offset] ^= 1
            replace(file, data)
            details['offset'] = offset
            if args.coherent_root:
                tree = json.loads((proof / 'recursion-om31/tree.json').read_text())
                top = proof / f"recursion-om31/fold-{tree['root']:06d}.proof"
                if before[str(top.relative_to(proof))] != before['recursion-om31/root.proof']:
                    raise RuntimeError('expected exported root to equal the original top fold')
                replace(top, data)
                details['coherent_top_fold'] = str(top.relative_to(proof))
        replace(proof / 'bundle.json', json.dumps(bundle).encode())
        try:
            verdict = R.receive_one(plan, request['block'], proof, directory, 16)
        except RuntimeError as error:
            # The positive-path harness raises on the expected nonzero child
            # exit, retaining its exact wait4 measurement on the exception.
            if not hasattr(error, 'measurement'):
                raise
            receiver_directory, = directory.glob('receiver-*')
            verdict = {'accepted': False, 'status': 'rejected', 'block': request['block'],
                       'process': error.measurement, 'directory': str(receiver_directory),
                       'receiver_sha256': R.P.sha(args.receiver),
                       'isolation': {'CUDA_VISIBLE_DEVICES': '', 'STWO_RV64_GPU_PCS_HELPER': '/bin/false',
                                     'STWO_ZIG_RV64_SETUP_CACHE': 'unset',
                                     'STWO_RV64_OUTER_PLAN_CLASS_STORE': 'unset',
                                     'STWO_RV64_FOLD_CLASS_CACHE': '0'}}
        verdict['store_present_during_receive'] = False
        stderr = (Path(verdict['directory']) / 'strict-receiver.stderr').read_text(errors='replace')
        errors = re.findall(r'^error:\s*([^\n]+)', stderr, re.M)
        explicit_reject = (not verdict['accepted'] and verdict['process']['exit_code'] > 0
                           and bool(errors) and not re.search(r'panic|segmentation fault|core dumped', stderr, re.I))
        result['cases'].append({'id': case, 'passed': explicit_reject, 'mutation': details,
                                'explicit_errors': errors, 'verdict': verdict,
                                'mutated_files': {name: digest for name, digest in fingerprint(proof).items() if before.get(name) != digest},
                                'omitted_files': sorted(set(before) - set(fingerprint(proof)))})
        result['original_byte_identical'] = before == fingerprint(original)
        (args.out / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'case': case, 'passed': explicit_reject, 'errors': errors,
                          'wall_s': verdict['process']['wall_ns'] / 1e9}), flush=True)
        if not explicit_reject or not result['original_byte_identical']:
            raise RuntimeError('tamper acceptance, crash, or original corruption: ' + case)
    result['passed'] = len(result['cases']) == len(chosen)
    (args.out / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
