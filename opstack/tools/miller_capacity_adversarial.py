#!/usr/bin/env python3
"""Replay retained full-span fixture roots against independent source mutations.

Requires a completed capacity_runtime_test root and its existing test binary;
never executes the guest or regenerates any native/recursive proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

P = (1 << 31) - 1

def adjust_first_coordinate(value, delta):
    if isinstance(value, dict):
        if set(value) == {'v'}:
            value['v'] = (value['v'] + delta) % P
            return True
        return any(adjust_first_coordinate(child, delta) for child in value.values())
    return False

def run(binary, cwd, config, reference, log):
    env = os.environ.copy()
    env.update(STWO_OP_MILLER_CAPACITY_CONFIG=str(config),
               STWO_OP_MILLER_CAPACITY_REFERENCE=str(reference),
               STWO_OP_MILLER_CAPACITY_MODE='verify')
    with log.open('xb') as output:
        result = subprocess.run([str(binary)], cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, check=False)
    return result.returncode, log.read_text()

def qualify(directory, binary, cwd):
    directory, binary, cwd = Path(directory).resolve(), Path(binary).resolve(), Path(cwd).resolve()
    out = directory / 'adversarial'
    out.mkdir(exist_ok=False)
    root_sha = hashlib.sha256((directory / 'group-root/root.bin').read_bytes()).hexdigest()
    config = json.loads((directory / 'config.json').read_text())
    source = json.loads((directory / 'source-only/detached-op.json').read_text())
    root = json.loads((directory / 'group-root/root.json').read_text())
    rc, _ = run(binary, cwd, directory / 'config.json', directory / 'reference.json', out / 'positive-before.log')
    if rc != 0:
        raise RuntimeError('original positive root must accept before mutations')
    names = ['missing_miller', 'duplicate_miller', 'truncated_span', 'shifted_first_id', 'extra_call', 'missing_Miller_receipt',
             'wrong_vm_profile', 'wrong_terminal_output', 'balanced_CPU_Miller_Wire']
    cases = []
    for name in names:
        case = out / name
        (case / 'source-only').mkdir(parents=True)
        (case / 'group-root').mkdir()
        cfg = json.loads(json.dumps(config))
        src = json.loads(json.dumps(source))
        meta = json.loads(json.dumps(root))
        if name == 'missing_miller':
            src['miller'] = []
        elif name == 'duplicate_miller':
            src['miller'].append(json.loads(json.dumps(src['miller'][0])))
        elif name == 'missing_Miller_receipt':
            meta['statement']['leaves'][1]['receipt'] = None
        elif name == 'truncated_span':
            src['miller'][0]['calls'] -= 1
        elif name == 'shifted_first_id':
            src['miller'][0]['first_id'] += 1
        elif name == 'extra_call':
            src['miller'][0]['calls'] += 1
        elif name == 'wrong_vm_profile':
            cfg['execution_profile'] = 'ethereum_services_v3'
        elif name == 'wrong_terminal_output':
            cfg['expected_output'] = ('0' if cfg['expected_output'][0] != '0' else '1') + cfg['expected_output'][1:]
        elif name == 'balanced_CPU_Miller_Wire':
            # CPU's appended frontier binding and both Miller claims feed the
            # SAME global Wire sum. Opposite shifts preserve that sum; only the
            # authenticated complete leaf frame/root can exclude them.
            assert adjust_first_coordinate(meta['statement']['leaves'][0]['claims'][-1], 1)
            assert adjust_first_coordinate(meta['statement']['leaves'][1]['claims'][0], -1)
        (case / 'config.json').write_text(json.dumps(cfg, indent=2) + '\n')
        (case / 'source-only/detached-op.json').write_text(json.dumps(src, indent=2) + '\n')
        (case / 'group-root/root.json').write_text(json.dumps(meta, indent=2) + '\n')
        shutil.copyfile(directory / 'source-only/cells.bin', case / 'source-only/cells.bin')
        for file in ['root.bin', 'templates.bin']:
            shutil.copyfile(directory / 'group-root' / file, case / 'group-root' / file)
        rc, log = run(binary, cwd, case / 'config.json', directory / 'reference.json', out / (name + '.log'))
        errors = re.findall(r'FAIL \(([^)]+)\)', log)
        if rc <= 0 or not errors or any(term in log for term in ['OutOfMemory', 'Segmentation fault', 'thread panic', 'StackOverflow']):
            raise RuntimeError(f'{name}: expected ordinary verifier refusal, got rc={rc}, errors={errors}')
        physical_errors = {'PoseidonGlobalLookupSum', 'InvalidNativeDotR7Authority', 'UntrustedPoseidonFixedCommitment'}
        reached = bool(set(errors) & physical_errors)
        if name == 'balanced_CPU_Miller_Wire' and not reached:
            raise RuntimeError(f'balanced Wire mutation must reach independently constructed root verifier: {errors}')
        cases.append(dict(case=name, returncode=rc, errors=errors,
                          physical_root_authority_reached=reached))
    rc, _ = run(binary, cwd, directory / 'config.json', directory / 'reference.json', out / 'positive-after.log')
    if rc != 0:
        raise RuntimeError('restored positive root must accept after mutations')
    assert hashlib.sha256((directory / 'group-root/root.bin').read_bytes()).hexdigest() == root_sha
    report = dict(schema='op-miller-capacity-source-only-adversarial/v1',
                  positive_controls=2, cases=cases, root_sha256=root_sha,
                  native_proof_read=False, guest_or_proof_regenerated=False,
                  scope='Source-admission/framing and independent root-verifier rejections, not all AIR mutations')
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return out / 'report.json'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('--binary', required=True)
    parser.add_argument('--cwd', required=True)
    args = parser.parse_args()
    print(qualify(args.directory, args.binary, args.cwd))
