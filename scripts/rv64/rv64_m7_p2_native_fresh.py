#!/usr/bin/env python3
"""Fresh-process acceptance and bounded-container negatives for trusted P0 RV64 fixture."""
import argparse
import hashlib
import json
import pathlib
import shutil
import struct
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--receiver', required=True, type=pathlib.Path)
    p.add_argument('--input', required=True, type=pathlib.Path)
    p.add_argument('--out', required=True, type=pathlib.Path)
    args = p.parse_args()
    args.receiver = args.receiver.resolve()
    args.input = args.input.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    names = ['manifest.raw-blake.binary', 'cpu-0.worker.binary', 'cpu-1.worker.binary']
    original = (args.input / names[1]).read_bytes()
    claims = struct.unpack_from('<I', original, 44)[0]
    assert 0 < claims <= 256 and original[:8] == b'P2CPUV02'
    proof = 56 + 32 * claims
    assert original[proof:proof + 8] == b'STP2OW02'
    assert struct.unpack_from('<I', original, proof + 32)[0] == 4
    changes = {
        'magic': lambda b: b.__setitem__(0, b[0] ^ 1),
        'profile': lambda b: b.__setitem__(8, b[8] ^ 1),
        'ordinal': lambda b: struct.pack_into('<I', b, 40, 1),
        'canonical_claim': lambda b: struct.pack_into('<I', b, 56, 2147483647),
        'inner_version': lambda b: b.__setitem__(proof + 7, ord('1')),
        'ninth_main_root_limb': lambda b: b.__setitem__(proof + 104, b[proof + 104] ^ 1),
        'truncated': lambda b: b.pop(),
        'trailing': lambda b: b.append(0),
    }
    result = {'schema': 'rv64-mixed-p2-native-fresh-process/v1',
              'status': 'trusted5step2CPU P0 fixture; no Ethereum/recursive/128bit claim',
              'receiver_sha256': sha(args.receiver),
              'input_sha256': {name: sha(args.input / name) for name in names},
              'runs': []}
    for label in ['accept', *changes]:
        dest = args.out / label
        dest.mkdir(exist_ok=True)
        for name in names:
            shutil.copyfile(args.input / name, dest / name)
        if label != 'accept':
            blob = bytearray(original)
            changes[label](blob)
            (dest / names[1]).write_bytes(blob)
        run = subprocess.run([str(args.receiver), 'verify', str(dest.resolve())],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, timeout=180)
        (dest / 'receiver.log').write_text(run.stdout)
        ok = run.returncode == 0 if label == 'accept' else run.returncode != 0
        if label == 'accept':
            ok = ok and 'P2_NATIVE_FRESH_RECEIVER accepted=true' in run.stdout
        row = {'case': label, 'returncode': run.returncode, 'passed': ok,
               'container_sha256': sha(dest / names[1])}
        result['runs'].append(row)
        print(json.dumps(row), flush=True)
        (args.out / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
        if not ok:
            raise SystemExit('fresh receiver gate failed: ' + label)
    result['accepted'] = 1
    result['rejected'] = len(changes)
    (args.out / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
