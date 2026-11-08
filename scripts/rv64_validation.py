"""Shared evidence checks for RV64 gates, comparisons, baskets and profiles.

This module validates receipts and payloads; it neither runs a prover nor
changes protocol semantics. Missing evidence never counts as acceptance.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

FROZEN_D2_PACKAGE = Path(__file__).resolve().parents[1] / 'vectors/fixtures/rv64-d2-composed-v1'

CASES = (
    'C00-control', 'S08-coherent-permute-native', 'S09-coherent-drop-native',
    'S10-coherent-dup-native', 'S11-coherent-permute-truth',
    'V02-cross-block-fold', 'V03-cross-block-leaf', 'V04-cross-block-root',
    'V05-cross-block-native', 'R04-root-proof-flip', 'R05-root-proof-truncate',
    'R06-leaf-proof-flip', 'R07-coherent-native-flip', 'R09-coherent-truth-flip',
    'X03-coherent-stage-one-flip', 'X04-coherent-cells-flip',
    'X06-coherent-terminal-value', 'T01-wrong-output', 'P01-wrong-native-profile',
)

CRASH_MARKERS = ("panic:", "reached unreachable", "Segmentation fault", "SIGSEGV", "SIGABRT", "integer overflow", "index out of bounds")
RESOURCE_ERRORS = ("FileTooBig", "OutOfMemory", "StreamTooLong")
MISSING_ERRORS = ("FileNotFound", "MissingRecursiveNodeProof")
CORPUS_ISOLATION = {'CUDA_VISIBLE_DEVICES': '', 'STWO_RV64_GPU_PCS_HELPER': '/bin/false',
                    'STWO_ZIG_RV64_SETUP_CACHE': 'unset', 'STWO_RV64_FOLD_CLASS_CACHE': '0',
                    'STWO_RV64_OUTER_PLAN_CLASS_STORE': 'unset'}


JOBS_FLAGS = ('STWO_RV64_M8_JOBS', 'STWO_RV64_M8_NATIVE_JOBS', 'STWO_RV64_M8_OUTER_JOBS')
NATIVE_LIBRARIES = ('STWO_RV64_M8_JOBS_LIBRARY', 'STWO_RV64_M8_OUTER_FS_LIBRARY')


def service_label(out, prefix='gate'):
    """Preserve independent receipts whose output directories share a name."""
    identity = hashlib.sha256(str(out.resolve()).encode()).hexdigest()[:16]
    return prefix + '-' + out.name + '-' + identity



def native_selected(environment):
    value = environment.get('STWO_RV64_M8_GPU_NATIVE', '1')
    if value not in ('0', '1'):
        raise RuntimeError('invalid GPU-native selection')
    if value == '1' and environment.get('STWO_RV64_M8_JOBS', '1') != '1':
        raise RuntimeError('GPU-native requires jobs')
    return value == '1'


def jobs_environment(runtime, extra_env):
    """Job-path environment a runtime JSON ships (`jobs_env`: STWO_* key -> path
    or value, `jobs_env_sha256`: key -> sha256 for every path entry).

    Applied to the native product default and explicitly selected job paths.
    GPU_NATIVE=0 is the reference opt-out; explicit overrides still win. Every
    shipped library is pinned by SHA-256 like the runtime assets (gate-14
    MissingM8OuterFsLibrary was a JOBS=1 gate without the outer-fs addon).
    """
    native = native_selected(extra_env)
    selected = native or any(extra_env.get(flag) == '1' for flag in JOBS_FLAGS)
    shipped = dict(runtime.get('jobs_env', {})) if selected else {}
    pins = runtime.get('jobs_env_sha256', {})
    for key, value in shipped.items():
        if not key.startswith('STWO_'):
            raise RuntimeError('runtime jobs_env key must be STWO_*: ' + key)
        if key.endswith('_LIBRARY') and key not in pins:
            raise RuntimeError('runtime jobs_env library without sha256: ' + key)
    if native and not all(k in {**shipped, **extra_env} for k in NATIVE_LIBRARIES):
        raise RuntimeError('GPU-native requires pinned jobs and outer-FS libraries')
    pinned_jobs = {key: value for key, value in shipped.items() if key in pins}
    if pinned_jobs:
        validate_assets(pinned_jobs, pins)
    validate_library_environment({**shipped, **extra_env},
                                 {**runtime.get('assets', {}), **pinned_jobs},
                                 {**runtime.get('asset_sha256', {}), **pins})
    return {k: v for k, v in shipped.items() if k not in extra_env}



def reject_class(first_error):
    if not isinstance(first_error, str) or not first_error.strip():
        return 'unclassified'
    if any(marker in first_error for marker in CRASH_MARKERS):
        return 'crash'
    if any(marker in first_error for marker in MISSING_ERRORS):
        return 'missing'
    if any(marker in first_error for marker in RESOURCE_ERRORS):
        return 'resource'
    return 'semantic'


def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def validate_assets(assets, pins):
    if not assets:
        raise RuntimeError('no pinned assets supplied')
    for name, path in assets.items():
        expected = pins.get(name)
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise RuntimeError('missing or invalid asset sha256: ' + name)
        if sha(path) != expected:
            raise RuntimeError('pinned asset changed: ' + name)


def validate_library_environment(environment, assets, pins):
    """Every effective library path must be an explicitly pinned asset.

    Check after overrides merge: validating only a preset's original value
    would let --env silently select a different, unrecorded binary.
    """
    by_path = {str(Path(path).resolve()): pins.get(name) for name, path in assets.items()}
    selected, selected_pins = {}, {}
    for key, value in environment.items():
        if not key.endswith('_LIBRARY') and key != 'LD_PRELOAD':
            continue
        paths = re.split(r'[:\s]+', value.strip()) if key == 'LD_PRELOAD' else [value]
        for index, path in enumerate(paths):
            if not path and key == 'LD_PRELOAD':
                continue
            pin = by_path.get(str(Path(path).resolve()))
            if pin is None:
                raise RuntimeError('library environment path is not a pinned asset: ' + key)
            name = f'{key}[{index}]'
            selected[name], selected_pins[name] = path, pin
    if selected:
        validate_assets(selected, selected_pins)


def payload_name(name):
    # Timing/setup telemetry may vary between requests. Receiver-owned proof
    # and binding artifacts must still match, including missing/extra files.
    return (name.endswith(('.bin', '.proof')) or
            name in ('bundle.json', 'candidate-source-bounds.json',
                     'recursion-om31/tree.json'))


def frozen_parity(proof, golden):
    proof = Path(proof)
    expected = {name: row for name, row in golden.items() if payload_name(name)}
    if not expected or 'recursion-om31/root.proof' not in expected:
        raise RuntimeError('frozen default has no complete proof fingerprints')
    actual = {str(p.relative_to(proof)): {'sha256': sha(p), 'bytes': p.stat().st_size}
              for p in proof.rglob('*') if p.is_file() and payload_name(str(p.relative_to(proof)))}
    if actual != expected:
        differences = sorted(k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k))
        raise RuntimeError('frozen default mismatch: ' + ', '.join(differences))
    return {'byte_identical': True, 'artifact_count': len(actual), 'fingerprints': actual}


def fingerprints(row, require_capture=False):
    import rv64_resident_basket as basket
    directory = Path(row['proof'])
    recursive = basket.recursive_snapshot(directory, row['leaves'])
    report = json.loads((directory / 'report.json').read_text())
    captured = report.get('captured_values_sha256')
    if require_capture and (not isinstance(captured, str) or not re.fullmatch(r'[0-9a-f]{64}', captured)):
        raise RuntimeError('required captured-input SHA256 guard missing')
    return {'native': {p.name: sha(p) for p in sorted(directory.glob('*.bin'))},
            'bundle': sha(directory / 'bundle.json'), 'tree': recursive['tree_sha256'],
            'recursive': recursive['proof_sha256'], **({'captured_values_sha256': captured} if require_capture else {})}


def check_corpus(receipt, receiver_sha256):
    if (not isinstance(receiver_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', receiver_sha256)
            or receipt.get('receiver_sha256') != receiver_sha256
            or receipt.get('receiver_env') != CORPUS_ISOLATION):
        raise RuntimeError('negative corpus receiver pin or CPU isolation is incomplete')
    results = receipt.get('results', [])
    if not isinstance(results, list) or any(not isinstance(row, dict) for row in results):
        raise RuntimeError('negative corpus results are malformed')
    ids = [row['id'] for row in results]
    if len(ids) != len(CASES) or set(ids) != set(CASES):
        raise RuntimeError('negative corpus omitted or duplicated required cases')
    pending = receipt.get('pending') or []
    if not isinstance(pending, list) or any(not isinstance(row, dict) or not isinstance(row.get('id'), str) for row in pending):
        raise RuntimeError('negative corpus pending catalog is malformed')
    if (receipt.get('unsupported') or set(row['id'] for row in pending).intersection(CASES)
            or not all(row.get('passed') is True for row in results)):
        raise RuntimeError('negative corpus failed or skipped required cases')
    if receipt.get('crashes') or receipt.get('unexpected_accepts'):
        raise RuntimeError('negative corpus crashed or unexpectedly accepted')
    limitations = {}
    for row in results:
        expect = 'accept' if row['id'] == 'C00-control' else 'reject'
        code = row.get('exit_code')
        if (row.get('status') != 'ran' or row.get('expect') != expect
                or row.get('verdict') != expect or type(code) is not int
                or (code != 0 if expect == 'accept' else code <= 0)):
            raise RuntimeError('negative corpus verdict is incomplete: ' + row['id'])
        kind = row.get('reject_class')
        if expect == 'accept':
            if kind is not None or row.get('same_statement_as_control') is not True:
                raise RuntimeError('negative corpus control statement is incomplete')
        elif kind not in ('semantic', 'resource', 'missing') or kind != reject_class(row.get('first_error')):
            raise RuntimeError('negative corpus rejection evidence is incomplete: ' + row['id'])
        elif kind != 'semantic':
            limitations[row['id']] = kind
    if receipt.get('nonsemantic_rejects', limitations) != limitations:
        raise RuntimeError('negative corpus rejection summary contradicts its cases')
    return {'status': 'PASS_WITH_LIMITATIONS' if limitations else 'PASS',
            'receiver_sha256': receiver_sha256, 'cpu_isolation_checked': True,
            'required_cases': len(CASES), 'completed_cases': len(results),
            'out_of_scope_pending_cases': len(pending),
            'semantic_rejection_complete': not limitations,
            'nonsemantic_rejects': limitations}


def validate_receivers(verdicts, proofs, receiver_sha256):
    if not isinstance(receiver_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', receiver_sha256):
        raise RuntimeError('fresh CPU receiver binary is not pinned')
    expected = set(proofs)
    if (not expected or len(expected) != len(proofs) or not isinstance(verdicts, list)
            or len(verdicts) != len(expected)):
        raise RuntimeError('fresh CPU receiver count mismatch')
    seen = set()
    for row in verdicts:
        isolation = row.get('isolation') or {}
        proof = row.get('proof')
        code = row.get('process', {}).get('exit_code')
        if (row.get('accepted') is not True or row.get('status') != 'accepted'
                or type(code) is not int or code != 0 or row.get('error')
                or row.get('receiver_sha256') != receiver_sha256
                or isolation.get('CUDA_VISIBLE_DEVICES') != ''
                or isolation.get('STWO_RV64_GPU_PCS_HELPER') != '/bin/false'
                or isolation.get('STWO_RV64_FOLD_CLASS_CACHE') != '0'
                or isolation.get('STWO_ZIG_RV64_SETUP_CACHE') != 'unset'
                or isolation.get('STWO_RV64_OUTER_PLAN_CLASS_STORE') != 'unset'
                or row.get('store_present_during_receive') is not False):
            raise RuntimeError('fresh isolated CPU acceptance is incomplete')
        if not isinstance(proof, str) or not proof or proof in seen:
            raise RuntimeError('fresh CPU receiver proof is absent or duplicated')
        seen.add(proof)
    if seen != expected:
        raise RuntimeError('fresh CPU receiver verified a different producer proof')
    return {'status': 'FRESH_ISOLATED_CPU_ACCEPTED', 'proofs': len(expected),
            'receiver_sha256': receiver_sha256}
