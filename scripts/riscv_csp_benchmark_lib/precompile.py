"""CSP guest acceleration through authenticated typed recovery and key matching.

Software fallback is itself proved. A host recovery result only selects a guest;
its verdict is never accepted as a proof of signature validity or rejection.
"""
from __future__ import annotations
import json
import statistics
import time
from pathlib import Path
from .contract import ROOT, BenchmarkError, SECURE_PCS_CONFIG, load_json, sha256_file, sha256_bytes

MANIFEST = ROOT / 'vectors/riscv_csp/ecdsa-precompile-v1.json'


def validate_manifest():
    manifest = load_json(MANIFEST)
    if manifest.get('schema') != 'stwo.csp.ecdsa-precompile-guests.v1':
        raise BenchmarkError('ECDSA precompile manifest schema drifted')
    if manifest.get('implementation') != 'typed_recovery_key_match_low_s_v1':
        raise BenchmarkError('ECDSA precompile implementation drifted')
    if not isinstance(manifest.get('guests'), dict) or set(manifest['guests']) != {'0', '1'}:
        raise BenchmarkError('ECDSA precompile guest parity set drifted')
    if not isinstance(manifest.get('sources'), list) or not manifest['sources']:
        raise BenchmarkError('ECDSA precompile source inventory missing')
    for entry in [*manifest['sources'], *manifest['guests'].values()]:
        if not isinstance(entry, dict) or not isinstance(entry.get('path'), str) or not isinstance(entry.get('sha256'), str):
            raise BenchmarkError('invalid ECDSA precompile inventory entry')
        path = (ROOT / entry['path']).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or sha256_file(path) != entry['sha256']:
            raise BenchmarkError(f"ECDSA precompile source/guest drifted: {entry['path']}")
    return manifest


def _object(raw: bytes):
    from .contract import _strict_object
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except (ValueError, UnicodeDecodeError) as exc:
        raise BenchmarkError('invalid ECDSA command JSON') from exc
    if not isinstance(value, dict):
        raise BenchmarkError('ECDSA command returned a non-object')
    return value


def benchmark_case(case, cli, trace_cli, *, run, software_benchmark, backend,
                   warmups, samples, timeout, admission, env, work_dir, workers=16):
    if case.target != 'ecdsa_secp256k1':
        return software_benchmark(case, cli, trace_cli, backend=backend, warmups=warmups,
                                  samples=samples, timeout=timeout, admission=admission,
                                  env=env, work_dir=work_dir)
    manifest = validate_manifest()
    route = _object(run([cli, 'ecdsa-csp-select', '--input', case.input_path], env=env, timeout=timeout).stdout)
    if route.get('schema') != 'stwo.csp.ecdsa-route.v1' or route.get('input_sha256') != case.input_sha256:
        raise BenchmarkError('ECDSA route is not bound to the canonical input')
    parity = route.get('recovery_id')
    if parity is None:
        row, commit = software_benchmark(case, cli, trace_cli, backend=backend, warmups=warmups,
                                        samples=samples, timeout=timeout, admission=admission,
                                        env=env, work_dir=work_dir)
        row['execution_mode'] = 'software_fallback'
        return row, commit
    if type(parity) is not int or parity not in (0, 1):
        raise BenchmarkError('invalid ECDSA recovery parity')
    guest = manifest['guests'][str(parity)]
    elf = ROOT / guest['path']
    stem = f'{case.target}_{case.input_size}'
    artifact = work_dir / f'{stem}.proof.bin'
    report_path = work_dir / f'{stem}.bench.json'
    started = time.monotonic_ns()
    process = run([cli, 'ecdsa-csp-bench', '--elf', elf, '--input', case.input_path,
                   '--proof-out', artifact, '--report-out', report_path,
                   '--samples', str(samples), '--warmups', str(warmups), '--workers', str(workers)],
                  env=env, timeout=timeout)
    outer_ns = time.monotonic_ns() - started
    (work_dir / f'{stem}.prover.log').write_bytes(process.stdout + process.stderr)
    report = load_json(report_path)
    required = {'schema': 'stwo.csp.ecdsa-guest-benchmark.v1', 'backend': backend,
                'proof_scope': 'riscv_guest', 'uses_precompile': True, 'recursion_enabled': False,
                'implementation_dirty': False, 'pcs_config': SECURE_PCS_CONFIG,
                'warmups': warmups, 'samples': samples, 'verified_samples': samples, 'workers': workers,
                'input_sha256': case.input_sha256, 'elf_sha256': guest['sha256'],
                'output_digest': case.expected_digest, 'recovery_id': parity}
    for key, expected in required.items():
        if report.get(key) != expected or type(report.get(key)) is not type(expected):
            raise BenchmarkError(f'ECDSA guest report {key} drifted')
    from .contract import HEX_40, HEX_32
    commit = report.get('implementation_commit')
    if not isinstance(commit, str) or not HEX_40.fullmatch(commit):
        raise BenchmarkError('ECDSA guest implementation identity missing')
    digest = report.get('statement_sha256')
    if not isinstance(digest, str) or not HEX_32.fullmatch(digest):
        raise BenchmarkError('ECDSA guest statement identity missing')
    measurements = report.get('measurements')
    if not isinstance(measurements, list) or len(measurements) != samples:
        raise BenchmarkError('ECDSA guest sample count drifted')
    for sample in measurements:
        if not isinstance(sample, dict) or set(sample) != {
            'execution_ns', 'witness_and_proving_ns', 'verification_ns', 'metal_dispatches', 'cpu_fallbacks'
        } or any(type(v) is not int or v < 0 for v in sample.values()):
            raise BenchmarkError('invalid ECDSA guest sample')
        if backend == 'metal' and sample['metal_dispatches'] == 0:
            raise BenchmarkError('ECDSA guest sample has no Metal dispatch')
        if backend == 'cpu' and (sample['metal_dispatches'] or sample['cpu_fallbacks']):
            raise BenchmarkError('CPU ECDSA guest carries Metal telemetry')
    encoded = artifact.read_bytes()
    artifact_hash = sha256_bytes(encoded)
    proof_bytes = report.get('proof_bytes')
    if (report.get('artifact_sha256') != artifact_hash or report.get('artifact_bytes') != len(encoded)
        or type(proof_bytes) is not int or not 0 < proof_bytes < len(encoded)
        or type(report.get('cycles')) is not int or report['cycles'] <= 0):
        raise BenchmarkError('ECDSA guest artifact or geometry drifted')
    verify_start = time.monotonic_ns()
    verified = run([cli, 'ecdsa-csp-verify', '--elf', elf, '--input', case.input_path,
                    '--artifact', artifact], env=env, timeout=timeout)
    verify_wall = time.monotonic_ns() - verify_start
    receipt = _object(verified.stdout)
    for key, expected in {'schema': 'stwo.csp.ecdsa-verify.v1', 'status': 'verified',
                          'artifact_sha256': artifact_hash, 'statement_sha256': digest,
                          'elf_sha256': guest['sha256'], 'input_sha256': case.input_sha256,
                          'pcs_config': SECURE_PCS_CONFIG}.items():
        if receipt.get(key) != expected:
            raise BenchmarkError(f'ECDSA retained verifier {key} drifted')
    (work_dir / f'{stem}.verify.json').write_bytes(verified.stdout)
    durations = [sample['execution_ns'] + sample['witness_and_proving_ns'] for sample in measurements]
    from .validation import peak_memory
    peak, memory_source = peak_memory(report)
    return {
        'system': 'stwo-zig-riscv', 'backend': backend, 'target': case.target,
        'input_size': case.input_size, 'recursion_enabled': False, 'uses_precompile': True,
        'execution_mode': 'precompile', 'proof_scope': 'riscv_guest',
        'proof_duration': round(statistics.mean(durations)),
        'verify_duration': round(statistics.mean(s['verification_ns'] for s in measurements)),
        'cycles': report['cycles'], 'proof_size': proof_bytes, 'preprocessing_size': elf.stat().st_size,
        'num_constraints': 0, 'peak_memory': peak,
        'protocol': {'name': 'secure', 'pcs_config': SECURE_PCS_CONFIG},
        'evidence': {'status': 'verified', 'public_io_bound_to_proof': True,
                     'input_sha256': case.input_sha256, 'guest_sha256': guest['sha256'],
                     'output_digest': report['output_digest'], 'expected_output_digest': case.expected_digest,
                     'statement_sha256': digest, 'artifact_sha256': artifact_hash,
                     'proof_sha256': sha256_bytes(encoded[-proof_bytes:]), 'artifact_bytes': len(encoded),
                     'artifact_path': str(artifact), 'benchmark_report_path': str(report_path),
                     'retained_verify_wall_ns': verify_wall, 'retained_verify_receipt': receipt,
                     'precompile_manifest_sha256': sha256_file(MANIFEST),
                     'precompile_dispatch_samples': measurements},
        'timing': {'source': 'production CLI internal stage timers',
                   'proof_definition': 'execution (including route computation) + witness + proof generation',
                   'verify_definition': 'artifact decode, guest/public-input binding and proof verification',
                   'samples_ns': measurements, 'median_proving_ns': statistics.median(durations),
                   'outer_command_wall_ns': outer_ns},
        'memory': {'source': memory_source, 'scope': 'self_process_lifetime'},
        'prover_log_sha256': sha256_bytes(process.stdout + process.stderr),
    }, commit
