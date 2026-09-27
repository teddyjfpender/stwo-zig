"""Full-width binary artifacts and verified phase reports for CSP workloads."""
from __future__ import annotations

import json
import math
import statistics
import struct
import time

from .contract import (BenchmarkError, HEX_32, HEX_40, SECURE_PCS_CONFIG,
                       _strict_object, sha256_bytes)
from .validation import peak_memory

PHASES = ('execution_ns', 'witness_ns', 'admission_ns', 'proving_ns',
          'artifact_encoding_ns', 'fresh_verification_ns')
PARTITION = 'execution+witness+admission+proving+artifact_encoding+fresh_verification'


def require(value, expected, label):
    if type(value) is not type(expected) or value != expected:
        raise BenchmarkError(f'full-width {label} drifted')


def policy(value):
    if not isinstance(value, dict):
        raise BenchmarkError('full-width PCS configuration missing')
    normalized = dict(value)
    normalized.setdefault('lifting_log_size', None)
    if normalized != SECURE_PCS_CONFIG:
        raise BenchmarkError('full-width canonical PCS configuration drifted')
    # Python bools compare equal to integers; reject those separately.
    if type(normalized['pow_bits']) is not int or any(
        type(v) is not int for v in normalized['fri_config'].values()
    ):
        raise BenchmarkError('full-width PCS integer encoding drifted')


def artifact_sections(raw):
    if not 28 <= len(raw) <= 768 * 1024 * 1024:
        raise BenchmarkError('full-width artifact length invalid')
    magic = raw[:8]
    if magic not in (b'B3RVART1', b'B3EVART1'):
        raise BenchmarkError('full-width artifact identity invalid')
    version, metadata_len, body_len = struct.unpack_from('<IQQ', raw, 8)
    if version != 1 or metadata_len > 96 * 1024 * 1024 or 28 + metadata_len + body_len != len(raw):
        raise BenchmarkError('full-width artifact framing invalid')
    metadata = raw[28:28 + metadata_len]
    if magic == b'B3EVART1':
        if len(metadata) < 468 or metadata[:12] != b'B3EHADM1\x01\0\0\0':
            raise BenchmarkError('full-width Ethereum manifest invalid')
        metadata = metadata[468:]
    if len(metadata) < 184 or metadata[:12] != b'B3EXADM1\x01\0\0\0':
        raise BenchmarkError('full-width native manifest invalid')
    pow_bits, blowup, last, queries, fold, lift, lift_log = struct.unpack_from('<7I', metadata, 76)
    if (pow_bits, blowup, last, queries, fold, lift, lift_log) != (26, 1, 0, 70, 1, 0, 0):
        raise BenchmarkError('full-width serialized PCS policy drifted')
    body = raw[28 + metadata_len:]
    ethereum = magic == b'B3EVART1'
    header = 64 if ethereum else 56
    if len(body) < header or body[:8] != (b'B3EHART1' if ethereum else b'B3EXART1') or struct.unpack_from('<I', body, 8)[0] != 1:
        raise BenchmarkError('full-width proof framing invalid')
    claims = struct.unpack_from('<I', body, 44)[0]
    extra = struct.unpack_from('<I', body, 48)[0] if ethereum else 0
    if ethereum and struct.unpack_from('<I', body, 52)[0] != 0:
        raise BenchmarkError('full-width proof reserved field invalid')
    size = struct.unpack_from('<Q', body, 56 if ethereum else 48)[0]
    start = header + claims * 16 + extra
    if not size or start + size != len(body):
        raise BenchmarkError('full-width STARK payload length invalid')
    return magic.decode(), metadata[12:44].hex(), metadata[44:76].hex(), body[start:]


def validate_report(report, case, *, backend, warmups, samples, experimental):
    expected = dict(schema='riscv_full_width_execution_v2', mode='bench',
                    proof_suite='blake3', security_policy='secure', backend=backend,
                    release_status='experimental_full_width', experimental=experimental,
                    verified_in_process=True, recursion_enabled=False, warmups=warmups,
                    samples=samples, verified_samples=samples, total_steps=case.expected_cycles,
                    timing_unit='nanoseconds', timing_partition=PARTITION,
                    elf_sha256=case.guest_sha256, input_sha256=case.input_sha256,
                    output_len=32, output_sha256=sha256_bytes(bytes.fromhex(case.expected_digest)),
                    implementation_dirty=False)
    for key, value in expected.items():
        require(report.get(key), value, key)
    policy(report.get('pcs_config'))
    for field in ('statement_blake3', 'transcript_digest_blake3', 'proof_sha256', 'executable_sha256'):
        if not isinstance(report.get(field), str) or not HEX_32.fullmatch(report[field]):
            raise BenchmarkError(f'full-width {field} invalid')
    if not isinstance(report.get('implementation_commit'), str) or not HEX_40.fullmatch(report['implementation_commit']):
        raise BenchmarkError('full-width commit invalid')
    timings = report.get('timings')
    if not isinstance(timings, list) or len(timings) != samples:
        raise BenchmarkError('full-width sample count invalid')
    for sample in timings:
        if not isinstance(sample, dict) or set(sample) != {*PHASES, 'total_ns'}:
            raise BenchmarkError('full-width timing fields invalid')
        if any(type(v) is not int or v < 0 for v in sample.values()) or sample['total_ns'] <= 0:
            raise BenchmarkError('full-width timing value invalid')
        if sum(sample[p] for p in PHASES) != sample['total_ns']:
            raise BenchmarkError('full-width timing partition invalid')
    median = statistics.median(t['total_ns'] for t in timings) / 1e9
    observed = report.get('median_seconds')
    if type(observed) not in (int, float) or not math.isfinite(observed) or not math.isclose(observed, median, rel_tol=1e-12, abs_tol=1e-12):
        raise BenchmarkError('full-width timing median invalid')
    devices = report.get('proof_device_counts')
    if not isinstance(devices, list) or len(devices) != samples:
        raise BenchmarkError('full-width device sample count invalid')
    for sample in devices:
        if not isinstance(sample, dict) or set(sample) != {'dispatches', 'cpu_fallbacks'} or any(type(v) is not int or v < 0 for v in sample.values()):
            raise BenchmarkError('full-width device counters invalid')
        if backend == 'metal' and sample['dispatches'] == 0:
            raise BenchmarkError('full-width Metal proof has no device dispatch')
        if backend == 'cpu' and any(sample.values()):
            raise BenchmarkError('full-width CPU proof claims device work')
    return timings


def finish(case, report, *, cli, backend, warmups, samples, admission, env, timeout,
           artifact_path, bench_path, execution, completed, wall_duration_ns, run, report_path):
    require(execution.get('cycles'), case.expected_cycles, 'trace cycles')
    require(execution.get('output_digest'), case.expected_digest, 'trace output')
    timings = validate_report(report, case, backend=backend, warmups=warmups,
                              samples=samples, experimental=admission.experimental)
    if artifact_path.stat().st_size > 768 * 1024 * 1024:
        raise BenchmarkError('full-width artifact exceeds file bound')
    raw = artifact_path.read_bytes()
    magic, elf_hash, input_hash, stark = artifact_sections(raw)
    require(report.get('artifact_magic'), magic, 'artifact magic')
    require(report.get('execution_profile'), 'rv32im_zkvm_ethereum_v1' if magic == 'B3EVART1' else 'rv32im_zkvm_v1', 'execution profile')
    require(elf_hash, case.guest_sha256, 'manifest ELF')
    require(input_hash, case.input_sha256, 'manifest input')
    require(report.get('proof_bytes'), len(raw), 'artifact size')
    artifact_hash = sha256_bytes(raw)
    require(report['proof_sha256'], artifact_hash, 'artifact hash')
    started = time.monotonic_ns()
    verified = run([cli, '--proof-suite', 'blake3', 'verify', '--artifact', artifact_path,
                    '--elf', case.guest_path, '--input', case.input_path, '--protocol', 'secure',
                    '--expect-statement-digest', report['statement_blake3']], env=env, timeout=timeout)
    retained_ns = time.monotonic_ns() - started
    bench_path.with_suffix('.verify.json').write_bytes(verified.stdout)
    try:
        receipt = json.loads(verified.stdout, object_pairs_hook=_strict_object)
    except (ValueError, UnicodeDecodeError) as error:
        raise BenchmarkError('full-width verifier receipt invalid') from error
    if not isinstance(receipt, dict):
        raise BenchmarkError('full-width verifier receipt is not an object')
    require(receipt.get('schema'), 'riscv_full_width_verify_v1', 'verifier schema')
    require(receipt.get('status'), 'verified', 'verifier status')
    for field in ('artifact_magic', 'execution_profile', 'proof_suite', 'security_policy', 'release_status',
                  'statement_blake3', 'transcript_digest_blake3', 'proof_bytes', 'proof_sha256',
                  'total_steps', 'elf_sha256', 'input_sha256', 'output_len', 'output_sha256',
                  'implementation_commit', 'implementation_dirty', 'executable_sha256'):
        require(receipt.get(field), report[field], 'verified ' + field)
    policy(receipt.get('pcs_config'))
    mean = {p: statistics.mean(t[p] for t in timings) for p in PHASES}
    peak, memory_source = peak_memory(report)
    evidence = dict(status='verified', public_io_bound_to_proof=True,
                    artifact_path=report_path(artifact_path), benchmark_report_path=report_path(bench_path),
                    input_sha256=case.input_sha256, guest_sha256=case.guest_sha256,
                    output_digest=execution['output_digest'], expected_output_digest=case.expected_digest,
                    public_values_sha256=execution['public_values_sha256'],
                    statement_blake3=report['statement_blake3'], proof_sha256=sha256_bytes(stark),
                    artifact_sha256=artifact_hash, artifact_bytes=len(raw),
                    retained_verify_wall_ns=retained_ns, retained_verify_receipt=receipt,
                    full_width_dispatch_samples=report['proof_device_counts'],
                    release_status=report['release_status'])
    return dict(system='stwo-zig-riscv', backend=backend, recursion_enabled=False,
                target=case.target, input_size=case.input_size,
                proof_duration=round(sum(mean[p] for p in PHASES[:4])),
                verify_duration=round(mean['fresh_verification_ns']), cycles=execution['cycles'],
                proof_size=len(stark), preprocessing_size=case.guest_bytes, num_constraints=0,
                peak_memory=peak, uses_precompile=case.uses_precompile, execution_mode='software',
                proof_scope='riscv_guest', evidence=evidence,
                timing=dict(source='verified full-width CLI phase timers',
                            proof_definition='execution + witness + admission + proof generation',
                            verify_definition='fresh metadata/key derivation + proof verification',
                            phase_means_ns=mean, median_end_to_end_seconds=report['median_seconds'],
                            verified_end_to_end_sample_seconds=[t['total_ns'] / 1e9 for t in timings],
                            outer_command_wall_ns=wall_duration_ns),
                memory=dict(source=memory_source, scope='self-process lifetime peak across verified samples',
                            includes_mandatory_self_verification=True),
                protocol=dict(proof_suite='blake3', commitment_model='full_width_blake3', name='secure', pcs_config=SECURE_PCS_CONFIG),
                prover_log_sha256=sha256_bytes(completed.stdout + completed.stderr)), report['implementation_commit']
