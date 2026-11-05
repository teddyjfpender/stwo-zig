#!/usr/bin/env python3
"""One canonical stack, six alternating isolated services; no feature benchmarks.

prepare freezes existing artifacts/source without touching a GPU. run is reserved
for Root AFTER native/device coverage hooks and exact process-budget guard are
ready. Every arm uses one immutable driver, receiver, a25 and addon set.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
DEFAULT_PRESET = HERE.parent / 'design/riscv-proving-stack/m7-handoff/integration-stack-preset.json'


def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.pending')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def clean_environment(environment):
    return {key: value for key, value in environment.items()
            if not key.startswith(('STWO_', 'CUDA_', 'RV64_')) and key != 'LD_PRELOAD'}


def arm_environment(preset, arm, assets):
    result = dict(preset['common'], **preset['arms'][arm])
    substitutions = dict(assets, library_dir=str(Path(assets['library']).parent))
    return {key: value.format(**substitutions) for key, value in result.items()}


def source_hashes(root):
    result = {}
    for relative in ('src', 'build_support', 'scripts', 'design/typed-air/artifacts'):
        for path in sorted((root / relative).rglob('*')):
            if path.is_file() and not path.is_symlink() and not set(path.parts).intersection({'.zig-cache', 'zig-cache', 'zig-out', '__pycache__', '.git'}):
                result[str(path.relative_to(root))] = sha(path)
    for name in ('build.zig', 'build.zig.zon'):
        result[name] = sha(root / name)
    return result


def prepare(args):
    root = args.source_root.resolve()
    assets = {name: str(getattr(args, name).resolve()) for name in ('driver', 'receiver', 'library', 'sparse', 'observer', 'process_budget_guard')}
    preset = json.loads(args.preset.read_text())
    if preset['measurement']['order'] != ['baseline', 'fullstack'] * 3:
        raise RuntimeError('exact six-service order is required')
    if args.block not in (26235156, 24628607):
        raise RuntimeError('development blocks only')
    manifest = {'schema': 'rv64-m7-canonical-stack-artifact/v1', 'source_root': str(root),
                'source_commit': args.source_commit, 'source_sha256': source_hashes(root),
                'assets': assets, 'asset_sha256': {name: sha(path) for name, path in assets.items()},
                'preset': preset, 'preset_sha256': sha(args.preset), 'block': args.block,
                'native_hooks_commit': args.native_hooks_commit, 'device_hooks_commit': args.device_hooks_commit,
                'process_budget_guard': assets['process_budget_guard'],
                'ready': bool(args.native_hooks_commit and args.device_hooks_commit and args.process_budget_guard),
                'scope': 'GPU-only global admission; host/RSS observed, not bounded. Baseline original auto arena without canary; full22GiB under enforced28e9physicalceiling. No proof format changes.',
                'created_utc_ns': time.time_ns()}
    write(args.out, manifest)
    print(json.dumps({'manifest': str(args.out), 'ready': manifest['ready'], 'asset_sha256': manifest['asset_sha256']}))


def validate_manifest(manifest):
    if not manifest.get('ready'):
        raise RuntimeError('Root native/device readiness and exact process-budget guard are required before GPU execution')
    for name, path in manifest['assets'].items():
        if sha(path) != manifest['asset_sha256'][name]:
            raise RuntimeError('immutable asset changed: ' + name)
    root = Path(manifest['source_root'])
    if source_hashes(root) != manifest['source_sha256']:
        raise RuntimeError('canonical source changed after freeze')


def command(manifest, arm, round_index, run_root, profile, label="one-stack"):
    root = Path(manifest['source_root'])
    assets = manifest['assets']
    preset = manifest['preset']
    tag = f'{label}-{round_index:02d}-{arm}'
    argv = [sys.executable, str(root / 'scripts/rv64_m4_resident.py'), 'daemon', str(manifest['block']),
            '--stream', run_root, '--build-stream', run_root, '--repeat', '2', '--store', 'none',
            '--receive', 'none', '--security-profile', preset['security_profile'], '--coalesce-truth-families',
            '--driver', assets['driver'], '--library', assets['library'], '--receiver', assets['receiver'],
            '--tag', tag, '--no-default-env', '--recursion-max-pending-authorities', str(preset['operational'][arm]['recursion_max_pending_authorities']), '--quiet-load-max', str(preset['measurement']['quiet_load_max']),
            '--quiet-steal-max', str(preset['measurement']['quiet_steal_max']), '--quiet-resource', preset['measurement'].get('quiet_resource', 'host-load'),
            '--quiet-pressure-max', str(preset['measurement'].get('quiet_pressure_max', 0.0)),
            '--quiet-timeout', str(preset['measurement']['quiet_timeout_s']),
            '--quiet-stable-samples', str(preset['measurement']['quiet_stable_samples'])]
    if arm == 'fullstack':
        argv += ['--process-budget-guard', assets['process_budget_guard']]
    if profile:
        argv.append('--nsys')
    for key, value in sorted(arm_environment(preset, arm, assets).items()):
        argv += ['--env', f'{key}={value}']
    return argv, tag


def fingerprints(row, require_capture=False):
    import rv64_resident_basket as basket
    directory = Path(row['proof'])
    recursive = basket.recursive_snapshot(directory, row['leaves'])
    report = json.loads((directory / 'report.json').read_text())
    captured = report.get('captured_values_sha256')
    if require_capture and (not captured or len(captured) != 64):
        raise RuntimeError('required captured-input SHA256 guard missing')
    return {'native': {p.name: sha(p) for p in sorted(directory.glob('*.bin'))},
            'bundle': sha(directory / 'bundle.json'), 'tree': recursive['tree_sha256'],
            'recursive': recursive['proof_sha256'], **({'captured_values_sha256': captured} if require_capture else {})}


def guard_verdict(receipt, arm):
    guard = receipt.get('physical_budget_guard') or {}
    if arm == 'baseline':
        if guard:
            raise RuntimeError('baseline auto arena must not be altered by a physical canary')
        return {'status': 'ORIGINAL_BASELINE_AUTO_UNGUARDED', 'ceiling_bytes': None, 'observed_exact_process_peak_bytes': None}
    if guard.get('status') != 'RELEASED' or guard.get('exit_code') != 0 or guard.get('failure'):
        raise RuntimeError('physical guard lifecycle did not close successfully')
    devices = guard['ready']['devices']
    return {'status': 'ENFORCED_PHYSICAL_CEILING',
            'ceiling_bytes': {str(d['device']): d['prover_physical_ceiling_bytes'] for d in devices},
            'observed_exact_process_peak_bytes': None,
            'scope': 'successful proof under physical availability ceiling; not an observed peak'}


def run(args):
    manifest = json.loads(args.manifest.read_text())
    validate_manifest(manifest)
    if args.smoke and manifest['block'] != 26235156:
        raise RuntimeError('first whole-stack correctness smoke is restricted to small development block26235156')
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    write(output / 'artifact.json', manifest)
    root = Path(manifest['source_root'])
    # P.src_root expects /workspace/m3/src/STREAM. Reuse canonical source; all
    # service names/output dirs remain unique below /workspace/m3/runs/STREAM.
    stream = root.name
    environment = clean_environment(os.environ)
    result = {'schema': 'rv64-m7-one-stack-experiment/v1', 'manifest_sha256': sha(args.manifest),
              'profiled': False, 'timing_scope': 'UNQUALIFIED_CORRECTNESS_WALLS' if args.smoke else 'six primary services unprofiled; optional ownership pair instrumented separately',
              'order': ((['fullstack'] * len(args.smoke_seeds)) if args.reference_run else ['baseline'] + ['fullstack'] * len(args.smoke_seeds)) if args.smoke else manifest['preset']['measurement']['order'] + (['baseline', 'fullstack'] if args.ownership_profile_pair else []), 'services': [], 'receivers_deferred': True, 'instrumentation': manifest['preset']['measurement'].get('instrumentation'),
              'smoke_only': args.smoke, 'global_admission_off_diagnostic': args.global_admission_off_diagnostic,
              'gpu_seconds_status': 'pending separate ownership pair' if args.ownership_profile_pair else 'unavailable without CUPTI; no surrogate claim',
              'exact_process_peak_gate': 'Root-owned guard required; observer/NVML samples alone are insufficient'}
    write(output / 'experiment.json', result)
    reference = None
    if args.reference_run:
        reference_receipt = json.loads((args.reference_run / 'receipt.json').read_text())
        matches = [r for r in reference_receipt['requests'] if r['block'] == manifest['block']]
        if not matches:
            raise RuntimeError('reference block missing')
        reference = fingerprints(matches[0], require_capture=args.smoke)
    for index, arm in enumerate(result['order']):
        validate_manifest(manifest)
        profile = not args.smoke and index >= 6
        argv, tag = command(manifest, arm, index, stream, profile, output.name + '-' + (('one-stack-v5-global0-smoke' if args.global_admission_off_diagnostic else 'one-stack-v5-smoke') if args.smoke else 'one-stack-v4'))
        seed = None
        if args.smoke:
            argv += ['--quiet-mode', 'diagnostic', '--request-timeout', str(args.smoke_request_timeout), '--env', 'STWO_RV64_CAPTURE_DIGEST=1']
        if args.global_admission_off_diagnostic:
            if not args.smoke or arm != 'fullstack':
                raise RuntimeError('GLOBAL0fallback is a fullstack correctness diagnostic only')
            argv += ['--env', 'STWO_RV64_GLOBAL_ADMISSION=0']
        if args.smoke and arm == 'fullstack':
            seed = args.smoke_seeds[index if args.reference_run else index - 1]
            argv += ['--env', f'STWO_RV64_RECURSION_SCRAMBLE_SEED={seed}']
        service = Path('/workspace/m3/runs') / stream / f'daemon-{manifest["block"]}-r2-{tag}'
        entry = {'arm': arm, 'order_index': index, 'run': str(service), 'argv': argv, 'profiled': profile, 'measurement_role': 'smoke' if args.smoke else ('ownership_profile' if profile else 'headline')}
        result['services'].append(entry)
        write(output / 'experiment.json', result)
        with (output / f'{index:02d}-{arm}.log').open('w') as log:
            code = subprocess.run(argv, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT).returncode
        entry['exit_code'] = code
        write(output / 'experiment.json', result)
        if code:
            raise RuntimeError(f'integration service failed; stop, preserve logs: {service}')
        receipt = json.loads((service / 'receipt.json').read_text())
        quiet = receipt.get('quiet_before_requests', [])
        if len(receipt['requests']) != 2 or any(not q or (q.get('mode') != 'diagnostic' if args.smoke else not q['accepted']) for q in quiet):
            raise RuntimeError('quiet admission/diagnostic receipt missing or failed')
        if len(receipt.get('quiet_before_requests', [])) != 2:
            raise RuntimeError('both requests require explicit quiet receipts')
        entry['physical_budget'] = guard_verdict(receipt, arm)
        if seed is not None:
            logged = f'RECURSION_ADMISSION_ORDER policy=seeded_scramble seed={seed}'
            if logged not in (service / 'producer.stderr').read_text(errors='replace'):
                raise RuntimeError('seeded scheduling proof gate did not activate')
            entry['scramble_seed'] = seed
            entry['scramble_activation_log'] = logged
        entry['service_assets'] = receipt['assets']
        for request in receipt['requests']:
            actual = fingerprints(request, require_capture=args.smoke)
            if reference is None:
                reference = actual
                result['payload_reference'] = {'run': str(service), 'ordinal': request['ordinal'], 'fingerprints': reference}
            if actual != reference:
                write(output / 'parity-failure.json', {'run': str(service), 'ordinal': request['ordinal'], 'expected': reference, 'actual': actual})
                raise RuntimeError('proof payload or captured-input SHA256 mismatch across arms/cold/warm')
        entry['payload_byte_parity'] = True
        entry['captured_sha_parity_required'] = args.smoke
        warm = receipt['requests'][1]
        entry['warm'] = warm
        entry['quiet'] = receipt['quiet_before_requests'][1]
        write(output / 'experiment.json', result)
    # Do not contaminate interleaved timings/quiet state with CPU receivers.
    verification = list(result['services'])
    if args.reference_run:
        verification.append({'order_index':'reference','arm':'reference','run':str(args.reference_run)})
    for entry in verification:
        argv = [sys.executable, str(root / 'scripts/rv64_m4_resident.py'), 'receive', '--run', entry['run'],
                '--which', 'all', '--receiver-workers', str(args.receiver_workers)]
        with (output / f'{entry["order_index"]}-{entry["arm"]}-receiver.log').open('w') as log:
            code = subprocess.run(argv, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT).returncode
        receipt = json.loads((Path(entry['run']) / 'receipt.json').read_text())
        if code or not receipt['receivers'] or not all(v.get('accepted') for v in receipt['receivers']):
            raise RuntimeError('fresh isolated receiver rejected: ' + entry['run'])
        entry['fresh_receivers'] = receipt['receivers']
        if entry['arm'] == 'reference':
            result['reference_fresh_receivers'] = receipt['receivers']
        write(output / 'experiment.json', result)
    if args.ownership_profile_pair and not args.smoke:
        for entry in result['services']:
            if not entry['profiled']:
                continue
            argv = [sys.executable, str(root / 'scripts/rv64_m7_gpu_seconds.py'), entry['run'], '--accepted-run', entry['run']]
            with (output / f'{entry["order_index"]:02d}-gpu-seconds.log').open('w') as log:
                subprocess.run(argv, cwd=root, env=environment, check=True, stdout=log, stderr=subprocess.STDOUT)
            entry['gpu_seconds'] = json.loads((Path(entry['run']) / 'gpu-seconds.json').read_text())
        result['gpu_seconds_status'] = 'separate instrumented ownership pair; exact clipped per-device CUPTI interval union'
    result['warm_median_s'] = {arm: statistics.median(s['warm']['marker']['request_wall_ns'] / 1e9 for s in result['services'] if s['arm'] == arm and not s['profiled']) for arm in set(s['arm'] for s in result['services'])}
    if not args.smoke:
        result['measured_fullstack_over_baseline'] = result['warm_median_s']['fullstack'] / result['warm_median_s']['baseline']
    result['status'] = 'SMOKE_BYTE_PARITY_AND_FRESH_ACCEPTED' if args.smoke else 'TIMED_BYTE_PARITY_AND_FRESH_ACCEPTED_METRICS_AUDIT_PENDING'
    write(output / 'experiment.json', result)
    print(json.dumps(result['warm_median_s']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--source-root', required=True, type=Path)
    p.add_argument('--source-commit', required=True)
    for name in ('driver', 'receiver', 'library', 'sparse', 'observer', 'process_budget_guard'):
        p.add_argument('--' + name.replace('_', '-'), required=True, type=Path)
    p.add_argument('--preset', type=Path, default=DEFAULT_PRESET)
    p.add_argument('--block', type=int, default=24628607)
    p.add_argument('--native-hooks-commit')
    p.add_argument('--device-hooks-commit')
    p.add_argument('--out', required=True, type=Path)
    p = sub.add_parser('run')
    p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--receiver-workers', type=int, default=16)
    p.add_argument('--ownership-profile-pair', action='store_true', help='after six unprofiled services, one baseline/fullstack CUPTI pair; never included in headline medians')
    p.add_argument('--smoke', action='store_true', help='small-block lane1 control then lane2 seeds17/29 cold/warm correctness services before headline experiment')
    p.add_argument('--global-admission-off-diagnostic', action='store_true', help='required same-day fallback diagnosis; allotherfullstackflags/guard unchanged, no performance qualification')
    p.add_argument('--smoke-seeds', nargs='+', type=int, choices=(17,29), default=[17,29], help='explicit seeded admission correctness cases; first activation may select17 only')
    p.add_argument('--smoke-request-timeout', type=float, default=120, help='terminate blocked correctness request with all producer/guard resources drained')
    p.add_argument('--reference-run', type=Path, help='proof-neutral accepted reference payload comparison, including capture SHA256')
    args = parser.parse_args()
    (prepare if args.mode == 'prepare' else run)(args)


if __name__ == '__main__':
    main()
