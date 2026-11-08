#!/usr/bin/env python3
"""GPU-native against default, six alternating isolated services.

prepare freezes existing artifacts/source without touching a GPU. run is reserved
for Root AFTER native/device coverage hooks and exact process-budget guard are
ready. Every arm uses one immutable driver, receiver, a25 and addon set.
"""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
from rv64_validation import fingerprints, sha, validate_assets, validate_receivers, validate_library_environment, jobs_environment, service_label, JOBS_FLAGS

HERE = Path(__file__).resolve().parent
DEFAULT_PRESET = HERE.parent / 'conformance/rv64/presets/integration-stack-preset.json'
# Canonical default CUDA runtime (owner decision 2026-11-07): the source-built
# opt-combined image. p0-runtime.json (frozen a25) stays as an explicit control.
DEFAULT_RUNTIME = HERE.parent / 'conformance/rv64/presets/default-runtime.json'
FROZEN_P0_RUNTIME = HERE.parent / 'conformance/rv64/presets/p0-runtime.json'
DEV_BLOCKS = (26235156, 24628607)
RUNTIME_ASSETS = ('library', 'sparse', 'observer', 'process_budget_guard')


def write(path, value, *, exclusive=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2) + '\n'
    if exclusive:
        with tempfile.TemporaryDirectory(dir=path.parent) as raw:
            temporary = Path(raw) / 'manifest.json'
            temporary.write_text(payload)
            path.hardlink_to(temporary)
        return
    temporary = path.with_suffix(path.suffix + '.pending')
    temporary.write_text(payload)
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
    for relative in ('src', 'build_support', 'scripts', 'src/frontends/riscv/air/lang/artifacts',
                     'conformance', 'vectors/fixtures', '.github', '.githooks'):
        for path in sorted((root / relative).rglob('*')):
            if path.is_file() and not path.is_symlink() and not set(path.parts).intersection({'.zig-cache', 'zig-cache', 'zig-out', '__pycache__', '.git'}):
                result[str(path.relative_to(root))] = sha(path)
    for name in ('build.zig', 'build.zig.zon'):
        result[name] = sha(root / name)
    for name in ('.gitignore', 'CONTRIBUTING.md', 'AGENTS.md'):
        if (root / name).is_file():
            result[name] = sha(root / name)
    return result


def load_runtime(path):
    """Pinned CUDA runtime JSON -> assets; every asset must match its pinned SHA-256."""
    runtime = json.loads(Path(path).read_text())
    assets = {name: runtime['assets'][name] for name in RUNTIME_ASSETS}
    validate_assets(assets, runtime['asset_sha256'])
    return runtime, assets


def check_block(block, allow_blocks):
    """Owner rule: development blocks only, unless this exact block is opted in."""
    if block in DEV_BLOCKS:
        return False
    if block not in set(allow_blocks or ()):
        raise RuntimeError(f'development blocks only ({DEV_BLOCKS}); opt in explicitly with --allow-block {block}')
    return True


def native_comparison_environment(preset, assets):
    if preset['measurement']['order'] != ['baseline', 'fullstack'] * 3:
        raise RuntimeError('exact six-service order is required')
    candidate = arm_environment(preset, 'fullstack', assets)
    baseline = arm_environment(preset, 'baseline', assets)
    if any(candidate.get(key) != '1' for key in ('STWO_RV64_M8_JOBS', 'STWO_RV64_M8_GPU_NATIVE')):
        raise RuntimeError('canonical candidate must select GPU-native jobs')
    if any(baseline.get(key) == '1' for key in (*JOBS_FLAGS, 'STWO_RV64_M8_GPU_NATIVE')):
        raise RuntimeError('canonical baseline must use the default request path')
    return candidate


def prepare(args):
    if args.out.exists():
        raise FileExistsError('canonical manifest already exists: ' + str(args.out))
    root = args.source_root.resolve()
    runtime, runtime_assets = load_runtime(args.runtime)
    for name in RUNTIME_ASSETS:
        if getattr(args, name) is None:
            setattr(args, name, Path(runtime_assets[name]))
    assets = {name: str(getattr(args, name).resolve()) for name in ('driver', 'receiver', 'library', 'sparse', 'observer', 'process_budget_guard')}
    preset = json.loads(args.preset.read_text())
    candidate = native_comparison_environment(preset, assets)
    shipped = jobs_environment(runtime, candidate)
    preset['arms']['fullstack'] = {**shipped, **preset['arms']['fullstack']}
    job_assets = {key: path for key, path in shipped.items() if key.endswith('_LIBRARY')}
    assets.update(job_assets)
    pins = {name: sha(path) for name, path in assets.items()}
    pins.update({key: runtime['jobs_env_sha256'][key] for key in job_assets})
    validate_assets(assets, pins)
    allowed_block = check_block(args.block, args.allow_block)
    manifest = {'schema': 'rv64-native-canonical-artifact/v1', 'source_root': str(root),
                'source_commit': args.source_commit, 'source_sha256': source_hashes(root),
                'assets': assets, 'asset_sha256': pins,
                'preset': preset, 'preset_path': str(args.preset.resolve()), 'preset_sha256': sha(args.preset), 'block': args.block,
                'allowed_block': allowed_block, 'runtime': str(args.runtime.resolve()), 'runtime_sha256': sha(args.runtime),
                'runtime_matches_assets': all(assets[n] == str(Path(runtime_assets[n]).resolve()) for n in RUNTIME_ASSETS),
                'native_hooks_commit': args.native_hooks_commit, 'device_hooks_commit': args.device_hooks_commit,
                'process_budget_guard': assets['process_budget_guard'],
                'ready': bool(args.native_hooks_commit and args.device_hooks_commit and args.process_budget_guard),
                'scope': 'GPU-native against default. Baseline auto arena without canary; native auto arena under the physical guard. No observed exact peak or proof format change claimed.',
                'created_utc_ns': time.time_ns()}
    write(args.out, manifest, exclusive=True)
    print(json.dumps({'manifest': str(args.out), 'ready': manifest['ready'], 'asset_sha256': manifest['asset_sha256']}))


def validate_manifest(manifest):
    if manifest.get('schema') != 'rv64-native-canonical-artifact/v1':
        raise RuntimeError('re-prepare the versioned GPU-native comparison manifest')
    if not manifest.get('ready'):
        raise RuntimeError('Root native/device readiness and exact process-budget guard are required before GPU execution')
    validate_assets(manifest['assets'], manifest['asset_sha256'])
    native_comparison_environment(manifest['preset'], manifest['assets'])
    if sha(manifest['runtime']) != manifest['runtime_sha256']:
        raise RuntimeError('canonical runtime changed after freeze')
    if sha(manifest['preset_path']) != manifest['preset_sha256']:
        raise RuntimeError('canonical preset changed after freeze')
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
            '--receive', 'none', '--security-profile', preset['security_profile'],
            '--driver', assets['driver'], '--library', assets['library'], '--receiver', assets['receiver'],
            '--tag', tag, '--no-default-env', '--recursion-max-pending-authorities', str(preset['operational'][arm]['recursion_max_pending_authorities']), '--quiet-load-max', str(preset['measurement']['quiet_load_max']),
            '--quiet-steal-max', str(preset['measurement']['quiet_steal_max']), '--quiet-resource', preset['measurement'].get('quiet_resource', 'host-load'),
            '--quiet-pressure-max', str(preset['measurement'].get('quiet_pressure_max', 0.0)),
            '--quiet-timeout', str(preset['measurement']['quiet_timeout_s']),
            '--quiet-stable-samples', str(preset['measurement']['quiet_stable_samples'])]
    if preset.get('coalesce_truth_families', True):
        argv.append('--coalesce-truth-families')
    if manifest.get('allowed_block'):
        argv += ['--allow-block', str(manifest['block'])]
    if arm == 'fullstack':
        argv += ['--process-budget-guard', assets['process_budget_guard']]
    if profile:
        argv.append('--nsys')
        if preset['measurement'].get('nsys_root'):
            argv += ['--nsys-root', preset['measurement']['nsys_root']]
    for key, value in sorted(arm_environment(preset, arm, assets).items()):
        argv += ['--env', f'{key}={value}']
    return argv, tag


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
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    write(output / 'artifact.json', manifest)
    root = Path(manifest['source_root'])
    # P.src_root expects /workspace/m3/src/STREAM. Reuse canonical source; all
    # service names/output dirs remain unique below /workspace/m3/runs/STREAM.
    stream = root.name
    environment = clean_environment(os.environ)
    result = {'schema': 'rv64-native-canonical-experiment/v1', 'manifest_sha256': sha(args.manifest),
              'profiled': False, 'timing_scope': 'six primary services unprofiled; optional ownership pair instrumented separately',
              'order': manifest['preset']['measurement']['order'] + (['baseline', 'fullstack'] if args.ownership_profile_pair else []), 'services': [], 'receivers_deferred': True, 'instrumentation': manifest['preset']['measurement'].get('instrumentation'),
              'gpu_seconds_status': 'pending separate ownership pair' if args.ownership_profile_pair else 'unavailable without CUPTI; no surrogate claim',
              'exact_process_peak_gate': 'Root-owned guard required; observer/NVML samples alone are insufficient'}
    write(output / 'experiment.json', result)
    reference = None
    for index, arm in enumerate(result['order']):
        validate_manifest(manifest)
        validate_library_environment(arm_environment(manifest['preset'], arm, manifest['assets']), manifest['assets'], manifest['asset_sha256'])
        profile = index >= 6
        argv, tag = command(manifest, arm, index, stream, profile, service_label(output, prefix='canonical'))
        service = Path('/workspace/m3/runs') / stream / f'daemon-{manifest["block"]}-r2-{tag}'
        entry = {'arm': arm, 'order_index': index, 'run': str(service), 'argv': argv, 'profiled': profile, 'measurement_role': 'ownership_profile' if profile else 'headline'}
        result['services'].append(entry)
        write(output / 'experiment.json', result)
        with (output / f'{index:02d}-{arm}.log').open('w') as log:
            code = subprocess.run(argv, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT).returncode
        validate_manifest(manifest)
        entry['exit_code'] = code
        write(output / 'experiment.json', result)
        if code:
            raise RuntimeError(f'integration service failed; stop, preserve logs: {service}')
        receipt = json.loads((service / 'receipt.json').read_text())
        quiet = receipt.get('quiet_before_requests', [])
        if len(receipt['requests']) != 2 or any(not q or not q['accepted'] for q in quiet):
            raise RuntimeError('quiet admission receipt missing or failed')
        if len(receipt.get('quiet_before_requests', [])) != 2:
            raise RuntimeError('both requests require explicit quiet receipts')
        entry['physical_budget'] = guard_verdict(receipt, arm)
        entry['service_assets'] = receipt['assets']
        for request in receipt['requests']:
            actual = fingerprints(request)
            if reference is None:
                reference = actual
                result['payload_reference'] = {'run': str(service), 'ordinal': request['ordinal'], 'proof': request['proof'], 'fingerprints': reference}
            if actual != reference:
                write(output / 'parity-failure.json', {'run': str(service), 'ordinal': request['ordinal'], 'expected': reference, 'actual': actual})
                raise RuntimeError('proof payload or captured-input SHA256 mismatch across arms/cold/warm')
        entry['payload_byte_parity'] = True
        entry['captured_sha_parity_required'] = False
        warm = receipt['requests'][1]
        entry['warm'] = warm
        entry['quiet'] = receipt['quiet_before_requests'][1]
        write(output / 'experiment.json', result)
    # Do not contaminate interleaved timings/quiet state with CPU receivers.
    for entry in result['services']:
        argv = [sys.executable, str(root / 'scripts/rv64_m4_resident.py'), 'receive', '--run', entry['run'],
                '--which', 'all', '--receiver-workers', str(args.receiver_workers)]
        with (output / f'{entry["order_index"]}-{entry["arm"]}-receiver.log').open('w') as log:
            code = subprocess.run(argv, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT).returncode
        receipt = json.loads((Path(entry['run']) / 'receipt.json').read_text())
        if code:
            raise RuntimeError('fresh isolated receiver rejected: ' + entry['run'])
        entry['receiver_acceptance'] = validate_receivers(
            receipt.get('receivers'), [r['proof'] for r in receipt['requests']],
            manifest['asset_sha256']['receiver'])
        entry['fresh_receivers'] = receipt['receivers']
        write(output / 'experiment.json', result)
    if args.ownership_profile_pair:
        for entry in result['services']:
            if not entry['profiled']:
                continue
            argv = [sys.executable, str(root / 'scripts/rv64_m7_gpu_seconds.py'), entry['run'], '--accepted-run', entry['run']]
            with (output / f'{entry["order_index"]:02d}-gpu-seconds.log').open('w') as log:
                subprocess.run(argv, cwd=root, env=environment, check=True, stdout=log, stderr=subprocess.STDOUT)
            entry['gpu_seconds'] = json.loads((Path(entry['run']) / 'gpu-seconds.json').read_text())
        result['gpu_seconds_status'] = 'separate instrumented ownership pair; exact clipped per-device CUPTI interval union'
    result['warm_median_s'] = {arm: statistics.median(s['warm']['marker']['request_wall_ns'] / 1e9 for s in result['services'] if s['arm'] == arm and not s['profiled']) for arm in set(s['arm'] for s in result['services'])}
    result['measured_fullstack_over_baseline'] = result['warm_median_s']['fullstack'] / result['warm_median_s']['baseline']
    result['status'] = 'TIMED_BYTE_PARITY_AND_FRESH_ACCEPTED_METRICS_AUDIT_PENDING'
    write(output / 'experiment.json', result)
    print(json.dumps(result['warm_median_s']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--source-root', required=True, type=Path)
    p.add_argument('--source-commit', required=True)
    for name in ('driver', 'receiver'):
        p.add_argument('--' + name.replace('_', '-'), required=True, type=Path)
    for name in RUNTIME_ASSETS:
        p.add_argument('--' + name.replace('_', '-'), type=Path, help='default: from --runtime')
    p.add_argument('--runtime', type=Path, default=DEFAULT_RUNTIME,
                   help='pinned CUDA runtime JSON (default: the canonical default-runtime.json; p0-runtime.json is the frozen a25 control)')
    p.add_argument('--preset', type=Path, default=DEFAULT_PRESET)
    p.add_argument('--block', type=int, default=24628607)
    p.add_argument('--allow-block', type=int, action='append', default=[],
                   help='explicit owner opt-in for one non-development block (e.g. 26235168); one block per service, repeat 2')
    p.add_argument('--native-hooks-commit')
    p.add_argument('--device-hooks-commit')
    p.add_argument('--out', required=True, type=Path)
    p = sub.add_parser('run')
    p.add_argument('--manifest', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--receiver-workers', type=int, default=16)
    p.add_argument('--ownership-profile-pair', action='store_true', help='after six unprofiled services, one baseline/fullstack CUPTI pair; never included in headline medians')
    args = parser.parse_args()
    (prepare if args.mode == 'prepare' else run)(args)


if __name__ == '__main__':
    main()
