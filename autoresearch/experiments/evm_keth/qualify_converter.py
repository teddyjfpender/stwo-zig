#!/usr/bin/env python3
"""Check fast converter bytes against every retained, verified bundle input."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

if __package__:
    from .bridge import PINS, ROOT, authenticate, digest, write_new
    from .verify_bundle import check_manifest
else:
    from bridge import PINS, ROOT, authenticate, digest, write_new
    from verify_bundle import check_manifest
sys.path.insert(0, str(ROOT))
from scripts.benchmark_cairo import measure


def qualify(bundle: Path, keth: Path, converter: Path, out: Path) -> dict:
    source = authenticate(keth, PINS['keth'])
    manifest_path = bundle / 'bundle-results.json'
    manifest = json.loads(manifest_path.read_text())
    check_manifest(manifest)
    if manifest['witness_transport'] != 'compact':
        raise ValueError('qualification requires retained compact reference inputs')
    out.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'keth-legacy-converter-qualification-v1', 'status': 'running',
              'source': source, 'manifest_sha256': digest(manifest_path),
              'converter_sha256': digest(converter), 'segments': []}
    started = time.monotonic_ns()
    try:
        number = manifest['workload']['block_number']
        for segment in manifest['segments']:
            name = segment['name']
            raw = bundle / 'data/1' / str(number) / '1' / f'prover_input_info_{number}_{name}'
            compiled = keth / 'build' / f'{segment["role"]}_compiled.json'
            reference = bundle / name / 'input.cpi'
            if digest(raw) != segment['legacy_input_sha256'] or digest(compiled) != segment['compiled_program_sha256'] or digest(reference) != segment['input_sha256']:
                raise ValueError('retained source, compiled program or reference input changed')
            target = out / f'{name}.cpi'
            receipt = out / f'{name}.json'
            process = measure([str(converter.resolve()), '--source', str(raw.resolve()),
                '--compiled', str(compiled.resolve()), '--target', str(target.resolve()),
                '--receipt', str(receipt.resolve())], out / f'{name}.log', dict(os.environ))
            if process['exit_code']:
                raise ValueError(f'{name}: converter failed')
            if digest(target) != segment['input_sha256']:
                raise ValueError(f'{name}: compact bytes differ from the verified reference')
            converted = json.loads(receipt.read_text())
            for key in ('schema', 'from_stwo_cairo', 'to_stwo_cairo', 'compiled_program_cells_checked',
                        'instruction_cache_cells_checked', 'execution_steps', 'transport'):
                if converted[key] != segment['conversion'][key]:
                    raise ValueError(f'{name}: conversion receipt mismatch: {key}')
            result['segments'].append({'name': name, 'input_sha256': segment['input_sha256'],
                'byte_identical': True, 'process': process,
                'reference_conversion_process': segment.get('conversion_process')})
            target.unlink()
        if authenticate(keth, PINS['keth']) != source or digest(converter) != result['converter_sha256'] or digest(manifest_path) != result['manifest_sha256']:
            raise ValueError('source or binary changed during qualification')
        result.update(status='qualified-byte-identical', proof_input_count=len(result['segments']),
            total_wall_ns=sum(s['process']['wall_ns'] for s in result['segments']),
            peak_rss_bytes=max(s['process']['max_process_tree_rss_bytes'] for s in result['segments']))
    except Exception as error:
        result.update(status='failed', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        result['elapsed_wall_ns'] = time.monotonic_ns() - started
        write_new(out / 'qualification.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'keth-checkout', 'converter', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.bundle, args.keth_checkout, args.converter, args.out)
    print(json.dumps({k: v for k, v in result.items() if k != 'segments'}, indent=2))
