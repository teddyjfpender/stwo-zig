#!/usr/bin/env python3
"""m8-gn-node proof-only arm: the gate's small-block-proof step + frozen D2 parity, no build/unit/corpus
(the binaries are the stream's last build). usage: gn_prove.py <out> <block> [--env K=V ...]"""
import json, subprocess, sys, time
from pathlib import Path
ROOT = Path('/workspace/m3/src/m8-gn-node')
sys.path.insert(0, str(ROOT / 'scripts'))
import rv64_m7_integration_stack as stack
import rv64_gate as gate
out = Path(sys.argv[1]).resolve(); block = int(sys.argv[2])
extra = gate.extra_environment([a.split('=', 1)[0] + '=' + a.split('=', 1)[1] for a in sys.argv[3:]])
out.mkdir(parents=True, exist_ok=False)
# GN_RUNTIME=<runtime.json>: the pinned image to prove on (default: the gate's p0 runtime).
import os
runtime_path = Path(os.environ.get('GN_RUNTIME', str(gate.RUNTIME)))
runtime = json.loads(runtime_path.read_text())
assets = dict(runtime['assets'])
bins = Path('/workspace/m3/build/m8-gn-node/zig-out/bin')
assets.update(driver=str(bins / 'rv64-word16-ethereum-gpu-combined'), receiver=str(bins / 'rv64-word16-ethereum-recursion-receiver'))
manifest = {'source_root': str(ROOT), 'assets': assets, 'block': block, 'preset': json.loads(stack.DEFAULT_PRESET.read_text())}
label = 'gnp-' + out.name
argv, tag = stack.command(manifest, 'baseline', 0, 'm8-gn-node', False, label)
argv += ['--quiet-mode', 'diagnostic', '--request-timeout', '600']
for k, v in sorted(extra.items()):
    argv += ['--env', f'{k}={v}']
receipt = {'schema': 'rv64-m8-gn-node-proof/v1', 'block': block, 'runtime': str(runtime_path), 'extra_env': extra, 'argv': argv, 'asset_sha256': {n: stack.sha(p) for n, p in assets.items()}, 'started_ns': time.time_ns()}
env = stack.clean_environment(__import__('os').environ)
env['ZIG_GLOBAL_CACHE_DIR'] = '/workspace/m3/cache/zig-global'; env['TMPDIR'] = '/workspace/m3/tmp'
with (out / 'proof.log').open('w') as log:
    code = subprocess.run(argv, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
receipt['exit_code'] = code
service = Path('/workspace/m3/runs/m8-gn-node') / f'daemon-{block}-r2-{tag}'
receipt['service'] = str(service)
try:
    produced = json.loads((service / 'receipt.json').read_text())
    golden_path = gate.GOLDEN / f'{block}-combined-d2-coalesce-v1/trial-1/artifact-fingerprints.json'
    golden = json.loads(golden_path.read_text())
    receipt['parity'] = [gate.frozen_parity(Path(r['proof']), golden) for r in produced['requests']]
    receipt['status'] = 'PASS' if code == 0 and len(produced['requests']) == 2 else 'FAIL'
except Exception as e:
    receipt['status'] = 'FAIL'; receipt['error'] = repr(e)
stack.write(out / 'proof.json', receipt)
print('GN_PROVE', receipt['status'], out)
