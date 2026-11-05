"""Retry only the failed diagnostic pair; preserve the original six timings."""
from pathlib import Path
import json
import os
import subprocess
import sys

ROOT = Path('/workspace/m3/src/m7-integrate')
BASE = Path('/workspace/m3/runs/m7-integrate')
ORIGINAL = BASE / 'p1-inter-reuse-headline-20261106-02'
OUT = BASE / 'p1-inter-reuse-profile-retry-20261106-02'
sys.path.insert(0, str(ROOT / 'scripts'))
import rv64_m7_integration_stack as S
import rv64_m4_resident as R

OUT.mkdir(exist_ok=False)
manifest = json.loads((ORIGINAL / 'artifact.json').read_text())
validation = json.loads((ORIGINAL / 'post-abort-receivers.json').read_text())
assert validation['status'] == 'ALL_12_TIMED_PROOFS_FRESH_CPU_ACCEPTED'
current = S.source_hashes(ROOT)
changed = sorted(k for k in current.keys() | manifest['source_sha256'].keys()
                 if current.get(k) != manifest['source_sha256'].get(k))
assert changed == ['scripts/rv64_m4_resident.py', 'scripts/tests/test_rv64_quiet_checkpoint.py'], changed
manifest['source_sha256'] = current
manifest['source_commit'] += '+profile-launch-env-ready-pid'
manifest['parent_manifest_sha256'] = S.sha(ORIGINAL / 'artifact.json')
S.validate_manifest(manifest)
S.write(OUT / 'artifact.json', manifest)
original = json.loads((ORIGINAL / 'experiment.json').read_text())
reference_run = Path(original['services'][0]['run'])
reference = json.loads((reference_run / 'receipt.json').read_text())['requests'][0]
reference_fingerprints = S.fingerprints(reference)
record = {'status': 'RUNNING_PROFILE_PAIR', 'scope': 'Separate diagnostic pair; no primary latency replacement',
          'primary_run': str(ORIGINAL), 'source_changes_from_timed_build': changed, 'services': []}
S.write(OUT / 'experiment.json', record)
env = S.clean_environment(os.environ)
try:
    for index, arm in enumerate(('baseline', 'fullstack'), 6):
        S.validate_manifest(manifest)
        argv, tag = S.command(manifest, arm, index, ROOT.name, True, OUT.name)
        service = BASE / f'daemon-24628607-r2-{tag}'
        entry = {'index': index, 'arm': arm, 'run': str(service), 'argv': argv, 'profiled': True}
        record['services'].append(entry)
        S.write(OUT / 'experiment.json', record)
        with (OUT / f'{index}-{arm}.log').open('w') as log:
            entry['exit_code'] = subprocess.run(argv, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
        S.write(OUT / 'experiment.json', record)
        assert entry['exit_code'] == 0, service
        receipt = json.loads((service / 'receipt.json').read_text())
        assert len(receipt['requests']) == 2
        assert len(receipt['quiet_before_requests']) == 2 and all(q['accepted'] for q in receipt['quiet_before_requests'])
        entry['physical_budget'] = S.guard_verdict(receipt, arm)
        assert all(S.fingerprints(r) == reference_fingerprints for r in receipt['requests'])
        entry['byte_identical_to_primary_reference'] = True
        S.write(OUT / 'experiment.json', record)
    # All profiling finishes before these fresh isolated CPU receivers start.
    for entry in record['services']:
        service = Path(entry['run'])
        entry['fresh_receivers'] = R.receive_run(service, 'all', 16)
        assert len(entry['fresh_receivers']) == 2 and all(v['accepted'] for v in entry['fresh_receivers'])
        with (OUT / f"{entry['index']}-gpu-seconds.log").open('w') as log:
            subprocess.run([sys.executable, str(ROOT / 'scripts/rv64_m7_gpu_seconds.py'), str(service),
                            '--accepted-run', str(service)], cwd=ROOT, env=env, check=True,
                           stdout=log, stderr=subprocess.STDOUT)
        entry['gpu_seconds'] = json.loads((service / 'gpu-seconds.json').read_text())
        S.write(OUT / 'experiment.json', record)
    record['status'] = 'PROFILE_PAIR_BYTE_IDENTICAL_FRESH_ACCEPTED_GPU_SECONDS_AVAILABLE'
except BaseException as error:
    record.update(status='PROFILE_PAIR_FAILED', error=str(error))
    raise
finally:
    S.write(OUT / 'experiment.json', record)
