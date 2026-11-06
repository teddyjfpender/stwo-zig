#!/usr/bin/env python3
"""M8 native-job: enqueue-only PCS + device OODS byte parity versus the legacy PCS pipeline.

Builds the job TUs (NAT/rv64/jobs/{pcs_enqueue,oods_points}.cu) and the parity harness against a
pinned base image, exports the masked native PCS fixtures (plain + imported OODS point), and runs:
  * matrix: {plain, imported} x {host, device coefficients} x {default, rolling beta2, rolling
    beta2 no-stream}: job words == legacy rv64_pcs_pipeline::run words, twice (warm);
  * oods: device channel (mix 4 roots, draw) -> device OODS/base point -> job PCS == legacy
    imported path (whose seed/point the host derived);
  * capture: the whole PCS enqueue captured in GLOBAL stream-capture mode (any synchronizing
    call invalidates capture), graph replayed twice == legacy;
  * compute-sanitizer memcheck/racecheck/synccheck/initcheck on the device-column rolling arm;
  * the independent native receiver (`verify`) on job outputs (+ its 8 mutation rejections);
  * a source lint: no sync/D2H/lease symbol in the job TUs;
  * the addon resolves against the pinned base image with RTLD_NOW.
No speed claim: fixture-scale timings are recorded as diagnostics only.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
NAT = ROOT / 'src/backends/cuda/native'
JOB_TUS = [NAT / 'rv64/jobs/pcs_enqueue.cu', NAT / 'rv64/jobs/oods_points.cu']
HARNESS = ROOT / 'tests/cuda/rv64/jobs/pcs_enqueue_parity.cu'
FORBIDDEN = re.compile(r'stwo_exec_context_sync|cudaStreamSynchronize|cudaEventSynchronize|cudaDeviceSynchronize|'
                       r'cudaMemcpy\(|cudaMemcpyDeviceToHost|memcpy_d2h|stwo_rv64_gpu_lease|gpu_session_submit')
NVCC = '/usr/local/cuda/bin/nvcc'
SANITIZER = '/usr/local/cuda/bin/compute-sanitizer'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(cmd, log, env=None, check=True):
    with open(log, 'w') as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
    if check and r.returncode:
        raise RuntimeError(f'{cmd[0]} failed ({r.returncode}); see {log}')
    return r.returncode, Path(log).read_text()


def lint():
    hits = []
    for tu in JOB_TUS:
        for n, line in enumerate(tu.read_text().splitlines(), 1):
            code = line.split('//', 1)[0]
            if FORBIDDEN.search(code):
                hits.append(f'{tu.relative_to(ROOT)}:{n}: {line.strip()}')
    return hits


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', required=True, type=Path, help='pinned libstwo-rv64-native.so')
    p.add_argument('--fixture-tool', required=True, type=Path, help='rv64-masked-pcs-fixtures')
    p.add_argument('--build', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--gpu-lock', default='/workspace/m3/locks/gpu.lock')
    p.add_argument('--build-lock', default='/workspace/m3/locks/build.2.lock')
    a = p.parse_args()
    a.build.mkdir(parents=True, exist_ok=True)
    a.out.mkdir(parents=True, exist_ok=True)
    receipt = dict(schema='rv64-m8-native-job-pcs-parity/v1', scope=__doc__.strip().splitlines()[0],
                   base_sha256=sha(a.base), fixture_tool_sha256=sha(a.fixture_tool),
                   inputs={str(x.relative_to(ROOT)): sha(x) for x in JOB_TUS + [HARNESS,
                           NAT / 'rv64/jobs/pcs_enqueue.h', NAT / 'rv64/jobs/oods_points.h',
                           NAT / 'rv64/pcs_pipeline.cuh']})
    hits = lint()
    receipt['sync_lint'] = dict(forbidden=FORBIDDEN.pattern, hits=hits, result='PASS' if not hits else 'FAIL')
    if hits:
        raise RuntimeError('sync lint: ' + '; '.join(hits))
    flags = ['-O3', '-std=c++17', '-lineinfo', '-gencode', 'arch=compute_120,code=sm_120', '-Xcompiler=-fPIC',
             '-Xcompiler=-pthread', f'-I{NAT}', f'-I{ROOT / "tests/cuda/rv64"}']
    objects = [a.build / (tu.stem + '.o') for tu in JOB_TUS]
    addon, harness = a.build / 'libstwo-rv64-jobs-native.so', a.build / 'pcs-enqueue-parity'
    started = time.monotonic()
    with open(a.build_lock, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for tu, obj in zip(JOB_TUS, objects):
            run([NVCC, *flags, '-c', str(tu), '-o', str(obj)], a.out / f'compile-{tu.stem}.log')
        run([NVCC, *flags, '-shared', *map(str, objects), '-o', str(addon)], a.out / 'link-addon.log')
        run([NVCC, *flags, str(HARNESS), *map(str, objects), str(a.base), '-o', str(harness)], a.out / 'link-harness.log')
    receipt['compile_seconds'] = time.monotonic() - started
    receipt['addon_sha256'], receipt['harness_sha256'] = sha(addon), sha(harness)
    ctypes.CDLL(str(a.base), mode=ctypes.RTLD_GLOBAL)
    lib = ctypes.CDLL(str(addon), mode=os.RTLD_NOW)
    receipt['addon_resolves_against_base_rtld_now'] = all(
        hasattr(lib, s) for s in ['stwo_rv64_pcs_job_plan_v1', 'stwo_rv64_pcs_job_enqueue_v1',
                                  'stwo_rv64_pcs_job_error_v1', 'stwo_rv64_job_oods_points_v1'])
    fixtures = {}
    for name, verb in [('plain', 'export'), ('imported', 'export-imported')]:
        run([str(a.fixture_tool), verb, str(a.out / name)], a.out / f'fixture-{name}.log')
        fixtures[name] = a.out / name / 'case-0.bin'
        receipt.setdefault('fixtures', {})[name] = sha(fixtures[name])
    env0 = dict(os.environ, STWO_RV64_DEVICE_ARENA='0')
    env0.pop('STWO_RV64_PCS_ROLLING_BETA2', None)
    variants = {'default': {}, 'beta2': {'STWO_RV64_PCS_ROLLING_BETA2': '1'},
                'beta2-nostream': {'STWO_RV64_PCS_ROLLING_BETA2': '1', 'STWO_RV64_PCS_STREAM': '0'}}
    line = re.compile(r'(PCS_JOB_\w+) (.*)')
    results = []
    verify = []
    with open(a.gpu_lock, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for fx in fixtures:
            for cols in ['host', 'device']:
                for vname, extra in variants.items():
                    tag = f'{fx}-{cols}-{vname}'
                    rc, text = run([str(harness), str(fixtures[fx]), cols, str(a.out / tag)], a.out / f'{tag}.log',
                                   env=dict(env0, **extra), check=False)
                    rows = [dict(kv.split('=', 1) for kv in m.group(2).split()) for m in map(line.search, text.splitlines()) if m]
                    results.append(dict(arm=tag, exit=rc, passed=rc == 0 and 'PASS pcs_enqueue_parity' in text, runs=rows))
        for vname in ['default', 'beta2']:
            tag = f'oods-{vname}'
            rc, text = run([str(harness), 'oods', str(fixtures['plain']), str(fixtures['imported']), str(a.out / tag)],
                           a.out / f'{tag}.log', env=dict(env0, **variants[vname]), check=False)
            rows = [dict(kv.split('=', 1) for kv in m.group(2).split()) for m in map(line.search, text.splitlines()) if m]
            results.append(dict(arm=tag, exit=rc, passed=rc == 0 and 'PASS pcs_enqueue_parity mode=oods' in text, runs=rows))
            verify.append((fixtures['imported'], a.out / f'{tag}.oods-job.bin'))
        for fx, vname in [('plain', 'default'), ('imported', 'beta2')]:
            tag = f'capture-{fx}-{vname}'
            rc, text = run([str(harness), 'capture', str(fixtures[fx]), str(a.out / tag)], a.out / f'{tag}.log',
                           env=dict(env0, **variants[vname]), check=False)
            rows = [dict(kv.split('=', 1) for kv in m.group(2).split()) for m in map(line.search, text.splitlines()) if m]
            results.append(dict(arm=tag, exit=rc, passed=rc == 0 and 'PASS pcs_enqueue_parity mode=capture' in text, runs=rows))
            verify.append((fixtures[fx], a.out / f'{tag}.graph1.bin'))
        sanitizers = {}
        for tool in ['memcheck', 'racecheck', 'synccheck', 'initcheck']:
            rc, text = run([SANITIZER, '--tool', tool, '--error-exitcode', '97', str(harness), str(fixtures['imported']),
                            'device', str(a.out / f'san-{tool}')], a.out / f'sanitizer-{tool}.log',
                           env=dict(env0, **variants['beta2']), check=False)
            sanitizers[tool] = dict(exit=rc, passed=rc == 0 and 'PASS pcs_enqueue_parity' in text)
    for fx in fixtures:
        verify.append((fixtures[fx], a.out / f'{fx}-device-beta2.job1.bin'))
    receivers = []
    for fixture, readback in verify:
        rc, text = run([str(a.fixture_tool), 'verify', str(fixture), str(readback)],
                       a.out / f'verify-{readback.stem}.log', check=False)
        receivers.append(dict(readback=readback.name, exit=rc,
                              passed=rc == 0 and 'native_verified=true native_proof_byte_parity=true' in text,
                              mutations_rejected=text.count('REJECT masked native PCS mutation=')))
    receipt.update(arms=results, sanitizers=sanitizers, receivers=receivers)
    ok = (receipt['addon_resolves_against_base_rtld_now'] and all(r['passed'] for r in results)
          and all(s['passed'] for s in sanitizers.values())
          and all(r['passed'] and r['mutations_rejected'] == 8 for r in receivers))
    receipt['result'] = 'PASS' if ok else 'FAIL'
    (a.out / 'receipt.json').write_text(json.dumps(receipt, indent=1) + '\n')
    print(json.dumps(dict(result=receipt['result'], arms=len(results), receivers=len(receivers),
                          receipt=str(a.out / 'receipt.json'))))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
