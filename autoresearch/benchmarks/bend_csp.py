#!/usr/bin/env python3
"""Experimental full-proof comparison on authenticated CSP workloads.

Uses the unchanged secure PCS configuration, validates canonical guest output,
requires CPU verification, and compares proof bytes. This does not enroll Bend
in the production CSP release registry or claim official leaderboard admission.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.riscv_csp_benchmark_lib.contract import validate_manifest, SECURE_PCS_CONFIG
from scripts.riscv_csp_benchmark_lib.public_output import reconstruct_public_output
from bend_common import digest


def run(argv, timeout):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        start = time.perf_counter_ns()
        child = subprocess.Popen(list(map(str, argv)), stdout=out, stderr=err, start_new_session=True)
        expired = threading.Event()
        def kill():
            expired.set()
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        timer = threading.Timer(timeout, kill)
        timer.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
        finally:
            timer.cancel()
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(), err.read().decode(errors='replace')
        if expired.is_set() or child.returncode:
            raise RuntimeError(f'exit={child.returncode} timeout={expired.is_set()} stderr={stderr[-3000:]}')
        r = json.loads(stdout)
        r.update(wall_ns=time.perf_counter_ns()-start, cpu_user_s=usage.ru_utime,
                 cpu_system_s=usage.ru_stime, peak_rss_bytes=usage.ru_maxrss*1024)
        return r


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli', type=Path, required=True)
    p.add_argument('--bend', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--targets', default='sha256,keccak,poseidon2_m31,ecdsa_secp256k1')
    p.add_argument('--samples', type=int, default=3)
    p.add_argument('--timeout', type=int, default=600)
    p.add_argument('--artifact-dir', type=Path, default=ROOT/'.zig-cache/bend-csp-proofs')
    args = p.parse_args()
    if args.samples < 1 or args.timeout < 1:
        p.error('samples and timeout must be positive')
    manifest, cases, _ = validate_manifest()
    targets = args.targets.split(',')
    if len(set(targets)) != len(targets) or any(t not in {c.target for c in cases} for t in targets):
        p.error('invalid targets')
    selected = [min((c for c in cases if c.target == t), key=lambda c:c.input_size) for t in targets]
    report = dict(schema='stwo-bend-csp-experiment-v1', manifest_sha256=digest(ROOT/'vectors/riscv_csp/manifest-v2.json'),
                  cli_sha256=digest(args.cli), bend_binary_sha256=digest(args.bend),
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  sources={str(f.relative_to(ROOT)):digest(f) for base,pattern in [('src/backends/bend','*.zig'),('bend/stwo','*'),('src/integrations/riscv_bend','*.zig')] for f in sorted((ROOT/base).glob(pattern)) if f.is_file()},
                  harness_sha256=digest(__file__), secure_pcs=SECURE_PCS_CONFIG, rows=[], all_verified=True,
                  scope='execution + witness + proof; verification separately; serialization excluded from compute, included in wall',
                  limitations=['experimental runner, not official CSP registry admission','CPU only, no GPU','host composition/interactions/Merkle/inversion','Bend results shadow-checked against Zig','fresh proof process, persistent Bend child per proof','minimum canonical input per selected target','shared host'],
                  bend_call_order=['fft','ifft','multiply','prefix','fri','lde_forward'])
    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
    args.artifact_dir.mkdir(parents=True,exist_ok=True)
    try:
        for case in selected:
            row = dict(target=case.target,input_size=case.input_size,cycles=case.expected_cycles,
                       guest_sha256=case.guest_sha256,input_sha256=case.input_sha256,samples=[])
            report['rows'].append(row)
            for sample in range(args.samples):
                pair = {}
                row['samples'].append(pair)
                save()
                order = ('cpu','bend') if sample%2==0 else ('bend','cpu')
                for backend in order:
                    proof = args.artifact_dir/f'{case.target}-{sample}-{backend}.proof'
                    receipt = run([args.cli.resolve(),backend,case.guest_path,case.input_path,proof.resolve()],args.timeout)
                    if receipt['verified_by']!='cpu' or receipt['backend']!=backend or receipt['secure_pcs']!=SECURE_PCS_CONFIG or receipt['cycles']!=case.expected_cycles:
                        raise ValueError('proof execution identity mismatch')
                    if reconstruct_public_output(receipt['public_values']).hex()!=case.expected_digest:
                        raise ValueError('canonical guest output mismatch')
                    if digest(proof)!=receipt['proof_sha256']:
                        raise ValueError('proof artifact digest mismatch')
                    calls=receipt['bend']['calls']
                    if backend=='bend' and (calls[1]==0 or calls[4]==0 or calls[0]+calls[5]==0):
                        raise ValueError('Bend transform/FRI execution not observed')
                    if backend=='cpu' and any(calls):
                        raise ValueError('CPU lane executed Bend')
                    pair[backend]=receipt
                    save()
                    print(f'{case.target} sample{sample} {backend}: {receipt["compute_ns"]/1e9:.3f}s, verified',flush=True)
                pair['proof_bytes_equal']=pair['cpu']['proof_sha256']==pair['bend']['proof_sha256']
                if not pair['proof_bytes_equal']:
                    raise ValueError('backend proof bytes differ')
                save()
            c=statistics.median(s['cpu']['compute_ns'] for s in row['samples'])
            b=statistics.median(s['bend']['compute_ns'] for s in row['samples'])
            row.update(cpu_median_ns=c,bend_median_ns=b,bend_over_cpu=b/c)
            save()
    except Exception as exc:
        report.update(all_verified=False,error=str(exc))
        save()
        raise
    save()


if __name__=='__main__':
    main()
