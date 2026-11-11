#!/usr/bin/env python3
"""Exact CUPTI interval accounting for resident request windows; no wall-speed inference."""

import argparse
import json
from pathlib import Path
import sqlite3
if __package__ in (None, ""):  # run as a file: make `scripts.*` importable
    __import__("sys").path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.rv64 import rv64_m3_timeline as T
from contextlib import closing
from scripts.rv64.rv64_validation import fingerprints, sha, validate_receivers
from scripts.rv64.rv64_m7_gpu_seconds_lib.census import request_census


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', type=Path)
    p.add_argument('--accepted-run', required=True, type=Path)
    args = p.parse_args()
    receipt = json.loads((args.run / 'receipt.json').read_text())
    accepted = json.loads((args.accepted_run / 'receipt.json').read_text())
    if receipt['assets'] != accepted['assets']:
        raise RuntimeError('profiled and accepted assets differ')
    fresh = {}
    for block in {row['block'] for row in receipt['requests']}:
        for verifier in accepted.get('receivers', []):
            matches = [row for row in accepted['requests'] if row['block'] == block and row['proof'] == verifier.get('proof')]
            if not matches:
                continue
            try:
                validate_receivers([verifier], [matches[0]['proof']], accepted['assets']['receiver'])
            except RuntimeError:
                continue
            fresh[block] = matches[0]
            break
        if block not in fresh:
            raise RuntimeError('reference lacks fresh isolated CPU acceptance for block ' + str(block))
    database = args.run / 'nsys/timeline.sqlite'
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        epoch = db.execute('SELECT utcEpochNs FROM TARGET_INFO_SESSION_START_TIME').fetchone()[0]
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        devices = [r[0] for r in db.execute('SELECT DISTINCT deviceId FROM CUPTI_ACTIVITY_KIND_KERNEL ORDER BY deviceId')]
        rows = []
        for request in receipt['requests']:
            lo, hi = request['utc_window_ns']
            lower, upper = lo - epoch, hi - epoch
            if 'CUPTI_ACTIVITY_KIND_GRAPH_TRACE' in tables:
                graph_count = db.execute('SELECT COUNT(*) FROM CUPTI_ACTIVITY_KIND_GRAPH_TRACE WHERE end>? AND start<?', (lower, upper)).fetchone()[0]
                if graph_count:
                    raise RuntimeError('GPU accounting incomplete: CUDA graph envelopes present in request window; node-kernel completeness is not established (' + str(graph_count) + ' graph records)')
            measured = {}
            for device in devices:
                kernels = db.execute('SELECT start,end FROM CUPTI_ACTIVITY_KIND_KERNEL WHERE deviceId=? AND end>? AND start<?', (device, lower, upper)).fetchall()
                copies = db.execute('SELECT start,end,bytes,copyKind FROM CUPTI_ACTIVITY_KIND_MEMCPY WHERE deviceId=? AND end>? AND start<?', (device, lower, upper)).fetchall()
                ks = [(max(s, lower), min(e, upper)) for s, e in kernels]
                cs = [(max(s, lower), min(e, upper)) for s, e, _, _ in copies]
                if not ks:
                    raise RuntimeError('empty request kernel window; clock alignment invalid')
                kinds = {}
                for _, _, size, kind in copies:
                    kinds[str(kind)] = kinds.get(str(kind), 0) + size
                measured[str(device)] = {'kernel_count': len(ks), 'kernel_duration_sum_s': sum(e - s for s, e in ks) / 1e9, 'kernel_busy_union_s': T.union(ks) / 1e9, 'memcpy_busy_union_s': T.union(cs) / 1e9, 'any_busy_union_s': T.union(ks + cs) / 1e9, 'copy_bytes_by_CUPTI_kind': kinds}
            reference = fresh[request['block']]
            identical = fingerprints(request) == fingerprints(reference)
            if not identical:
                raise RuntimeError('profiled artifacts differ from fresh-accepted reference')
            rows.append({'block': request['block'], 'trial': request['trial'], 'utc_window_ns': [lo, hi], 'profiled_request_wall_s': request['stages']['request_wall_s'], 'byte_identical_to_fresh_accepted_reference': identical, 'devices': measured, 'cuda_census': request_census(db, lower, upper), 'kernel_busy_gpu_seconds': sum(v['kernel_busy_union_s'] for v in measured.values()), 'any_busy_gpu_seconds': sum(v['any_busy_union_s'] for v in measured.values())})
        result = {'schema': 'rv64-m7-request-gpu-seconds/v1', 'author': 'OpenAI Codex', 'scope': 'Exact per-device union of CUPTI kernels/copies clipped to complete UTC request windows; summed across devices. Profiled walls include profiler overhead and are not latency claims. Whole-request accounting, not native-only attribution.', 'cuda_graph_envelopes_in_measured_windows': 0, 'kernel_accounting_complete': True, 'assets': receipt['assets'], 'accepted_run': str(args.accepted_run), 'fresh_accepted_reference_blocks': sorted(fresh), 'accepted_receipt_sha256': sha(args.accepted_run / 'receipt.json'), 'profile_receipt_sha256': sha(args.run / 'receipt.json'), 'sqlite_sha256': sha(database), 'nsys_report_sha256': sha(args.run / 'nsys/timeline.nsys-rep'), 'session_start_utc_ns': epoch, 'requests': rows}
    (args.run / 'gpu-seconds.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps([{k: v for k, v in row.items() if k not in ('devices', 'utc_window_ns')} for row in rows], indent=1))


if __name__ == '__main__':
    main()
