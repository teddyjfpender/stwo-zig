#!/usr/bin/env python3
"""Real observer ABI/counter smoke. Owner runs under the existing GPU lock.

Scope: registered requested/reserved/rounded bytes and diagnostic fence tags;
not a whole-prover test, physical node peak, throughput or latency result.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

U, Q, V = C.c_uint32, C.c_uint64, C.c_void_p


class Options(C.Structure):
    _fields_ = [("version", U), ("device", U), ("lanes", U), ("staging", U)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--library", required=True)
    ap.add_argument("--out", help="Optional compact JSON path outside the repository")
    args = ap.parse_args()
    for key, value in {
        "STWO_RV64_ALLOCATION_OBSERVER": "1",
        "STWO_RV64_DEVICE_ARENA": "2G",
        "STWO_RV64_DEVICE_ARENA_CHUNK": "32M",
        "STWO_RV64_DEVICE_ARENA_SMALL_CHUNKS": "16",
        "STWO_RV64_DEVICE_ARENA_PREMAP": "1",
        "STWO_RV64_GLOBAL_ADMISSION": "0",
        "STWO_RV64_PINNED_STAGING": "0",
    }.items():
        os.environ[key] = value
    os.environ.pop("STWO_RV64_DEVICE_ARENA_POISON", None)
    lib = C.CDLL(args.library)

    def fn(name, types):
        result = getattr(lib, name)
        result.argtypes, result.restype = types, C.c_int
        return result

    create = fn("stwo_exec_context_create_options", [C.POINTER(Options), C.POINTER(V)])
    destroy = fn("stwo_exec_context_destroy", [V])
    allocate = fn("stwo_exec_context_alloc_u32", [V, Q, C.POINTER(V)])
    free = fn("stwo_exec_context_free_u32", [V, V])
    sync = fn("stwo_exec_context_sync", [V])
    stream = fn("stwo_exec_context_lane_stream", [V, U, C.POINTER(V)])
    scratch_alloc = fn("stwo_exec_arena_scratch_alloc", [V, Q, C.POINTER(V)])
    scratch_free = fn("stwo_exec_arena_scratch_free", [V, V])
    begin = fn("stwo_exec_context_allocation_observer_begin_v1", [V, C.POINTER(U), U, U, U, U])
    next_stage = fn("stwo_exec_context_allocation_observer_next_v1", [V, U, U])
    end = fn("stwo_exec_context_allocation_observer_end_v1", [V])
    bind = fn("stwo_exec_context_allocation_observer_bind_v1", [V, V, Q])
    capability = fn("stwo_exec_context_allocation_observer_capability_v1", [])
    assert capability() == 1
    assert C.sizeof(Options) == 16

    def ok(status):
        assert status == 0, f"CUDA/runtime status {status}"

    rejected = 0

    def run_device(device):
        nonlocal rejected
        a, b = V(), V()
        ok(create(C.byref(Options(1, device, 2, 32)), C.byref(a)))
        ok(create(C.byref(Options(1, device, 2, 32)), C.byref(b)))
        live, active, scratch = [], {}, []

        def start(context, ordinal):
            key = (U * 8)(*[device * 1000 + ordinal + i for i in range(8)])
            ok(begin(context, key, ordinal, 1, 1, 0))
            active[context.value] = context

        def close(context):
            ok(end(context))
            active.pop(context.value)

        def alloc(words):
            pointer = V()
            ok(allocate(a, words, C.byref(pointer)))
            live.append(pointer)
            return pointer

        def release(pointer):
            ok(free(a, pointer))
            live.remove(pointer)

        try:
            # S=1028 requested ->1536 small rounded; L=4MiB+4 ->32MiB.
            start(a, 10)
            small, large = alloc(257), alloc((4 << 20) // 4 + 1)
            ok(next_stage(a, 2, 0))
            release(small)
            ok(next_stage(a, 3, 1))
            release(large)
            ok(next_stage(a, 4, 0))
            tiny = alloc(1)
            release(tiny)
            close(a)

            # Same semantic node starts epoch 2 with no inherited large peak.
            start(a, 10)
            tiny = alloc(1)
            ok(next_stage(a, 2, 0))
            release(tiny)
            close(a)

            # A smaller active cache use retains the whole original reservation.
            start(a, 30)
            cached = alloc(1025)  # 4100 requested, 4608 rounded.
            ok(bind(a, cached, 100))
            ok(next_stage(a, 2, 0))
            for context, pointer, size in ((b, cached, 64), (a, cached, 4101), (a, V(cached.value + 4), 64)):
                assert bind(context, pointer, size) != 0, "invalid bind accepted"
                rejected += 1
            ok(next_stage(a, 3, 0))
            ok(bind(a, cached, 0))
            ok(next_stage(a, 4, 0))
            ok(bind(a, cached, 64))
            ok(next_stage(a, 5, 0))
            release(cached)
            close(a)

            # Registered scratch follows its birth-node tag when another
            # context stream frees it. No raw CUDA allocation bypasses registry.
            start(a, 40)
            start(b, 50)
            sa, sb, pointer = V(), V(), V()
            ok(stream(a, 0, C.byref(sa)))
            ok(stream(b, 0, C.byref(sb)))
            ok(scratch_alloc(sa, 1032, C.byref(pointer)))
            scratch.append((sb, pointer))
            ok(scratch_free(sb, pointer))
            scratch.clear()
            ok(next_stage(b, 2, 1))
            close(a)
            close(b)
        finally:
            for owner in (a, b):
                ok(sync(owner))
            for pointer in reversed(live):
                ok(free(a, pointer))
            for owner_stream, pointer in scratch:
                ok(scratch_free(owner_stream, pointer))
            for owner in list(active.values()):
                ok(end(owner))
            ok(destroy(b))
            ok(destroy(a))

    saved = os.dup(2)
    with tempfile.TemporaryFile(mode="w+b") as captured:
        try:
            os.dup2(captured.fileno(), 2)
            for device in (0, 1):
                run_device(device)
        finally:
            C.CDLL(None).fflush(None)
            os.dup2(saved, 2)
            os.close(saved)
            captured.seek(0)
            stderr = captured.read().decode(errors="replace")
            if sys.exc_info()[0]:
                sys.stderr.write(stderr)

    rows = []
    for line in stderr.splitlines():
        if line.startswith("GPU_NODE_ALLOC_STAGE "):
            fields = dict(word.split("=", 1) for word in line.split()[1:])
            rows.append({key: int(value) if key != "key" and value.isdigit() else value for key, value in fields.items()})
    assert "GPU_NODE_ALLOC_COVERAGE_GAP" not in stderr, stderr
    assert len(rows) == 28, f"expected 14 rows/device, got {len(rows)}"

    def row(device, ordinal, stage, epoch=1):
        matches = [r for r in rows if (r["device"], r["ordinal"], r["stage"], r["epoch"]) == (device, ordinal, stage, epoch)]
        assert len(matches) == 1, (device, ordinal, stage, epoch, matches)
        return matches[0]

    def expect(r, **fields):
        for key, value in fields.items():
            assert r[key] == value, f'{r["device"]}/{r["ordinal"]}/{r["stage"]}: {key}={r[key]}, expected {value}'

    S, SR, L, LR, CR = 1028, 1536, (4 << 20) + 4, 32 << 20, 4608
    for r in rows:
        expect(r, version=1, carve_bytes=2 << 30, small_slab_bytes=512 << 20,
               coverage_gaps=0, stage_coverage_gaps=0, diagnostic_host_join=1,
               timing_qualified=0, physical_node_peak_qualified=0, end_pending_rounded_bytes=0,
               global_pending_fence_bytes=0, device_memory_rc=0)
    for d in (0, 1):
        expect(row(d, 10, "main_witness"), baseline_requested_bytes=0,
               active_requested_peak_bytes=S+L, requested_reservation_peak_bytes=S+L,
               rounded_reservation_peak_bytes=SR+LR, rounded_small_peak_bytes=SR,
               rounded_large_peak_bytes=LR, end_requested_bytes=S+L, end_rounded_bytes=SR+LR)
        expect(row(d, 10, "main_commit"), baseline_requested_bytes=S+L,
               pending_requested_peak_bytes=S, pending_rounded_peak_bytes=SR,
               rounded_including_pending_upper_peak_bytes=SR+LR,
               end_requested_bytes=L, end_rounded_bytes=LR)
        expect(row(d, 10, "inter_witness"), baseline_requested_bytes=L,
               rounded_reservation_peak_bytes=LR, rounded_small_peak_bytes=0,
               pending_requested_peak_bytes=L, pending_rounded_peak_bytes=LR,
               rounded_including_pending_upper_peak_bytes=LR, end_rounded_bytes=0)
        expect(row(d, 10, "inter_commit"), baseline_requested_bytes=0,
               requested_reservation_peak_bytes=4, rounded_reservation_peak_bytes=512,
               pending_requested_peak_bytes=4, pending_rounded_peak_bytes=512,
               node_requested_peak_bytes=S+L, node_rounded_peak_bytes=SR+LR)
        expect(row(d, 10, "main_witness", 2), node_requested_peak_bytes=4,
               node_rounded_peak_bytes=512, rounded_reservation_peak_bytes=512)
        expect(row(d, 10, "main_commit", 2), pending_requested_peak_bytes=4,
               pending_rounded_peak_bytes=512, node_rounded_peak_bytes=512)
        expect(row(d, 30, "main_commit"), baseline_active_bytes=100,
               baseline_requested_bytes=4100, baseline_rounded_bytes=CR,
               active_requested_peak_bytes=100, requested_reservation_peak_bytes=4100,
               rounded_reservation_peak_bytes=CR)
        expect(row(d, 30, "inter_witness"), end_requested_bytes=0, end_rounded_bytes=0,
               idle_cache_rounded_end_bytes=CR, shared_unattributed_rounded_end_bytes=CR,
               global_rounded_end_bytes=CR)
        expect(row(d, 30, "inter_commit"), baseline_requested_bytes=0,
               active_requested_peak_bytes=64, requested_reservation_peak_bytes=4100,
               rounded_reservation_peak_bytes=CR, idle_cache_rounded_end_bytes=0)
        expect(row(d, 30, "composition"), baseline_active_bytes=64,
               pending_requested_peak_bytes=4100, pending_rounded_peak_bytes=CR,
               rounded_including_pending_upper_peak_bytes=CR, end_rounded_bytes=0)
        expect(row(d, 40, "main_witness"), requested_reservation_peak_bytes=1032,
               rounded_reservation_peak_bytes=1536, pending_requested_peak_bytes=1032,
               pending_rounded_peak_bytes=1536, rounded_including_pending_upper_peak_bytes=1536,
               end_requested_bytes=0, node_rounded_peak_bytes=1536)
        for name in ("main_witness", "main_commit"):
            expect(row(d, 50, name), requested_reservation_peak_bytes=0,
                   rounded_reservation_peak_bytes=0, pending_requested_peak_bytes=0,
                   pending_rounded_peak_bytes=0, node_rounded_peak_bytes=0)

    result = {
        "schema": "rv64-node-observer-abi-smoke/v1",
        "status": "OBSERVER_ABI_COUNTER_PASS_NOT_PROVER_OR_PHYSICAL_PEAK_QUALIFICATION",
        "scope": __doc__, "devices": [0, 1], "rows": len(rows), "invalid_binds_rejected": rejected,
        "library_sha256": hashlib.sha256(Path(args.library).read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "captured_stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
        "peak_rule": "Each simultaneous upper peak is asserted separately; independent maxima are never added.",
        "records": rows,
    }
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "records"}))


if __name__ == "__main__":
    main()
