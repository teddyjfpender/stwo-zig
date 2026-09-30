#!/usr/bin/env python3
"""Reproduce research evidence from receipts and authenticated AIR templates.

No CUDA execution, network, or production algorithm changes. Liveness outputs
are abstract storage models, not predicted compiler frames or GPU speedups.
"""
import hashlib
import json
from pathlib import Path
import re
import statistics
import struct

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
STAGES = ["ingress", "trace_generation", "trace_commit", "constraint_evaluation",
          "oods", "quotient", "fri_commit", "pow", "decommit", "proof_assembly"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n")


def profile():
    path = ROOT / "autoresearch/notes/2026-09-29-cairo-cuda-local/nvidia-v45-repeated-suite.json"
    data = json.loads(path.read_text())
    result = {"source": str(path.relative_to(ROOT)), "source_sha256": sha(path.read_bytes()),
              "scope": "Existing v45 cold-process runs; not new CUDA measurements or warm service results",
              "gpu": data["gpu"], "security": data["security"], "results": []}
    for name in sorted({r["benchmark"] for r in data["results"]}):
        rows = [r for r in data["results"] if r["benchmark"] == name]
        assert len(rows) == 3 and all(r["status"] == "verified" for r in rows)
        trials = [r["backend_trial"] for r in rows]
        counters = [t["verdict"]["counters"] for t in trials]
        assert all(c["cpu_fallback_attempts"] == 0 for c in counters)
        assert all(t["verdict"]["aot"]["aot_misses"] == 0 for t in trials)
        stage_profiles = []
        for index, stage in enumerate(STAGES):
            samples = [c["stages"][index] for c in counters]
            stage_profiles.append({"stage": stage, "counters": {
                k: statistics.median(s[k] for s in samples)
                for k in samples[0] if isinstance(samples[0][k], (int, float))}})
        result["results"].append({"benchmark": name, "trials": len(rows),
            "proof_execute_and_decode_ns_median": statistics.median(t["proof_execute_and_decode_ns"] for t in trials),
            "adapted_input_until_publication_ns_median": statistics.median(t["adapted_input_until_publication_ns"] for t in trials),
            "max_sampled_device_bytes": max(r["highest_sampled_device_used_bytes"] for r in rows),
            "max_host_rss_bytes": max(r["host_peak_rss_bytes"] for r in rows),
            "arena_bytes": trials[0]["planned_arena_bytes"],
            "ingress_timings_ns_median": {k: statistics.median(t["ingress_timings"][k] for t in trials) for k in trials[0]["ingress_timings"]},
            "transport_median": {k: statistics.median(c[k] for c in counters) for k in
                ["h2d_bytes", "d2d_bytes", "d2h_proof_operations", "d2h_proof_bytes", "memset_bytes", "sync_calls", "kernel_launches", "graph_launches"]},
            "stage_profiles": stage_profiles})
    result["stage_caveat"] = "CUDA event intervals can include host-feed idle time and are not isolated kernel-compute attribution."
    write("profile-summary.json", result)


def memory():
    path = OUT / "host-admission.log"
    text = path.read_text()
    result = {"source": str(path.relative_to(ROOT)), "source_sha256": sha(path.read_bytes()),
        "scope": "Host admission planner, all four actual adapted inputs; 2/2 host tests passed. No GPU proof was run.",
        "completeness": "Diagnostic prints slots >=2^26 words only. Stage sums are lower bounds; peak-live total is reported by complete planner.", "results": []}
    for index in range(1, 5):
        name = f"SN_PIE_{index}"
        slots = []
        for m in re.finditer(rf"canonical_host_slot {name} kind=(\w+) ordinal=(\d+) bytes=(\d+) offset=(\d+) lifetime=(\w+)\.\.(\w+)", text):
            kind, ordinal, size, offset, first, last = m.groups()
            slots.append({"kind": kind, "ordinal": int(ordinal), "bytes": int(size), "offset": int(offset), "first": first, "last": last})
        peak = int(re.search(rf"canonical_host_peak {name} live_bytes=(\d+)", text).group(1))
        arena = int(re.search(rf"canonical_host_admission {name} .*?planned_arena_bytes=(\d+)", text).group(1))
        stages = {stage: sum(s["bytes"] for s in slots if STAGES.index(s["first"]) <= i <= STAGES.index(s["last"])) for i, stage in enumerate(STAGES)}
        largest = max(stages, key=stages.get)
        counterfactuals = []
        for removed in (("writer_lookup_inputs",), ("writer_lookup_inputs", "relation_denominators")):
            reduced = {stage: sum(s["bytes"] for s in slots if s["kind"] not in removed and
                STAGES.index(s["first"]) <= i <= STAGES.index(s["last"])) for i, stage in enumerate(STAGES)}
            new_stage = max(reduced, key=reduced.get)
            counterfactuals.append({"perfectly_eliminated_slots": removed,
                "largest_printed_stage": new_stage, "printed_live_bytes_lower_bound": reduced[new_stage],
                "caveat": "Hypothetical perfect elimination with no replacement storage; ignores unprinted slots, replan packing, runtime/private/pool overhead. Not an implementable arena or observed GPU peak."})
        result["results"].append({"benchmark": name, "arena_bytes": arena,
            "complete_planner_peak_live_bytes": peak, "largest_printed_stage": largest,
            "unprinted_bytes_at_reported_peak_if_same_stage": peak - stages[largest],
            "stage_printed_live_bytes_lower_bound": stages, "large_slots": slots,
            "counterfactuals": counterfactuals})
    write("memory-inventory.json", result)


def peak(intervals):
    # Inclusive intervals match the production allocator's conservative rule.
    events = []
    for start, end in intervals:
        events.extend([(start, 1), (end + 1, -1)])
    live = high = 0
    for _, delta in sorted(events):
        live += delta
        high = max(high, live)
    return high


def liveness(base, ext, roots, nb, ne, unordered):
    spans = [[[None, 0] for _ in range(nb)], [[None, 0] for _ in range(ne)]]
    final = {}
    def update(bank, reg, time, written=False):
        item = spans[bank][reg]
        if written:
            item[0] = time if item[0] is None else min(item[0], time)
        item[1] = max(item[1], time)
    for i, inst in enumerate(base):
        op, _, dst, a, b, _ = inst
        update(0, dst, 2 * i, True)
        for r in ([a, b] if op in (4, 5, 6) else [a] if op in (7, 8) else []):
            update(0, r, 2 * i)
    for i, inst in enumerate(ext):
        op, _, dst, a, b, c, d = inst
        t = 2 * (len(base) + i)
        update(1, dst, t, True)
        final[dst] = t
        for r in ([a, b, c, d] if op == 0 else []):
            update(0, r, t)
        for r in ([a, b] if op in (3, 4, 5) else [a] if op == 6 else []):
            update(1, r, t)
    root_time = 0
    for root in roots:
        root_time = final[root] + 1 if unordered else max(root_time, final[root] + 1)
        update(1, root, root_time)
    return [peak([s for s in bank if s[0] is not None]) for bank in spans]


def slices(base, ext, roots):
    # Version every imperative write. Read dependencies use the previous version
    # even when dst aliases an operand. Thus root reachability is well defined.
    nodes, current = [], [{}, {}]
    for bank, instructions in enumerate((base, ext)):
        for inst in instructions:
            op, _, dst, a, b, *tail = inst
            refs = []
            if bank == 0:
                refs = [(0, r) for r in ([a, b] if op in (4, 5, 6) else [a] if op in (7, 8) else [])]
            elif op == 0:
                refs = [(0, r) for r in [a, b, *tail]]
            elif op in (3, 4, 5, 6):
                refs = [(1, r) for r in ([a] if op == 6 else [a, b])]
            dependencies = {current[k][r] for k, r in refs}
            current[bank][dst] = len(nodes)
            nodes.append((bank, dependencies))
    root_nodes = [current[1][r] for r in roots]
    closures = []
    for root in root_nodes:
        closure, pending = set(), [root]
        while pending:
            node = pending.pop()
            if node not in closure:
                closure.add(node)
                pending.extend(nodes[node][1])
        closures.append(closure)

    def bundle_model(root_group, reachable):
        order = sorted(reachable)
        position = {node: 2 * i for i, node in enumerate(order)}
        last = dict(position)
        for node in order:
            for dependency in nodes[node][1]:
                last[dependency] = max(last[dependency], position[node])
        for root in root_group:
            last[root] = max(last[root], position[root] + 1)
        sizes = []
        for bank in (0, 1):
            sizes.append(peak([(position[n], last[n]) for n in order if nodes[n][0] == bank]))
        return sizes, len(order)

    all_reachable = set().union(*closures)
    full_sizes, full_work = bundle_model(root_nodes, all_reachable)
    result = {"ssa_unsliced_dependency_work": full_work,
              "ssa_unsliced_peak_base": full_sizes[0], "ssa_unsliced_peak_ext": full_sizes[1],
              "ssa_unsliced_peak_bytes": 4 * full_sizes[0] + 16 * full_sizes[1], "root_bundles": []}
    for width in (32, 64, 128, 256):
        largest = work = bundles = 0
        for start in range(0, len(roots), width):
            reachable = set().union(*closures[start:start + width])
            sizes, count = bundle_model(root_nodes[start:start + width], reachable)
            largest = max(largest, 4 * sizes[0] + 16 * sizes[1])
            work += count
            bundles += 1
        result["root_bundles"].append({"roots_per_bundle": width, "bundles": bundles,
            "maximum_model_private_bank_bytes": largest, "total_dependency_instruction_work": work,
            "work_ratio_to_ssa_unsliced": work / full_work})
    return result


def air():
    folder = ROOT / "zig-out/share/stwo-zig/cairo/official"
    manifest = json.loads((folder / "air_template_library_v1.json").read_text())
    outputs = []
    for source in manifest["sources"]:
        path = folder / source["bundle"]["path"]
        data = path.read_bytes()
        assert sha(data) == source["bundle"]["sha256"]
        assert data[:8] == b"STWZEVA\0"
        count = struct.unpack_from("<I", data, 28)[0]
        cursor = 40
        for _ in range(count):
            label_len, reserved = struct.unpack_from("<HH", data, cursor)
            values = struct.unpack_from("<10I", data, cursor + 4)
            cursor += 44
            instance, trace_log, eval_log, constraints, rc_offset, spans, pp, denoms, es, parts = values
            label = data[cursor:cursor + label_len].decode()
            cursor += label_len + spans * 12 + pp * 4 + denoms * 4 + es * 32
            for part in range(parts):
                rc_base, length, semantic = struct.unpack_from("<IIQ", data, cursor)
                cursor += 16
                program = data[cursor:cursor + length]
                cursor += length
                assert struct.unpack_from("<I", program)[0] == 0x31505453
                nsections = struct.unpack_from("<I", program, 8)[0]
                nb, ne = struct.unpack_from("<II", program, 48)
                payload = 96 + nsections * 24
                sections = {}
                for j in range(nsections):
                    kind, stride, offset, n = struct.unpack_from("<IIQQ", program, 96 + 24 * j)
                    sections[kind] = (stride, n, program[payload + offset:payload + offset + stride * n])
                h = 0xcbf29ce484222325
                for kind in range(1, 6):
                    for byte in sections[kind][2]:
                        h = ((h ^ byte) * 0x100000001b3) & ((1 << 64) - 1)
                assert h == semantic == struct.unpack_from("<Q", program, 16)[0]
                base = list(struct.iter_unpack("<BBHIIi", sections[3][2]))
                ext = list(struct.iter_unpack("<BBHIIII", sections[4][2]))
                roots = [r[0] for r in struct.iter_unpack("<I", sections[5][2])]
                assert len(roots) == constraints or parts > 1
                conservative = liveness(base, ext, roots, nb, ne, False)
                independent = liveness(base, ext, roots, nb, ne, True)
                outputs.append({"role": source["role"], "label": label, "part": part,
                    "program_sha256": sha(program), "source_bundle_sha256": sha(data),
                    "base_instructions": len(base), "ext_instructions": len(ext), "constraints": len(roots),
                    "declared_base_regs": nb, "declared_ext_regs": ne,
                    "current_conservative_interval_peak": {"base": conservative[0], "ext": conservative[1], "bytes": 4 * conservative[0] + 16 * conservative[1]},
                    "indexed_completion_root_interval_peak": {"base": independent[0], "ext": independent[1], "bytes": 4 * independent[0] + 16 * independent[1]},
                    "ssa_root_slice_model": slices(base, ext, roots)})
        assert cursor == len(data)
    write("air-liveness.json", {"scope": "Authenticated source templates, not live-device compiler frames; normalization preserves instruction/register structure.",
        "model": "First comparison: fixed instruction schedule and one conservative interval per logical register, with earliest final-root consumption and original coefficient indices. Additional SSA model: exact read-before-write dependencies, dead-code removal, contiguous root bundles, independent dependency recomputation, original topological instruction order. Abstract 4-byte base/16-byte extension slots; no compiler frames, scalar facts, rescheduling, shared partial outputs, or machine register allocation modeled. Instruction work is unweighted and not elapsed time.",
        "authority": manifest["authority"], "programs": sorted(outputs, key=lambda x: -x["current_conservative_interval_peak"]["bytes"])})


if __name__ == "__main__":
    profile()
    memory()
    air()
    print("Wrote profile-summary.json, memory-inventory.json, air-liveness.json")
