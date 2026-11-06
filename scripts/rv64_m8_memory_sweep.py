#!/usr/bin/env python3
"""M8 memory sweep: replay production allocation order at a fixed arena.

Modelled on Airbender gpu_prover/src/memory_sweep + bin/gpu_memory_sweep and
v3 execution_prover memory_sweep / memory_policy/generated.rs: for each node
class, replay the exact arena reservation/release order recorded by
STWO_RV64_M8_MEM_TRACE (device_arena_runtime.cuh) under each policy at a
fixed arena size, including worst-case overlap with the next node's inputs,
and emit a generated per-class policy table plus high-water marks.

Inputs are diagnostic traces (observer host-joins at stage boundaries), so
the replay is an allocator-order model, not a GPU-completion residency
measurement: a fenced release is treated as reusable at the release row.

Policies (each is a trace transformation; the replay is the same):
  keep             production behaviour, as recorded.
  next_input       keep + the next node's inputs (its first-stage live bytes)
                   reserved from the current node's first row until the next
                   node starts (Airbender 3-stage pipeline overlap).
  shared_offload   next_input + shared/long-lived (untagged) reservations
                   not resident while a node runs: modelled as removed, i.e.
                   setup/class constants re-uploaded from pinned host and
                   recomputed (Airbender setup.rs:137-160). Upper bound on
                   the saving; the re-upload cost is not modelled.

Arena models:
  vmm     our VMM arena: large region is fungible chunks (physical
          fragmentation impossible), small slab separate.
  static  Airbender-style single static allocation: best-fit offsets in one
          contiguous region with Top/Bottom placement alternating by node
          parity; reports fit and fragmentation (span - live).

  rv64_m8_memory_sweep.py replay TRACE.tsv [...] --out DIR [--arena 22G]
  rv64_m8_memory_sweep.py check --policy DIR/policy.json --arena 22G --chunk 32M --small-chunks 16
"""
import argparse
import bisect
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

SCHEMA_TRACE = "# rv64-m8-arena-trace/v1"
SCHEMA_POLICY = "rv64-m8-memory-policy/v1"
POLICIES = ("keep", "next_input", "shared_offload")
INPUT_STAGES = ("main_witness",)
GiB = 1 << 30
MiB = 1 << 20


def parse_bytes(text):
    text = str(text).strip()
    scale = {"K": 1 << 10, "M": MiB, "G": GiB}.get(text[-1:].upper(), 1)
    return int(text[:-1] if scale != 1 else text) * scale


def read_trace(path):
    rows = []
    with Path(path).open() as handle:
        header = handle.readline().rstrip("\n").split("\t")
        if header[0] != SCHEMA_TRACE:
            raise ValueError(f"{path}: not an rv64-m8 arena trace")
        names = header[1:]
        for number, line in enumerate(handle, 2):
            parts = line.rstrip("\n").split("\t")
            if len(parts) != len(names):
                raise ValueError(f"{path}:{number}: {len(parts)} fields, expected {len(names)}")
            row = dict(zip(names, parts))
            for key in ("t_us", "device", "offset", "rounded", "requested", "long", "small", "fenced",
                        "context", "ordinal", "domain", "epoch"):
                row[key] = int(row[key])
            rows.append(row)
    return rows


def node_id(row):
    return None if row["ordinal"] < 0 else (row["domain"], row["ordinal"], row["epoch"])


def tree_classes(tree):
    """Recursion node class by structure: leaf, fold<arity>, root."""
    return {i: "root" if i == tree["root"] else "leaf" if not n["children"] else f"fold{len(n['children'])}"
            for i, n in enumerate(tree["nodes"])}


def class_of(node, classes):
    if node is None:
        return "shared"
    domain, ordinal, _ = node
    if domain != 1:
        return f"domain{domain}"
    return classes.get(ordinal, f"node{ordinal}")


class StaticArena:
    """Best-fit offset allocator over [0, capacity) with Top/Bottom placement."""

    def __init__(self, capacity, granule):
        self.capacity, self.granule = capacity, granule
        self.free = [(0, capacity)]  # sorted, coalesced (offset, length)
        self.span_hw = 0

    def allocate(self, size, top):
        size = -(-size // self.granule) * self.granule
        best = None  # smallest fitting hole; Top prefers the highest such hole
        for index, (offset, length) in enumerate(self.free):
            if length >= size and (best is None or length < self.free[best][1] or
                                   (length == self.free[best][1] and top)):
                best = index
        if best is None:
            return None
        offset, length = self.free.pop(best)
        if top:
            placed = offset + length - size
            if length > size:
                self.free.insert(best, (offset, length - size))
        else:
            placed = offset
            if length > size:
                self.free.insert(best, (offset + size, length - size))
        self._update_span()
        return placed, size

    def release(self, offset, size):
        bisect.insort(self.free, (offset, size))
        merged = []
        for start, length in self.free:
            if merged and merged[-1][0] + merged[-1][1] == start:
                merged[-1] = (merged[-1][0], merged[-1][1] + length)
            else:
                merged.append((start, length))
        self.free = merged

    def _update_span(self):
        # capacity - largest contiguous hole: live bytes plus fragmentation
        # that a single large request cannot use.
        if not self.free:
            self.span_hw = self.capacity
            return
        largest = max(length for _, length in self.free)
        self.span_hw = max(self.span_hw, self.capacity - largest)


def transform(rows, policy, classes):
    """Return (events, input_bytes_by_node). Events: (kind, key, bytes, small, node)."""
    nodes_in_order, first_index, input_bytes = [], {}, defaultdict(int)
    live_input = {}
    for index, row in enumerate(rows):
        node = node_id(row)
        if node is not None and node not in first_index:
            first_index[node] = index
            nodes_in_order.append(node)
        if row["op"] == "A" and node is not None and row["stage"] in INPUT_STAGES:
            live_input[(row["device"], row["offset"])] = (node, row["rounded"])
        elif row["op"] == "F":
            live_input.pop((row["device"], row["offset"]), None)
        elif row["op"] == "S" and node is not None and row["stage"] in INPUT_STAGES:
            input_bytes[node] = max(input_bytes[node], sum(b for n, b in live_input.values() if n == node))
    events = []
    successor = {nodes_in_order[i]: nodes_in_order[i + 1] for i in range(len(nodes_in_order) - 1)}
    started, offloaded = set(), set()
    for index, row in enumerate(rows):
        node = node_id(row)
        if policy != "keep" and node is not None and node not in started:
            started.add(node)
            # This node's own prefetched inputs are now consumed by its real
            # allocations; release the reservation, then reserve the next one.
            events.append(("F", ("next", node), input_bytes.get(node, 0), False, node))
            nxt = successor.get(node)
            if nxt is not None:
                events.append(("A", ("next", nxt), input_bytes.get(nxt, 0), False, node))
        if row["op"] == "S":
            events.append(("S", None, 0, False, node))
            continue
        key = (row["device"], row["offset"])
        # Offload is decided by the reservation's BIRTH tag: an idle cache
        # binding untags a live reservation, so its release row may be
        # untagged while its reservation row was tagged (and vice versa).
        if policy == "shared_offload":
            if row["op"] == "A" and node is None:
                offloaded.add(key)
                continue
            if row["op"] == "F" and key in offloaded:
                offloaded.discard(key)
                continue
        events.append((row["op"], key, row["rounded"], bool(row["small"]), node))
    return events, dict(input_bytes)


def replay(rows, policy, arena, small_bytes, chunk, classes):
    events, inputs = transform(rows, policy, classes)
    live = {}  # key -> (bytes, small, node, static placement)
    total_large = total_small = 0
    by_node = defaultdict(int)
    static = StaticArena(arena, chunk)
    static_fail = None
    node_stats = {}
    current = None
    parity = defaultdict(int)
    for kind, key, size, small, node in events:
        if node is not None and node != current and kind == "A":
            current = node
            parity[node] = len(parity) % 2
        if kind == "A":
            if key in live:  # reused virtual offset without a recorded free (should not happen)
                raise ValueError(f"double reservation at {key}")
            placement = None
            if not small and size:
                placement = static.allocate(size, top=bool(parity.get(node, 0)))
                if placement is None and static_fail is None:
                    static_fail = {"node": list(node) if node else None, "bytes": size, "live_large": total_large}
            live[key] = (size, small, node, placement)
            if small:
                total_small += size
            else:
                total_large += size
            if node is not None:
                by_node[node] += size
        elif kind == "F":
            entry = live.pop(key, None)
            if entry is None:
                if key and key[0] == "next":
                    continue
                continue  # release of a pre-trace reservation
            size, small, owner, placement = entry
            if placement:
                static.release(*placement)
            if small:
                total_small -= size
            else:
                total_large -= size
            if owner is not None:
                by_node[owner] -= size
        if current is not None:
            s = node_stats.setdefault(current, {"class": class_of(current, classes), "own_peak": 0,
                                                "envelope_large_peak": 0, "envelope_small_peak": 0,
                                                "envelope_peak": 0, "shared_at_peak": 0})
            s["own_peak"] = max(s["own_peak"], by_node[current])
            s["envelope_large_peak"] = max(s["envelope_large_peak"], total_large)
            s["envelope_small_peak"] = max(s["envelope_small_peak"], total_small)
            if total_large + total_small > s["envelope_peak"]:
                s["envelope_peak"] = total_large + total_small
                s["shared_at_peak"] = total_large + total_small - by_node[current]
                other_recursion = sum(b for n, b in by_node.items() if n != current and n[0] == 1)
                native = sum(b for n, b in by_node.items() if n != current and n[0] != 1)
                s["at_peak"] = {"own": by_node[current], "other_recursion_nodes": other_recursion,
                                "native_packets": native,
                                "untagged": total_large + total_small - by_node[current] - other_recursion - native}
    large_capacity = arena - small_bytes
    for node, s in node_stats.items():
        s["fits_vmm"] = s["envelope_large_peak"] <= large_capacity and s["envelope_small_peak"] <= small_bytes
        s["input_bytes"] = inputs.get(node, 0)
    return node_stats, {"static_fit": static_fail is None, "static_first_failure": static_fail,
                        "static_unusable_high_water": static.span_hw}


def sweep(paths, arena, chunk, small_chunks, classes):
    by_device = defaultdict(list)
    sources = []
    for path in paths:
        rows = read_trace(path)
        sources.append({"path": str(path), "rows": len(rows),
                        "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()})
        for row in rows:
            by_device[row["device"]].append(row)
    small_bytes = small_chunks * chunk
    results = {}
    for policy in POLICIES:
        results[policy] = {}
        for device, rows in sorted(by_device.items()):
            stats, arena_model = replay(rows, policy, arena, small_bytes, chunk, classes)
            results[policy][device] = {"nodes": stats, "arena_model": arena_model}
    # Per-class table: worst node of each class across devices.
    table = {}
    for policy in POLICIES:
        for device, value in results[policy].items():
            for node, s in value["nodes"].items():
                if node[0] != 1:
                    continue
                cls = s["class"]
                row = table.setdefault(cls, {p: None for p in POLICIES})
                prev = row[policy]
                if prev is None or s["envelope_peak"] > prev["envelope_peak"]:
                    row[policy] = dict(s, device=device, node=list(node),
                                       static_fit_device=value["arena_model"]["static_fit"])
    own_max = defaultdict(int)
    for device, value in results["keep"].items():
        for node, st in value["nodes"].items():
            if node[0] == 1:
                own_max[st["class"]] = max(own_max[st["class"]], st["own_peak"])
    generated = {}
    for cls, row in sorted(table.items()):
        chosen = next((p for p in POLICIES if row[p] and row[p]["fits_vmm"] and p != "keep"), None)
        generated[cls] = {
            "policy": chosen or "DOES_NOT_FIT",
            "keep_envelope_peak": row["keep"]["envelope_peak"] if row["keep"] else None,
            "next_input_envelope_peak": row["next_input"]["envelope_peak"] if row["next_input"] else None,
            "shared_offload_envelope_peak": row["shared_offload"]["envelope_peak"] if row["shared_offload"] else None,
            "own_peak": own_max.get(cls),
            "keep_at_peak": row["keep"].get("at_peak") if row["keep"] else None,
            "input_bytes": row["keep"]["input_bytes"] if row["keep"] else None,
        }
    return {
        "schema": SCHEMA_POLICY, "label": "[D] allocator-order replay of a host-joined diagnostic trace",
        "layout": {"arena_bytes": arena, "chunk_bytes": chunk, "small_chunks": small_chunks,
                   "small_slab_bytes": small_bytes, "large_region_bytes": arena - small_bytes},
        "policies": list(POLICIES), "sources": sources, "generated": generated,
        "per_device": {p: {str(d): {"arena_model": v["arena_model"],
                                    "nodes": {"/".join(map(str, n)): s for n, s in v["nodes"].items()}}
                           for d, v in r.items()} for p, r in results.items()},
    }


def markdown(policy):
    g = lambda v: "—" if v is None else f"{v / 1e9:.3f}"
    out = ["# RV64 M8 memory sweep (generated)", "",
           f"[D] replay of production allocation order at arena {policy['layout']['arena_bytes'] / GiB:.1f} GiB "
           f"(chunk {policy['layout']['chunk_bytes'] // MiB} MiB, small slab {policy['layout']['small_slab_bytes'] // MiB} MiB). "
           "Envelope = all arena reservations live while the node runs (node + shared + next-input reservation). "
           "Decimal GB.", "",
           "| Class | Max own peak | keep envelope | at keep peak: own / other recursion / native / untagged | +next input | shared offload | input bytes | generated policy |",
           "|---|---:|---:|---|---:|---:|---:|---|"]
    for cls, row in policy["generated"].items():
        a = row.get("keep_at_peak") or {}
        split = " / ".join(g(a.get(k)) for k in ("own", "other_recursion_nodes", "native_packets", "untagged"))
        out.append(f"| {cls} | {g(row['own_peak'])} | {g(row['keep_envelope_peak'])} | {split} | {g(row['next_input_envelope_peak'])} | "
                   f"{g(row['shared_offload_envelope_peak'])} | {g(row['input_bytes'])} | {row['policy']} |")
    out += ["", "Static (single contiguous allocation, Top/Bottom) model per device:", "",
            "| Policy | Device | Fits | capacity − largest hole, high-water GB | First failure |", "|---|---:|---|---:|---|"]
    for p, devices in policy["per_device"].items():
        for d, v in devices.items():
            m = v["arena_model"]
            out.append(f"| {p} | {d} | {m['static_fit']} | {g(m['static_unusable_high_water'])} | {json.dumps(m['static_first_failure'])} |")
    return "\n".join(out) + "\n"


def check(policy_path, arena, chunk, small_chunks):
    """Service-start validation: the preset layout must equal the swept layout
    and every class must have a fitting generated policy."""
    policy = json.loads(Path(policy_path).read_text())
    if policy.get("schema") != SCHEMA_POLICY:
        raise ValueError("not an rv64-m8 memory policy")
    want = {"arena_bytes": arena, "chunk_bytes": chunk, "small_chunks": small_chunks}
    have = {k: policy["layout"][k] for k in want}
    if have != want:
        raise ValueError(f"preset layout {want} != swept layout {have}; re-run the sweep")
    missing = sorted(c for c, r in policy["generated"].items() if r["policy"] == "DOES_NOT_FIT")
    if missing:
        raise ValueError("classes with no fitting policy at this arena: " + ", ".join(missing))
    return policy


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("replay")
    r.add_argument("traces", nargs="+", type=Path)
    r.add_argument("--out", required=True, type=Path)
    r.add_argument("--arena", default="22G")
    r.add_argument("--chunk", default="32M")
    r.add_argument("--small-chunks", type=int, default=16)
    r.add_argument("--classes", type=Path, help="JSON {ordinal: class} for domain-1 nodes")
    r.add_argument("--tree", type=Path, help="recursion-om31/tree.json: classes leaf / fold<arity> / root")
    c = sub.add_parser("check")
    c.add_argument("--policy", required=True, type=Path)
    c.add_argument("--arena", default="22G")
    c.add_argument("--chunk", default="32M")
    c.add_argument("--small-chunks", type=int, default=16)
    args = p.parse_args(argv)
    if args.command == "replay":
        classes = {int(k): v for k, v in json.loads(args.classes.read_text()).items()} if args.classes else {}
        if args.tree:
            classes.update(tree_classes(json.loads(args.tree.read_text())))
        policy = sweep(args.traces, parse_bytes(args.arena), parse_bytes(args.chunk), args.small_chunks, classes)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "policy.json").write_text(json.dumps(policy, indent=1) + "\n")
        (args.out / "policy.md").write_text(markdown(policy))
        print(json.dumps({"out": str(args.out), "classes": len(policy["generated"]),
                          "does_not_fit": [c for c, r in policy["generated"].items() if r["policy"] == "DOES_NOT_FIT"]}))
        return 0
    try:
        check(args.policy, parse_bytes(args.arena), parse_bytes(args.chunk), args.small_chunks)
    except ValueError as error:
        print("M8_MEM_POLICY_REJECTED " + str(error), file=sys.stderr)
        return 2
    print("M8_MEM_POLICY_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
