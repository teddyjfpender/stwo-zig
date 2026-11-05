#!/usr/bin/env python3
"""Sync lint for the outer (OM31 recursion) node prove (stream enqueue, M6).

M6 contract (/workspace/m3/M6-INTERFACES.md, enqueue EQ1/EQ3): nothing reachable from one outer node prove() may
block the host on the device except at the few Fiat-Shamir readback points. This lint has two arms.

static   python3 scripts/rv64_sync_lint.py check [--update]
         Scans the sources on the outer-node prove path (OUTER_PATH below; the set the runtime tracer attributes
         recursion syncs to) for host-blocking calls: CUDA stream/event/device syncs, blocking cudaMemcpy, the
         context host join (stwo_exec_context_sync / join_all_lanes, owner->sync()), Zig session joins (`.join()`,
         `.sync(...)`) and staged readbacks (`.download(`, `api.download(`). Every site is keyed by
         file::function::pattern and compared against the ratchet allowlist (ALLOWLIST). A NEW site, or MORE sites
         under an existing key, fails. Fewer sites print a ratchet-down hint; `--update` rewrites the allowlist and
         refuses to grow it unless `--allow-grow` (which must be justified in the commit).

runtime  python3 scripts/rv64_sync_lint.py runtime WINDOWS.json [--max-blocking-per-node N] [--max-launches-per-node N]
         Reads tools/rv64-sync-trace/window.py output (measured per-request recursion windows under the LD_PRELOAD
         tracer) and fails when blocking calls or kernel launches per node exceed the budget. Defaults are the M6
         ratchet (RUNTIME_BUDGET); the M6 exit gate is 10 blocking calls and 500 launches per node.
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "vectors/reports/rv64-m6-20261105/enqueue/sync-allowlist.json"
OUTER_PATH = [
    # Zig: outer node prove controller and its device stages (as attributed by tools/rv64-sync-trace)
    "src/integrations/circuit_cpu/om31/device_prove.zig",
    "src/integrations/riscv_cuda/rv64/outer_source.zig",
    "src/integrations/riscv_cuda/rv64/outer_source_main.zig",
    "src/integrations/riscv_cuda/rv64/outer_source_interaction.zig",
    "src/integrations/riscv_cuda/rv64/outer_source_composition.zig",
    "src/integrations/riscv_cuda/rv64/outer_fixed.zig",
    "src/integrations/riscv_cuda/rv64/outer_assignment.zig",
    "src/integrations/riscv_cuda/rv64/assignment_runs.zig",
    "src/integrations/riscv_cuda/rv64/trace_commit.zig",
    "src/integrations/riscv_cuda/rv64/resident_composition.zig",
    "src/integrations/riscv_cuda/rv64/pcs_native.zig",
    "src/integrations/riscv_cuda/rv64/session_context.zig",
    "src/integrations/riscv_cuda/rv64/immutable_setup.zig",
    # CUDA: the native entry points those stages call
    "src/backends/cuda/native/rv64/pcs_native.cu",
    "src/backends/cuda/native/rv64/pcs_pipeline.cuh",
    "src/backends/cuda/native/rv64/deep.cu",
    "src/backends/cuda/native/rv64/fri.cu",
    "src/backends/cuda/native/rv64/channel.cu",
    "src/backends/cuda/native/rv64/events.cu",
    "src/backends/cuda/native/rv64/circuit_interaction.cu",
    "src/backends/cuda/native/rv64/circuit_assignment.cu",
    "src/backends/cuda/native/rv64/global.cu",
    "src/backends/cuda/native/rv64/trace.cu",
    "src/backends/cuda/native/transcript/transcript.cu",
]
# M6 runtime ratchet (measured, 24628607 + 26235156, see vectors/reports/rv64-m6-20261105/enqueue/). Lower it as
# sites are removed; the M6 exit gate is 10 / 500.
RUNTIME_BUDGET = {"blocking_per_node": 180.0, "launches_per_node": 5300.0}
GATE = {"blocking_per_node": 10.0, "launches_per_node": 500.0}

C_PATTERNS = {
    "cudaStreamSynchronize": re.compile(r"\bcu(da)?StreamSynchronize\s*\("),
    "cudaEventSynchronize": re.compile(r"\bcu(da)?EventSynchronize\s*\("),
    "cudaDeviceSynchronize": re.compile(r"\b(cudaDeviceSynchronize|cuCtxSynchronize)\s*\("),
    "cudaMemcpy(blocking)": re.compile(r"\bcudaMemcpy\s*\("),
    "context_host_join": re.compile(r"\bstwo_exec_context_(sync|join_all_lanes)\s*\("),
    "owner_sync": re.compile(r"(->|\.)sync\s*\(\s*\)|^\s*sync\s*\(\s*\)\s*;|[;{]\s*sync\s*\(\s*\)\s*;"),
}
ZIG_PATTERNS = {
    "session_join": re.compile(r"\.join\s*\(\s*\)"),
    "host_sync": re.compile(r"\.sync\s*\(\s*(raw|native_context|ctx|self\.native_context|o\.ctx)?[^)]*\)"),
    "staged_readback": re.compile(r"\.download\s*\("),
}
ZIG_FN = re.compile(r"^\s*(?:pub\s+)?(?:inline\s+)?fn\s+(\w+)")
C_FN = re.compile(r"^(?:extern \"C\"\s+)?[A-Za-z_][\w:<>,\s\*&]*?\b([A-Za-z_]\w*)\s*\([^;]*$")
C_COMMENT = re.compile(r"//.*$")


def strip_zig_comment(line):
    i = line.find("//")
    return line if i < 0 else line[:i]


def scan_text(path, text):
    """Yield (function, pattern, line_number, source_line) for every host-blocking site."""
    zig = path.endswith(".zig")
    patterns = ZIG_PATTERNS if zig else C_PATTERNS
    function = "<file>"
    in_test = False
    for number, raw in enumerate(text.splitlines(), 1):
        if zig:
            if re.match(r"^test\s+\"", raw):
                in_test = True
                function = "<test>"
                continue
            if re.match(r"^\S", raw) and not raw.startswith("}"):
                in_test = False
            m = ZIG_FN.match(raw)
            # Methods sit at indent <= 4; deeper fns are helpers nested in a function body.
            if m and not in_test and len(raw) - len(raw.lstrip(" ")) <= 4:
                function = m.group(1)
            line = strip_zig_comment(raw)
            if in_test:
                continue
        else:
            m = C_FN.match(raw)
            if m and not raw.startswith(("#", " ", "\t", "}")):
                function = m.group(1)
            line = C_COMMENT.sub("", raw)
            if "Synchronize" in line and ("define" in line or line.strip().startswith("*")):
                continue
        for name, pattern in patterns.items():
            for _ in pattern.finditer(line):
                yield function, name, number, raw.strip()


def scan(root=ROOT, files=OUTER_PATH):
    sites = {}
    detail = []
    missing = []
    for rel in files:
        path = root / rel
        if not path.is_file():
            missing.append(rel)
            continue
        for function, name, number, source in scan_text(rel, path.read_text(errors="replace")):
            key = f"{rel}::{function}::{name}"
            sites[key] = sites.get(key, 0) + 1
            detail.append({"key": key, "line": number, "source": source[:160]})
    return sites, detail, missing


def check(args):
    sites, detail, missing = scan()
    total = sum(sites.values())
    if args.update:
        old = json.loads(ALLOWLIST.read_text())["sites"] if ALLOWLIST.is_file() else {}
        grew = {k: v for k, v in sites.items() if v > old.get(k, 0)}
        if old and grew and not args.allow_grow:
            print("refusing to grow the allowlist without --allow-grow:", file=sys.stderr)
            for k, v in grew.items():
                print(f"  {k}: {old.get(k, 0)} -> {v}", file=sys.stderr)
            return 1
        ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
        ALLOWLIST.write_text(json.dumps({"schema": "rv64-sync-allowlist/v1", "total": total, "files": OUTER_PATH, "sites": dict(sorted(sites.items()))}, indent=1) + "\n")
        print(f"allowlist written: {total} sites in {len(sites)} keys -> {ALLOWLIST.relative_to(ROOT)}")
        return 0
    allowed = json.loads(ALLOWLIST.read_text())["sites"]
    failures = []
    for key, count in sorted(sites.items()):
        if count > allowed.get(key, 0):
            lines = [d for d in detail if d["key"] == key]
            failures.append((key, allowed.get(key, 0), count, lines))
    shrunk = {k: (v, sites.get(k, 0)) for k, v in allowed.items() if sites.get(k, 0) < v}
    for rel in missing:
        print(f"note: {rel} not present in this checkout (sparse?)", file=sys.stderr)
    if failures:
        print("SYNC LINT FAILED: new host-blocking call(s) on the outer-node prove path", file=sys.stderr)
        for key, was, now, lines in failures:
            print(f"  {key}: allowed {was}, found {now}", file=sys.stderr)
            for d in lines:
                print(f"      line {d['line']}: {d['source']}", file=sys.stderr)
        print("Enqueue instead (events / lane ordering / deferred readback), or justify and run --update --allow-grow.", file=sys.stderr)
        return 1
    if shrunk:
        print(f"ratchet: {sum(a - b for a, b in shrunk.values())} site(s) removed; run `--update` to lock it in:")
        for k, (a, b) in sorted(shrunk.items()):
            print(f"  {k}: {a} -> {b}")
    print(f"sync lint OK: {total} allowlisted host-blocking sites on the outer-node prove path")
    return 0


def runtime(args):
    data = json.loads(Path(args.windows).read_text())
    bad = []
    for row in data["requests"]:
        rec = row["recursion"]
        for metric, limit in (("blocking_per_node", args.max_blocking_per_node), ("launches_per_node", args.max_launches_per_node)):
            value = rec[metric]
            gate = GATE[metric]
            state = "FAIL" if value > limit else "ok"
            print(f"{row['block']} {metric}={value} budget={limit} (M6 gate {gate}) {state}")
            if value > limit:
                bad.append((row["block"], metric, value, limit))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check")
    c.add_argument("--update", action="store_true")
    c.add_argument("--allow-grow", action="store_true")
    r = sub.add_parser("runtime")
    r.add_argument("windows")
    r.add_argument("--max-blocking-per-node", type=float, default=RUNTIME_BUDGET["blocking_per_node"])
    r.add_argument("--max-launches-per-node", type=float, default=RUNTIME_BUDGET["launches_per_node"])
    args = ap.parse_args()
    return check(args) if args.command == "check" else runtime(args)


if __name__ == "__main__":
    sys.exit(main())
