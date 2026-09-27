"""Conservative exact-count proposal from the complete 256-leaf row census.

Additive per-component rows are only a sizing bound. Every resulting segment
still needs actual admission geometry and a canonical proof before use.
"""
from pathlib import Path
import hashlib
import json

H = Path(__file__).resolve().parent
source = H / "work-schedule-qualification-v1/geometry-256.jsonl"
out = H / "exact-schedule-proposal-v1"
out.mkdir(exist_ok=False)
raw = source.read_bytes()
items = [json.loads(line) for line in raw.splitlines() if b'"target"' in line]
assert len(items) == 256 and [x["target"] for x in items] == list(range(256))
assert all(x["commitment_trace_fits"] and len(x["commitment_rows"]) == 8 for x in items)
assert sum(x["cycles"] for x in items) == 139_214_856

row_limit = 1 << 24
cycle_limit = 1 << 22
best = [None] * (len(items) + 1)
best[-1] = (0, 0, ())
for first in range(len(items) - 1, -1, -1):
    rows = [0] * 8
    cycles = 0
    for last in range(first, len(items)):
        item = items[last]
        cycles += item["cycles"]
        rows = [a + b for a, b in zip(rows, item["commitment_rows"])]
        if cycles > cycle_limit or any(value > row_limit for value in rows):
            break
        tail = best[last + 1]
        allocated = sum(1 << (value - 1).bit_length() for value in rows)
        candidate = (1 + tail[0], allocated + tail[1], (cycles,) + tail[2])
        if best[first] is None or candidate[:2] < best[first][:2]:
            best[first] = candidate
assert best[0] is not None
count, allocated, budgets = best[0]
assert sum(budgets) == 139_214_856 and count == len(budgets)
(out / "schedule.json").write_text(json.dumps(budgets, separators=(",", ":")) + "\n")
(out / "proposal.json").write_text(json.dumps({
    "scope": "proposal only; additive 256-leaf row upper bounds, no merged-segment proof or fresh geometry admission",
    "source": str(source.relative_to(H)),
    "source_sha256": hashlib.sha256(raw).hexdigest(),
    "segments": count,
    "cycles": sum(budgets),
    "allocated_component_rows_additive_bound": allocated,
    "maximum_cycles": max(budgets),
    "row_limit": row_limit,
    "cycle_limit": cycle_limit,
}, indent=2) + "\n")
print(f"exact proposal: {count} segments, {max(budgets)} max cycles")
