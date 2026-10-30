# Optimize the actual Ethereum precompile mix

The retained block's two complete historical execution censuses agree on
139,214,856 cycles, **32,835 Keccak calls, 78 recoveries and zero SHA calls**.
These are host-replay observations, not a verified block proof. They establish
which arithmetic work exists; the synthetic SHA fixtures do not establish the
block's proving-time distribution.

| Historical schedule | Windows | Keccak-bearing windows | Recovery-bearing windows | SHA-bearing windows |
|---|---:|---:|---:|---:|
| Exact memory/commitment schedule | 218 | 120 | 10 | 0 |
| Balanced schedule | 256 | 154 | 11 | 0 |

The schedules partition the same execution differently. Neither is the current
67-window v5 collection or a qualified v7 whole-block plan. The maximum observed
per-window demand is 886 Keccak calls and 47 recoveries in both schedules.

## What the batching model establishes

Grouping consecutive windows is a diagnostic enumeration, not a scheduling
optimizer. Sum each family's calls in each group, count nonempty groups, and
round each group's call count to a power of two. This is linear work per tested
group width and preserves the recorded call census. Actual AIR rows, minimum
domains, shared tables, ownership projections and memory are deliberately not
inferred from that call-slot proxy.

For the 256-window schedule, groups of 16 would reduce repeated Keccak
arithmetic inventories from 154 to 12 (**12.8x fewer inventories**) while the
call-slot padding proxy grows from 42,413 to 47,168 (**11.2%**). A whole-block
group would have only one inventory but 65,536 padded call slots (**54.5% more**).
This supports bounded batches as an experiment; it does not predict a 12.8x
proving speedup or prove a memory-optimal batch size.

Every window still requires its authenticated program/state/register and
frame-aware RAM obligations. The shared arithmetic proof must consume exactly
those calls. SHA batching is a useful ownership prototype, followed by Keccak
integration on real native execution. It is not the workload-level win itself.

## Empty SHA is not a free deletion

The prior active caller layout kept all five SHA AIRs even when the independently
admitted call count was zero. Their padded rows produce nonzero lookup requests.
Consequently omitting only their columns, or merely setting their claimed sums
to zero, breaks the global relation contract.

The active-inventory change must do all of the following together:

1. Derive absence from the validated SHA descriptor/call count, never a
   producer-selected component mask.
2. Omit the five arithmetic components and every SHA-derived shared-table
   projection; keep the Ethereum byte provider and active families.
3. Stop registering padded zero-call SHA requests in active caller collections.
   Full legacy callers retain their original registration.
4. Require every omitted physical SHA claim to equal zero, including attacks
   that compensate two claims while retaining their aggregate.
5. Reflect the changed identity and geometry in transcript, recursive equation
   construction and saved qualification artifacts.
6. Qualify a complete mixed-window proof with a SHA-free caller and the ordinary
   shared provider. An isolated caller proof alone does not test lookup closure.

The initial implementation still constructs the tiny omitted raw/interactions
before filtering them. Removing those allocations is separate from removing
their commitment, opening and recursive-verification costs.

## Reproduce the census

```sh
python3 scripts/analyze_v7_block_call_batches.py \
  autoresearch/notes/2026-09-24-ethereum-block-delivery/exact-schedule-geometry-v1/segments.jsonl \
  autoresearch/notes/2026-09-24-ethereum-block-delivery/work-schedule-qualification-v1/geometry-256.jsonl \
  --output /tmp/block-call-batches.json \
  --windows-tsv /tmp/block-call-windows.tsv
```

The reader rejects incomplete, overlapping or reordered windows and checks the
summary against their exact cycle sum. It excludes summary records from call
totals, pins source SHA-256 values and checks that both schedules agree on the
execution/call totals. Durable outputs are
[`v7-real-block-call-batches-20261029.json`](v7-real-block-call-batches-20261029.json)
and [`v7-real-block-call-windows-20261029.tsv`](v7-real-block-call-windows-20261029.tsv).
