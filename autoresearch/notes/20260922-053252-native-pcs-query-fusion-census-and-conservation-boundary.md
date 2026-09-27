---
title: Native PCS query fusion census and conservation boundary
author: Teddy Pender
created_utc: 2026-09-22T05:32:52Z
---

# Native PCS query fusion: measured integration boundary

A shared read-only census now accepts the canonical graph/binding view, retaining
the original detached Prepared wrapper and matcher. The actual native BLAKE3
capture has 16,069 DEEP nodes, 621 queried inputs (537 single-use, 84 shared),
574 dot4 groups and 134 groups eligible in the arithmetic graph.

The focused ReleaseSafe build completed 8/8 steps, 6/6 tests: the native census
passed in 10 s / 1 GiB; the five existing PCS fusion tests passed in 708 ms.
Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-arithmetic-census test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
```

## Required native integration

The detached PCS opening AIR consumes recursion_trace_query_value tuples. Native
BLAKE3 does not supply those tuples: its scalar producer emits recursion_wire
with graph uses plus two external uses. blake3_opening_inputs.Builder.trace
connects those two consumers to readonly_input and field-byte encoding.
Consequently the detached AIR cannot be selected unchanged, and arithmetic-only
single use cannot justify dropping all scalar emissions.

For each eligible native query, the original scalar producer emits multiplicity
three and dot4 consumes one. A fused native component must emit the same base-field
wire with multiplicity two, preserving both external authentication consumers.
The scalar value can become one main coordinate inside the fused opening, with
literal zero extension coordinates. Accumulator/weight consumes and output emit
remain identical. Shared queried inputs retain their original producer/rows.
This is a derived signed-multiset equivalence, still requiring executable closure
and mutation tests before roster integration.

The candidate native layout is 29 main + 13 fixed fields, compared with the
existing dot4's 54 logical fields plus four seven-field scalar rows: 40 fewer
logical fields per eligible group, or 21,440 bytes across 134 groups. Four scalar
rows per group could disappear (536 total), while the fused row preserves their
external emissions. These are conditional unpadded layout counts, not implemented
savings, committed size or timing predictions. The detached census's 26-field
input-row cost does not describe native routing.

The next implementation must validate each eliminated scalar producer's exact
circuit/node, value, multiplicity and inactive routing fields; conserve all input
inventory entries; replace only admitted dot4 rows; version the roster/key/codec;
and prove closure plus independent verification. Production parameters and Metal
remain unqualified. No production path or constraint was changed by this census.
