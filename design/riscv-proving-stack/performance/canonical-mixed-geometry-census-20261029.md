# Canonical mixed-verifier geometry census

This diagnostic sizes the complete 12-child mixed fixture under the canonical
70-query, 26-bit PoW profile **without producing any proof**. It is not a block
proving benchmark or a security-qualification result.

The fixture performs genuine canonical execution collection, source sealing,
independent provider admission and pinned PAGE operand collection. It then
compiles each original verifier's fixed roster separately and releases it before
the next child. Neither q8 admissions nor received proof keys are relabelled.

```sh
STWO_BLOCK_V6_CANONICAL=1 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_complete_root_integration_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'canonical mixed verifier geometry'
```

The implementation is test-only in
`src/frontends/riscv/prover/tests/block_v6_canonical_geometry_census.zig`.
The complete-root and provider-preparation qualification scopes are unchanged.

## Inputs and claims

The original family order is native execution, range16, RAM lanes, ROM, native
lookup, caller arithmetic, caller fused, RAW source pages and FOLD source pages.
The actual source manifest selects each instance and first commitment.

Native and caller scalar claims are explicitly **shape-only proposals**: these
values enter original public-input ports; their validity is not asserted. Their
lengths, row counts, fetch census and framing are admitted. The caller memory
count proposal preserves the independently known total and per-slot bounds.
No result here is exported as an authenticated public claim or success receipt.

PAGE semantic claims are different: their values enter the original semantic
graph as constants. The diagnostic therefore replays the original authenticated
RAW/FOLD operand files, checks their original premix pins, and computes the exact
original claim-proposal equations at the canonical epoch. The wide replay owner
is destroyed before compiling the corresponding recursive verifier. These
proposals still have no proof authority.

## Recorded geometry

`CENSUS_CHILD` records:

1. family and original index;
2. compact fixed-row bytes;
3. padded MAIN-column bytes;
4. padded fixed-column bytes;
5. padded interaction-column bytes;
6. maximum cohort row log;
7. public wire and namespace counts;
8. live and peak charged allocation of that child's cold fixed compiler.

`CENSUS_COHORT` records every original AIR cohort's row count and MAIN/fixed
width. The exact existing G-shard partition rule is respected. Counts include
empty-cohort minimum domains, matching the original fixed-key row-log function.
`CENSUS_ADMISSION` records independent admission-owner live/peak allocation.

These are **not process RSS or complete prover peak memory**. The column counts
exclude separately shared lookup tables, commitment/FFT/FRI scratch, allocator
and thread overhead, capture witnesses and overlapping request lifetimes.
Cold compilation peaks describe setup only.

`CENSUS_BATCH` greedily splits the canonical contiguous roster at 64 children or
a nominal 4 GiB retained MAIN-plus-compact-fixed threshold. It recomputes padding
from summed per-cohort counts rather than summing independently padded child
sizes. This is a planning diagnostic, not an admitted recursive range plan or a
proof of batch feasibility. A singleton exceeding the threshold is explicitly
reported as not fitting; it is never omitted or silently accepted as fitting.
Complete parent-memory planning must add the other phases before selecting a
production batch budget.

`CENSUS_TOTAL` and `CENSUS_SOURCE` compare whole-roster and RAW/FOLD geometry.
Their padded totals are nonlinear; do not subtract them to attribute exact
per-family padding. Sum the compact fixed bytes or use the separate child/cohort
records when comparing original-family shares.

The q8 complete-root qualification remains separate in
`complete-mixed-root-qualification-20261028.json`. A canonical geometry census
does not upgrade that proof's security profile.

## Recorded result

The ReleaseSafe diagnostic passed all 12 tests. The exact row census is in the
adjacent `-children.csv`, `-cohorts.csv`, `-batches.csv` and `.json` files.

| Quantity | Canonical layout |
|---|---:|
| Original children | 12 |
| Compact fixed rows | 5.46 GiB |
| Padded MAIN columns | 17.78 GiB |
| Padded fixed columns | 7.77 GiB |
| Padded interaction columns | 17.54 GiB |
| One copy of all padded trace columns | 43.09 GiB |
| Retained MAIN + compact fixed rows | 23.24 GiB |
| Largest cohort row log | 24 |
| Nominal contiguous batches at 4 GiB retained threshold | 8 |

The 43.09 GiB figure is logical storage for one copy of these columns, **not a
measured peak or a requirement that all copies coexist**. It excludes commitment
extensions and proof scratch. No monolithic canonical proof was attempted.

RAW/FOLD accounts for 53.41% of compact fixed bytes. Eliminating it therefore
cannot alone eliminate the remaining caller, lookup, execution and range16
verifier work. Caller arithmetic and caller fused each require their own batch
at the nominal threshold, as does each source PAGE. Independent admission
metadata stayed small: native/provider peak 852,946 bytes and PAGE peak 486,322
bytes. The expensive part is compiling and proving the verifier matrices.

An initial attempt exposed the caller arithmetic cold graph compiler's nested
512 MiB scratch cap. Only this test diagnostic now grants 4 GiB scratch to caller
compilation, under a 16 GiB per-family cap. Production defaults are unchanged.
The final caller arithmetic cold setup peak was 3,534,547,518 charged bytes.
