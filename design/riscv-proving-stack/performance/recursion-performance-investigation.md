# Recursion performance investigation — 2026-09-21

Typed recursion is qualified for the retained development profile. The next
performance target is host preparation and witness traffic, followed by reducing
the recursive verification circuit. GPU composition is already implemented.

## Evidence and scope

This investigation reads PR #198's merged implementation (merge
`414644125a19d887d7ed6989efc90c730c4cb076`) and the retained
[parent baseline](../../../vectors/reports/recursive-product-20260921/speed-research-parent-baseline-v1/README.md).
No new benchmark or optimization is claimed. The baseline has three alternating
fresh-process samples per backend, independently verified after producer exit,
with identical qualified key, claim and proof hashes. The unit is the final
two-child parent of the qualified eight-segment, 16-address tree.

| Instrumented median | CPU seconds | Metal seconds |
| --- | ---: | ---: |
| Complete parent process | 9.754 | 6.782 |
| Child PCS preparation | 2.311 | 2.328 |
| Source tuple projection | 1.283 | 1.284 |
| Typed interaction generation | 1.201 | 0.425 |

PCS preparation includes authority construction (1.028 s Metal) and row
construction (0.841 s); these are nested, not additional costs. Preparation and
tuple projection together take 3.612 s, approximately 53% of Metal elapsed time.
Composition evaluation is approximately 0.100 s, outer-proof FRI quotient
construction/commitment 0.079 s, and PoW 0.004 s. These outer-prover stages must
not be confused with expressing child verification in the recursive AIR.

The profile is development `recursive_q193_v1`: 193 queries, 16 PoW bits,
log blowup 1, fold step 4. It is not the CSP leaf's 70-query/26-bit profile or
a production-security qualification. The retained scaling ladder has only
35/98/227/482 instructions at 1/2/4/8 segments and 16 memory addresses.
Its eight-segment production time is 153.198 s CPU / 115.526 s Metal (single
observations), not the cost of one parent. The tree gate serializes parents
within each level. Large-program scaling and parallel throughput remain to be
measured with representative segment sizes and memory.

## Concrete host bottlenecks

1. [PCS preparation](../../../src/frontends/riscv/recursion/detached_pcs_preparation_v1.zig)
   builds a multi-lane authority from each individual child, allocates padded
   temporary columns, then extracts selected-lane rows. Some owners already
   generate only the selected lane; others generate the full template.
   The [authority constructor](../../../src/frontends/riscv/recursion/binary_fri_outer_source_fri_rows_authority.zig)
   rebuilds preprocessing, definitions, bindings and inactive evaluations.
   Selected-lane construction and reuse of authenticated immutable geometry are
   concrete candidates. The profile does not isolate every constructor's cost.
2. [Main finalization](../../../src/frontends/riscv/recursion/detached_parent_prepared_v1.zig)
   projects tuples into a compact ledger before constructing range multiplicities
   and closing provider tuples. Reduce materialization and repeated passes while
   retaining exact closure and canonical order. This is a checked proving boundary.
3. Typed device interactions still bridge host columns to device output and back.
   Metal sample 0 takes 417 ms for typed interactions versus roughly 10 ms summed
   reported kernel execution. Separately measure allocation, staging and waits
   before choosing a residency change.

Child preparation is sequential. Parallelization requires separate owned arenas,
bounded memory and independent admission; sharing the existing arena across
threads is not valid. Tree concurrency also needs memory/GPU contention measurements.

Halving preparation plus tuple projection alone would ideally reduce 6.78 s to
about 4.98 s (1.36x). Eliminating them entirely gives about 3.17 s (2.14x).
These are arithmetic bounds holding other work fixed, not predicted results.

## Precompile opportunities

The recursive verifier already uses specialized typed AIR rather than executing
an entire software verifier in ordinary RISC-V instructions. Compact Poseidon,
QM31 multiply-add, inverse and four-term opening accumulation already exist,
as do GPU composition and 29 typed device interaction components. A verification
opcode would still have to prove its work. Guest ECDSA/SHA/Keccak acceleration
can reduce leaf work but does not directly eliminate parent PCS verification.

The strongest new component candidate is a larger fused PCS/DEEP opening and
FRI verification operation, reducing intermediate arithmetic wires, input rows
and lookup traffic. Existing logical row bytes in Metal sample 0:

| Existing component | Rows | Logical bytes |
| --- | ---: | ---: |
| PCS DEEP input | 782,056 | 81,333,824 |
| QM31 multiply-add | 678,113 | 73,236,204 |
| Four-term opening accumulation | 231,932 | 50,097,312 |
| Linear operations | 217,792 | 44,429,568 |

These account for 73.5% of the recorded 339,039,024 logical row bytes. This is
a footprint signal, not per-component runtime, peak RSS or padded committed
trace size. Fusion is a research candidate with no measured speedup yet. It must
preserve transcript challenges, query/column order, denominators, roots and final
FRI equality. Circuit changes require new authenticated identities, keys and
matching backend artifacts.

Batched Poseidon or shared Merkle-path verification is another candidate; first
count duplicate paths and provider hash work. Existing Poseidon acceleration
means adding a hash precompile is not a missing foundational step. The small
Poseidon interaction time is not total hashing time across the pipeline.

## Focused implementation order

1. Remove selected-lane preparation duplication; measure authority, allocation,
   row generation and extraction separately. Preserve proof bytes.
2. Reduce tuple projection passes and host/device staging on the same pinned parent.
3. Prototype one fused PCS/DEEP component; compare padded columns, provider events,
   full process time and memory, not just arithmetic throughput.
4. Promote improvements through complete products and the scaling ladder; add
   representative large programs and separately measure bounded tree concurrency.

For host-only candidates, build only the affected producer, alternate baseline
and candidate runs, independently verify artifacts and check byte identity.
Run focused admission/rejection and lifetime checks. Broaden to complete-product
qualification on promotion. Circuit changes also require focused AIR soundness
and parity checks plus regenerated admitted artifacts. Keep proof parameters fixed.

## Implemented follow-up

The [first research batch](../../../autoresearch/notes/2026-09-21-recursion-preparation/README.md)
implements selected-lane PCS/FRI input emission, exact packed tuple keys, blocked
column materialization and structural hash helper inlining. Its confirmed Metal
parent result is 7.062 to 5.572 seconds (1.266x), with identical independently
verified artifacts. The tenfold total-time aspiration remains unmet; see the
[remaining experiments](../../../autoresearch/notes/2026-09-21-recursion-preparation/NEXT.md).

The subsequent [upstream architecture comparison](../recursion/recursion-architecture-comparison.md)
inspects StarkWare, ZisK/Proofman and zkDTVM, and records a concurrent-sibling
diagnostic with fresh independent verification. It distinguishes current native
verifier AIR costs from the qualification runner's explicit serialization.
