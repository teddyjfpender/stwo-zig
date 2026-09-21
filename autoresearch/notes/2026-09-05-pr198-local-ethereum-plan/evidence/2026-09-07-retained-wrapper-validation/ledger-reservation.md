# Tuple ledger reservation — 2026-09-07

Read-only resource investigation. No production changes or builds. Decision: retain the current reservation; do not add a counting pass without evidence of useful physical-memory savings.

## Observed capacity versus physical use

[stopped-replay.log](stopped-replay.log), lines13–20, records136 bytes per contribution:

| Source | Reserved upper bound | Actual contributions |
| --- | ---: | ---: |
| Prefix | 3,811,136 | 944,216 |
| Suffix | 452,820 | 138,944 |
| Native | 142,942,382 | 67,705,177 |
| Public statement | 450 | 450 |
| Range provider | 65,536 | 85 |
| Total | 147,272,324 | 68,788,872 |

Allocated capacity is20,029,036,064 bytes; initialized records occupy9,355,286,592 bytes. Unused capacity is10,673,749,472 bytes. These are decimal byte counts, not measured resident sizes.

The reservation uses raw allocation and leaves unused pages untouched. The log's lifetime peak physical footprint is unchanged at17,825,133,960 bytes across reservation, which takes381,625ns. After native append the lifetime peak is27,320,914,080 bytes, about9.50GB higher. Lifetime peak is not current RSS, and transient row allocations also occur; nevertheless, this evidence does **not** support treating the full20.03GB capacity or its10.67GB slack as resident memory.

## Exact allocation reason

- `src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_universal_cohort_v4_complete.zig:213` sums prefix/suffix/native upper bounds, the full range table and450 public terms, then allocates before appending at`:233`.
- Prefix `recursive_common_ethereum_incremental_leaf_transcript_cohort_v4.zig:193`, suffix `recursive_common_ethereum_incremental_leaf_suffix_cohort_v4.zig:98`, and native `recursive_common_ethereum_incremental_leaf_native_core_v4.zig:472` bound each retained logical row by **all** authenticated plan events. Native additionally counts provider calls and selected public terms. This is conservative liveness slack, not power-of-two padding or ArrayList growth. Native contributes75,237,205 of the unused slots.
- `src/frontends/riscv/recursion/air/relation_interaction_tuple_audit.zig:13` evaluates actual prepared entries and applies the domain mask. `relation_interaction_tuple_ledger.zig:137` skips zero signed weights, explaining the smaller actual count.
- `src/integrations/riscv_cpu/ethereum_tuple_ledger_reservation_v1.zig:16` attaches exact-capacity `rawAlloc` storage to the empty ledger;`:32` releases it with `rawFree`. This avoids safe-mode allocation/free poisoning of unused pages. The observed final capacity equals the initial bound, so this replay did not grow the ledger.
- `recursive_common_ethereum_incremental_leaf_range_provider_v4.zig:103` derives the signed range counter from the actual ledger; only85 table rows have nonzero contributions. Replacing this derivation with an observed constant would be incorrect.

## Smallest possible tighter reservation and tradeoff

A count-only pass could reuse the **same** `appendSourceTupleContributions` traversal (`universal_cohort_v4_complete.zig:444`), counting after the ledger's zero-weight test but before prefix copying, hashing or storage. Reserve exact source count plus the existing65,536 range bound, then perform normal append and require the source count to agree. For this fixture that would reserve68,854,323 records /9,364,187,928 bytes, leaving only8,901,336 bytes of range slack. Counting mode must never produce a successful empty closure receipt or replace the real append/classification pass.

This avoids duplicated event predicates or hardcoded fixture counts, but costs another evaluation traversal. Native append also reconstructs temporary logical-row arrays (`recursive_fri_outer_part_06.zig:53`, including arithmetic rows at`:244`), so a count pass is not literally allocation-free even though it stores no ledger records. Its runtime cost has not been measured. Exact range sizing would additionally accumulate a bounded65,536-entry signed counter during counting; that is unnecessary complexity for eliminating only the last8.90MB of virtual slack.

Do not switch to normal geometric growth: the older `/tmp/ethereum-shared-claim-complete-proof.log` recorded capacity90,811,043 and a38.64GB lifetime peak at native append, though it is a different source snapshot and not a controlled benchmark. Growth can copy live records and touch spare capacity. Shrinking after append cannot reduce an already-observed peak. Current raw reservation already addresses the demonstrated page-touch problem, so reducing its virtual slack alone does not justify an extra full pass.
