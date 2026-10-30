# Prove the common execution-epoch transcript once

Status: exact compiler census, authenticated continuation and constrained
fan-out groundwork qualified with a genuine joined original-AIR proof. The
current independent child verifiers and mixed-root assembly remain unchanged.
There is no shared-epoch mixed-root qualification or end-to-end speed claim.

## Problem match

The task is common-subexpression elimination in a proof dependency graph.
Every v7 native, joint-memory, ROM and lookup child authenticates the same
epoch digest and derives the same Universal47, Word5 and interval challenges.
The caller derives that same prefix, then its own fourteen relation pairs.
The repeated object is a constrained computation, not a cached witness value.

Inputs are the independently admitted epoch/version, exact ordered original
entry roster, child types and namespace maps, and bounded draw-attempt capacity.
Output must be the same original verifier predicate and public statements.
The cost model is emitted unpadded AIR rows and exact wire traffic; wall time,
power-of-two domains, memory and proof-key changes require later measurements.
The scale below is a requested scenario of 67 execution segments, not a new
measurement of an Ethereum block roster.

| Candidate | Match and guarantee | Cost / risk |
|---|---|---|
| Cache native challenges on the host | Witness-generation reuse only | Does not remove verifier constraints |
| Supply challenges as public constants | Changes verification authority | Rejected: a prover must not choose challenges or resumed channel state |
| Share one constrained prefix inside the same parent | Exact proof-graph common subexpression elimination | Removes duplicate hashing; adds explicit fan-out and namespace accounting |
| Prove one prefix in a separate recursive child | Compositional proof reuse | Extra proof/verification overhead; unnecessary before measuring in-parent reuse |

Selected transfer: retain one exact prefix gadget inside a mixed parent and
route its constrained outputs to every child suffix and composition circuit.
Construction complexity remains linear in child count because every original
proof still needs checking. The prefix-hash portion becomes constant per mixed
parent; broadcasting outputs remains linear. This is derived from the actual
operation grammar, not a claim about an external prover.

## Exact emitted work

Reproduce with:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_epoch_cost_test_root.zig \
  -OReleaseSafe -fstrip
```

The gate passed 87 tests. It invokes the existing fixed operation recorder and
bounded transcript compiler, with epoch version 3. There are 58 operations,
including 54 secure draw operations exporting 106 extension-field values.
The interval uses **two single draws**, preserving the original native channel;
it is not interchangeable with a paired draw.

| Attempt capacity | G rows | XOR rows | Boundary | Challenge | Route | Retry | Counter |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6,496 | 1,856 | 2,415 | 54 | 1,005 | 54 | 54 |
| 2 | 12,544 | 3,584 | 4,521 | 108 | 1,923 | 108 | 108 |
| 4 | 24,640 | 7,040 | 8,733 | 216 | 3,759 | 216 | 216 |

At capacity 2:

| Scenario | Repeated G | One prefix G | Removable G | Removable XOR |
|---|---:|---:|---:|---:|
| 67 native + ROM + lookup + joint memory = 70 children | 878,080 | 12,544 | 865,536 | 247,296 |
| Same plus 67 callers = 137 children | 1,718,528 | 12,544 | 1,705,984 | 487,424 |

At capacity 4 those removable G counts are 1,700,160 and 3,351,040. These
counts exclude new fan-out rows and domain padding. The exact shared prefix
already exports every challenge once; 70 or 137 consumers need 7,420 or 14,522
field deliveries, plus the channel-state dependency. These are routing work,
not additional hashes. This change does not eliminate the original arithmetic,
DEEP, FRI or Merkle verification work and proves no 10× total-time improvement.

## Required authority and integration boundary

1. The mixed admission factory derives one prefix from an independently
   selected epoch and capacity. It must check that every child uses that same
   epoch. A matching untrusted digest alone is not a roster admission check.
2. Preserve all rejection checks, selected-draw constraints, counters and
   canonical field decoding. Capacity exhaustion still fails closed; no
   silently increased retry budget or zeroed challenge limbs.
3. Export the final channel state through authenticated byte-word ports. The
   new opt-in boundary exposes the exact digest source and producer/consumer
   use schedule. Merely constructing a suffix recorder from `final_digest`
   and `next_draw` witness values remains unsound.
4. Define an explicit authenticated continuation operation. Either route the
   full state and counter, or restrict the boundary to a mandatory first
   absorption that demonstrably resets the counter. Current native,
   joint-memory, compact-lookup and caller suffixes begin with an absorption;
   a general-purpose draw-first continuation must not inherit that assumption.
5. Every shared output producer must carry the exact summed consumer
   multiplicity. The bounded draw currently exports a single selected value
   through the retry-control route. Reusing its `DrawOutput` pointer across
   children without a constrained fan-out or adjusted producer accounting is
   not sufficient. The same rule applies to final-state hash output ports.
6. Map caller ports explicitly: common Universal indices 0–46 stay unchanged;
   Word indices 47–51 map to caller 61–65; interval index 52 maps to caller 66.
   Caller indices 47–60 remain its distinct fourteen pairs after its own entry
   absorption. No child-specific claims, roots or composition draws are shared.
7. Cold and live compilers must use the same shared namespace, continuation
   grammar, fan-out schedule and final G-row partition. Bind the new protocol
   and layout to key/context identity. Existing standalone original proofs and
   their native transcript bytes need not change.

The relevant existing implementations are
`recursion/air/block_v7_epoch_transcript_v1.zig`,
`block_v7_native_transcript_v1.zig`,
`block_v7_memory_joint_transcript_v1.zig`,
`block_v7_lookup_compact_transcript_v1.zig`,
`block_v7_caller_joint_transcript_v1.zig`,
`blake3_transcript_witness.zig`, `blake3_bounded_draw.zig` and
`blake3_challenge_links.zig`. Reuse their original grammars and arithmetic
consumers; do not invent another independent challenge schema.

## Qualification and falsifiers

First require exact native channel, challenge and original proof byte parity
for distinct epochs and multiple retry capacities. Then compare independently
compiled fixed rows/ports with live rows, prove a multi-family parent and
verify after producer destruction. Negative gates must alter every challenge
limb, an epoch, the final state, a draw counter/selection, a child map, a
fan-out multiplicity and a continuation operation. Missing/duplicate consumers
and a caller Word/interval remapping error must fail.

Measure the full parent before and after with identical children, security,
capacity and key ownership. If new routing or unchanged padded domains consume
the predicted savings, this is not a useful total-time optimization despite
the unpadded G reduction. Prefix savings are bounded by its share of total
verification work; this mechanism cannot justify a block-proving time forecast
without that denominator.

## Implemented continuation boundary and evidence

The shared transcript witness now provides an opt-in `Boundary`:

```text
resume_before_absorb: optional { source: Caller, value: [32]u8 }
final_state_uses: [8]u32
```

`value` is private witness data. The first resumed operation must absorb; a
draw, query, PoW check, restart or empty suffix is rejected at this boundary.
The existing frame AIR consumes the external source, computes the absorption,
and resets the draw counter exactly as the original channel does. No producer
of the supplied digest is silently created. The prefix's final hash outputs
carry the independently specified use counts. `Prepared.resumed_state` and
`exported_state` return those exact port schedules.

`Plan.initBoundary` / `prepareBoundary` implement the full-row oracle.
`initBoundaryCompact` / `prepareBoundaryMainColumns` use compact fixed metadata
and direct hash/nonhash column emission. Old entrypoints use an empty boundary
and preserve their old identity. The new key extension binds source coordinates
and multiplicities, never a resumed witness digest. The epoch digest was already
routed through `mixPublicRoot`; differing epoch digest values do not by
themselves specialize the prefix fixed rows.

`blake3_transcript_continuation_v1.requireExact` checks that the prefix's eight
producer multiplicities equal the sum of admitted suffix reads, including
coordinate, missing-consumer and overflow rejection. This scheduling helper
does not replace the AIR's wire argument.

`blake3_transcript_fanout_v1.prepare` uses the existing parent scalar-wire AIR
(slot 12). Each row consumes one selected scalar and produces one alias with
the verifier's consumer count. Thus 106 fields require 424 scalar rows once,
plus their existing per-child consumers. Duplicate or overlapping source/role
routes, self aliases, zero/overflow multiplicities and malformed scalar values
are rejected. The original retry-selection AIR is unchanged.

Focused gate:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_epoch_continuation_test_root.zig \
  -OReleaseSafe -fstrip
```

Evidence obtained:

- A genuine prefix → resumed suffix with two constrained challenge consumers
  proves and freshly verifies using the original hash, retry, counter, scalar,
  boundary and lookup-table AIRs; independently wrong fan-out preprocessing is
  rejected. This fixture uses one paired draw per prefix/suffix, not all 53
  epoch pairs and not a production mixed root.
- The complete original channel and split channel have identical final digest
  and draw counter. Full-row, compact and direct-column paths have identical
  fixed keys and every main/fixed row coordinate.
- A changed resumed digest computes a locally valid but different hash suffix.
  Its original cross-component wire multiset fails against the retained correct
  prefix. Missing producers, changed source maps, missing/extra consumers and
  wrong fan-out multiplicities also fail. This is relation-level rejection,
  not a metadata comparison of digest witness bytes.
- Altering a selected challenge fails the original wire relation; altering the
  retry selection fails the original retry AIR's direct constraints; changing
  a counter fails the exact original wire closure.

Remaining integration: build one exact epoch prefix, sum every independently
admitted child read, rebase the child suffix and challenge schedules to the
shared producers, preserve the caller's distinct fourteen pairs, and compile
the same resulting fixed roster cold and live before deriving the final key.
Canonical-security and multi-family mixed-root negative proof gates are still
required. No current receiver treats these open gadgets alone as authority.

### Opt-in complete mixed implementation

The new `block_v7_shared_epoch_mixed_*` modules now compile the same independently
admitted native, caller, ROM, lookup and joint-memory equations with one shared
Epoch prefix. Each original child suffix keeps a separately rebased namespace.
Exact byte-wire bridges connect the prefix's final digest to each suffix; exact
scalar-wire bridges connect all 424 epoch challenge limbs. The caller's fourteen
additional relation pairs remain local to its own transcript. The baseline mixed
route remains available and unchanged.

Cold construction independently recreates the prefix, every suffix, namespace,
bridge and public input schedule. The new protocol uses distinct key, proof and
claim domains. The receiver checks the key, trusted policy and epoch security
configuration before decoding. Newly allocated prefix/join state has an explicit
host budget; row caps include both the prefix and every bridge.

A first complete mixed runtime reached cold setup but rejected an external
challenge as though its export index were a local suffix operation. The fix
introduces explicit external draw records in the live transcript planner. Each
record must exactly match one independently compiled boundary export; missing,
duplicate, reordered or differently routed exports fail. Locally generated draws
retain their secure-operation, role and width checks. These live values are only
witness cross-checks: the shared prefix and original wire relations supply proof
authority. The focused actual-Epoch substitution test passes, including missing
external records, wrong routes and wrong local draw provenance.

The complete shared root is still being requalified. There is no measured
end-to-end speedup claim from the row-count model or from the focused helper tests.

### Complete shared-root qualification

The opt-in complete shared-Epoch root passed all 11 focused tests on 2026-10-29.
The genuine fixture executes two segments, 12 cycles, one SHA call and one Keccak
call, with 77 RAM events and 13 program fetches. Six original proofs are reduced
to one 158,707-byte parent. All original proof/producer state is destroyed before
fresh root verification; the expected key and public schedule come from the
independent cold compiler. Missing caller, changed public output and altered
public claims are rejected. The original global execution/provider closure is
unchanged. The shared route remains opt-in.

Observed diagnostic stages from that qualification run (not a controlled timed
A/B campaign):

| Stage | Seconds |
|---|---:|
| Metadata | 0.2440 |
| Independent fixed compiler | 8.1763 |
| Verifier witness construction | 15.5414 |
| Join and fixed-row parity | 1.6646 |
| Live key and plan | 2.8632 |
| Parent proof | 17.6402 |
| Fresh root verification | 0.5273 |

Joined retained row storage is 1,432,408,076 bytes. Process maximum RSS is
6,428,721,152 bytes; this includes qualification/setup and is not proof-only
memory. The earlier baseline qualification recorded 24.3267 seconds for its
parent proof and 1,783,477,464 retained row bytes. These observations support the
structural reduction but do not replace an idle-host repeated comparison.

The repaired join issue was an independently constructed byte-route bridge's
**disabled** second source: its zero circuit identifier had not undergone the
ordinary child rebasing. The bridge now assigns that inactive coordinate to its
admitted child namespace, keeping its lookup weight and all source-selection
coefficients zero. Cold and live identity agree, and the unchanged strict
namespace checker passes. No namespace validation or relation was removed.

Limits: diagnostic q8/PoW0 only, a tiny genuine execution, no Ethereum block,
no canonical-security qualification, no production default switch. The bounded
separate-memory-cohort route has its own original and complete recursive
qualification, recorded in the memory-cohorts document. The complete shared
proof above uses the joint memory route.


## Production producer integration

`block_v7_complete_cpu_producer_v1.For(true)` selects the shared-prefix
protocol; the existing module-level `produce`, `Options`, and `Output` remain
aliases of `For(false)`. Both use one implementation in
`block_v7_complete_cpu_family_v1`. Typed collection similarly delegates to
`block_v7_mixed_collection_family_v1.For(shared)`, selecting the original
family verifier once and supplying the shared-epoch preparation option to every
native, full/active caller, ROM, lookup, joint memory or separate RAM/provider
child. Compiler capsules and the independent fixed-tree commitment retain the
same reuse/lifetime checks in both modes.

The shared variant requires one complete roster of at most 64 original
children. It rejects partial windows before capture/preparation. The bounded
batch producer continues to use the unchanged baseline aliases; sharing one
prefix within bounded partial batches is a separate integration task.

The production fixture calls `qualify(true)` explicitly from a distinct test
root (it does not infer selection from `@import("root")`), avoiding codegen
for both complete implementations in one binary:

```sh
STWO_V7_ACTIVE_CALLERS=1 STWO_V7_SCALE_MEMORY_COHORTS=1 \
STWO_V7_SCALE_ITERATIONS=4096 STWO_V7_SCALE_RAM_EVENTS_PER_SHARD=4096 \
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_shared_streaming_complete_root_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 shared production'
```

Genuine combined production qualification is now **PASS11**: 20,495 cycles,
8,293 guest RAM events, two native proofs, one active-caller proof, three RAM
cohorts, three memory providers, ROM and lookup. The eleven original proofs
reduce to one 159,810-byte shared-prefix root. Independent cold/live equality,
fixed-commitment reuse, final verification after original-owner destruction,
missing-cohort rejection and compensated-claim rejection all pass. The log
explicitly records `shared_epoch=true`.

The matched geometry gives a much smaller structural gain than the earlier
small-fixture observations suggested: retained verifier rows fall from
1,600,790,316 to 1,586,276,404 bytes, only **0.91%**. Prefix factoring is therefore
not a major overall improvement on this workload. It is useful infrastructure,
but the next optimization must target a larger measured cost.

| Diagnostic observation | Baseline | Shared prefix |
|---|---:|---:|
| Parent proof | 23.725 s | 22.466 s |
| Execution to fresh verified root | 62.981 s | 65.665 s |
| Charged peak | 7,375,674,152 B | 7,355,830,800 B |
| Retained verifier rows | 1,600,790,316 B | 1,586,276,404 B |

These are qualification runs on a busy host, not a controlled timing comparison;
no proving-time speedup is claimed. The adjacent
`shared-epoch-production-20261029.json` preserves stage data and scope. Security
remains diagnostic q8/PoW0. Canonical security, full-block scale and shared-prefix
bounded-batch reduction are not qualified by this run.

The first attempted production selector used `@import("root")` and actually
ran the baseline, as its `shared_epoch=false` log showed. That run is excluded
from shared-prefix qualification; the explicit `qualify(true)` entrypoint above
is the qualified route.
