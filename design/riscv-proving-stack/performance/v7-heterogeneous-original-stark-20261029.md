# Batch execution components before recursive verification

Status: architecture investigation and isolated original-proof prototype,
2026-10-29. No existing proof protocol or acceptance path changed. The larger
measurement is a 20,495-cycle RV32 SHA/Keccak fixture, not an Ethereum block, at
diagnostic q8/PoW0 security on a shared CPU host. The separate small prototype
qualification below is not a complete execution or recursive proof.

The core already supports one STARK over heterogeneous components. The most
promising larger change is to use that facility before creating many original
proofs. Merely concatenating their verifier circuits retains most column-wise
work. A further change—batching repeated operations as rows of one component
family—can reduce that work as well.

## Problem match, before implementation

**Task and semantics.** Prove the conjunction of independently selected native,
caller, RAM, initialization, terminal, ROM and lookup AIRs, plus their complete
typed global relation closure. Preserve the independent ELF/initial-register
policy, exact execution windows, first-halt rule and public 43-byte output.
Changing proof packaging must not replace original proof verification with an
authenticated-looking producer receipt.

**Inputs and model.** Heterogeneous polynomial columns with known degree bounds,
original component evaluators, a canonical source roster and first-round
commitments. Costs are field operations, committed cells, Merkle work, recursive
opening work, peak live bytes and sequential/random storage traffic. Current
evidence is recorded in
[`block-v7-heterogeneous-design-20261029`](../../../vectors/reports/block-v7-heterogeneous-design-20261029/receipt.json).

**Canonical match.** Random-linear-combination batching of polynomial identities
and polynomial openings, followed by one FRI argument. This is an exact
algebraic reduction with a new Fiat–Shamir transcript, not a way to concatenate
already produced proof bytes. Resource-bounded batching is a separate scheduling
problem; contiguous batch selection can use dynamic programming over independently
admitted batch sizes once an actual cost model is available.

| Candidate | Relationship / guarantee | Fit and implementation | Main risk |
|---|---|---|---|
| Native + active caller in one original STARK per segment | Exact conjunction of existing equations; shared composition/PCS | Bounded first experiment; reuse existing component handles and retained trees | Small roster savings; most caller openings remain |
| All original components in one STARK | Same conjunction and global closure, with one proof shell | Core supports arbitrary trees and heterogeneous components | Current scheme retains all input trees; no bounded external-memory lifetime yet |
| Batch repeated component instances as rows | New AIR layout, not equivalent by renaming columns | Removes repeated column inventories and padding; strongest scaling hypothesis | Must constrain segment boundaries, local clocks, per-call identities and census |
| More recursive fan-in | Existing proof conjunction | Already available | Does not remove any child verifier's column work |

**Prior implementation / source.** Local `engine.prove`, `ComponentProvers` and
`CommitmentSchemeProver` are the reusable implementation; no third-party code is
copied. Upstream Stwo's [prover](https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/mod.rs)
accepts multiple components, builds one composition and calls one PCS opening
proof. Its [PCS](https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/pcs/mod.rs)
also accepts owned or borrowed committed trees. These primary sources establish
the batching mechanism, not a speedup for our workload.

**Selected transfer.** First qualify a bounded native/caller union using original
equations and immutable private roots. Then measure a complete fixture in one
original STARK. Only pursue row batching or out-of-core proving after separating
their gains from the proof-shell savings. Do not build a second verifier stack.

**Falsifier.** If union metadata still has nearly the same opened column count,
same recursive arithmetic bucket and similar G-row count, shell fusion alone
cannot deliver the desired order-of-magnitude improvement. Reject a whole-block
resident implementation if it breaks the explicit memory budget.

## What the current measurement actually says

The saved source log digest and exact summary are in `receipt.json`; the
per-family extraction is in `verifier-census.tsv`. These are a re-analysis of an
existing run, not fresh benchmarks. This is the active-caller + three RAM-cohort
variant; the earlier six-proof full-caller run is a different architecture.

| Measured quantity | Value |
|---|---:|
| Execution → freshly verified recursive root | 62.981 s |
| Original producer, excluding recursive consumer | 7.841 s |
| Recursive consumer | 53.878 s |
| Recursive cold-key preparation | 9.973 s |
| Recursive capture/witness/join | 17.689 s |
| Recursive parent proving | 23.725 s |
| Final recursive verification | 0.769 s |
| Original proofs | 11 |
| Retained recursive rows | 1,600,790,316 bytes |
| Charged peak | 7,375,674,152 bytes |
| Durable checkpoint bytes | 68,968,544 |

The eleven verifier instances contain 650,166 arithmetic rows, 2,622,592 BLAKE3 G
rows, 749,312 XOR rows and 1,312 planned path openings. The active caller alone
accounts for 518,226 arithmetic rows (79.7%) and 1,264,928 G rows (48.2%). These
are exact recorded preparation counters, not an attribution of wall time.

There are 125,878 arithmetic rows above the 2^19 threshold. Retaining the current
caller verifier leaves only 6,062 rows for everything else if the target is one
2^19 arithmetic table. This is why “eleven proofs become one” is not a reliable
eleven-fold performance prediction.

Even optimistically deleting the entire recursive consumer and final recursive
verification leaves 8.334 s in the measured end-to-end accounting: at most 7.56×
for that subtraction alone. A 10× target is 6.298 s and requires original-path
improvement too. This is an accounting bound, not a forecast for a direct proof;
constructing and verifying the replacement can add work.

Parent composition alone was 9.768 s. Parent FRI build/commit was 1.788 s and
trace decommitment 0.894 s. Optimizing only the final FRI loop cannot remove the
23.725 s parent proving stage, much less its 53.878 s preparation-plus-proof cost.

## Concrete compatibility and implementation boundaries

* `src/prover/engine.zig:178` accepts a component slice and an owned PCS scheme.
  `src/prover/prove.zig:435` constructs one composition for that slice.
* `src/prover/pcs/scheme.zig:746` / `tree_builders.zig:83`
  `appendCommittedTree` adopts or retains an existing tree and mixes its root.
  It does not recompute the wide witness commitment.
* Core preprocessing is special: `src/core/air/components.zig:222` and `:321`
  address one fixed tree at index zero. Simply appending several independent
  fixed trees is not a correct union. Build a canonical fixed-column union at
  tree zero, independently reconstruct its root, and remap fixed indices.
* `block_v7_memory_joint_component_v1.ForPlacement` demonstrates checked column
  placement for three-tree components. `block_v6_caller_joint_components_v1`
  demonstrates exact mask unions over five trace trees, including Keccak's
  nontrivial mask positions. Neither is a generic arbitrary-tree union as-is.
* `withCompositionGeometryOverrideV1` may be needed to lift smaller split
  geometries. Preserve each original quotient denominator and mask shift;
  changing only the split label is unsound. Check domain and OODS evaluations
  against the original components under the new global maximum domain.
* Recursive PCS ports currently admit exactly 4/5/6/10 commitments
  (`recursion/air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig:95`). A new
  nine-tree profile is not admitted by changing a count on an old key. It needs
  a new finite profile and exact independently compiled opening geometry.

For one native with ordinary accesses and one active caller, preserving private
and interaction trees gives: one merged fixed tree, two native private trees,
two caller private trees, one native interaction tree, two caller interaction
trees and one composition tree: **nine commitments instead of eleven**. It
removes one composition and one FRI invocation. It does **not** remove the six
private/interaction trees or their column openings. Combining interactions
before their first commitment can reduce root count further, but changes those
roots and lifted-leaf geometry; measure it separately.

## New protocol schedule required for the union

1. Independently derive the exact source roster, union geometry, fixed columns,
   scope, profile, public statement and an exhaustive source→batch cover. Reject
   missing, repeated or foreign sources. A union proof covers multiple existing
   source frames; it is not accepted once per source with an unchecked map.
2. Collect each native/caller/private/provider first-round root once. Bind every
   root and source identity before the shared 53 challenge pairs. The existing
   `block_v7_execution_epoch_v1.Epoch` defines this ordering. Bind the new union
   plan/domain before these challenges as well; do not reuse old receipts.
3. Derive each caller's additional 14 pairs from the epoch prefix and its own
   framed entry (`block_v7_caller_active_source_v1.draw`). Deriving one caller's
   challenge from preceding claims would change relation semantics. Reuse the
   exact original relation challenges in each original component.
4. Generate native/caller/provider interaction columns. On a separately tagged
   union proof channel, absorb **every physical claim**, including all nineteen
   active-caller physical frames and the constrained omitted zeros, in canonical
   source order. `recordAfterChallenges` bodies can supply the original framing;
   no aggregate-only substitute is permitted.
5. Commit every interaction tree, then draw the composition coefficient/OODS
   point and produce one DEEP/FRI proof. Retain every original equation, public
   endpoint and independently fixed root requirement.
6. Fresh verification reconstructs union geometry and fixed columns, verifies
   the original STARK, and only then extracts typed source claims. Reuse the
   existing per-window/global closure algebra to enforce initial PC/SP/GP/all
   registers, state/register residuals, ROM fetches, lookup demands, RAM
   transitions/links, initialization, range counts, first halt and terminal I/O.

A complete direct-STARK receiver can return one independently verified block
statement without proving the verifier circuit. That is a different publication
format and does not substitute for a recursive root required by an existing
consumer. If recursive compatibility remains mandatory, wrap the single combined
original proof once and measure the still-present opening workload.

## Memory and I/O: do not trade one bottleneck for another

The bounded native/caller prototype loads at most one matching pair of existing
checkpoints. `block_v7_native_checkpoint_v1.load` and
`block_v7_caller_active_checkpoint_v1.load` already restore immutable trees;
caller coefficients are retained explicitly. The additional resident cost is
the sum of the pair, merged fixed columns and the common composition/FRI scratch.
Measure that peak; maximum-of-individual-peaks is an invalid estimate.

Whole-block adoption into the current scheme keeps every source tree alive:
`scheme_views.polynomials` borrows all columns, composition receives one trace,
and `LazyQuotientProvider` retains input-column views. Its chunked output bounds
quotient scratch, **not source-tree residency**. `tiled_commit.zig` reduces
commitment scratch through retained coefficients but is not a file-backed
whole-proof engine. Existing checkpoint loads fully materialize their trees.

A genuinely bounded whole-block proof needs three explicit passes after first
roots: (a) restore one component cohort and accumulate composition with exact
global coefficient offsets; (b) after composition/OODS, evaluate columns and
accumulate the globally weighted DEEP quotient into per-domain accumulators;
(c) after FRI query selection, reopen only queried leaves/paths. Store both
coefficients and necessary Merkle state, enforce per-file and aggregate limits,
and authenticate final openings in the actual proof. Count all bytes read and
written. A row-major quotient loop that rereads every checkpoint per tile can
be much worse than retaining the data; transposition/pass order is part of the
design, not an implementation detail to hide.

The follow-up [bounded input-tree design](v7-bounded-input-trees-20261029.md)
details that storage path. In particular, row batching seven log22 RAM cohorts
into log25 increases padding by 14.3%; the existing 228-column, four-times-domain
quotient materialization would itself require 114 GiB. Reducing the number of
opened column sets without changing that materialization is not a feasible
small-memory implementation.

For repeated component families, row stacking is the stronger next experiment:
commit one column inventory at a larger row domain instead of many inventories
at smaller domains. It preserves total arithmetic roughly in proportion to
actual rows while reducing repeated OODS columns and fixed padding. But local
clock reset, segment ordinal, boundary activation and per-call table identity
must be constrained against a canonical schedule. It requires new AIRs/identities;
it cannot reinterpret the existing per-segment polynomials.

## Qualification sequence and decision

1. New isolated union placement adapter: original-vs-union random OODS and domain
   parity, exact masks/degree bounds, collision/offset negatives, checked ownership.
2. Genuine native+SHA, native+Keccak, native+recovery and boundary-only native
   union proofs. Prove both originals as the oracle; compare typed exports, not
   proof bytes (the new transcript intentionally changes bytes). Reject an
   omitted component, compensated physical claims, altered native/caller binding,
   wrong fixed root, wrong halt/output and mixed source epochs.
3. Independently compile the union recursive profile and compare cold/live fixed
   rows. Measure original cells, recursive G/arithmetic rows, path openings,
   proof size, retained bytes and root proof time on the same ELF.
4. Only then attempt a complete direct original proof and bounded multi-cohort
   storage. Retain the current separately proven path as a differential oracle.

There is no low-risk production switch to flip: the new channel, fixed-tree union
and exact source cover are soundness boundaries. The existing eleven-proof
execution and recursively closed root remain unchanged.

## Isolated native/caller prototype result

New `block_v7_native_caller_union_{components,proof}_v1.zig` modules now implement
the finite nine-tree union. A genuine executed native store plus SHA and Keccak
fixture passed 11 ReleaseSafe tests, including allocator leak checking. Evidence:
[`receipt.json`](../../../vectors/reports/block-v7-native-caller-union-20261029/receipt.json)
and [`results.tsv`](../../../vectors/reports/block-v7-native-caller-union-20261029/results.tsv).

The original private commitments remain byte-identical. The merged fixed tree is
independently rebuilt. Both original proofs are generated under the same epoch
as a differential oracle; the union's freshly verified native/caller OPEN exports
match exactly after the wide producers are destroyed and the STARK is serialized
and decoded. Mutations of physical claims (including compensating SHA claims),
fixed/private/interaction roots and ordering, an opening value, caller provenance
and epoch all reject. No complete-block receipt or nine-tree recursive adapter
is introduced.

| Quantity | Separate originals | Union |
|---|---:|---:|
| Original STARKs / FRI invocations | 2 | 1 |
| Commitment roots | 11 | 9 |
| OODS values | 33,169 | 33,153 |
| Queried field values for this proof | 127,652 | 129,216 |
| Diagnostic original proving | 2.487 s | 1.471 s |
| Union fresh verification | — | 0.993 s |
| Union STARK bytes | — | 1,169,498 |

The timings come from one shared-host run, union first then the separate oracle;
they are not a controlled speedup result. The exact opening census is more
instructive: only sixteen OODS values disappear, and the new query/domain
combination increases queried values. Native/caller fusion demonstrably removes
one proof shell, but does not make the caller's wide verifier disappear.

Implementation qualification caught two issues before this result: use the full
independently derived fixed-column inventory rather than inferring it from only
opened fixed indices; and direct schedule helper allocations to the proof-lifetime
arena instead of leaking through the source schedule's stored allocator. Both
are fixed in the final passing gate.

## Finite complete direct-STARK experiment

The next isolated route is `block_v7_complete_union_{scope,proof}_v1.zig`.
The finite contract admits exactly one complete native window, one active caller,
one ROM provider, one compact lookup provider and one joint RAM provider. A
nonempty native access family is required. It does not accept a partial window as
an Ethereum block or silently reinterpret an old recursive proof.

| Family | Original local trees relocated into union |
|---|---|
| Native and ordinary access | 0, 1, 2, 8 |
| Active caller and external access | 0, 3, 4, 9, 10 |
| Independently decoded ROM | 0, 5, 11 |
| Compact native lookup | 0, 6, 12 |
| Joint RAM, initialization, range16 and terminal | 0, 7, 13 |

Tree 0 is the canonical concatenation of the five fixed-column inventories.
Tree 14 is the single composition commitment. The original ROM's empty private
tree remains explicit at index 5. All seven private roots are checked against the
original epoch. Every original fixed root and the merged root are independently
reconstructed. The new `B7UF` transcript binds the finite mapping, configuration,
epoch, merged fixed root and every original physical claim before any interaction
root. It preserves the shared 53 relation draws and the caller's original suffix.

Admission reconstructs the complete initialized ELF and initial PC/SP/GP/register
state, the final halt and 43-byte terminal ABI, the exact one-window boundary,
caller provenance, decoded ROM leaves and all six lookup demand bounds. After one
fresh STARK verification, the shared pure execution-claim accumulator closes the
original per-window state/register relations, ROM fetches, RAM transitions, lookup
relations and natural event/fetch censuses. The joint memory's original link,
first-touch, range and terminal claims also close. The accumulator is algebra,
not a proof or receipt; both the old five-proof receiver and the new verifier call
it only after their respective proof checks.

The expected shell count is 23 commitment roots/five FRIs to 15 roots/one FRI.
The architectural objective is to eliminate recursive verification entirely for
this bounded complete batch. Column, quotient, OODS and query work remain real;
no proportional speedup is implied by the shell count. The finite resident design
holds all five first rounds and is not yet the bounded-memory whole-block design.
The out-of-core/row-batched architecture remains separate work.

Qualification uses the same scaling guest ELF generator as the recorded
20,495-cycle recursive campaign. The default 20-cycle fixture executes two SHA
calls, one Keccak call, native RAM work and the complete terminal suffix. It
constructs both the direct proof and the original five-proof oracle under the
same epoch, destroys all wide stage/witness owners, serializes and decodes the
direct proof, and freshly verifies it against the independently selected ELF and
output. Physical-claim cancellation, roots/order, missing provider, memory
geometry and public output mutations are negative cases. Runtime qualification now passed both diagnostic and canonical profiles.
The20,495-cycle contiguous direct path measured5.094s diagnostic and6.018s canonical,
with less than368MB charged peak, after all producer owners were destroyed.
See [`complete-union evidence`](../../../vectors/reports/block-v7-complete-union-20261029/README.md)
for exact phases, original-proof differential checks, durable artifacts and the
output-contract boundary below. These are single-sample measurements, not a
same-contract compact-root speedup claim.

### Output-contract boundary

The direct result is an independently closed **original heterogeneous STARK**,
not the compact recursively aggregatable root used by the previous pipeline.
The diagnostic proof is about 1.26 MB; the canonical 70-query/26-bit-PoW proof is
about 5.84 MB. The previous 20,495-cycle recursive result was 158,878 bytes.
There is no qualified 15-tree recursive adapter or final publication wrapper for
this new proof yet. Removing that wrapper is a valid latency tradeoff for a
finite independently verified execution, but it does **not** demonstrate a 10×
improvement at the same compact-root/aggregation contract.

The opening census makes the remaining issue concrete: the 20,495-cycle union
has 34,534 OODS values, compared with 34,598 across the five separate originals.
A later recursive wrapper still has essentially all of that column verification
work. Reducing the original proof count alone is insufficient. The next scalable
work is independently admitted multiwindow placement, bounded checkpoint-backed
PCS ownership, and row batching or another proven reduction in column/opening
work. Either the whole complete original proof must fit the declared memory
budget, or its bounded groups need a separately qualified recursive adapter and
complete global closure. Neither condition is claimed by the one-window gate.

## Bounded multiwindow extension (not yet proof-qualified)

The next explicit protocol is `B7UM` in `block_v7_multi_union_proof_v1.zig`.
It takes the independently derived scope and placement in
`block_v7_multi_union_scope_v1.zig`. That scope admits complete contiguous native
windows, ordered active callers coupled to their exact native identities, and
one ROM, compact lookup and joint memory provider. It reconstructs the ELF,
initial registers, window boundaries, complete ROM leaves, lookup demand and
joint memory geometry. Missing sources or fully resealed clock/register gaps
reject. Metadata-only three-window qualification passed; the original multiwindow
STARK and fresh complete closure still require the new genuine proof fixture.

The map is derived, never supplied as arbitrary proof authority. All private
first trees precede all interaction trees; fixed columns are concatenated in
source order. Native sources with no ordinary access have three local trees,
not a dummy access tree. An all-precompile native window retains the original
constrained physical frame and zero interaction pad. Each caller keeps its two
interaction trees. Original component equations are delegated through the same
bounded dynamic placement body used by the static pair/one-window wrappers.

`B7UM` binds the source ordering, root counts and every map in its new transcript,
then absorbs every original physical claim before interaction roots. One STARK
verification is followed by the original pure ledger: each state/register window
must close individually, then ROM, RAM, lookup and natural censuses close. No
aggregate-only substitute is introduced.

The scope requires an explicit retained-PCS byte budget, bounds trace trees to
at most 256 and windows to at most 64 (default eight), and derives conservative
coefficient/LDE/Merkle residency before restored-tree admission. That estimate is
not a whole-prover peak: raw witnesses and quotient/FRI scratch require a hard
outer allocator budget. The initial producer still holds a bounded set of stages
resident; durable checkpoint loading and column-tiled/spilled PCS are subsequent
integration. A retained 67-native Ethereum roster is outside the current hard
window cap. Neither scalable whole-block completion nor a compact aggregation
contract is claimed by this extension.
