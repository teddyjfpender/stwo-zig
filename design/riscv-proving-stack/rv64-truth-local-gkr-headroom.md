# Truth-local GKR: headroom and missing integration

Source-cost audit, 2026-11-02. Current production experimental truths use classic
OM31 local lookup arguments. Existing truth fraction/metadata/input modules are
foundations, not a qualified truth-GKR worker, execution receiver or recursive leaf.
No implementation or measured speedup is claimed by this counterfactual.

## Actual retained-block headroom

For the default25-CPU / five-truth roster, truth-local INTER is3,127,439,360
M31 cells:43.2502% of all7,231,037,952 INTER cells. Replacing each truth role's
classic local argument by the current16-column authenticated GKR Eq/prefix
binding would retain20,328,448 cells and save3,107,110,912 cells, **17.7939% of
all17,461,658,112 MAIN+INTER cells**. Global arguments and MAIN are unchanged.
This would reduce total cells by about1.216x, not a several-fold full-prover gain.
The intrinsic1.196billion fact reductions add numerical GKR work; no cell-count
projection establishes a wall-time multiplier without matched full proof runs.

| Role | Local queries / physical row | Classic OM8 columns | GKR binding columns | Padded lanes |
| --- | ---: | ---: | ---: | ---: |
| Keccak permutation | 1,920 (CHI1,600 + XOR5320) | 5,128 | 16 | 2,048 |
| CHI table | 1 | 16 | 16 | 1 |
| XOR5 table | 1 | 16 | 16 | 1 |
| secp product, canonical inputs | 220 | 888 | 16 | 256 |
| secp linear, canonical inputs | 64 | 264 | 16 | 64 |
| BYTE table | 1 | 16 | 16 | 1 |

The canonical-input byte policy is receiver-owned and depends on independently
closed canonical positive Wire35 producers. It does not permit omitting the
remaining unit byte queries. `truth_classic.packing` is three for Keccak, two
for secp and one for tables. Counts above follow original `truth_frame.forSource`,
`truth_fractions` and secp `layout.byteCountFor`; tables remain authenticated
weighted providers, not free host multiplicities.

The optional K16 roster changes padding and adds six Keccak proofs. Its analogous
saving is2,939,600,896 cells, **17.0662%** of that roster's17,224,735,232 MAIN+INTER.
It has slightly more table/binding rows but fewer padded permutation rows.
Receipts under `vectors/reports/rv64-gkr-tree-checkpoints-20261102/truth-local-cost/`
record every role's geometry, query count, variable count, facts, columns and cells.
These are native own-height cells, not lifted-tree opening or recursive gate costs.

## Numerical work and admission are substantial

Default K18 truth scopes total1,196,182,272 padded facts. Materializing all dense
M31 numerators plus OM31 denominators over the execution would write43.06GB;
those planes must never all remain resident. One K18 child has2^29 permutation
facts (29variables), plus its CHI/XOR5 providers. The existing `truth_frame.Plan`
uses the old136-byte/fact numerical contract, about68GiB for this one child,
and fails the32GiB GKR budget. That foundation is deliberately fail-closed.

Even transferring the newly qualified **CPU** streamed68 strategy hypothetically
to truth would require about34.0006GiB per K18 child, before MAIN/PCS/fixed setup,
metadata, binding aux and checked headers. It still does not fit32GiB. A smaller
bound is not justified merely because empirical requested peaks look lower.

| Child geometry | Largest variables | Padded facts across its three roles | Hypothetical68B/fact numerical payload |
| --- | ---: | ---: | ---: |
| K18, each of two children | 29 | 536,880,128 | 34.0006GiB |
| K16, each full child | 27 | 134,226,944 | 8.5006GiB |
| Last K16/log15 child | 26 | 67,118,080 | 4.2506GiB |
| Large secp ADD child | 26 | 83,886,336 | 5.3125GiB |
| Small secp ADD child | 19 | 786,688 | 0.0498GiB |
| secp DOUBLE child | 25 | 37,748,992 | 2.3906GiB |

K16 total padded facts are1,129,128,704, about5.6% fewer than K18. Table replication
is included. These68B figures are counterfactual numerical payloads only: the
current truth adapter does not implement the CPU streamed path or its qualified
exact-cap lifecycle. CPU `source_inputs.Reader` has an explicit128-lane row sink;
truth1920 cannot be routed through it by weakening validation. Truth needs its
own bounded original-authority range source, query framing and checked plan,
with no all-tuple planes or silent dense fallback. Critically, the current CPU
source reader emits an entire <=128-query row for each64-fact requested span.
Merely enlarging that row to1920 would repeat the complete Keccak query emission
about32 times per padded2048-lane row. Truth needs `emitRange` / event-index tuple
projection, reading each requested CHI/XOR5 tuple directly from retained packed
state/parity getters. It must not re-emit the whole row or reconstruct expanded
MAIN to answer a64-fact span. The existing raw truth
`Inputs.init` is a dense allocation path and its old admission must be replaced
only alongside a newly qualified resource contract.

## Does Keccak still force4n?

Yes, simply removing classic local fractions does **not** make the current
Keccak truth component2n. `truth_role` calls the original
`K.equations.emitDirectFor(..., true)`: the boundary Boolean gate includes
boundary*active*bit*(1-bit), degree4. Current classic triple lookup constraints
reach degree5; replacing them removes that degree5 source, but degree4 still
requires the current split2/4n quotient geometry.

A separately qualified existing direct authority offers `emitDirectFor(...,
false)`, removing the active factor using the already-enforced padding lemma.
That direct authority is degree3. With proper GKR terminal binding and the
existing pure KIO globals also bounded by degree3, a new truth profile could
use2n. This is an explicit authority/profile/receiver change, not a safe edit to
an integer degree declaration. The full joined native/packed/circuit finite-
difference gates, inactive/padding adversarial witnesses and actual physical
proofs must establish degree and semantic parity before changing geometry.
Secp direct arithmetic and classic global Wire are already degree3/2n.

## What is reusable and what is missing

Reusable: `truth_fractions` preserves original signed CHI/XOR5 and unit BYTE
queries, fixed-table weighted supplies and a distinct OM8 namespace. The
polynomial compression draw is explicitly framed before relation draws.
`truth_metadata.Provider` reconstructs Keccak lookup tuples directly from packed
state/parity cells and secp bytes without expanding MAIN. `truth_global` retains
original KIO/Wire tuples. The numerical OM GKR engine and bounded opaque source
are shared foundations; immutable fixed authority and fully parked MAIN already
exist independently of the argument choice.

Missing before an accepted execution:

1. A mandatory receiver-owned truth-GKR profile/catalog. Current manifest rejects
   truth local children in the explicitly classic-truth profile; it must not
   silently admit optional producer-selected omission or reinterpret these scopes
   as CPU frames. Canonical wire must encode the actual truth child and bound it.
2. Typed truth source/streamed plan with <=2048 queries, exact padding0/1,
   checked characteristic mass including inactive rows and provider support,
   bounded scratch, all-OOM cleanup, pole rejection and real requested/backing
   capacity qualification. Adopt K16 or independently prove a lower K18 resource
   contract; do not reuse32GiB by weakening the current admission check.
3. Truth GKR scope replay from independently expected statement, ordinal,
   FIXED/MAIN and exact query catalog, all child bytes/claims transcript-bound,
   and per-role terminal N/D marginals authenticated by the same physical MAIN.
   Per-role MAIN constraints and KIO/Wire globals remain under that same MAIN span.
   A mathematically valid child or host-supplied marginal is insufficient.
4. New truth role packed domain/OODS masks and Eq/prefix producer using the
   original lookup tuple authority, including Keccak's shifted state masks.
   No forged zero legacy INTER or duplicated MAIN span. Keep local closure
   separate from global KIO/Wire, and reject nonzero absent claims.
5. Independent complete receiver and recursion statement binding the new profile,
   geometry, child transcript and all global obligations. Native proof savings
   do not imply cheap recursion: sumcheck/GKR terminal checks are additional work,
   and Keccak's wide MAIN/shifted openings remain. Compare lifted opening samples,
   hash gates, child bytes and total fresh verification cost on matched requests.

Qualification must include real service children and complete output, mutated
public endpoint/MAIN/root/catalog/namespace/child/marginal, D=0 including0/0,
wrong-but-balanced service/RAM witnesses, cross-shard coverage, parked abort and
later-worker failure. CPU controls remain unchanged. The whole128 and recursive
construction certificate stays fail-closed independently of these software gates.
