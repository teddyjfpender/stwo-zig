# LS canonical range induction

> Superseded encoding: this note qualifies LS48. The current LS32 encoding
> additionally removes the after-value and load-C queries under
> [rv64-ls-joint-write-induction.md](rv64-ls-joint-write-induction.md); the
> dependency order below remains its prerequisite (P1-P3 there).

This review and implementation evolve the concrete `load_store_v2` encoding on
0751982fd. They do not change `load_store_v1`, the OWNER19 or RAM14 tuple, or the
RV64 alignment policy. A bare LS proof has open lookup debts and is not an
accepting memory verifier. The argument below applies to the closed execution
receivers listed below, subject to the existing randomized multiset argument's
soundness error. It is a source-level argument, not a machine-checked proof.

## Physical accounting

`air/memory/load_store_v2/layout.zig` retains U16 columns
`12,18,19,20,21,24,25,40,41,42,43,68` and U8 columns `13,26,73,74`.
These are after-clock low; four RAM after-value limbs; epoch/low-clock gaps;
four load-result limbs; address quotient; after-clock high; high-clock gap;
and the two store-byte split values. OWNER and selection add two fractions.
Thus 18 affine denominators use nine strict pair inverses (36 M31 columns),
one local prefix (4), and the separate RAM inverse/prefix (8): **48 INTER**.
MAIN remains 79 and the local residual count becomes 261. Degree remains three,
with native 2n evaluation and split one. The previous layout had 35 U16 +5 U8
queries, 96 INTER, and 273 residuals.

The native metadata retains all original 35 U16 and five U8 coordinates in its
original 82-byte representation. `U16_CACHE`/`U8_CACHE` map the reduced query
list into those caches; OWNER/RAM reconstruction after MAIN release is unchanged.
Histogram mass and geometry admission use the reduced query counts, including
padding. Inactive rows still zero every main coordinate except the active bit
and still incur strict range/selection denominator obligations.

## Dependency order

1. **Commitment and admission.** Every main and multiplicity column is committed
   before its challenges. The complete manifest binds actual fixed/main roots,
   role geometry, expected program and public endpoints. Every physical claim
   enters the proof transcript before interaction commitment and composition
   coefficients. Each relevant positive query mass is admitted below M31's
   characteristic. Boolean unit RAM activity cannot be replaced by multiplicity. CPU OWNER
   weights are Boolean and LS OWNER uses that SAME Boolean active bit; neither
   side permits arbitrary state-effect multiplicities.
2. **Canonical produced RAM clocks.** OWNER19 matches the LS after epoch to the
   independently selected public CPU epoch (u16), and after tick to `4*row+4`.
   Kept after-low U16 and after-high U8 queries, together with the unmasked
   recomposition equation, make that a canonical 24-bit clock representation.
   Keccak/secp producers retain their existing canonical after-clock ranges.
3. **Canonical consumed RAM clocks.** Complete RAM14 multiset closure matches
   every active before token to either independently anchored INIT or a produced
   after token. All such clocks are canonical by step 2 and the expected INIT.
   This does not assume the address or value is already canonical.
4. **Strict RAM order.** In `closed_ram/equations.transitionLocalFor`, same-epoch
   low/high equations imply `T_before + gap16 + 65536*gap8 +1 = T_after`.
   Ranged gaps and canonical endpoints put the integer sum below 2^25 < p.
   Cross-epoch equality similarly gives `E_before + epochgap +1 = E_after`,
   with sum at most 131071 < p. Thus each edge strictly increases lexicographic
   `(epoch,tick)`. Finite unit-flow components cannot be cycles or orphan chains;
   tracing predecessors must reach INIT. No assumption about native HashMap
   uniqueness substitutes for these AIR and physical-closure obligations.
5. **Canonical RAM addresses and before values.** Each transition preserves its
   address and rights in both RAM tuples. INIT is canonical, aligned, unique and
   independently image/policy checked; its physical claim is separately anchored.
   Strict predecessor induction therefore propagates canonical addresses/rights.
   Kept four after-value U16 queries independently canonicalize every LS write;
   service producers have existing canonical byte/word anchors. This covers ALL
   admitted writers, including ordinary stores, Keccak and secp updates; an
   unanchored future writer cannot join this encoding. Before values
   consequently inherit canonicality from INIT or those produced tokens.
6. **Independent register induction.** CPU REG6 clocks are fixed after-times
   `4*row+slot+1`; clock gap16/U8 remain ranged. Initial local clocks are zero.
   Closed REG claims and bounded gaps establish strict integer predecessor order.
   Initial GPR values are receiver-admitted; every producing functional provider
   canonicalizes its result or uses a ROM-authenticated constant. LS load C4
   ranges are deliberately retained as independent register write anchors. Hence
   all A/B reads are canonical without using RAM canonicality as a premise.
7. **Immediate and owner binding.** ROM30 authenticates immediate limbs. The
   CPU affine OWNER19 tuple matches all four A, I, B, C limbs, including upper
   store-B limbs unused by a narrow store. A/I/B queries can therefore be removed
   without weakening the LS effective-address arithmetic. C4 stays ranged.

There is no REG/RAM circularity: load register outputs and RAM write outputs both
retain independent canonical ranges. All gap ranges and after-clock limb ranges
remain. This first reduction does not rely on selection truth implying C ranges.

## Required acceptance context

`word16_execution/execution.verify` closes local REG/ROM/FUNCTION/OWNER/ranges
and RAM against canonical image-derived INIT/TERM claims. Global execution,
Keccak shared, secp and combined-services receivers additionally verify every
physical proof under the complete manifest and close the shared RAM relation
across all shards; first INIT and final TERM remain independently anchored.
Ethereum's receiver adds known terminal PC/output/halt checks. CSP and Sail use
the closed execution receiver with independently expected image/output authority.
Local clocks reset only for registers; global RAM epochs and ticks are preserved.

The initial/terminal RAM claims must remain separately compared to expected
canonical tuples; checking only their sum is insufficient. The existing
`memory/boundary_anchor_test.zig` constructs a valid physical proof with balanced
noncanonical address ghosts and demonstrates rejection by the full receiver.
No new public accepting open-RAM or owner-stub verifier is introduced.

## Counterexamples defining the retained obligations

* Without epoch-gap range, a future epoch 2 can precede epoch 1 using gap `p-2`.
* Without low-gap range, tick 8 can precede tick 4 using gap `p-5`.
* Without high-gap range, the same reversal uses lowgap 65531, carry 1 and
  highgap `p-1`. All three gap ranges therefore remain.
* A limb compensation `low+65536, high-1` preserves a represented native word
  while violating canonical encoding. Removing A/I/B queries is safe only with
  the full canonical REG/ROM/OWNER closure, not with host advice validation.
* A store-byte operation can hide compensation in upper B limbs from its local
  byte semantics; OWNER must bind all four B limbs.
* With A=65535 and I=1, a false carry can yield effective low=65536/high=0.
  Removing address queries relies on canonical INIT ancestry, not local EA
  equations. Balanced forged INIT/TERM vectors must fail expected claim anchors.
* A before-low value `p-1` can satisfy local same-epoch equations with after-low 4
  and lowgap 4. It cannot match any canonical produced or initial clock token.
* Removing after-value/C ranges as well would require a further joint write
  lemma. That stronger reduction is outside this encoding.

All current local prefixes authenticate only the sum of OWNER/range/selection
ledger shares. RAM is separately physical. Neither the proof nor this argument
asserts independent authentication of those four local shares; their provenance
is the distinct randomized typed denominator families and complete closure.

## Qualification structure

`memory/range_induction_test.zig` constructs satisfying local polynomial
counterexamples for removed A/I/B/address/before-clock queries and demonstrates
why the retained write and gap queries are essential. This explicitly prevents
mistaking local native validation for the acceptance argument.

`memory/range_induction_proof_test.zig` commits false MAIN advice and reconstructs
its lookup interactions from those actual field coordinates, bypassing the
canonical native Event type only in tests. Its six cases cover upper store-B
compensation, before-clock aliases, read/write value aliases, future epochs,
reversed ticks and an orphan two-event RAM cycle. Each must produce a real
physical STARK accepted by a fresh polynomial verifier, then receive the precise
`UnclosedExecutionRelations` rejection from the fresh closed execution receiver.
The pre-existing boundary-ghost test separately exercises expected INIT/TERM
claim authority while keeping the total ledger balanced.

The native oracle reconstructs retained pairs directly from wide MAIN, rather
than sharing the metadata cache mapping. Q finite differences cover every
residual with arbitrary current/previous inputs; packed-base and packed-secure
comparisons cover sixteen independent lanes. Circuit tests use actual builder
wires for typed challenges, claims and masks, and compare every residual with Q;
challenge, claim, pair-inverse and C-wire mutations must invalidate the circuit.
This qualifies the arithmetic lane authority, not a new recursive receiver.

Legacy `load_store_v1` retains its 433,488-byte q70/P26 proof hash
`9124b54a04df4b3de6fe184e905fe283438211b827b3e85ae39938b030e0e664`.
The new LS encoding intentionally changes full-execution proof bytes. Its
five-proof mixed K/ADD/DOUBLE fixture is checked in a separate receiver process
against independently reconstructed image, program, final CPU values and keys.
See the accompanying qualification JSON for the final gate results and pins.
