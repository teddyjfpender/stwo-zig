# M6 second review: native v2, the diet outer profile, fold v3 (stream profiles)

Stream `profiles`, branch `codex/rv64-m6-profiles`, 2026-11-05. profiles is the second reviewer of three M6 proof-format
streams (M6-INTERFACES.md §profiles P3). Each finding is **SIGN-OFF**, **CONDITIONAL** (sign-off once the listed hook or test
exists), or **REOPEN** (blocks integrate from promoting that name). Labels: **[M]** measured, **[D]** arithmetic on measured
or pinned numbers, **[E]** estimate.

Inputs reviewed (round 1, about 20:40 pod time):
- native-format: M6-INTERFACES §native-format NF0–NF5 (v0 draft), `design/riscv-proving-stack/rv64-m6-native-v2.md` (draft in
  the worktree), `rv64-native-gkr.md` (native-gkr v1 note), `services/gkr_local/binding.zig`;
- diet-wire: M6-INTERFACES §diet-wire DW-1/DW-2, `outer_gkr/binding.zig`, `rv64-m5-outer-gkr.md` §5;
- fold-v3: M6-INTERFACES §fold-v3 FV1–FV3.

Registry entries for every name below: `om31_security_candidate.zig` `FORMAT_VERSIONS` (14 entries), with tests in
`om31_security_candidate_test.zig`. Corpus case IDs: `scripts/rv64_m5_negative_corpus.py` v4.

---

## 1. diet-wire: the outer profile

### DW-R1 (REOPEN, blocking for every entry with `outer_gkr = true`): the eq column is unconstrained

diet-wire found this while wiring, and it is a soundness break, not a missing optimisation.

`outer_gkr/binding.zig` (the CPU reference for the outer AIR hook H2) and `rv64-m5-outer-gkr.md` §5 constrain only the
prefix: `Pre[x+1] = Pre[x] + E[x]·v[x]` together with the boundary. Nothing constrains `E[x] = eq(z_row, x)`. So the
prover chooses E freely.

**Attack.** Take a row x* with v(x*) ≠ 0. Set `E(x*) = (T − Σ_{x≠x*} E(x)v(x)) / v(x*)` for any target `T`. The prefix
constraint and the boundary then hold for any terminal claims `(N_g, D_g)`. The GKR reduces its roots to those claims,
so the roots, and therefore the outer LogUp closure, are free. One forged row breaks all of it.

The M5 corpus case `M02` (final-claim tamper) does not catch this: its honest prover keeps the honest E.

**Fix: port the native construction. It already exists and was reviewed in M4.** `services/gkr_local/binding.zig`
`emitFor` has three constraints:
1. endpoints: `(E − eq0)·first + (E − eq1)·second = 0`;
2. carry recurrence: `E − E_next2 · carry = 0`;
3. cyclic prefix: `Pre − Pre_prev − E·v + target_per_row = 0`.

Here `first`, `second` and the eight `carry` coordinates are **public auxiliary columns** derived by the verifier from
the checked GKR row point. They are not producer witnesses and are not committed (`rv64-gkr-public-aux-preparation.md`;
physical bit-reversed indexing is already solved there).

That gives diet-wire option (a) of DW-1 at no new design risk. Option (b), a second sumcheck, does not remove the
problem. It reduces to an MLE evaluation of committed columns at a fresh point, which needs the same eq-column argument
again.

Conditions:
- **Cyclic form.** The outer note's `Pre[0] = 0` / `Pre[2^r] = target` form is only correct with explicit first and last
  selectors. On the cyclic trace domain, `Pre[2^r]` *is* `Pre[0]`. Use the native `target_per_row` cyclic form, whose
  sum over the 2^r rows gives `Σ E·v = target`. Case **DW11**.
- **The in-circuit verifier** of a child outer proof must evaluate `first`, `second` and `carry` at the OODS point
  *succinctly*, in O(r) OM31 operations.
  - The native CPU receiver does not do this. `public_aux.zig init` interpolates all 2^r values, which is fine on a CPU
    but impossible in-circuit. I found no succinct evaluator in the tree.
  - The standard one exists: stwo's MLE-eval component evaluates the eq carry quotient at a circle point in O(log N),
    using the coset's doubling structure and the two singleton selectors.
  - diet-wire must build it, plus a differential test of the succinct OODS value against `public_aux.zig` at random
    points.
  - Cost [E]: r ≤ 24 OM31 products plus about 2r circle doublings per component. That is negligible against the 40.9 M
    cells of the in-circuit GKR verifier [M5].
- **Degenerate points.** The carry is the ratio form of `eq`, so it needs `z_i ≠ 1` for the row coordinates. diet-wire
  inherits the native guard. If the native guard turns out to be implicit, add an explicit strict-draw rejection of
  `z_i = 1`. Its probability is r·2^-243 per proof, so it costs no completeness and no ledger bits.
- **Corpus.**
  - **DW10** (W): forge `E` on one row and recompute `Pre` consistently. The **eq constraint**, not the boundary, must fail.
  - **DW11** (W): a non-cyclic prefix edge, where the wrap row carries the target.

  Both are added to corpus v4.
- `outer_gkr/binding.zig` is diet-wire's file now. Its header comment must state the three constraints, so that the CPU
  reference and the AIR cannot drift again.

### DW-R2 (SIGN-OFF): `kary-v1`, i.e. 3-ary folds on r1

- No new soundness argument is needed. The k-ary lemma (`rv64-m5-binding.md` §4.3) covers k = 3.
- The arity is bound three times: the version word `(3<<8)|2`, the class key, and the receiver-derived
  `Plan.initArity`.
- The mass fold is an integer sum at any k ≤ 4 (`m5FoldMass`, tested at k = 4 in the registry).

**Condition** (R tier, profiles runs it when diet-wire posts the run directories): a k = 3 proof under a k = 2 receiver
policy, and the reverse, must be rejected cleanly (DW07 or DW08 via `--alt-format-run`).

4-ary folds OOM [M, DW-1], so the registry bound for every diet entry is 3.

### DW-R3 (CONDITIONAL): fused Blake2s, one instance per node

The design matches the blake-gadget review: one instance, and xor8 rows in `(a<<8)|b` order. Before promotion:
- **BG08 over all consumers.** `requireBlakeTableMass` (new) takes every consumer of `VerifyBitwiseXor_8` per proof, not
  only the gadget's 704 lookups per compression. [D] For the largest r1 fold, 94,237 × 704 = 66.3 M, plus the node-wide
  lookup bound 294.9 M, gives 361 M < p (2.6 bits of margin). This is pinned in a test.
- Hooks for **DW05** (instance count and log are class constants) and **DW06** (the tape is in builder creation order;
  the M5 shadow gather order is non-deterministic).

### DW-R4 (SIGN-OFF): the q51 profile is deferred

The q51 profile OOMs on the GPU [M5]. This is a resource limit, not a soundness one. `m6_outer_diet_m3_b4_q51_p26_fold4_v1`
stays reserved. Its arithmetic is 2·51 + 26 = 128 conjectured bits, with Johnson ×2 = 154.

### DW-R5 (SIGN-OFF): the outer GKR algebraic budget at M6 facts

At the 24628607 shape [D] (33 outer proofs, 16 instances, 2^24 rows, arity 8), the OM31 draws clear 128 + 2 + 21 bits,
and the conservative characteristic bound 2^28 < p holds. Both are tests. QM31 draws would fail (M09).

---

## 2. native-format: native v2

### NV-R1 (SIGN-OFF on design, CONDITIONAL on hooks): the strict roster closes canon-native A1

NF1 makes the declared component vector of every segment *equal* to the rung vector of its (f, r). The receiver derives
`r_k` by equality, and there is no unclassed segment under v2. So the chain's `structure(f, r)` equals the `T_nat` leaf
structure, and the vkhash in the chain is the `T_nat` leaf vkhash.

This is exactly the condition A1 asked for. As a consequence:
- setup is block-independent;
- the native table is a function of (image, profile).

Conditions:
- U hooks **NV01** and **NV02**;
- a golden vector in which one class's chain vkhash and its `T_nat` leaf vkhash are byte-equal;
- a hook for **NV07**. Unused rung components are committed as all-padding instances, so their padding rows must carry
  zero multiplicity and zero yield.

### NV-R2 (CONDITIONAL, medium): bind the v2 version before stage-one draws

NF0 puts the version identity in the chain IV, so it reaches the transcript only through χ, at stage two. Under v2-strict,
the stage-one local-GKR challenges are drawn from MAIN *before* χ exists (binding note §3.2(1) [R2]).

Meanwhile, the native candidate `profileIdentity` that the fixed authority mixes is the admitted one. It still hashes
`LOCAL_RELATIONS = 9` (M6 P4).

Stage-one statements are the same AIR in v1 and v2, so I have no attack. Still, the frozen-heart rule says every
version-dependent word is mixed before the first challenge that depends on it.

Request, either one of:
- (a) mix the v2 version identity at native channel start, so that `formatIdentity(m6_native_v2_*)` (which hashes 10) is
  bound from the first draw; or
- (b) write in the v2 note why a stage-one transcript shared between versions is harmless.

Case **NV05** checks that a 9-relation identity is refused under v2.

### NV-R3 (CONDITIONAL): the characteristic bound of the v2-gkr section

At the NF4 bounds (128 instances × 2^28 rows), the conservative mass is 2^35 ≥ p. This is pinned: the test
"native v2-gkr GKR section at its declared bounds" shows the conservative bound is refused. So `requireNativeGkrSecurity`
must use the per-relation, multiplicity-weighted, source-bound mass, as NF4 says. Never the instance × height bound.

The field-size side is fine. [D] At 256 proofs × 128 instances × 2^28, OM31 clears 151 bits. QM31 would not.

Nit: the native-gkr v1 note's §4 table uses caps P = 1,024 and i = 64. The NF4 bounds are 128 instances, and the receiver
cap is MAX_PROOFS = 256. Please restate the table at the NF4 bounds.

### NV-R4 (SIGN-OFF on design, pending code): the v2-gkr transcript order and binding

NF4 order: identity, then the header, statement, FIXED and MAIN, then χ, roster header, salt, local lookup elements, the
batched GKR (roots mixed at join), γ, ρ_g, and finally the INTER commit. This satisfies "claims before consumers" and
late binding.

The binding is the native `binding.zig` construction, *with* the eq constraints (DW-R1 is the outer copy that lost
them). Global claims are GKR roots in place of classic claimed sums, and the cross-proof closure argument is unchanged.

Re-salting on a strict-draw rejection is ordinary Fiat–Shamir grinding. It is covered by the work term of
`requireConditionalRomBudget`.

**Condition:** the hook for **NV06**, a W-tier layer-claim or round tamper.

---

## 3. fold-v3: in-circuit binding and the standalone root-only receiver

### FV-R1 (CONDITIONAL): the native VK section of the receiver table

FV1 is sound if every entry's content (FIXED identity and root, suite, logs) is recomputed from the pinned source by the
receiver, and `PROOF` only *selects* which classes appear. Conditions:
- **RO08** (R tier, stores and caches absent, must still accept) passes;
- a U test shows an entry's FIXED root equals an independent source commit, not a value copied from the proof.

Once native v2 lands, the table is image-level, so the other block's pin may legitimately verify. **RO09** therefore
expects `reject_or_same_statement`: changed in corpus v4.

### FV-R2 (PENDING): fold v3 itself

There is nothing to review until FV3 posts the NS word layout and the `T_rec` v2 leaf words for k-ary and set-v2 classes
(diet-wire DW-1 asks fold-v3 for them).

The registry entry `m6_outer_fold_v3_r1_b2_q108_p20_fold4_v1` (component `rv64-m6-fold-v3/v1`, arity bound 3) is reserved.
When the review happens, it will check:
- the corpus cases **F301–F308**;
- the binding note §4.1 constraints 2 and 5 in circuit, including the two-sided index range (L05) and the
  every-child range on `seg_hi − seg_lo` (§4.1(5) [R1]);
- that **RO10** holds: a pre-v3 root is refused under the v3 policy unless `--audit` is given.

---

## 4. Summary for integrate

| name | verdict | blocks promotion until |
|---|---|---|
| `m6_outer_setv2_kary_r1_b2_q108_p20_fold4_v1` | SIGN-OFF (DW-R2) | the k = 2 / k = 3 cross-policy R run |
| `m6_outer_gkr_setv2_kary_r1…`, `m6_outer_diet_*`, `m6_outer_diet_fold_v3_*` | **REOPEN (DW-R1)** | eq constraints ported (native form), DW10 and DW11 hooks |
| fused Blake components inside the diet entries | CONDITIONAL (DW-R3) | BG08 over all consumers, DW05 and DW06 |
| `m6_native_v2_b2_q108_p20_fold4` (v2-strict) | SIGN-OFF design (NV-R1), CONDITIONAL NV-R2 | NV01, NV02 and NV07 hooks; the version bound before stage one, or the argument |
| `m6_native_v2_gkr_b2_q108_p20_fold4` | CONDITIONAL (NV-R3, NV-R4) | source-bound mass gate; NV06 |
| `m6_outer_fold_v3_r1…` | PENDING (FV-R2) | the NS layout and T_rec v2 words are posted |
| standalone root-only receiver | CONDITIONAL (FV-R1) | RO08 green; the source-commit U test |
