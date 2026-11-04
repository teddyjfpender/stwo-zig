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

**Condition run [M], round 2.** Full-tree receiver (M5 integrate receiver-v2), fresh CPU process, on diet-wire's
`<block>-2gpu-k{2,3}-ab1` proofs. On both blocks and in both directions, the control is accepted under its own arity
policy and the other arity's whole proof directory is rejected cleanly:

| block | policy | control | other arity | first error |
|---|---|---|---|---|
| 26235156 | k = 3 | accepted, 38.4 s | rejected | `MissingRecursiveNodeProof` |
| 26235156 | k = 2 | accepted, 45.5 s | rejected | `MissingRecursiveNodeProof` |
| 24628607 | k = 3 | accepted, 58.2 s | rejected | `MissingRecursiveNodeProof` |
| 24628607 | k = 2 | accepted, 65.0 s | rejected | `MissingRecursiveNodeProof` |

The rejection comes from the receiver-derived plan, which is structural (class "missing"): the policy's node files do
not exist. It is not a digest check. That is the correct authority for the full-tree path. The root-only path does
*not* yet consult the arity (FV-R3, P04).

Receipts: `vectors/reports/rv64-m6-20261105/profiles/<block>-corpus-v4-dw07-policy-k{2,3}.json`.

**Verdict:** DW-R2 is signed off for the full-tree receiver. For root-only it waits on FV-R3.

### DW-R3 (CONDITIONAL): fused Blake2s, one instance per node

The design matches the blake-gadget review: one instance, and xor8 rows in `(a<<8)|b` order. Before promotion:
- **BG08 over all consumers.** `requireBlakeTableMass` (new) takes every consumer of `VerifyBitwiseXor_8` per proof, not
  only the gadget's 704 lookups per compression. [D] For the largest r1 fold, 94,237 × 704 = 66.3 M, plus the node-wide
  lookup bound 294.9 M, gives 361 M < p (2.6 bits of margin). This is pinned in a test.
- Hooks for **DW05** (instance count and log are class constants) and **DW06** (the tape is in builder creation order;
  the M5 shadow gather order is non-deterministic).

### DW-R6 (CONDITIONAL): the in-circuit Merkle cap of `m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1` (DW-3)

The fold's child verifier guesses the 8 nodes at level 3 of each child tree. It hashes them to the child root once,
and every path stops at its cap node. The child proof bytes are unchanged, only the fold circuit differs, so the cap is
a VK and profile change.

It is sound under the collision bound **iff** all three hold:
- (i) the cap-to-root hash rebuilds the exact top 3 levels of the binary tree: 8 → 4 → 2 → 1, with the same node
  hasher and domain tags as the path nodes. A different hasher at the top would let a "cap" that is not the real level
  be accepted;
- (ii) the cap node a path ends at is selected by the **top 3 bits of that query's position**, which is an already
  constrained wire. It must never be selected by a guessed index or a free mux. Otherwise one valid path could be
  "landed" on any cap slot;
- (iii) the root it reproduces is the same wire that seeds the child transcript (`mixRoot`).

Cases:
- **DW12** (W): select the cap node by a guessed index, so a path lands on the wrong slot;
- **DW13** (W): cap nodes not hashed to the transcript root, or hashed with a different node domain.

`rv64-m6-diet-wire.md` §5 (`13e429783`) states the soundness as "root = H(cap)". That H must be the **binary-tree
rebuild** 8 → 4 → 2 → 1 with the path node hasher, not a flat hash of the 8 nodes. A flat hash would give a different
root from the committed one, and so a "root" that the child transcript never mixed. Condition (i) makes this explicit.

The completeness bound there checks out [D]: at c = 3, 2^(c−1)(1 − 2^-(c−1))^108 = 4 · 0.75^108 ≈ 1.3·10^-13 per tree.
c = 4 needs a producer-exported cap.

The fit arithmetic that the profile depends on is pinned in a test:
- the 4-ary fold's 8,680,080 G rows [M] drop to ~7.77 M < 2^23 with the ~10.5% cap saving [D];
- the margin is ~7%: a fold with 8% more G rows re-crosses 2^23 even with the cap.

`m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1`: SIGN-OFF, as DW-R2. Arity is a profile constant, and a mismatching
`STWO_RV64_FOLD_ARITY` gives a clean `Om31ProfileFoldArityMismatch`.

Both are registered with diet-wire's exact component strings. The speculative staged names from round 1 are removed.

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

Confirmed by a code read at `aa291ac35`: the v2 version identity enters only `manifest.zig:220` (`chainIv(versionIdentity)`).
Nothing mixes it at native channel start.

Stage-one statements are the same AIR in v1 and v2, so I have no attack. Still, the frozen-heart rule says every
version-dependent word is mixed before the first challenge that depends on it.

Request, either one of:
- (a) mix the v2 version identity at native channel start, so that `formatIdentity(m6_native_v2_*)` (which hashes 10) is
  bound from the first draw; or
- (b) write in the v2 note why a stage-one transcript shared between versions is harmless.

Case **NV05** checks that a 9-relation identity is refused under v2.

Registry alignment: the hashed tag is `rv64-m6-native-chi-chain/v2` (`canon_native.zig .version_v2`, note §1).
`rv64-m6-native/v2` is only the policy name. The registry component now equals the hashed tag.

The admission relaxation of note §2 ("absent implies no rows" under v2) is **signed off**:
- presence is a receiver-derived class constant;
- an empty instance is closed by the same closures with receiver-derived zero claims;
- every mass bound already counts the instance at 2^log rows.

NV07 remains the hook that pins it.

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

### FV-R3 (CLOSED in round 3 by fold-v3 b78ff8c9b; found by the corpus [M]): the root-only receiver ignored the fold-arity policy

Corpus v4 `--format m6-root` was run against fold-v3's receiver (sha `1971181a`, per-block receiver-derived tables,
`--table-root` pin) on both dev blocks. It passed 44/45 (26235156) and 43/44 (24628607). Receipts:
`vectors/reports/rv64-m6-20261105/profiles/<block>-corpus-v4-fold-v3-receiver.json`.

**The failure is `P04` on both blocks.** With `STWO_RV64_OUTER_PROFILE=r1_b2_q108_p20_fold4` and
`STWO_RV64_FOLD_ARITY=4`, the receiver accepted a binary-fold proof, with the control's statement.
- M5's canonical root-only runs rejected P04 only by `VkTableOuterProfileMismatch` (an explicit r1 against a canonical
  table).
- On old-format proofs the table header binds the outer profile but not the fold arity, so the arity policy is never
  consulted.

This is not a false-statement acceptance: the proof is a valid binary-fold proof of the same statement. It is an
admission-policy hole. It matters once diet-wire's `k3` and `k4-cap3` are separate named profiles with separate review
verdicts: a receiver whose policy names one arity must not accept another.

Fix:
- the table header carries the fold arity, i.e. the `versionWord(k)` that rootverify's `foldClassKey` lacks (M5 integrate
  note);
- `derive-vk-tables` records the arity policy it ran under;
- `verify-root-candidate` refuses a table whose arity or profile differs from the current policy, with a clean exit.

P04 then rejects.

The other measured results on both blocks:
- C00 control accepted;
- RO08 (stores absent) accepted with the control statement, which is FV-R1's first condition;
- RO09 (the other block's pin) rejected with `VkTableRootPinMismatch`;
- RR01–RR05 as expected;
- no crashes.

Wall per accepted case [M, single observations, load 10–11, above the quiet bar]: **1.6 s (26235156) and 2.1 s
(24628607)** root-only, against 9.5 / 13.7 s at M5.

**Round 3 [M]: closed.** fold-v3 `b78ff8c9b` derives the expected root from `Plan.initArity(n, foldArity())` with k-ary
class keys. Its receiver (sha `88416b28`) passes corpus v4 `m6-root` at **45/45 (26235156) and 44/44 (24628607)**,
with no unexpected accepts and no crashes. **P04 now rejects** with `VkTableMissingFoldClass`, a semantic rejection.

If a table holding both arities were used, the k-ary expected root would still differ from a binary root (different VK
and digest), so the check does not depend on the table's contents.

Root-only C00: 1.57 s (26235156) and 2.22 s (24628607) [M, single observations, load 14–24].

Receipts: `<block>-corpus-v4-fold-v3-receiver-r3.json`.

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
| `m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1` | SIGN-OFF (DW-R2) | the k = 2 / k = 3 cross-policy R run; root-only refuses an arity mismatch (FV-R3) |
| `m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1` | CONDITIONAL (DW-R6) | conditions (i)–(iii); DW12 and DW13 hooks |
| `m6_outer_diet_*` (all-component), `m6_outer_diet_fold_v3_*` | **REOPEN (DW-R1)** | eq constraints ported (native form), DW10 and DW11 hooks |
| fused Blake components inside the diet entries | CONDITIONAL (DW-R3) | BG08 over all consumers, DW05 and DW06 |
| `m6_native_v2_b2_q108_p20_fold4` (v2-strict) | SIGN-OFF design (NV-R1), CONDITIONAL NV-R2 | NV01, NV02 and NV07 hooks; the version bound before stage one, or the argument |
| `m6_native_v2_gkr_b2_q108_p20_fold4` | CONDITIONAL (NV-R3, NV-R4) | source-bound mass gate; NV06 |
| `m6_outer_fold_v3_r1…` | PENDING (FV-R2) | the NS layout and T_rec v2 words are posted |
| standalone root-only receiver | CONDITIONAL (FV-R1) | RO08 green [M, done]; the source-commit U test. FV-R3 closed [M, round 3: 45/45, 44/44] |
