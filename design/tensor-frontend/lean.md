# Lean formal proofs for the tensor frontend

Status: second increment (round 4: multi-column LogUp, LogUp-GKR layers and composition, a model
of `validateStatementBounds`, one end-to-end op statement; sections 6-9). A zero-dependency Lean 4 project (`leanprover/lean4:v4.35.0`, Lean core
only, no Mathlib) at `formal/tensor-frontend/`. It proves the field-level and arithmetic lemmas that
the tensor protocol's soundness argument (security.md) rests on. It does **not** prove the soundness
of the protocol as a whole, and it has no Lean verifier. FlashProve's Lean library does both
(comparison below).

Run it:

```
cd src/tensor && zig build lean              # or: formal/tensor-frontend/scripts/check.sh
# on shared hosts: ~/Coding/ge-ops/bin/memguard run --gb 6 -- zig build lean
```

`scripts/check.sh` runs `lake build` (every module under `TensorFrontend/`, imported or not), builds
the `tensor-security-check` executable, prints `#print axioms` for the 41 headline theorems and the 3 GF(2) instance checks
(`Audit.lean`) and fails unless each depends only on `propext`, `Classical.choice` and `Quot.sound`
(or on no axiom). It also fails on any `sorry` / `admit`, any `axiom` declaration (with modifiers
or indentation), `native_decide`, `implemented_by`, `@[extern]` or `unsafe` in the sources, then runs
the security cross-check. Building from scratch takes a few seconds and well
under 1 GB.

## What is proven

Every theorem below is machine-checked with no `sorry` and no new axiom. The hypotheses are the
theorem's own, as stated. The "modelling assumptions" list says where the Lean model departs from
the Zig code.

### 1. Integer kernel semantics vs M31 (`TensorFrontend/Kernel.lean`)

A field identity of an integer expression `E` (in the signed representatives of the witness) is
modelled as `E % p = 0` with `p = 2^31 - 1` (`FieldZero`). That is exactly what the ring map
Z -> M31 gives.

| Lean theorem | Statement | Zig code |
|---|---|---|
| `fieldZero_small` | `E ≡ 0 (mod p)` and `|E| < p` imply `E = 0` | the reason for every bound check |
| `requant` / `requant_unique` | `requant s acc = floor((acc + 2^(s-1)) / 2^s)`. If `acc + 2^(s-1) - 2^s y - r = 0` with `0 <= r < 2^s`, then `y = requant s acc` and `r` is the remainder | `protocol.zig requant`, the virtual remainder column |
| `matmul_sound` | `|x| <= 2^bx`, int8 weights (`|w| <= 2^7`), `K = 2^logK` with `bx + 7 + logK <= 30`, `1 <= s <= 22`, `y ∈ [-128,128)`, `r ∈ [0,2^s)`, and the M31 remainder identity together imply `y = requant_s(Σ x w)` exactly | `bounds.zig` matmul check (`StatementAccumulatorBound`, `StatementShift`) |
| `hadamard_sound` | the same for `a ⊙ b` with `ba + bb <= 30` | `bounds.zig` hadamard check |
| `requant_einsum_sound` | `|acc| <= 2^b` with `b <= REQUANT_MAX_BITS = 29`, `s + out_bits <= 30`, the output key `y + 2^(ob-1) ∈ [0, 2^ob)`, and the remainder in range imply `y = requant_s(acc)` | `bounds.zig` ext einsum check, `shift > 0` |
| `exactRule` / `exact_einsum_sound` | the rule `ba + bb + n_k <= EXACT_MAX_BITS = 29` gives `|Σ a b| <= 2^29`. A witness entry `y` with `|y| < p/2` and the field identity `y = Σ a b` is then that integer | `bounds.zig einsumBound`, exact-einsum check |
| `onehot_bound` | a Boolean, at most one-hot selector gives `|Σ a b| <= 2^bb` | `einsumBound` one-hot case |
| `lineq_sound` | the sum of term magnitudes `< p` turns the field identity into an integer identity | `bounds.zig exprMagnitude`, `lineq` / `exprCheck` |
| `softmax_div_unique` | for `den > 0`, `0 <= 2acc + den - 2 o den < 2 den` holds for exactly one `o`, namely `floor((2acc + den) / (2den))`, the round-half-up quotient | `transformer.zig` softmax-PV (`@divFloor(2x + dn, 2dn)`) |
| `softmax_div_err` | the same inequality gives `-den < 2(o den - acc) <= den` | the transformer test's rounding check |
| `softmax_div_sound` | two range-checked slacks `u, v ∈ [0, 2^(lt+9))`, their M31 identities, `od = o·den` (as integers; this is what `exact_einsum_sound` gives for the `od` einsum), and the bounds `|acc|, |od|, |den| <= 2^28`, `lt <= 19` together imply `den > 0` and `o = round(acc/den)` | `transformer.zig` `rangeWide` pair |

### 2. Sumcheck soundness (`TensorFrontend/Poly.lean`, `TensorFrontend/Sumcheck.lean`)

| Lean theorem | Statement |
|---|---|
| `roots_le` | a coefficient list of length `n` that is not all zero vanishes at at most `n - 1` points of any duplicate-free list (factor theorem by synthetic division, over any `Lean.Grind.Field`) |
| `agree_count` | two round polynomials with `<= d+1` coefficients and different `g(0)+g(1)` agree on at most `d` field elements |
| `sumcheck_sound` | for any `f` with `IndDeg d n f`, any false claim and **any adaptive prover**, at most `n · d · |F|^(n-1)` of the `|F|^n` challenge vectors make the verifier accept. So acceptance has probability `<= n d / |F|` |

The field is any `Lean.Grind.Field` with a duplicate-free enumeration of its elements (`FinEnum`).
The verifier (`accepts`) checks the message length (degree), `g(0) + g(1) = claim`, folds the claim
to `g(r)`, and finally checks `claim = f(r)`, the oracle query that the protocol turns into a PCS
opening. This matches the per-round `deg/|F|` terms in `security.zig accountSumcheck` and
`accountGkr`.

### 3. LogUp (`TensorFrontend/LogUp.lean`)

| Lean theorem | Statement |
|---|---|
| `fsum_group` | `Σ c/(x - z)` regroups by distinct pole: coefficient `coefSum L z` per pole |
| `fsum_eq`, `num_eval_pole`, `num_allZero_iff` | away from the poles, `fsum = num/den`. With distinct poles, the cleared numerator at pole `z_k` is `c_k ∏_(l≠k) (z_k - z_l)`, so `num` is the zero polynomial iff every grouped coefficient is 0. In other words, a fractional sum is the zero rational function iff all its coefficients are 0 |
| `ncast_inj` | with the characteristic hypothesis `0 < k < p → (k : F) ≠ 0`, the map `k ↦ k·1` is injective below `p` |
| `logup_identity_sound` | identically-zero fractional sum (table `t_i` with multiplicities `m_i`, values `a_j`) and all counts `< p` imply `Σ_(t_i = z) m_i = #{j : a_j = z}` for every `z` |
| `multisetOK_mem` | from that, every looked-up value is a table entry with positive multiplicity |
| `logup_random_sound` | if the multiset relation fails (counts `< p`), at most `2U - 1` of the `x ∈ F` are poles or make the sum vanish, where `U` is the number of distinct poles (`<= |T| + |A|`) |

`logup_random_sound` is the single-variable (arity-1) form of the term that `security.zig
accountLogup` charges as `2 g D / |F|`. It also shows why `bounds.zig` / `logup_below_p` requires
`D < p`.

### 4. Security accounting (`TensorFrontend/Security.lean`, `TensorFrontend/Data/Toy20Johnson.lean`)

| Lean theorem | Statement |
|---|---|
| `union_le` | on a finite uniform sample space, the number of samples in a union of events is at most the sum of the event counts. This is the composition `security.zig summary` uses for `sum_with` / `sum_without` |
| `dyadic_union_sound` | if event `i` has probability `<= mant_i / 2^S` and `dyadicOK mants S K` (i.e. `Σ mant_i · 2^K <= 2^S`), then Pr[union] `<= 2^-K` |
| `toy20Johnson_with_bits`, `toy20Johnson_without_bits` | kernel-decided (`decide`, no axioms): the 23 terms of the toy 2^20 Johnson+OOD product proof sum to `<= 2^-113` with proof of work and `<= 2^-96` without |

How the toy check is produced:
`TENSOR_TERMS=<tsv> TENSOR_OOD=1 TENSOR_DEEP=76,3,20 tensor-bench product 20 1 122 2 20 2 76 3 20 2 2`
dumps the total's full term list (new `Account.writeTerms`, used only when `TENSOR_TERMS` is set).
`scripts/terms_to_lean.py` turns each term into an exact upper-bound mantissa
`ceil(count · 2^(S + log2_err - pow) · (1 + 2^-40))` with `S = 200` and writes the Lean module. The
`tensor-security-check` executable recomputes the totals from the mantissas: 113.469 / 96.760 bits.
The Zig report prints 113.47 / 96.76, so they agree. The largest integer `K` the exact check accepts
is 113 / 96. The input is `formal/tensor-frontend/scripts/toy20_johnson_terms.tsv`. If the
calculator or the configuration changes, re-dump and regenerate.

### 5. Non-vacuity (`TensorFrontend/Instance.lean`)

The sumcheck and LogUp theorems are generic over a `Lean.Grind.Field` with a `FinEnum`. Lean core
has no finite-field instance, so `Instance.lean` builds one for GF(2) (`Fin 2`), proves
`IndDeg` for a concrete function and the LogUp characteristic hypothesis for `p = 2`, and
instantiates `sumcheck_sound` and `logup_identity_sound` on it. This shows only that the
hypotheses are satisfiable (the theorems are not vacuous). It says nothing about QM31, which is
still not constructed.

### 6. Multi-column LogUp keys (`TensorFrontend/LogUpMulti.lean`)

A key of arity `a` is a coefficient list `k = [v_0, ..., v_(a-1)]`; its LogUp denominator is
`alpha - eval k beta = alpha - (v_0 + beta v_1 + ... + beta^(a-1) v_(a-1))`, exactly the form in
`security.zig accountLogup`. The relation is a list of (net coefficient, key) pairs.

| Lean theorem | Statement | Zig |
|---|---|---|
| `fsum_random_count` (LogUp.lean) | the counting core of `logup_random_sound`, for any pair list whose grouped numerator is nonzero: `<= 2U - 1` bad `x` | refactor, no new claim |
| `isolated_coef` | if at `beta` no other key's combined value equals `eval s beta`, the grouped coefficient of that pole is the key-level coefficient `coefKey L s` | - |
| `pair_collision`, `collision_count` | two distinct keys of the same arity `a` combine to the same value for `<= a - 1` betas; so `<= #{entries with key != s} (a - 1)` betas make *some* key collide with `s` | the "(cols - 1)/|F|" collision term |
| `logupMulti_count` | if some key has a nonzero net coefficient, `<= ((N-1)(a-1) + 2N - 1) |F|` of the `|F|^2` pairs `(beta, alpha)` are poles or zeros of the fractional sum (`N` = fractions) | |
| `logupMulti_sound` | the same from a failing keyed multiset relation, all counts `< p` (`logup_below_p`) | `accountLogupDegree` precondition `D < p` |
| `logupMulti_charge` | for arity 1 or `>= 3`: `(N-1)(a-1) + 2N - 1 <= 2 g N`, `g = max(a-1, 1)`: Lean certifies the charged `2 g D / |F|` | `accountLogup` |
| `logupMulti_charge_arity2` | arity 2: the sequential bound is `3N - 2`, **above** the charged `2N` | gap, see below |

The argument is sequential (first `beta`, then `alpha`), not the joint two-variable
Schwartz-Zippel bound in the Zig comment. Fix a key `s` with nonzero coefficient. If `eval s beta`
collides with no other key, the univariate LogUp at that `beta` has a nonzero coefficient, and
`fsum_random_count` bounds the bad `alpha`. Otherwise `beta` is one of `<= (N-1)(a-1)` collision
points. For arity 2 this loses `N - 1` against the joint bound `2N - 1`, so the charged `2N/|F|`
term is **not** certified for 2-column keys. That is at most `log2(1.5) = 0.58` bit on that one term.
Closing it needs the joint bivariate argument (a nonzero polynomial of total degree `(N-1) g` in
`(alpha, beta)`), which needs a bivariate polynomial type.

### 7. LogUp-GKR (`TensorFrontend/Compose.lean`, `TensorFrontend/Gkr.lean`)

| Lean theorem | Statement | Zig |
|---|---|---|
| `Compose.chain_sound` | sequential composition: steps with challenge lists `Ω_i`. If from every bad state step `i` reaches a good state for `<= e_i/D` of its challenges, a bad start ends good for `<= (Σ e_i)/D` of the challenge tuples. The bound holds for every state, so an adaptive prover is covered when the state carries the transcript | `summary` `sum_with` (round-by-round union bound) |
| `frac_combine` | `p0/q0 + p1/q1 = (p0 q1 + p1 q0)/(q0 q1)` for nonzero `q0, q1`: the fraction layer | `lookups` GKR layer |
| `hsum_summand` | the batched layer sum is `Vp(r) + lam Vq(r)` | - |
| `scFinal_accepts` | the sumcheck rounds returning the final claim refine `accepts` | - |
| `mu_level` | with a false combined claim and a sumcheck point that does not accept, at most one `mu` makes the line-reduced claims true | the line (mask-fold) term |
| `layer_sound` | one layer with `n` variables, any prover: from a false `(cp, cq)`, `<= (3n + 2)` out of every `|F|` of the challenges `(lam, rho, mu)` give true claims about the next layer (1 for `lam`, `3n` for the degree-3 rounds, 1 for `mu`) | `accountGkr`: per layer `(2 active + 1) + 3 rounds + active`. That is `3n + 4` for one instance, `>= 3n + 2` |
| `gkr_sound` | `N` layers, every adaptive prover (the prover of layer `k` sees the whole transcript): a false root claim ends in true input-layer claims with probability `<= Σ_(k<N) (3k + 2)/|F|` (`errSum_gkr`) | `accountGkr` summed over layers |

Model: layer `k` has `k` variables. `PT k, QT k` are the layers' multilinear extensions, and the
combined variable is the first one. `LayerConsistent` (a structure, i.e. a hypothesis) states what
the honest MLEs satisfy: layer `k` at `r` is `Σ_x eq(r,x) (fraction combination of layer k+1)`,
layer `k+1` is linear in its first variable, and every batched summand has `IndDeg 3`. These are
facts of multilinear extensions, stated like `IndDeg`, not derived. `LayerConsistent N` asks for
them only for the layers `k < N` of the `N`-layer circuit (an earlier draft quantified over all
`k`, which forced an infinite tower of layers below the leaves). Only one GKR instance is
modelled. The Zig verifier batches several instances (powers of the batching challenge, degree
`<= 2 · instances`) and handles masks for instances of different depth. Neither is formalised.

### 8. Statement bounds (`TensorFrontend/Bounds.lean`)

A Lean model of `bounds.zig validateStatementBounds` on an op-graph fragment: `matmul`,
`hadamard`, `range8`, ext `exact` einsum (shift 0) and ext `requant` einsum (shift > 0). The
bound state is `Nat → Option Nat` (`none` = `UNB`).

* `setb`: ignores `v > 30` and only lowers, as `State.setb` does.
* Seed: int8 outputs get 7, a requant einsum output gets `out_bits - 1`.
* Fixpoint `pass`: exact einsums get `ba + bb + nk` if `<= EXACT_MAX_BITS`.
* Final `checkOp`: `bx + 7 + logK <= 30`, `ba + bb <= 30`, shift in `[1, 22]`, exact
  `<= EXACT_MAX_BITS`, requant `<= REQUANT_MAX_BITS` and `shift + out_bits <= 30`. An unbounded
  operand fails.

| Lean theorem | Statement |
|---|---|
| `sound_setb`, `sound_seed`, `exact_bound`, `sound_pass`, `sound_iter`, `sound_bounds` | every bound the algorithm records is true of any witness whose op facts hold (`OpHolds`: field identity + LogUp range facts + int8 weights). Each pass preserves this, so it holds for **every** number of passes, including bounds.zig's `ext.ops.len + 3` cap and its early exit |
| `validate_sound` | if `validate ops fuel = true`, every op satisfies its integer identity (`OpInt`): the hypotheses of `matmul_sound`, `hadamard_sound`, `exact_einsum_sound`, `requant_einsum_sound` are discharged from the computed bounds. So over the fragment, the whole statement's field identities are integer identities |
| two `example`s by `decide` | a concrete accepted graph (range8 -> matmul K=2^16 -> exact einsum) and a rejected one (`7 + 7 + 17 > 30`): the constants agree with bounds.zig's on these cases |

The tie to Zig is by reading. The constants are `EXACT_MAX_BITS`, `REQUANT_MAX_BITS` (the Kernel
defs), 30, `[1, 22]` and 7. There are no differential tests against the Zig function yet. Not
modelled: lookup / glu / product core ops, key-derived bounds (`coveringTerm`, `exprCheck`), lineq
derivation, slices, one-hot facts, Boolean einsums, publics. Each of these only *adds* facts, and
each would need its own soundness case in `sound_pass`.

### 9. End to end: one matmul + requant + range op (`TensorFrontend/EndToEnd.lean`)

`e2e_matmul`: a LogUp range check at a random `x` plus a sumcheck of the committed identity at
`ρ`. For every prover, the number of pairs `(x, ρ)` on which the verifier accepts but
`y != requant_s(Σ x w)` is `<= (2U - 1) |F|^n + |F| · n d |F|^(n-1)`, i.e.
`Pr[accept ∧ relation false] <= (2U - 1)/|F| + n d/|F|`. It composes `logup_random_sound`,
`sumcheck_sound` and `matmul_sound`. The assumptions are explicit hypotheses:

* `IdealOracle ans f`: the PCS is an ideal oracle (the opening equals the committed polynomial's
  value). This replaces the PCS proximity / binding terms.
* `MatmulEncoding`: a valid LogUp multiset gives the integer range facts (table contents), and a
  true sumcheck claim gives the M31 remainder identity. This is the statement's layout, not
  randomness.
* the bound conditions, which `validate_sound` discharges.

Scope: the theorem is about one output entry `y` and one sumcheck whose true claim gives that
entry's identity (`MatmulEncoding.ident`). For a whole output matrix the identity is checked at a
random point of the output MLE, which adds a Schwartz-Zippel term (`opClaimDim / |F|` in
security.zig) and is not modelled; neither are the int8 weights (taken as `hw`, from the key
proof). `OpInt`-style integer statements in `Bounds.lean` are existential over the operand list
(the same list the field identity uses), not tied to a fixed index map.

## Modelling assumptions (stated, not derived)

* **`IndDeg d n f`** (sumcheck): every round function of `f` is a degree `<= d` polynomial. This
  holds for any polynomial of individual degree `<= d`, but the Lean development has no
  multivariate-polynomial type that derives it. The products of multilinears in the matmul /
  einsum / GKR sumchecks are such polynomials. That is a paper fact here.
* **Field model**: QM31 is not constructed in Lean. The sumcheck and LogUp theorems hold for every
  `Lean.Grind.Field` with an explicit element list, which includes QM31. The LogUp characteristic
  hypothesis is a theorem argument. For QM31 it holds with `p = 2^31 - 1`.
* **Integer model**: witness values are the signed representatives in `(-p/2, p/2)`. A field
  identity is a congruence mod `p` of the integer expression. The Lean theorems take the per-tensor
  bounds (`|x| <= 2^bx`, ...) as hypotheses. They prove that the *rule* in `bounds.zig` implies no
  wrap. They do **not** prove that `validateStatementBounds` implements the rule (the fixpoint, the
  slice cover and the one-hot bookkeeping are not modelled), nor that the Zig code matches the Lean
  definitions. That correspondence is by reading.
* **Security per-term values**: the Lean checker re-sums the terms. It does not derive any term.
  The PCS proximity (unique / Johnson), the OOD collision, the lambda/query terms, the PoW discount
  `2^-pow` (a random-oracle claim) and the Fiat-Shamir compilation (`compiledLevel`) are outside the
  Lean development. The mantissas come from the f64 `log2_err` printed by security.zig. The 2^-40
  margin covers f64 rounding of `2**x`. Errors in security.zig's own formulas would not be caught.
* **LogUp shape**: multi-column keys are covered (section 6) with a sequential bound that matches
  the charge for arity 1 and arity `>= 3`, but not for arity 2. LogUp-GKR is covered for one
  instance (section 7) under `LayerConsistent`. Instance batching and masks are not.
* **GKR layer consistency** (`LayerConsistent`): the MLE identities of the honest fraction circuit
  are hypotheses, as `IndDeg` is.
* **Ideal PCS** (`IdealOracle`, section 9) and the **encoding** facts (`MatmulEncoding`) are
  hypotheses of the end-to-end theorem.

## What is not proven (gaps)

1. End-to-end soundness of the *whole* tensor protocol (all ops, GKR batching, gamma batching, PCS,
   Fiat-Shamir) as one Lean theorem. Round 4 states it for one matmul + requant + range op with an
   ideal PCS (`e2e_matmul`), and gives the composition rule (`chain_sound`) and an op-graph no-wrap
   theorem (`validate_sound`). It does not instantiate them for a real statement, and it does not
   link the LogUp-GKR root to the LogUp check of `e2e_matmul`: that theorem uses the direct
   fractional sum.
2. The PCS (Ligero-style, pcs2 recursion), proximity gaps, the Johnson list bound, OOD sampling.
3. Zero knowledge (zk.md). No simulator is stated.
4. A Lean executable verifier, or any refinement between Lean definitions and the Zig code.
5. Multivariate polynomials (so `IndDeg` and `LayerConsistent` are assumed), the batching/`gamma`
   random-linear-combination lemmas for many identities (`lin_count` is the two-term case), and
   the joint two-variable Schwartz-Zippel for `(α, β)`. Without it, arity-2 keys are 0.58 bit
   short of the charged term.
6. The `bounds.zig` rules outside the modelled fragment (slices, one-hot nesting, key coverage,
   lineq derivation, lookups/glu/product), differential tests of the Lean model against the Zig
   function, and the RoPE / RMSNorm / SwiGLU table semantics.
7. Multi-instance GKR (batching by powers, masks for mixed depths), the gap between the GKR root
   and the LogUp claim, and the OOD / PCS terms of the composed bound.

## Comparison with FlashProve's Lean

FlashProve (`~/Coding/ge-cache/flashprove/fp/lean`, Lean 4.29.1 + Mathlib, about 29,500 `.lean`
files) proves six theorems about one compiled committer/prover/verifier `compile (flashProve setup)`
in the random-oracle model (`lean/THEOREM.md`):

* soundness, `q/2^124 + 2^-101`;
* soundness with binding;
* completeness on servable requests;
* zero knowledge (`<= 2^-154`);
* refused requests get the empty proof;
* reply-count fit.

Their IOPs are proved down to Reed-Solomon proximity bounds (adapted from ArkLib/Mathlib), against
an integer model of the network (`IntegerModel/`). Their verifier is a Lean term, run as
`lean-verify`. Their own caveats say that the C++/CUDA programs are *tested*, not proved, to run the
Lean protocol.

| | FlashProve | stwo-zig tensor (rounds 3 + 4) |
|---|---|---|
| Integer model / no-wrap | full integer model of the network (`IntegerModel/`), statement-level bounds | requant, matmul / hadamard / einsum / lineq no-wrap, softmax division: lemmas, not a network model |
| Sumcheck | inside the proven IOPs | `sumcheck_sound`, any adaptive prover, counting bound `n d/|F|`. Round-by-round composition `chain_sound` |
| LogUp | inside the proven IOPs | arity 1 and multi-column `(α, β)` (sequential bound; arity 2 0.58 bit short of the charge), single-instance LogUp-GKR layers + N-layer composition |
| Statement no-wrap | integer model of the network | `validate_sound` on a model of `validateStatementBounds` (fragment: matmul, hadamard, range8, exact/requant einsum) |
| End to end | the six top-level theorems | one op (matmul + requant + range), ideal PCS as a hypothesis |
| PCS / codes | proved (RS proximity, Johnson, BCHKS25 Thm 4.6 as their Lemma 5.13) | none |
| Fiat-Shamir / ROM | proved (q-query bound) | none |
| Zero knowledge | proved | none |
| Security accounting | the final bound is a theorem | union-bound rule proved. Toy term list re-summed exactly. Terms trusted |
| Executable verifier | yes (`lean-verify`) | no (only the security re-check executable) |
| Dependencies | Mathlib (pinned) | none (Lean core 4.35.0) |

FlashProve's Lean is far ahead: it covers the whole protocol, and rounds 3 + 4 cover the
arithmetic core, the sumcheck / LogUp / LogUp-GKR building blocks, a statement no-wrap model and one end-to-end op. The design choices here (zero-dep, abstract
`Lean.Grind.Field`, counting probability) keep the build fast and auditable. A full development of
FlashProve's kind would need Mathlib/ArkLib (as `supercompiler-stark/lean` uses for its LogUp-GKR
and sumcheck entries) for polynomials, probability and codes.

## Next steps (suggested order)

1. A multivariate individual-degree polynomial type, so that `IndDeg` and `LayerConsistent` are
   derived. With it, the joint `(α, β)` Schwartz-Zippel bound, which closes the arity-2 gap.
2. Multi-instance GKR batching and masks, then link `gkr_sound`'s root claim to the LogUp check, so
   that `e2e_matmul` uses LogUp-GKR rather than the direct fractional sum.
3. Extend the `Bounds` model to slices, one-hot facts, key coverage and lineq derivation, and test
   it against `bounds.zig` (dump the bound vector from `validateStatementBounds(.., out)` for the
   test statements and compare it with the Lean `bounds`), as `formal/riscv-refinement` does for
   the RV64 AIR.
4. A Lean statement of the full IOP and a port of ArkLib's proximity results for the PCS. That is
   where Mathlib becomes necessary.
