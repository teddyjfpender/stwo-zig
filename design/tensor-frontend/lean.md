# Lean formal proofs for the tensor frontend

Status: first increment. A zero-dependency Lean 4 project (`leanprover/lean4:v4.35.0`, Lean core
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
the `tensor-security-check` executable, prints `#print axioms` for the 24 headline theorems
(`Audit.lean`) and fails unless each depends only on `propext`, `Classical.choice` and `Quot.sound`
(or on no axiom). It also fails on any `sorry`, `axiom` declaration or `native_decide` in the
sources, then runs the security cross-check. Building from scratch takes a few seconds and well
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
| `softmax_div_sound` | two range-checked slacks `u, v ∈ [0, 2^(lt+9))`, their M31 identities, `od = o·den`, and the bounds `|acc|, |od|, den <= 2^28`, `lt <= 19` together imply `o = round(acc/den)` | `transformer.zig` `rangeWide` pair |

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
* **LogUp shape**: the theorems are for arity-1 keys (a single field value per entry, one random
  `x`). The multi-column keys `α - (v_0 + β v_1 + ...)` with two challenges, and LogUp-**GKR** (the
  layered fraction-sum sumcheck), are not formalised. The GKR layers' sumcheck rounds are covered
  by `sumcheck_sound` only in the abstract.

## What is not proven (gaps)

1. End-to-end soundness of the tensor protocol (composition of GKR, op sumchecks, batching, PCS,
   Fiat-Shamir) as one Lean theorem. Nothing here states "accepting implies the outputs are the
   integer model's".
2. The PCS (Ligero-style, pcs2 recursion), proximity gaps, the Johnson list bound, OOD sampling.
3. Zero knowledge (zk.md). No simulator is stated.
4. A Lean executable verifier, or any refinement between Lean definitions and the Zig code.
5. Multivariate polynomials (so `IndDeg` is assumed), the batching/`gamma` random-linear-combination
   lemmas (a Schwartz-Zippel bound for degree-1 combinations follows from `roots_le` but is not
   stated), and multi-variable Schwartz-Zippel for the LogUp `(α, β)` denominators.
6. The `bounds.zig` derivation algorithm itself (fixpoint, slices, one-hot nesting) and the RoPE /
   RMSNorm / SwiGLU table semantics.

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

| | FlashProve | stwo-zig tensor (this increment) |
|---|---|---|
| Integer model / no-wrap | full integer model of the network (`IntegerModel/`), statement-level bounds | requant, matmul / hadamard / einsum / lineq no-wrap, softmax division: lemmas, not a network model |
| Sumcheck | inside the proven IOPs | `sumcheck_sound`, any adaptive prover, counting bound `n d/|F|` |
| LogUp | inside the proven IOPs | identity form and random-evaluation form, arity 1. No GKR |
| PCS / codes | proved (RS proximity, Johnson, BCHKS25 Thm 4.6 as their Lemma 5.13) | none |
| Fiat-Shamir / ROM | proved (q-query bound) | none |
| Zero knowledge | proved | none |
| Security accounting | the final bound is a theorem | union-bound rule proved. Toy term list re-summed exactly. Terms trusted |
| Executable verifier | yes (`lean-verify`) | no (only the security re-check executable) |
| Dependencies | Mathlib (pinned) | none (Lean core 4.35.0) |

FlashProve's Lean is far ahead: it covers the whole protocol, and this increment covers the
arithmetic core and two IOP building blocks. The design choices here (zero-dep, abstract
`Lean.Grind.Field`, counting probability) keep the build fast and auditable. A full development of
FlashProve's kind would need Mathlib/ArkLib (as `supercompiler-stark/lean` uses for its LogUp-GKR
and sumcheck entries) for polynomials, probability and codes.

## Next steps (suggested order)

1. A multivariate individual-degree polynomial type, so that `IndDeg` is derived. Add the batching
   lemma (random linear combination, `deg/|F|`).
2. LogUp-GKR: the layered fraction sumcheck reduction, then the `(α, β)` multi-column keys
   (two-variable Schwartz-Zippel).
3. A Lean model of `validateStatementBounds` (fixpoint over the rules proved here), refined against
   the Zig code by differential tests, as `formal/riscv-refinement` does for the RV64 AIR.
4. A Lean statement of the full IOP and a port of ArkLib's proximity results for the PCS. That is
   where Mathlib becomes necessary.
