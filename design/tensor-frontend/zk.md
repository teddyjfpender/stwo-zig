# Tensor frontend: zero-knowledge mode (`Config.hiding`)

Stream: zero knowledge (branch `codex/tensor-zk`). Code: `src/tensor/zk_pcs.zig`
(hiding PCS), `src/tensor/zk_sumcheck.zig` (masked sumcheck), `src/tensor/zk.zig`
(hiding protocol, hiding weight store), `src/tensor/zk_bench.zig` (`tensor-bench ... zk`).
The non-hiding protocol (`protocol.zig`, `pcs.zig`) is unchanged. The only edit there
is two new `Config` fields, `hiding = false` and `weight_mask_slots`.

## 1. Goal and model

The statement is public: ops, shapes, shifts, tables and the weight commitment's root.
The witness is private: activations, requant remainders, LogUp multiplicities. So are the
weights: the committed int8 table.

The claim is honest-verifier zero knowledge of the interactive protocol, with simulator
error ≤ `poly(#claims, n) / |QM31|` ≈ 2^-110. Compiled with Fiat–Shamir (Blake2s channel)
and salted Merkle commitments, it is zero knowledge in the random-oracle model against
verifiers that see any number of proofs, under two conditions:

1. **Fresh prover randomness per proof.** A ChaCha20 stream keyed by 32 bytes of OS
   entropy (`zk_pcs.Rng.initOs`). There is no seed parameter in the proving API.
2. **The weight commitment's opening budget is respected.** See §3.4. It is enforced in
   code: the prover refuses with `error.OpeningBudgetExceeded` before releasing anything.

This matches FlashProve's model ("fresh random masks, one commitment, opening budget"),
with the budget enforced instead of being an operator duty.

## 2. What the non-hiding v1 protocol reveals

Inventory used to decide what to mask:

| v1 proof field | content | leak |
|---|---|---|
| witness / weight combined rows `u_g = Σ a_i row_i` | `C` linear combinations of table rows | direct linear leak of witness and weights |
| opened columns | `t` RS symbols per row, unsalted leaves | linear leak; leaves allow testing guesses |
| `witness_value`, `weight_values`, `op_finals`, `lookup_in_values` | MLE evaluations at random points | linear functionals of witness / weights |
| sumcheck round polynomials | partial sums of products | low-degree functions of the witness |
| **LogUp-GKR** output claims | per-instance root fractions `Σ_x 1/(α − key(x))` (num, den) | symmetric functions of each key multiset, i.e. of the multiplicity histograms |
| GKR layer masks | `num_k, den_k` MLEs of every tree layer at `(r, 0)`, `(r, 1)` | evaluations of partial fraction sums of the witness keys; the bottom layer gives the key MLEs at a random point |
| GKR layer sumchecks | degree-3 round polynomials of every layer | as above |

A GKR transcript can be made hiding (Libra/Virgo: a masking polynomial per layer
sumcheck, plus committed per-layer masks that blind the layer evaluations). That needs
per-layer pad terms inside each layer's sumcheck and a separate treatment of the top
layers, whose domain is smaller than a pad, and it changes stwo's fast GKR prover. See §7.
This implementation instead **replaces GKR in hiding mode** by LogUp with committed
inverses. Every check is then a masked zero-check or a linear claim, and one argument (§4)
covers the whole proof.

## 3. Hiding PCS (`zk_pcs.zig`)

Tables of `R` rows × `C = 2^lc` columns of M31. The row-major index `row·C + col` gives
the MLE with row variables first.

### 3.1 Masked encoding

Row `i` is the circle polynomial with coefficients `(m_i[0..C), τ_i[0..S))`: the message
followed by `S = slots` uniform M31 coefficients. It is RS-encoded on the canonic coset
of size `E = 2^(lc+lb)`, with `C + S ≤ E/2`.

**Lemma 1 (any S/2 columns are uniform).** The slot basis elements are
`b_{C+s} = π^{lc-1}(x)·b_s` for `s < S ≤ C`, where `b` is stwo's circle FFT basis and
`π` is the doubling map. So their span is `π^{lc-1}(x)·L_S`, with
`L_S = {p(x) + y·q(x) : deg p, q < S/2}`.

- `π^{lc-1}(x)` has no zero on the canonic coset when `lb ≥ 1`. Its zeros are at angles
  `π/2^lc · odd`, and the coset points sit at `2π/2^(lc+lb+1) · odd`.
- `y ≠ 0` on the coset.

For a set `Q` of at most `S/2` positions, split `Q` into conjugate pairs and singletons.
Choosing `p` and `q` by univariate interpolation on the at most `S/2` distinct
x-coordinates (`p` on all of them, `q` on the paired ones) hits any target values. So the
evaluation map `τ ↦ Enc(0; τ)|_Q` is onto, and `Enc(m; τ)|_Q` is uniform and independent
of `m`.

Test `masked encoding: slot span is onto any slots/2 positions` checks the rank over 300
sampled position sets, including adjacent and strided clusters. It also checks that every
position has a non-zero slot evaluation.

**Cost to soundness.** The code rate becomes `(C + S)/E`. The bench reports
`conjectured_bits = t·log2(E/(C+S)) + pow` and the unique-decoding bound for that rate.

### 3.2 Salted leaves

`leaf_j = Blake2s(column_j ‖ salt_j)`, with a 32-byte salt per column from the prover RNG.
A salt is revealed only with its column. In the ROM, unopened leaves and Merkle siblings
are uniform strings, so the root and the paths are simulatable.

### 3.3 Masked combined rows and the opening

A claim is a rank-1 form. It has a row-coefficient vector per table and a column vector
`b`. A group shares `b`. Every revealed combined row gets its own 4 mask rows `M_0..M_3`:
rows of uniform cells, never used by any other claim.

- **Proximity row:** `u_0 = Σ_i β_i row_i + β_μ Σ_k e_k M^0_k`. The `β` are uniform per
  row, `e_k` is the QM31 basis over M31, and `β_μ` is one challenge. The map
  `(M_0..M_3) ↦ β_μ Σ e_k M_k` is a bijection onto `QM31^(C+S)` when `β_μ ≠ 0`.
- **Group `g`:** the prover first sends `μ_g = Σ_k e_k ⟨M^g_k, b_g⟩`, which is batched as
  one more claim on rows that are already committed. Then
  `u_g = Σ_c γ_c a_c·rows + γ_μ Σ_k e_k M^g_k`, and the verifier checks
  `⟨u_g[0..C), b_g⟩ = Σ_c γ_c v_c + γ_μ μ_g`.
- **Queries:** after PoW, the verifier draws `t` positions shared by all tables of the
  opening. For each table and position it receives the column, the salt and the Merkle
  path, and checks `Enc(u)[j] = Σ_tables Σ_i A_i·col_i[j]` for every combined row.

**Soundness.** This is the v1 Ligero argument with more claims. The mask claim `μ_g` is
an ordinary claim on committed rows, and it is batched with a challenge drawn after
`μ_g` is fixed. Structured coefficients `γ e_k` on the 4 mask rows act as one QM31-valued
row (the QM31 code is the M31 code ⊗ QM31, and agreement of a QM31 row on a set implies
agreement of each M31 coordinate). The per-proof mask table of the weight opening is not
separately proximity-tested. If it is far from the code, `Σ a·W + γ e·M` is far from the
code, because `W` is close by the commit-time test and the mask term is a non-zero
multiple of a fixed far word. The `t` consistency queries then reject except with
probability `(1−δ)^t`.

**Lemma 2 (opening ZK).** Given the claim values, the opening is simulatable while every
table opens at most `S/2` distinct columns. The simulator:

1. samples the `μ_g` uniformly;
2. samples each `u` uniformly subject to its single eval check;
3. samples every non-mask row's columns at `Q` uniformly (Lemma 1);
4. solves the mask rows' columns from the consistency equations, a bijection per
   position because the mask coefficients are `c·e_k`, `c ≠ 0`; the group masks are
   solved first and the proximity masks last, since the proximity row also touches
   group masks.

The real distribution is the same: each `u` is uniform because of its own masks, data
columns are uniform by Lemma 1, and mask columns are then determined.

### 3.4 Opening budget

`budget = S/2` distinct columns per commitment over its lifetime. `Commitment.budget`
counts the union of opened positions and `finish` refuses to exceed it. The per-proof
witness tables use `S = slotsFor(t)`, the next power of two ≥ `2t` (128 for t = 54 or
64). They are opened once.

The weight table (`ZkWeights`) is committed once with `S = weight_mask_slots`. Its
commit-time proximity test and each proof spend up to `t` columns. Tradeoff, measured on
mlp 8 10 11 (`C_w = 1024`, lb 2, t 64):

| weight_mask_slots | weight rate | conj. bits (weights) | budget (columns) | proofs per commitment |
|---|---|---|---|---|
| 1024 | 0.5 | 84.0 | 512 | ~7 |
| 256 | 0.3125 | 127.4 | 128 | ~1 |

With the production shape (`C_w = 4096`, 1024 slots) the rate is 0.3125: 127 bits and a
budget of 512 columns, about 7 proofs per commitment. FlashProve's budget is 44M columns
because its rows are much longer. Raising this budget is the main open item for weight
hiding; see §8 (weight-specific blowup, re-randomized copies with a link proof). Weights
also carry 4 pad rows `R_W` (`C_w` cells each) for the masked weight evaluations of §4.2.
They tolerate about `4·C_w` revealed functionals, which never binds.

## 4. Masked sumchecks and the protocol (`zk_sumcheck.zig`, `zk.zig`)

### 4.1 Masked sumcheck

To prove `Σ_{x∈{0,1}^n} G(x) = c` for `G = Σ_t coeff_t Π_j F_j` of degree `d ≤ 3`, with
`c` public:

- **Hiding polynomial** (FlashProve `blocks/iop/hp.h`, after Libra):
  `U(X_0..X_{n−1}, Y) = Σ_l w_l(X_l)·Π_{j>l} ψ_j(X_j)`.
  - `ψ = X` for plain variables, summed by `φ(g) = g(0)+g(1)`.
  - `ψ_Y = 1` for one extra variable `Y`, summed by `φ_Y(g) = g(0)`.
  - Each `w_l` has `d+1` uniform QM31 coefficients. The constant term is 0 except for
    `Y`, so there are `(n+1)d+1` entries.
  - The coefficients are cells of the committed witness table, 4 M31 cells per entry.
- The prover sends `σ = ΣU`. The verifier draws `ε`, and the sumcheck runs on `U + εG'`
  with claim `σ + εc`. Round messages are `q(0), q(2..d)` for plain variables
  (`q(1)` is implied), and `q(1..d)` for `Y` (`q(0)` is implied, because `φ_Y`).
- **Hat round** (variable `Y`). `G'(x, Y)` uses `F^_j(x, Y) = (1−Y)F_j(x) + Y·p_j` for
  every committed factor. `p_j` is the value of a committed pad at a point derived from
  the sumcheck point. Public factors (`eq`) are constant in `Y`. Since `φ_Y` reads only
  `Y = 0`, the claimed sum is that of `G`. After challenge `γ`, the prover reveals the
  hats `F^_j = (1−γ)F_j(r) + γ p_j` and `u = U(r, γ)`.
- **Verifier:** `q_Y(γ) = u + ε·G(hats, public values)`. It then queues linear claims:
  `σ` and `u` on the U cells (`Hp.sumForm`, `Hp.evalForm`, tested against brute force),
  and each hat as `(1−γ)·scale·T(local point) + γ·Pad(last 4 coords)` on the factor's
  tensors.

**Soundness.** `σ` and `u` are verified through the PCS. `ε` is drawn after `σ`, so a
false `c` makes the total claim false except with probability 1/|F|. Then apply standard
sumcheck soundness over `n + 1` variables. The `Y` variable is one more variable with
functional `g ↦ g(0)`, error `d/|F|`.

**ZK (Lemma 3).** For any fixed challenges, the map from U's coefficients to
`(σ, round polynomials)` is a bijection onto the transcripts that pass the round checks.
This is FlashProve's "fact 2"; there, small fields were checked by enumeration. So the
messages of `U + εG'` are uniform given the claim. The hats are uniform given everything
else, because each carries `γ·(fresh pad functional)` with `γ ≠ 0`. `u` is determined by
the final check.

### 4.2 Statements as masked zero-checks (public claims only)

For each relation, `ρ` is a suffix of one common random vector. All matmuls share
`ρ_n`, so all weight claims share their column point.

- **product** `c = a∘b`: `Σ eq(ρ,x)(a·b − c) = 0`.
- **hadamard** with requant: `Σ eq(ρ,x)(A·B − 2^s Y − r) = −2^(s−1)`. The remainder `r`
  is a committed tensor in hiding mode; it is virtual in v1.
- **matmul** with requant: `Σ_z [X(ρ_t, z)·W(z, ρ_n) + eq(ρ, z)(−2^s Y(z) − r(z))] = −2^(s−1)`.
  This is one sumcheck over `max(lk, lt+ln)` variables with top zero-extension, so the
  hats carry the scale `Π(1 − r_hi)`. The prover folds `X·eq(ρ_t)` and `W·eq(ρ_n)` as in
  v1. The W hat is a claim on the weight commitment, padded by `R_W(s, colpoint)`.
- **LogUp** (range8, requant output range, remainder range `2^s`, int8 lookup with `β`).
  Table 2 is committed after `α, β`. It holds `h_k = 1/(α − key_k)` as 4 M31 limb
  tensors, plus pads. Per key instance there is a masked zero-check
  `Σ eq(ρ,x)·h(x)·(α − key(x)) = 1`. Per relation there is a linear claim with public
  value 0: `Σ_k Σ_x h_k(x) − Σ_t m(t)/(α − key_t) = 0`.
  - Soundness: `m` is committed before `α` and `h` after it. The zero-check forces
    `h = 1/(α − key)` on the cube except with probability `n/|F|`. LogUp then gives
    multiset inclusion except with probability `(#keys + #table)/|F|`, since the
    characteristic exceeds the counts.

All claim values are public (0, ±2^(s−1), 1), so nothing about the witness enters as a
claimed value.

### 4.3 Batch and openings

- **Batch.** All linear claims on tables 1 and 2 are combined with `γ`s drawn after every
  value is in the transcript. Hats, `σ` and `u` are mixed by the sumchecks; the zeros
  are public. One masked sumcheck `Σ T_1 E_1 + Σ T_2 E_2` follows, with `E` public, the
  tables zero-extended, and only `max(used)` entries touched.
- **Batch hats.** Pad: one full row `R_b` per table, evaluated at the batch column point.
  So `(1−γ)·T(r) + γ·R_b(r_col)` is a single group with column vector `eq(r_col)`
  spanning both tables.
- **Batch hiding polynomial.** It sits in one row of table 1. Its claims `σ_b` and `u_b`
  are combined with `ζ`, drawn after `u_b` is mixed; this was a soundness fix during
  development. They form a second group with an explicit column vector.
- **Witness opening.** One multi-table opening: the proximity row plus groups A and B,
  each with its own 4 mask rows in table 1.
- **Weight opening.** One group, with the weight table and a fresh per-proof 4-row mask
  table (committed at the start, root in the transcript). No proximity row; that test
  is done at commit time.

### 4.4 Zero-knowledge argument (whole proof)

Hybrid over the transcript, in order:

1. **Commitments.** Roots are uniform (salted leaves, ROM).
2. **`α, β, ρ`.** Public coins.
3. **Each masked zero-check.** Messages are uniform given the public claim (Lemma 3).
   Each hat is `γ·(pad functional) + (witness part)`. `u` is determined.
4. **Batch.** Messages are uniform given the public batch claim (Lemma 3). The batch
   hats are padded by the `R_b` rows. `ζ`; `σ_b + ζu_b` is determined.
5. **Openings.** Simulatable given the group claim values (Lemma 2), which steps 3–4
   already simulate.

**Rank condition.** Let `P` be the vector of all pad cells. The revealed linear values
are `A_D·D + A_P·P`, and they are jointly uniform iff `A_P` has full row rank.

- Every pad tensor has 16 cells (or `R_b`/`R_W` rows of `C` cells). It is used only by
  hats of its own tensor, at points that are fresh random points of different
  sumchecks.
- The most uses are about 3 hats per tensor in the MLP: for example `X` in two matmuls
  and range8, or `Y_g` in matmul, y-range and lookup.
- `eq` vectors of ≤ 16 distinct random points in 16 dimensions are independent except
  with probability ≤ 16·4/|F|.
- Mask rows and `R_b` appear in the batch's table evaluation too, but each revealed
  value has its own fresh direction: hat ↔ its pad, `σ`/`u` ↔ its U, `μ` and `u` rows ↔
  their masks.

The prover's randomness is fresh per proof, except the weight table's `τ`, `R_W` and
proximity masks, which are shared across proofs. Their exposure is bounded by the budget
(columns) and by `4·C_w` (`R_W` functionals).

**Tests that exercise this** (`zk.zig`):
- Two proofs of the same statement have different roots and hats.
- Statistical sanity: an all-zero witness versus a uniform witness. Opened column values
  of every row, combined rows and all hats have a top-bit ratio and a mean within 0.02
  of 1/2, and no zeros (without masks the zero witness gives zero data columns and zero
  finals).
- Tampering with each proof field is rejected (§6).

## 5. Measurements

M4 Max, AC power, `ReleaseFast`, memguard. FlashProve CPU numbers are from fp-bench on
the same machine.

| bench | mode | prove | verify | proof | notes |
|---|---|---|---|---|---|
| product 20, 1 thread, t 54 | non-hiding | 0.337 s | 1.63 ms | 323,352 B | 128 conj bits |
| product 20, 1 thread, t 54 | **hiding** | **0.360 s** | **2.31 ms** | **400,824 B** | 125.6 conj bits (rate (4096+128)/16384); 56 queries for 128 |
| FlashProve toy (`a∘b = c`, 2^20, 1 core, hiding) | hiding | 8.37 s | 14 ms | 341 KB | reference |
| mlp 8 10 11, 8 threads, t 64 | non-hiding | 0.195 s | 7.4 ms | 1,966,288 B | GKR |
| mlp 8 10 11, 8 threads, t 64 | **hiding** | **0.74–0.90 s** | **13–17 ms** | **2,844,720 B** | committed-inverse LogUp; weight slots 1024 → weights 84 conj bits (256 slots: 127.4 bits, 2,832,432 B) |

Hiding MLP breakdown (0.74 s run):
- commit 0.31 s (tables 1+2, 22.4M cells; table 2 = 17.8M of them),
- LogUp zero-checks 0.07 s,
- op sumchecks 0.04 s,
- batch 0.27 s,
- openings 0.03 s.

Before the active-length change the hiding MLP prove took 1.01 s and peak RSS was 3.2 GB.
After it, RSS is 2.2 GB.

## 6. Adversarial tests (all passing, `zig build test -Doptimize=ReleaseSafe`)

- `zk_pcs`:
  - two tables with groups and masks: wrong claim value, tampered `μ`, salt, column
    value and combined row are each rejected;
  - the budget refuses to exceed `slots/2`;
  - slot-span rank test.
- `zk_sumcheck`:
  - hiding-polynomial forms against brute force for `d = 2, 3`;
  - masked sumcheck completeness;
  - a wrong claim and a tampered hat each break the final check.
- `zk` product:
  - tampered hat, `σ`, `u`, round message, batch hat, batch `σ`, opening row, `μ`,
    column and root are each rejected;
  - a wrong witness is refused by the prover.
- `zk` MLP:
  - weight proximity verifies and a tampered proximity row is rejected;
  - the proof verifies;
  - tampered W hat, LogUp round, weight-opening row, shift and weight root are each
    rejected;
  - after a few proofs the budget is exhausted and the prover refuses
    (`error.OpeningBudgetExceeded`);
  - a wrong forward value is refused.
- Statistical sanity test (§4.4).

## 7. GKR in hiding mode: analysis and the route to a hiding GKR

What stwo's batched LogUp-GKR reveals is listed in §2. A hiding GKR needs three things.

1. **Masked layer sumchecks.** `zk_sumcheck` applies directly: 7 factors
   `eq, λn0, λn1, d0, d1, eq_tail, Q`, degree 3.
2. **Hats on every layer's four finals**, with 16-cell pads per final. The next layer's
   claim is then `(1−γ)·layer(r) + γ·pad(t)`. That layer's sumcheck must absorb
   `γ·pad(t)` as an extra term `Σ_x eq(s, x)·Q(x)`, where `Q` is the pad broadcast over
   the trailing variables. For layers with fewer than 4 variables, `Q` is the pad
   partially evaluated at the leading coordinates of `t`. Its final value is one more
   independent linear claim on the pads.
3. **A multiplicative blinder leaf `(0, ρ)`** per relation tree, so that the root
   denominator is uniform. The root numerator is checked to be 0. Table leaves go
   inside each relation tree with numerators `−m(t)`, so the root is public.

This removes table 2 (17.8M cells in mlp 8 10 11) and its batch and opening share. The
estimate is about 0.4 s for hiding MLP proving and about 0.6 MB less proof. It is not
implemented in this stream. The committed-inverse route was chosen because every
component is a reuse of the two primitives above, with one uniform ZK argument.

Rejected shortcut: interleaving random pad leaves (MSB half) makes all GKR layers above
the leaves uniform, so only the bottom layer would need masking. But the pads must be
uniform QM31 fractions, which is 8 committed M31 cells per data leaf, worse than the
4 limbs of committed inverses.

## 8. Not done / caveats

- **Weight budget.** About 7 proofs per weight commitment at the production shape. Next
  steps:
  - weight-specific PCS parameters (higher blowup and fewer queries for the
    committed-once table, e.g. lb 4: 2 more bits per query, so about 36 queries, a
    budget of `C_w/2`, and a smaller weight opening);
  - re-randomized weight copies with a link proof, a 2-table opening of `T_old − T_new`
    at a random point with claim 0.
- **GKR hiding** (§7) is designed, not implemented. The hiding mode uses
  committed-inverse LogUp: 5× the non-hiding MLP prove time at this size.
- `hiding` is a separate entry point (`zk.prove` / `zk.verify` / `zk.commitWeights`).
  `protocol.prove` ignores the flag; the bench selects with a `zk` argument.
- **ZK is honest-prover zero knowledge.** It needs fresh OS entropy. A verifier cannot
  check that the prover used fresh randomness (same caveat as FlashProve and s31).
- The proofs here are written arguments, not machine-checked. The bijection lemma for
  the hiding polynomial is taken from FlashProve (enumeration-checked there). Lemma 1 is
  proven above and spot-checked by the rank test.
- **Security accounting.** The slots raise the code rate (witness 1.96 instead of
  2.00 bits per query at lb 2). The bench reports conjectured and unique-decoding bits
  per opening. The weight opening at `C_w = 1024` with 1024 slots has only 84
  conjectured bits; use ≤ `C_w/4` slots or a larger weight blowup.
