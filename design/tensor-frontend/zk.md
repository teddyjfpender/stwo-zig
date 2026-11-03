# Tensor frontend: zero-knowledge mode (`Config.hiding`)

Stream: zero knowledge (branch `codex/tensor-zk`). Code:

- `src/tensor/zk_pcs.zig`: hiding PCS.
- `src/tensor/zk_sumcheck.zig`: masked sumcheck.
- `src/tensor/zk.zig`: hiding protocol, hiding LogUp-GKR, hiding weight store.
- `src/tensor/zk_bench.zig`: `tensor-bench ... zk`.

The non-hiding protocol (`protocol.zig`, `pcs.zig`) is unchanged. The only edits there are
new `Config` fields: `hiding = false`, `weight_mask_slots`, `weight_pcs`, and
`zk_logup_gkr = true`.

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

Hiding mode therefore runs its own **masked LogUp-GKR** (§4.3, default) in place of stwo's
fast GKR prover. Each layer's sumcheck is masked, each layer's evaluations are revealed
only as pad-masked hats, and the root denominator is blinded. LogUp with committed inverses
is kept as an option (`Config.zk_logup_gkr = false`). It is simpler, but costs 4 committed
M31 cells per key.

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

The weight table (`ZkWeights`) is committed once with `S = weight_mask_slots`, and has its
own PCS parameters (`Config.weight_pcs`, bound into the transcript). Its commit-time
proximity test and each proof spend up to `t_w` columns. Measured on mlp 8 10 11
(`C_w = 1024`):

| weight lb / queries / slots | rate | conj. bits (weights) | budget (columns) | used per proof | weight opening |
|---|---|---|---|---|---|
| 2 / 64 / 1024 | 0.5 | 84.0 | 512 | ~62 | 1.66 MB |
| 2 / 64 / 256 | 0.3125 | 127.4 | 128 | ~62 | 1.65 MB |
| 4 / 36 / 1024 | 0.125 | 128.0 | 512 | ~36 | 0.95 MB |
| **4 / 30 / 1024 with `C_w = 4096`** (bench default, §4.4) | 0.078 | **130.3** | 512 | **~30** | **0.47 MB** |

The hiding weight table may be wider than the smallest matmul output dimension
(`weight_log_cols`, default `min(ld+2, 14)` in the bench). Each matmul whose output
dimension is smaller than the column count then gets its own opening group.

With the bench defaults (lb 4, slots = `C_w/4`, queries for 128 bits) a commitment serves
about `C_w/(8·30)` proofs: about 17 at `C_w = 4096` and about 68 at `C_w = 16384`. The
cost is a 4× larger one-time weight encoding (0.08 → 0.28 s at this size), and 16× the
weight count in M31 cells of memory at lb 4. FlashProve's budget is 44M columns because
its rows are much longer.

Weights also carry 4 pad rows `R_W` (`C_w` cells each) for the masked weight evaluations
of §4.2. They tolerate about `4·C_w` revealed functionals, which never binds.

### 3.5 Recursive hiding PCS (`zk_pcs2.zig`, `Config.two_level`)

The flat hiding opening sends every masked combined row `u_o` (`C + S` QM31 values each),
plus `t` full columns with full Merkle paths. That is most of the hiding proof. The
recursive mode keeps the outer tables and the combination rows of §3.3 exactly as they are,
and opens them the pcs2 way (size.md §1): the rows are committed, not sent.

**Construction.** After `zkp.drawCoeffs` (claim values and `μ_g` mixed, `γ`, `β`, `β_μ`)
and the combined rows `u_o` (proximity row first, then one row per group, each carrying
`c·Σ_k e_k M_k` of its own 4 mask rows):

1. The prover commits `V[g][c][k] = limb_c(u_g[k])`. The rows are zero-padded to
   `G' = 2^⌈log G⌉` and to a `2C`-coefficient message; `S ≤ C` is required. This is a
   plain `pcs.commit` with the inner parameters. The inner root is mixed.
2. `ρ` (log G' coordinates), then `λ = eq(ρ, ·)`, PoW, then `t` query positions shared
   by all outer tables. **Lifetime budgets are charged here**, before anything is
   released.
3. Opened outer columns: values plus salt per table, with one Merkle **multiproof** per
   table (sorted, deduplicated positions; leaf `Blake2s(column ‖ salt)`). The verifier
   computes `y_j = ⟨Σ_o λ_o A_o, col_j⟩`.
4. Claims on `U`:
   - the eval checks `⟨u_g[0..C), b_g⟩ = Σ_c γ_c v_c + γ_μ μ_g`;
   - the **head-restricted** encodings `Σ_g λ_g Enc_head(u_g)[j] = y_j`, where
     `Enc_head(u)[j] = Σ_{k < C+S} u_k b_k(P_j)`.

   Both are batched with `γ'`. One degree-2 sumcheck over the `G' × 2C` cube reduces them
   to `U~(r)`. The verifier evaluates `W~(r)` in `O(t·lc)`:
   - the eval part is `(1 − r_k0)·b~_g(r_k[1..])`;
   - the head is two aligned blocks, `[0, C)` and `[C, C+S)`, each a product of
     per-variable factors (`zk_pcs2.headEval`, tested against brute force).
5. The four limb values `V~(r_g, c, r_k)` are sent and form one claim group of the
   committed-row table. Levels ≥ 1 are **plain pcs2 levels** (`pcs2.openRec` /
   `verifyRec`): unsalted, no slots, no masks, proximity at every level.

Wiring:

| opening | outer tables | proximity row |
|---|---|---|
| witness | tables 1 (+2) | yes, mask rows of table 1 |
| weights | weight table + per-proof mask table | **new**: 4 extra mask rows, covers both tables |
| weight proximity (once) | weight table | yes |
| re-randomization link | old, new, per-proof mask table (8 rows) | yes, covers all three |

The mode and the inner parameters (depth, inner queries / blowup / PoW, work shift,
proximity rows) are mixed into the statement transcript. A flat-mode verifier rejects a
recursive proof and vice versa (`error.ProofShape`), and so does a verifier with another
depth. With `two_level = null` every hiding proof is byte-identical to before.

**Witness column split.** `recLogCols` picks `lc` to minimize the predicted opening bytes
(`zk_pcs2.predictBytes`: outer columns, salts, multiproof, and pcs2's model for the levels
below). The committed-row encoding (`2 · 4 · 2C` cells at the inner blowup) must stay
within `max(used >> inner_work_shift, 2^14)`, as in pcs2. The choice depends only on
public sizes, so prover and verifier agree.

**Lemma 4 (zero knowledge of the recursive opening).** Fix the claim values and the outer
query set `Q`, with `|Q| ≤ S/2` per table over the table's lifetime. The view of the
opening is

    (μ, inner root, ρ, PoW, Q, cols_Q, y, γ', sumcheck messages, limb values, inner levels)

Every component after `cols_Q` is a deterministic function of the combined rows
`U = (u_o)`, the public coins and public data:
- `y` is computed from `cols_Q`;
- `V = limbs(U)`, so the inner root, the sumcheck messages, the limbs and every pcs2
  level are functions of `U` and of coins;
- PoW nonces are functions of the transcript.

Lemma 2 (§3.3) already simulates `(μ, U, cols_Q)` jointly: in the flat mode exactly these
values are revealed, `U` row by row. The simulator therefore:
1. samples `(μ, U, cols_Q)` with Lemma 2's simulator;
2. runs the honest recursive prover on the simulated `U` with the simulated coins.

The output has the real distribution: the real view is the same function applied to the
real `(μ, U, cols_Q)`. ∎

Consequences:
- **Inner levels need no masks, slots, salts or budget of their own.** Opening any number
  of inner columns reveals only functions of `U`. "Per-level budgets" are therefore:
  - outer per-proof tables: `t ≤ S/2`, by `slotsFor(t)`;
  - the long-lived weight table: the union of all its opened positions, over the proximity
    proof, every proof and every link, is ≤ `S_w/2`. This is enforced by
    `Commitment.budget`, as before; the recursive mode spends `t_w` per proof, like the
    flat mode;
  - inner tables: none needed.
- Masking every level, with salted leaves, slots and mask rows, would be redundant. It
  would cost about `(S_l + 4·rows)` extra cells per level and inner opening bytes, and
  would not improve the simulator.
- **Fiat–Shamir.** Standard compilation of a public-coin HVZK argument in the ROM:
  - the simulator programs the oracle at the challenge points;
  - unopened salted outer leaves and their multiproof siblings are uniform strings;
  - the inner Merkle tree is computed honestly from the simulated `U`, so its unsalted
    leaves need no programming.

**Soundness.**
1. **Proximity of the outer tables.** Treat the outer tables as one stacked table: same
   columns, same query positions. Every outer table is close to the code of message
   length `C + S` (rate `ρ_c = (C+S)/E`), in the correlated-agreement sense:
   - the witness tables, by the per-proof proximity row;
   - the weight table, by its commit-time proximity proof;
   - the per-proof weight-mask and link-mask tables, by the proximity rows above. These
     tables are not tested anywhere else. The flat mode instead argues them through the
     consistency check (§3.3).

   Mask rows are ordinary committed rows. Each `μ_g` is an ordinary claim on them, mixed
   before `γ`.
2. **Committed rows.** This is size.md §4.1, items 1–3, with the decoded outer rows of
   message length `C + S` and with `U*` the decoded limb table read as QM31 rows. The check
   only involves the head `[0, C+S)` of each `U*` row, because `W` is zero on the tail.
   So a non-zero tail, which the prover controls, never enters an equation. Without the
   head restriction, the binding argument would be over the code of message length `2C`:
   rate 1/2 at lb 2, about 1 bit per query instead of about 1.9.

   If the heads differ from `Σ A·rows°`:

       Pr[all t queries pass] ≤ (ρ_c + δ)^t · 2^-pow + t·log G'/|F|

   That is the conjectured `t·log2(E/(C+S)) + pow` bits, as in the flat mode.
3. **Reductions.** The `γ'` batching costs `1/|F|`. The sumcheck over `log G' + lc + 1`
   variables costs `2(log G' + lc + 1)/|F|`. Each inner level contributes its own pcs2
   error, with conjectured `t_in·lb_in + pow_in` bits (`inner_conjectured_bits` in the
   bench).

**Tests.** `zk_pcs2.zig`:
- `headEval` against brute force;
- `Enc` of `C + S` coefficients against the `2C` circle tensor;
- depth 1/2 roundtrips. Tampering with `μ`, salts, column values, multiproof siblings,
  the inner root, the sumcheck, the limbs, PoW, the inner columns, the final rows, the
  placeholder level or the depth is rejected, and so is a wrong claim value;
- a corrupted committed table (half a row's symbols changed, tree rebuilt) is rejected;
- lifetime budget enforcement;
- statistical sanity with zero data rows: every revealed value at every level, outer
  columns, committed-row sumcheck, limbs, inner columns and final rows, has a top-bit
  ratio within 0.03 of 1/2 and no zeros. Inner-table rows lying wholly in the public zero
  tail are excluded.

`zk.zig` (recursive mode):
- product at depth 1/2: verifies; every recursive field tampered, the batch hat and the
  root each rejected; the flat verifier and another depth reject; depth 0 is refused;
- MLP with public IO: weight proximity, the proof, the weight and witness openings
  (including the per-proof mask table's columns), the W hat, a GKR hat, a wrong weight
  root;
- the re-randomization link: tampered, swapped, or between different weights;
- the outer weight budget is exhausted after a few proofs (`error.OpeningBudgetExceeded`);
- statistical sanity, zero vs random witness: all recursive-opening values and batch hats
  are within 0.02 of uniform, with no zeros, and alike.

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

`zk_sumcheck.proveWith` takes a comptime evaluator for the summand; the GKR layer uses a
4-multiplication form of its 7-multiplication term list.

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
- **matmul** with requant:
  `Σ_z [X(ρ_t, z)·W(z, ρ_n) + eq(ρ, z)(−2^s Y(z) − r(z))] = −2^(s−1)`.
  This is one sumcheck over `max(lk, lt+ln)` variables with top zero-extension, so the
  hats carry the scale `Π(1 − r_hi)`. The prover folds `X·eq(ρ_t)` and `W·eq(ρ_n)` as in
  v1. The W hat is a claim on the weight commitment, padded by `R_W(s, colpoint)`.
- **LogUp** covers range8, the requant output range, the remainder range `2^s` and the
  int8 lookup with `β`. The y-range key of a requant output is dropped when that output is
  also a lookup input: the table match already forces `[-128,128)`. Default proof: hiding
  GKR (§4.3). Option (`zk_logup_gkr = false`):
  - Table 2 is committed after `α, β`. It holds `h_k = 1/(α − key_k)` as 4 M31 limb
    tensors, plus pads.
  - Per key instance: a masked zero-check `Σ eq(ρ,x)·h(x)·(α − key(x)) = 1`.
  - Per relation: a linear claim with public value 0,
    `Σ_k Σ_x h_k(x) − Σ_t m(t)/(α − key_t) = 0`.
  - Soundness: `m` is committed before `α` and `h` after it. The zero-check forces
    `h = 1/(α − key)` on the cube except with probability `n/|F|`. LogUp then gives
    multiset inclusion except with probability `(#keys + #table)/|F|`, since the
    characteristic exceeds the counts.

All claim values are public (0, ±2^(s−1), 1, and the GKR claims `(0, d_0)`), so nothing
about the witness enters as a claimed value.

### 4.3 Hiding LogUp-GKR (`gkrProveRel` / `gkrVerifyRel`)

**Trees.** Either one fraction tree per relation, or one **tagged tree** for all
relations, whichever has fewer padded leaves. Key counts are powers of two, so a
relation's `2^s + 1` table and blinder leaves usually double its own tree. In the tagged
tree every key and table entry of relation `r` uses the denominator `α − key − τ·r`, with
`τ` drawn together with `α` and `β`; this is standard multi-table LogUp.

- **Soundness (tagged).** `F(α, τ) = Σ_r [Σ_keys 1/(α − k − τr) − Σ_t m_t/(α − t − τr)]`
  is a non-zero bivariate rational function if any relation fails, because poles of
  different relations are distinct polynomials in `τ`. Schwartz–Zippel over `(α, τ)`
  bounds the error.
- **Effect.** mlp 8 10 11 goes from 3 trees with `2^22 + 2^20 + 2^20` leaves (for about
  3.3M keys) to one tree with `2^22` leaves.

Within a tree: Leaves, laid out as aligned segments in
`n` variables:

- key leaves `(1, α − key(x))`;
- table leaves `(−m(t), α − key_t)`;
- one **blinder leaf** `(0, ρ)`, where `ρ` is a uniform non-zero committed cell;
- padding leaves `(0, 1)`.

The split is MSB: node `x` of layer `k−1` is node `x` ⊕ node `x + 2^(k−1)` of layer `k`,
with `(n, d) ⊕ (n', d') = (n d' + n' d, d d')`.

**Root.** The prover sends only the root denominator `d_0`. The numerator must be 0, and
the verifier checks `d_0 ≠ 0`.

**Layer `k = 1..n`.** The incoming claim is `(â, b̂)` with challenges `λ_k` and `γ'`. For
`k = 1` the claim is `(0, d_0)` and `γ' = 0`. The layer is a masked sumcheck over `k−1`
variables:

    (λ â + b̂)/(1 − γ') = Σ_x eq(r, x)·[λ n0 d1 + λ n1 d0 + d0 d1](x) + Σ_x et(x)·Q(x)

- Factors: `eq, λn0, λn1, d0, d1, et, Q`, degree 3.
- **Hats.** The four finals are revealed only as hats padded by four fresh 16-cell pads
  `P_{k,·}`, at `t_k` = the last 4 coordinates of `(aux ‖ r')`, where `aux` is 4
  challenge coordinates per tree. The next claim is
  `â = (1−c)·n̂0 + c·n̂1 = (1−γ)·num_k(c, r') + γ·[(1−c) P_{k,n0} + c P_{k,n1}](t_k)`, and
  `b̂` likewise.
- **Q term.** `et·Q` absorbs the previous layer's pad part
  `γ'/(1−γ')·[λ P_a + P_b](t_{k−1})`. With `m = k−1` and `m' = min(m, 4)`:
  - `Q(x) = [x_head = 0]·coef·Σ_j w_j P_j(t_lead, x_tail)`, the pads partially evaluated
    at the leading `4−m'` coordinates of `t`;
  - `et = eq((0^(m−m'), t_tail), ·)`, so that `Σ_x et·Q` is exactly that pad part.
  - `Q` is a prover-computed, uncommitted vector. Its final value is a linear claim on the
    previous layer's pads: `coef·eq(r'_head, 0)·Σ_j w_j P_j(t_lead, r'_tail)`.
  - For `k = 1` there is no previous layer, and the verifier requires `Q̂ = 0`.

**Leaves.** The last layer's hats become two linear claims, one on numerators and one on
denominators, each `(1−γ)·leaf-MLE(c, r') + γ·pads(t_n)`. The leaf MLE expands per
segment: block `eq` times the key's affine tensor form, `−m`, `ρ`, the public table key
MLE (`identityMle`, or the act-table MLE) and the padding indicator `1 − Σ blocks`. These
claims go to the batch.

**Soundness.**
- Root: numerator 0 and `d_0 ≠ 0` give `Σ_keys 1/(α−k) − Σ_t m_t/(α−t) = 0`, with every
  denominator non-zero. `ρ` contributes `0/ρ`. Standard LogUp error.
- Layer: masked-sumcheck soundness (§4.1). `Q` is pinned to the honest pad-derived vector
  because its evaluation at the random final point is verified against the committed pads,
  and `et` is public. So the sumcheck proves
  `λ(â − γ'P_a(t)) + (b̂ − γ'P_b(t)) = (1−γ')(λ·num_{k−1}(r) + den_{k−1}(r))`, with the
  pads fixed at commitment time. `λ` is drawn after `â, b̂`, so both components hold except
  with probability 1/|F|. This is the usual GKR claim reduction, shifted by committed
  constants.
- Error: per tree, about `Σ_k (3k + 4)/|F|` plus LogUp's `(#keys + #table)/|F|`.

**ZK.**
- `d_0 = ρ·Π(other denominators)` is uniform in F*.
- Layer messages are uniform given the public claim (Lemma 3).
- Each hat carries `γ·(own pad functional)`.
- Each layer's 64 pad cells see 5 functionals: the 4 hats at `t_k` (one per pad) and one
  `Q` value at an independent point. These are linearly independent except with
  probability `O(1)/|F|`.
- The layer values never appear unmasked; the leaf claim values are determined by the
  hats.

What a GKR proof contains in hiding mode: roots `d_0` (16 B per tree) and per layer a
masked sumcheck (`3k + 7` QM31 values). Total about 39 KB for mlp 8 10 11 (3 trees, 62
layers).

**Rejected shortcut.** Interleaving random pad leaves (MSB half) makes all layers above
the leaves uniform, so only the bottom layer would need masking. But the pads must be
uniform QM31 fractions, which is 8 committed M31 cells per data leaf.

### 4.4 Batch and openings

- **Batch.** All linear claims on the witness table(s) are combined with `γ`s drawn after
  every value is in the transcript. Hats, `σ` and `u` are mixed by the sumchecks; the
  zeros are public. One masked sumcheck `Σ T E` follows, with `E` public. In
  committed-inverse mode it is `Σ T_1 E_1 + Σ T_2 E_2`, with the tables zero-extended and
  only `max(used)` entries touched.
- **Batch hats.** Pad: one full row `R_b` per table, evaluated at the batch column point.
  So `(1−γ)·T(r) + γ·R_b(r_col)` is a single group with column vector `eq(r_col)`.
- **Batch hiding polynomial.** It sits in a tiny per-proof **aux table**, 9 rows × 256
  columns, committed together with table 1: row 0 holds the coefficients, plus 4 proximity
  and 4 group mask rows. Its claims `σ_b` and `u_b` are combined with `ζ`, drawn after
  `u_b` is mixed; this was a soundness fix during development. The aux table is opened
  separately with its own parameters: lb 4, no PoW, 38 queries, ≥ 128 conjectured bits,
  about 22 KB. Before this, the claim used a whole combined row of the witness table
  (`C + S` QM31 values).
- **Witness opening.** The proximity row plus group A, each with its own 4 mask rows in
  table 1.
- **Weight opening.** The weight table plus a fresh per-proof mask table with 4 rows per
  group, committed at the start with its root in the transcript. Claims are grouped by
  column point:
  - matmuls whose output dimension covers the table's columns share one point, a suffix
    of `ρ`;
  - every other matmul has its own point, which contains its sumcheck coordinates.

  `weightGroupCount` fixes the mask-table shape for both sides. There is no proximity
  row; that test is done at commit time.

### 4.4b Public tensors (public input/output)

`provePublic` / `verifyPublic` take `PublicTensor{id, values}`, for example the model's
input and output.

- The values' hash is mixed into the transcript with the statement.
- After the commitments, each public tensor gets the linear claim
  `T~(z) = MLE(values)(z)` at a fresh random `z`. The verifier computes the value by
  folding the integers.
- **Soundness.** Schwartz–Zippel: a committed tensor that differs from the values passes
  with probability ≤ `n/|F|`.
- **ZK.** The value is public, and the claim reveals nothing about other tensors. The
  public tensor's own pads then only mask public data.

Without this, every witness tensor, including the output, is hidden, and a hiding proof
cannot attest to a result. The non-hiding v1 has no public-IO binding either.

### 4.5 Zero-knowledge argument (whole proof)

Hybrid over the transcript, in order:

1. **Commitments.** Roots are uniform (salted leaves, ROM).
2. **`α, β, ρ`.** Public coins.
3. **Each masked zero-check.** Messages are uniform given the public claim (Lemma 3).
   Each hat is `γ·(pad functional) + (witness part)`. `u` is determined.
   **GKR trees.** Covered by §4.3 (ZK), given the public claims `(0, d_0)`.
4. **Batch.** Messages are uniform given the public batch claim (Lemma 3). The batch hats
   are padded by the `R_b` rows. `ζ`; `σ_b + ζu_b` is determined.
5. **Openings.** Simulatable given the group claim values (Lemma 2), which steps 3–4
   already simulate.

**Rank condition.** Let `P` be the vector of all pad cells. The revealed linear values
are `A_D·D + A_P·P`, and they are jointly uniform iff `A_P` has full row rank.

- Every pad tensor has 16 cells (or `R_b`/`R_W` rows of `C` cells). It is used only by
  hats of its own tensor or GKR layer, at points that are fresh random points of
  different sumchecks.
- The most uses are about 3 hats per tensor in the MLP: for example `X` in two matmuls
  and range8, or `Y_g` in matmul, y-range and lookup.
- `eq` vectors of ≤ 16 distinct random points in 16 dimensions are independent except
  with probability ≤ 16·4/|F|.
- Mask rows and `R_b` appear in the batch's table evaluation too, but each revealed value
  has its own fresh direction: hat ↔ its pad, `σ`/`u` ↔ its U, `μ` and `u` rows ↔ their
  masks, GKR `d_0` ↔ `ρ`.

The prover's randomness is fresh per proof, except the weight table's `τ`, `R_W` and
proximity masks, which are shared across proofs. Their exposure is bounded by the budget
(columns) and by `4·C_w` (`R_W` functionals).

**Tests that exercise this** (`zk.zig`):
- Two proofs of the same statement have different roots and hats.
- Statistical sanity: an all-zero witness versus a uniform witness (product). Opened
  column values of every row, combined rows and all hats have a top-bit ratio and a mean
  within 0.02 of 1/2, and no zeros (without masks the zero witness gives zero data
  columns and zero finals).
- Statistical sanity: an MLP with all-zero input versus random input. GKR roots, all GKR
  layer hats and `Q` values, and op-check hats are uniform-looking, within 0.04 of 1/2.
- Tampering with each proof field is rejected (§6).

### 4.6 Weight re-randomization with a link proof

`rerandomizeWeights` commits the same weights again with fresh `τ`, `R_W` pads and
proximity masks, then proves a link. The link is a 2-table hiding opening of old, new and
a fresh 4-row mask table, for the single claim `W_old~(z) − W_new~(z) = 0` at a random `z`
over the data rows.

- **Soundness.** Both tables are close to the code by their own commit-time proximity
  proofs, so the claim binds the decoded tables. A non-zero difference has a non-zero MLE
  at a random `z` except with probability `(lr+lc)/|F|`.
- **ZK.** The claim value is the public 0, and the opening is simulatable (Lemma 2). It
  spends `t_w` columns of both budgets.

A chain of links serves an unbounded number of proofs from one set of weights, matching
FlashProve's "copies of the table with fresh masks, each with a link".
`ZkWeights.budgetLeft()` tells the operator when to rotate.

## 5. Measurements

M4 Max, AC power, `ReleaseFast`, memguard. FlashProve CPU numbers are from fp-bench on
the same machine. Commands:

- `tensor-bench product 20 1 [54 2 20] [zk]`
- `tensor-bench mlp 8 10 11 8 64 2 20 [zk]`. In zk mode, input and output are public by
  default (`ZK_PUBLIC_IO=0` disables). Weight overrides: `ZK_WEIGHT_LC`, `ZK_WEIGHT_LB`,
  `ZK_WEIGHT_SLOTS`, `ZK_WEIGHT_Q`.

| bench | mode | prove | verify | proof | notes |
|---|---|---|---|---|---|
| product 20, 1 thread, t 54 | non-hiding | 0.337 s | 1.63 ms | 323,352 B | 128 conj bits |
| product 20, 1 thread, t 54 | hiding (first version) | 0.360 s | 2.31 ms | 400,824 B | 125.6 conj bits |
| product 20, 1 thread, t 56, lb 2 | **hiding** | **0.327 s** | **1.92 ms** | **368,520 B** | 129.5 conj bits (rate (4096+128)/16384); aux table |
| product 20, 1 thread, t 37, lb 3 | **hiding** | 0.505 s | 2.22 ms | **301,304 B** | 129.4 conj bits; smaller than FlashProve's 341 KB |
| FlashProve toy (`a∘b = c`, 2^20, 1 core, hiding) | hiding | 8.37 s | 14 ms | 341 KB | reference |
| mlp 8 10 11, 8 threads, t 64 | non-hiding (v1) | 0.195 s | 7.4 ms | 1,966,288 B | stwo fast GKR |
| mlp 8 10 11 | hiding, committed inverses, weights lb 2 t 64 | 0.74–0.90 s | 13–17 ms | 2,844,720 B | weights only 84 conj bits |
| mlp 8 10 11 | hiding, committed inverses, weights lb 4 t 36 | 0.72 s | 10.8 ms | 2,136,112 B | weights 128.0 conj bits |
| mlp 8 10 11 | hiding, masked GKR, weights lb 4 t 36 | 0.43–0.46 s | 10.3 ms | 1,574,864 B | generic GKR prover |
| mlp 8 10 11 | hiding, masked GKR, weight lc 10 | 0.30–0.32 s | 9.7–11 ms | 1,469,504 B | GKR 0.136 s (eq factored out); aux table; RSS 1.2 GB |
| mlp 8 10 11 | **hiding (current)**, weight lc 12, lb 4, t 30 | **0.32–0.33 s** | **10.4 ms** | **980,768 B** | 0.5× the non-hiding proof |
| mlp 8 10 11 | hiding + public input/output, 3 GKR trees | 0.33 s | 17.9 ms | 980,768 B | +7.5 ms to fold 2 × 2^18 public values |
| mlp 8 10 11 | **hiding (current) + public input/output**, 1 tagged GKR tree | **0.285 s** | **15.5–16 ms** | **955,584 B** | GKR 0.092 s, 22 layers, 14.6 KB |
| mlp 8 10 11, **1 thread**, t 56 | non-hiding (v1), t 64 | 0.597 s | 7.7 ms | 1,966,288 B | |
| mlp 8 10 11, **1 thread**, t 56 | hiding + public IO (3 GKR trees) | 1.26 s | 18.7 ms | 958,816 B | 130.7 conj bits |

Hiding MLP breakdown, current version (8 threads):
- witness commit 0.085 s,
- GKR 0.092 s,
- op sumchecks 0.03 s,
- batch 0.053 s,
- openings 0.013 s.

Weights (once per commitment), with `C_w = 4096`:
- commit 0.28 s (lb 4);
- proximity 2.5–4.6 ms prove, 2 ms verify, 284 KB;
- re-randomize plus link 0.30 s, link verify 2.8 ms, link 503 KB.

For product 20 the hiding prover now costs the same as the non-hiding one at 128 bits
(0.327 s vs 0.328 s). Verify is +24% and size +14%, or −7% with lb 3.

History, at the same shape:
- First version (committed inverses, full zero-extension): 1.01 s, 3.2 GB RSS.
- Active-length factors: 0.74 s.
- Weight-specific PCS parameters: 2.84 MB → 2.14 MB.
- Hiding GKR: 0.45 s, 1.57 MB.
- GKR evaluator with 4 instead of 7 multiplications: GKR 0.38 → 0.26 s.
- Aux table for the batch hiding polynomial: 1.57 → 1.47 MB (product 401 → 361 KB).
- Gruen-style GKR layer prover (`eq` never materialized or folded; byte-identical
  messages): GKR 0.22 → 0.136 s, MLP 0.40 → 0.31 s.
- Wider hiding weight table (lc 12, one group per narrow matmul): weight opening
  954 → 466 KB, MLP proof 1.47 → 0.98 MB.
- Tagged single GKR tree: GKR 0.136 → 0.092 s, MLP 0.33 → 0.285 s, proof 956 KB.

The hiding MLP proof (0.98 MB) is now half the v1 non-hiding proof (1.97 MB). Higher
weight blowup with fewer queries, plus a wider weight table with per-matmul groups, would
shrink the non-hiding proof as well; the weight opening is about 80% of it.

## 6. Adversarial tests (all passing, `zig build test -Doptimize=ReleaseSafe`, 20 tests)

- `zk_pcs`:
  - two tables with groups and masks: wrong claim value, tampered `μ`, salt, column
    value and combined row are each rejected;
  - the budget refuses to exceed `slots/2`;
  - slot-span rank test.
- `zk_sumcheck`:
  - hiding-polynomial forms against brute force for `d = 2, 3`;
  - masked sumcheck completeness;
  - a wrong claim and a tampered hat each break the final check;
  - the GKR layer prover sends byte-identical messages to the generic prover
    (`n = 0, 1, 3, 5, 9`).
- `zk` product:
  - tampered hat, `σ`, `u`, round message, batch hat, batch `σ`, opening row, `μ`, aux
    opening row, aux `μ`, column and root are each rejected;
  - two proofs differ;
  - a wrong witness is refused by the prover.
- `zk` MLP:
  - weight proximity verifies and a tampered proximity row is rejected;
  - the proof verifies;
  - tampered W hat, op round, weight-opening row, shift and weight root are each
    rejected;
  - hiding GKR: tampered root, layer hats (first, last and middle layer), round message,
    `u_val`, `Q` value and `σ` are each rejected;
  - committed-inverse mode verifies, and its proof is rejected under the GKR config;
  - separate weight PCS parameters work, and mismatched parameters are rejected;
  - weight re-randomization: the link verifies and the new commitment serves proofs; a
    tampered link, swapped roots and a link between different weights are each
    rejected;
  - a weight table wider than every output dimension uses 3 groups, verifies, and a
    tampered group row or W hat is rejected;
  - public input/output verifies; an altered public output, or a missing public-tensor
    list, is rejected; the prover refuses public values that differ from the witness;
  - a statement whose weight shapes differ from the key is rejected (`StatementShape`);
  - `protocol.prove` refuses `Config.hiding` (`HidingRequiresZkProve`);
  - after a few proofs the budget is exhausted and the prover refuses
    (`error.OpeningBudgetExceeded`);
  - a wrong forward value is refused.
- Two statistical sanity tests (§4.5).

## 7. Not done / caveats

- **Weight budget.** About 17 proofs per commitment at `C_w = 4096` with the bench
  defaults. After that, rotate with `rerandomizeWeights` and the link proof (§4.6). Each
  rotation costs about the weight commit, plus a 0.5 MB link and a 0.28 MB proximity
  proof at this size.
- **Weight memory at lb 4.** The encoded weight table holds 16× the weight count in M31
  cells: 6.4 GB for 100M weights. For the full-size model use `ZK_WEIGHT_LB=3` (2× less),
  or keep lb 2 with fewer slots and more queries.
- **Hiding prover cost.** About 1.46× the non-hiding v1 at mlp 8 10 11 with 8 threads
  (0.285 vs 0.195 s). The hiding mode commits the requant remainders, which v1 keeps
  virtual: about 40% of table 1. The GKR kernels are scalar QM31, not stwo's packed SIMD.
  A tagged tree still pads up to the next power of two; at this shape about 3.3M keys sit
  in 4.2M leaves.
- **Big shapes not run here** (host rule). Hiding memory is dominated by:
  - table 1 (witness plus committed remainders);
  - the GKR layer arrays: 2 × 2 × 16 B per leaf, all layers kept;
  - the batch vectors (2 QM31 per table-1 cell).
  Expect several GB at 1024×4096×8192. The remainders could stay virtual: route the GKR
  remainder-leaf claims through the matmul check, with a `Q`-style pad term.
- `hiding` is a separate entry point (`zk.prove` / `zk.verify` / `zk.commitWeights`,
  plus `provePublic` / `verifyPublic`). `protocol.prove` refuses `Config.hiding`; the
  bench selects with a `zk` argument.
- **ZK is honest-prover zero knowledge.** It needs fresh OS entropy. A verifier cannot
  check that the prover used fresh randomness (same caveat as FlashProve and s31).
- The proofs here are written arguments, not machine-checked. The bijection lemma for
  the hiding polynomial is taken from FlashProve (enumeration-checked there). Lemma 1 is
  proven above and spot-checked by the rank test. The rank condition of §4.5 is argued,
  not computed.
- **Security accounting.** The slots raise the code rate (witness 1.96 instead of
  2.00 bits per query at lb 2). The bench reports conjectured and unique-decoding bits
  per opening.
