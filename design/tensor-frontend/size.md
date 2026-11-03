# Tensor frontend: proof size (stream `size`)

Branch `codex/tensor-size`. New files: `src/tensor/pcs2.zig` (recursive
tensor PCS), `src/tensor/batch_sumcheck.zig` (shape-class matmul batching),
`src/tensor/size_tests.zig` (end-to-end tests). `protocol.zig` changes are
opt-in config switches; with the defaults (`two_level = null`,
`batch_matmuls = false`) the protocol is unchanged (same proof sizes as the base branch:
product 2^20 323 352 B, MLP 2^8x2^10x2^11 1 966 288 B).

How to run (bench args after the legacy ones select pcs2):

```
tensor-bench product <log_n> <thr> <q> <lb> <pow> [depth inner_q inner_lb inner_pow work_shift prox_rows]
tensor-bench mlp <lt> <ld> <lf> <thr> <q> <lb> <pow> [depth inner_q inner_lb inner_pow work_shift prox_rows]
TENSOR_BATCH_MATMULS=1 tensor-bench mlp ...          # shape-class batching
tensor-bench model <log_total> <used> <n_rows> <q> <lb> <depth> <inner_q> <inner_lb> [work_shift]
```

Recommended configs:
* conjectured 128: `54 2 20 2 54 2 20` (product) / `64 2 20 2 54 2 20` (MLP), batching on;
* proven-query 128 (unique decoding): `160 2 20 2 160 2 20` (see 4.3 for the
  field-size caveat), batching on.

## 1. What changed

Plain Ligero (`pcs.zig`) opens an R x C table by sending one combined row
`u_g = sum_i a_g[i] row_i` (C QM31 = 16 C bytes) per claim group plus a
proximity row, and t opened columns (t * rows_used * 4 B) with Merkle paths.
The MLP proof was 7.6 MB because (a) all claims in a group must share the
column part of their point, so the weight table could only use as many column
variables as the GKR ood suffix shared by every matmul (12 for D = 4096):
C = 2^12, R = 2^15 and 64 columns of 24 576 rows cost 6.3 MB; and (b) the
combined rows are sent in full, so the single-level optimum is ~128 sqrt(N) B.

1. **Committed combined rows (`pcs2`).** At each non-final level the prover
   commits `U = (u_0..u_{G-1})` (proximity rows first) as an M31 table
   `V[g][c][k] = limb_c(u_g[k])` with a fresh `pcs.commit`. The verifier's two
   checks on U become linear claims on the committed U:
   * evaluation: `<u_g, eq(z_col_g)> = sum_c gamma_c v_c`;
   * column consistency at query j: `sum_g lambda_g Enc(u_g)[j] = y_j`, with
     `y_j = <sum_g lambda_g a_g, col_j>` computed by the verifier from the
     opened column, `lambda = eq(rho, .)`, rho drawn after U is committed.

   `Enc(u)[j]` is a tensor functional of the coefficient vector: stwo's circle
   basis is `b_k(P) = prod_b f_b(P)^{bit_b(k)}`, `f = (y, x, pi(x), pi^2(x), ..)`
   at `P_j = domain.at(bit_reverse(j))` (`pcs2.circleFactors`, tested
   bit-for-bit against `Twiddles.encode`). Its MLE at r is
   `prod_v (1 + r_v (f_v - 1))`, so the verifier evaluates it in O(log C).
   All claims are batched with independent random gamma' and reduced by one
   degree-2 sumcheck over `sum_{g,k} U[g,k] W[g,k]` (full G' x C cube) to
   `U~(r)`; the prover sends the four limb values `V~(r_g, c, r_k)`, which share
   their column point and form one claim group (with proximity) of the next
   level, opened recursively. The last level sends its rows.
2. **One group per distinct column point.** An extra group adds one row of U
   (4C M31 to the inner object, i.e. ~sqrt growth in bytes), so the weight
   table split is free. `pcs2.groupByColumn` groups claims; the verifier
   regroups from its own points.
3. **Merkle multiproofs.** Sorted, deduplicated query positions; only
   non-recomputable siblings are sent. `verifyMultiproof` rejects unsorted,
   duplicate or out-of-range positions and missing or unconsumed siblings.
4. **Per-level parameters and a size model.** `Params.outer` (big table),
   `Params.inner` (committed-row tables), `depth`, `prox_rows`,
   `inner_work_shift`. `bestOuter`/`bestInner` choose log_cols per table by
   predicted bytes (model below), subject to a prover-cost bound
   `4 * 2^lc * 2^inner_lb <= used >> inner_work_shift` that keeps the
   committed-row encoding small next to the row combination. Prover and
   verifier evaluate the same deterministic function of public sizes; the
   weight table's shape lives in the weight key.
5. **Shape-class batched matmuls (`batch_matmuls`).** All matmuls with equal
   (T, K, N) are proven by one sumcheck over k of
   `sum_e xi_e X_e(rho_t,k) W_e(k,rho_n) = sum_e xi_e acc_e(rho)` with shared
   challenges (`batch_sumcheck.zig`, standard `sumcheck.Proof` format). Every
   member's weight claim then lies at the same local point `(r, rho_n)`, so a
   class is one PCS claim group. In the MLP, gate/up form one class.
6. **Hardening found on the way.** `verify` now rejects
   `op_finals.len != op_sumchecks.len` (previously an out-of-bounds index on a
   malformed proof), and weight values are matched against an explicitly
   collected list (equivalent to the old positional loop, but also correct
   for batched classes).

## 2. Size model

Per opening level l (table of `N_l` used entries, `2^lc_l` columns, `n_l`
combined rows, `t_l` queries, blowup `2^b_l`):

```
cols_l  = t_l * ceil(N_l / 2^lc_l) * 4
sibs_l ~= t_l * (lc_l + b_l - log2 t_l + 1) * 32                (multiproof)
final:     rows = n_l * 2^lc_l * 16
non-final: 32 (root) + 2*16*(log2 G'_l + lc_l) (sumcheck) + 64 (limbs) + level l+1
           with N_{l+1} = 4 * n_l * 2^lc_l,  n_{l+1} = 1 + prox_rows
```

Bytes(opening) = sum over levels + 8 B nonce per level. With depth d the
optimum scales roughly like N^{1/(d+2)} (flat Ligero: sqrt(N)). Model vs
measurement: 288 vs 281 KB and 242 vs 237 KB on the 25.2M-weight opening.

Protocol overhead outside openings: GKR proof (stwo format, ~28 KB for the
MLP: round polys `~ L^2/2 * 64 B` plus masks `64 B * instances * layers`),
op sumchecks (`2-3 * 16 B * K-bits` per sumcheck), 16-48 B of finals per op.

## 3. Measurements (M4 Max, AC power, shared host)

Sizes are deterministic. Times are from a host shared with other agents
(load average 6-8); product times are best of 3; MLP single runs varied up to
+-15% for identical configs. PoW grinding (20 bits per level) adds a
transcript-dependent but fixed-per-input cost of a few ms per level.

### product a(.)b = c, 2^20, 1 thread (FlashProve toy: 341 KB, 8.37 s, 14 ms)

| config | bits (query) | proof | prove | verify |
|---|---|---|---|---|
| flat 54q lb2 (base) | conj 128 / proven 57 | 323 352 B | 0.337 s | 1.54 ms |
| pcs2 d1, inner 54q lb2 | conj 128 | 130 640 B | 0.357 s | 0.71 ms |
| pcs2 d2, inner 54q lb2 | conj 128 | **117 976 B** | 0.364 s | 0.67 ms |
| flat 160q lb2 | proven 128.5 | 697 320 B | 0.333 s | 2.77 ms |
| pcs2 d1, inner 160q lb2 | proven 128.5 | 295 440 B | 0.346 s | 1.69 ms |
| pcs2 d2, inner 160q lb2, work_shift 2 | proven 128.5 | **250 456 B** | 0.373 s | 1.37 ms |
| pcs2 d2, 160q, 2 proximity rows | proven 128.5 | 359 320 B | 0.358 s | 1.73 ms |

### MLP T=2^8, D=2^11, F=2^12 (25.2M weights), 8 threads

| config | proof | weight open. | witness open. | prove | verify |
|---|---|---|---|---|---|
| flat 64q (base) | 3 693 760 B | 3 205 640 | 457 480 | 0.330 s | 14.3 ms |
| pcs2 d1 54q | 471 312 B | 281 488 | 159 184 | 0.355 s | 2.65 ms |
| pcs2 d2 54q | 342 272 B | 182 680 | 128 952 | 0.38-0.41 s | 2.18 ms |
| pcs2 d2 54q + batching | **329 312 B** | 168 568 | 130 456 | 0.37-0.41 s | 2.12 ms |
| flat 160q (proven-query 128) | 8 746 048 B | 7 964 936 | 750 472 | 0.341 s | 29.1 ms |
| pcs2 d2 160q + batching | **727 616 B** | 390 744 | 306 584 | 0.374 s | 4.30 ms |

Earlier, MLP 2^8x2^10x2^11: 1 966 288 B -> 304 064 B (d1), verify 7.2 -> 1.8 ms.
Weight proximity proof (one-time, at commit): 3.2 MB -> 153 KB (d2).

Prover overhead: the extra work is the committed-row encoding, the query
functional sum (t * C), one sumcheck over G' * C and per-level PoW. At 25.2M
weights the opening stages grow from ~13 ms to ~40-60 ms (of ~0.37 s). These
costs grow like C (~N^{2/3} at depth 2) while proving grows like N * T, so the
relative overhead shrinks at the headline size; the coordinator's 1024 x 4096
x 8192 run should confirm it stays within the 10% budget (expected ~3-5%).

### Headline MLP (1024 tok, 4096 x 8192, 100.7M weights) — model

| part | flat (today) | pcs2 d2 conj (64q/54q) | pcs2 d2 proven-query (160q/160q) |
|---|---|---|---|
| weight opening | 6.4 MB (measured) | 231 KB (batched, 2 groups) | 518 KB |
| witness opening | ~1.2 MB | 193 KB | 446 KB |
| GKR + sumchecks + finals | ~35 KB | ~35 KB | ~35 KB |
| **total** | **7.6 MB** | **~0.46 MB** | **~1.0 MB** |

## 4. Soundness

### 4.1 One pcs2 level

Setting: outer table T (committed by `root`), claims grouped by column point,
`delta < (1 - rho_code)/2` (unique decoding), `|F| = |QM31| ~ 2^124`,
E = 2^(lc + b). Transcript order (prover = verifier, checked by the
"transcripts end in the same state" test): claim values -> gamma ->
proximity betas -> **inner root** -> rho -> PoW -> query indices ->
verifier-derived y_j -> gamma' -> sumcheck rounds -> limb values -> next level.

1. *Binding of U.* The inner root is fixed before rho and the queries. By
   induction on the next level (the final level is plain Ligero), except with
   the next level's error the inner table is delta-close to a unique codeword
   table with decoded message V*, and every limb claim accepted at that level
   is a true MLE evaluation of V*. U* := V* read as QM31 rows; U* is fixed
   before rho and the queries.
2. *Committed-row Ligero.* Let `u°_g = sum_i a_g[i] row°_i` with row° the
   decoded outer rows (exist by 4). Let `d_g = Enc(u*_g) - Enc(u°_g)` and B the
   positions where some `d_g[j] != 0`. If U* != U°, |B| >= (1 - rho_code) E.
   The committed columns agree with the codeword rows outside <= delta E
   positions (correlated agreement), so the check at j can pass for j in B
   (minus that set) only if `sum_g lambda_g d_g[j] = 0`, which for fixed j has
   probability <= log G'/|F| over rho (nonzero multilinear in rho). With
   `b = |B|/E` and `c_lambda` the fraction of cancelling positions,
   `Pr[all t queries pass] <= E_rho[(1 - b + delta + c_lambda)^t]
   <= (rho_code + delta)^t + t * log G'/|F|`
   (mean-value bound, E[c] <= b log G'/|F|) — no union bound over E needed.
3. *Claims to one point.* The claims on U* (evaluation targets, y_j) are fixed
   before gamma' (independent coefficients: error 1/|F|) and reduced by a
   degree-2 sumcheck over log(G' C) variables (error 2 log(G' C)/|F|). The final
   check `final = (sum_c e_c V~_c(r)) * W~(r)` uses W~ computed by the verifier
   (evaluation part `sum_e gamma'_e eq(r_g, g_e) eq(r_k, z_e)`, query part
   `eq(rho, r_g) sum_j gamma'_j prod_v (1 + r_v (f_jv - 1))`). W is defined on
   the full G' x C cube (U's padded rows are zero by the inner commitment's
   rows_used and W is not truncated) — a bug in the first draft (truncated
   W) was caught by the roundtrip test.
4. *Proximity.* With proximity the first U rows are `sum_i beta_i row_i`
   (k = prox_rows independent beta vectors). Plain Ligero re-encodes the sent
   row; here `Enc(u*_0)` is a codeword by construction (evaluation of a
   committed coefficient vector), so the standard argument is unchanged: if the
   outer table is not delta-close in the correlated sense, each random
   combination is delta-far except with the BCIKS20 unique-decoding error
   `~ E/|F|`, and then the lambda-combined check catches it except with
   `(1 - delta)^t + t log G'/|F|` (as in 2).
5. *Weights.* Proximity of the weight table is proven once at commit time
   (`proveWeightProximity`, now also via pcs2); per-batch weight openings
   are consistency-only, as before; item 2 applies to the decoded weight rows.

### 4.2 Shape-class batching

`acc_e(rho)` for every member is determined by GKR terminal claims already in
the transcript before `xi` is drawn; a false member claim survives the random
combination with probability <= 1/|F| (independent xi), then the degree-2
sumcheck over K variables adds 2 log K/|F|. Members' shapes are re-checked by
the verifier (weight dims vs X dims and output size). The verifier derives the
class partition from the public statement, so prover and verifier agree.

### 4.3 What "proven 128" means here (caveat)

Query error at 160 queries, blowup 4: `(1 - delta)^160 * 2^-20 ~ 2^-128.5`
per level (`Params.provenBits`). The field-size terms do not reach 2^-128 with
QM31 (124 bits): the proximity-gap term of one proximity row is ~E/|F|
(~2^-105 at E = 2^19); `prox_rows = 2` squares it (~2^-210), leaving the
lambda term `t log G'/|F|` (~2^-115) and sumcheck terms (~2^-118). So
the proven-query configs are ~105 bits overall with one proximity row and
~114 bits with two (the flat PCS has the same E/|F| term). Reaching a full
proven 128 needs a larger extension (or repeated lambda/sumcheck checks) —
not done. Conjectured security uses `t * log_blowup + pow` per level.

### 4.4 Adversarial tests

* `pcs2.zig`: depth 0/1/2/3 roundtrips (and depth 0/2 with two proximity
  rows); for every level: tampered opened column value, multiproof sibling,
  final row, limb value, inner root, sumcheck round, PoW nonce are rejected;
  wrong claimed value and wrong root rejected; multiproof rejects tampered
  leaves, missing siblings, wrong positions; a committed table that is not a
  codeword (half a row's encoded symbols corrupted, Merkle rebuilt) is
  rejected by the proximity check; circle factors reproduce `Twiddles.encode`
  at every position and the tensor MLE matches the folded table.
* `batch_sumcheck.zig`: finals match MLE evaluations; wrong claim rejected.
* `size_tests.zig`: MLP (pcs2 depth 1 and 2) and product under pcs2;
  tampered witness value, weight value, column and limb values of both
  openings, wrong weight root, verifier with a different depth, flat
  verifier on a pcs2 proximity proof — all rejected. Batched classes (flat and
  pcs2): each batched final, a member's weight value, a batched round, a
  member's shift and weight id, and verifying a batched proof without
  batching — all rejected.

## 5. Extrapolation to Llama-4 Maverick

Assumptions: 400.7B committed int8 weights (log_total 39); 48 layers, each
with attention projections, a shared expert and 128 routed experts (3
matrices each): ~18.8K matmul weight claims per window, but only ~8 shape
classes; per request 1024 tokens with ~9M committed witness entries/token
(activations, attention scores/softmax, expert hidden states, range
multiplicities) -> ~9.3e9 entries (log_total 34). Batch of 24 requests,
weights opened once per batch.

| part | flat Ligero | pcs2 conj (64q/54q) | pcs2 proven-query (160q/160q) |
|---|---|---|---|
| weight opening, 18.8K groups (no class batching), d3 | 11.2 GB | 17.7 MB | — |
| weight opening, 8 groups (class batching), d3 | 232 MB | **0.90 MB** | 2.08 MB |
| witness opening per request, d3 | 17.5 MB | **0.38 MB** | 0.92 MB |

Per-request proof with weights amortised over the batch of 24: ~0.42 MB
(conj) / ~1.0 MB (proven-query), plus the non-opening parts — which, at this
scale, need two more changes to stay small: (a) one sumcheck per shape class
(done: `batch_matmuls`; unbatched op sumchecks would be ~8 MB of round
polys and finals), and (b) merging GKR instances per lookup table (one
LogUp instance per table instead of per op; otherwise GKR masks ~64 B *
~1000 instances * ~33 layers ~ 2 MB). With both, the non-opening part is
~0.5-1 MB (op finals are 32 B per matmul and the separately sent weight
values duplicate them: another 16 B/matmul that could be dropped). FlashProve
reports 18.78 MB.

## 6. Not done / next steps

* GKR instance merging per table and dropping the duplicated weight values
  (both protocol-format changes; see 5).
* Proximity/binding beyond unique decoding (Johnson regime with OOD samples)
  would cut outer queries by ~1/3 for the proven configuration; not attempted
  — needs a list-decoding binding argument for committed-row Ligero.
* Level-specific parameters (high blowup on the tiny deepest levels) — ~5%.
* Prover overhead at headline scale not measured here (host rules); expected
  ~3-5% from the stage profile.
