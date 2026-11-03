# Tensor frontend: proof size (stream `size`)

Status: recursive tensor PCS (`src/tensor/pcs2.zig`) implemented, wired into
`protocol.zig` behind `Config.two_level` (legacy flat Ligero remains the
default when the field is null), tested end to end.

## 1. What changed

Plain Ligero (`pcs.zig`) opens a table of R x C entries by sending one
combined row `u_g = sum_i a_g[i] row_i` (C QM31 = 16 C bytes) per claim
group plus a proximity row, and t opened columns (t * rows_used * 4 bytes)
with Merkle paths. Two things made the MLP proof 7.6 MB:

* all claims in a group must share the column part of their point, so the
  weight table could only use as many column variables as the GKR ood suffix
  shared by every matmul (12 for D = 4096): C = 2^12, R = 2^15, and the 64
  opened columns of 24 576 rows cost 6.3 MB;
* the combined rows are sent in full, so making C larger trades column bytes
  for row bytes (single-level optimum ~ 128 sqrt(N) bytes).

`pcs2` removes both limits:

1. **Committed combined rows.** At each non-final level the prover commits
   `U = (u_0..u_{G-1})` (proximity row first) as an M31 table
   `V[g][c][k] = limb_c(u_g[k])` with a fresh `pcs.commit`, instead of sending
   it. The verifier's two checks on U become linear claims on the committed U:
   * evaluation: `<u_g, eq(z_col_g)> = sum_c gamma_c v_c`;
   * column consistency at query j: `sum_g lambda_g Enc(u_g)[j] = y_j` with
     `y_j = <sum_g lambda_g a_g, col_j>` computed by the verifier from the
     opened column, `lambda = eq(rho, .)` for a random rho drawn after U is
     committed.
   `Enc(u)[j]` is a tensor functional of the coefficient vector: stwo's circle
   basis is `b_k(P) = prod_b f_b(P)^{bit_b(k)}`, `f = (y, x, pi(x), pi^2(x),
   ..)` at the domain point `P_j = domain.at(bit_reverse(j))`
   (`pcs2.circleFactors`; tested bit-for-bit against `Twiddles.encode` in
   "circle factors reproduce the stwo circle-FFT encoding"). Its MLE at r is
   `prod_v (1 + r_v (f_v - 1))`, so the verifier evaluates it in O(log C).
   All claims are batched with random gamma' and reduced by one degree-2
   sumcheck over `sum_{g,k} U[g,k] W[g,k]` to `U~(r)`; the prover sends the
   four limb values `V~(r_g, c, r_k)`, which share their column point and form
   one claim group (with proximity) of the next level, opened recursively.
   The last level sends its rows (plain Ligero).
2. **One group per distinct column point.** Each extra group only adds one
   row to U (inner object grows by 4C M31), so weight claims no longer need a
   shared column point and the weight table split is free. Claims are grouped
   with `pcs2.groupByColumn` (verifier regroups from its own points).
3. **Merkle multiproofs.** Query indices are sorted and deduplicated, opened
   columns are sent once, and only siblings that cannot be recomputed are sent
   (`pcs2.multiproof` / `verifyMultiproof`, which rejects unsorted, duplicate,
   out-of-range positions and unconsumed or missing siblings).
4. **Per-level parameters.** `Params.outer` (big table: blowup, queries, PoW)
   and `Params.inner` (all committed-row tables, which are small, so a large
   blowup is cheap); `depth` = number of committed-row levels.
5. **Size-model-driven shapes.** `pcs2.bestOuter` / `bestInner` pick
   log_cols per table minimising predicted bytes; prover and verifier compute
   the same shapes deterministically from public data (the weight table's
   shape is part of the weight key).

## 2. Soundness argument (per level)

Setting: outer table T (R x C, committed by Merkle root `root`), claims
`f(z_c) = v_c` grouped by column point. Let `delta < (1 - rho_code)/2`
(unique decoding), `|F| = |QM31| ~ 2^124`, E = 2^(log C + log blowup).

Order of the transcript (prover = verifier, checked by the
"prover and verifier transcripts end in the same state" test):
claim values -> gamma -> (proximity beta) -> **inner root** -> rho -> PoW ->
query indices -> (verifier-derived y_j mixed) -> gamma' -> sumcheck rounds ->
limb values -> next level.

1. *Binding of U.* The inner root is fixed before rho and the queries. By the
   next level's soundness (induction; the final level is plain Ligero), except
   with the next level's error, the inner table is delta-close to a unique
   codeword table, whose decoded message is V*, and every limb claim checked at
   that level is a true MLE evaluation of V*. Define U* from V* (limbs ->
   QM31). U* is fixed before rho and the queries.
2. *Ligero with committed rows.* Let `u°_g = sum_i a_g[i] row°_i` where row°
   are the decoded outer rows (exist by the proximity row, see 4). If
   `U* != U°` in some row, `D_g = Enc(u*_g) - Enc(u°_g)` is nonzero for some g
   and `sum_g lambda_g D_g` is a nonzero codeword except with probability
   `<= log G'/|F|` over rho (multilinear in rho, rho drawn after U* fixed),
   hence nonzero on `>= (1 - rho_code) E` positions. The committed columns
   agree with the codeword rows outside a set of `<= delta E` positions
   (correlated agreement), so the query check
   `sum_g lambda_g Enc(u*_g)[j] = y_j` fails at `>= (1 - rho_code - delta) E`
   positions; t uniform queries all miss with probability
   `<= (rho_code + delta)^t`. (For positions where several d_g are nonzero
   the lambda-combination could cancel; a union bound over all E positions
   costs `E log G'/|F|`, negligible.)
3. *Claims to one point.* The verifier's claims on U* (evaluation targets and
   y_j) are batched with gamma' drawn after they are fixed (error
   `<= (n_claims - 1)/|F|` — powers would give that; independent gammas give
   `1/|F|`) and reduced by a degree-2 sumcheck over `log(G' C)` variables
   (error `<= 2 log(G'C)/|F|`). The final check
   `final = (sum_c e_c V~_c(r)) * W~(r)` uses W~ computed by the verifier: the
   evaluation part is `sum_e gamma'_e eq(r_g, g_e) eq(r_k, z_col_e)` and the
   query part `eq(rho, r_g) sum_j gamma'_j prod_v (1 + r_k,v (f_{j,v} - 1))`.
   W is defined on the full G' x C cube (padded rows of U are zero by the
   inner commitment's `rows_used`, W is not truncated), matching what the
   sumcheck folds.
4. *Proximity.* With proximity the first U row is `u_0 = sum_i beta_i row_i`;
   in plain Ligero the verifier re-encodes it, here `Enc(u*_0)` is a codeword
   by construction (it is the evaluation of the committed coefficient vector),
   so the standard argument applies unchanged: if the outer table is not
   delta-close in the correlated sense, `sum beta_i row_i` is delta-far from
   the code except with the BCIKS20 correlated-agreement error, so it
   disagrees with the codeword `Enc(u*_0)` on `>= delta E` positions and the
   lambda-combined query check catches it with probability `>= 1-(1-delta)^t`
   (same lambda-cancellation union bound as in 2).
5. *Weights.* Weight proximity is proven once at commit time
   (`proveWeightProximity`, now also via pcs2); per-batch weight openings use
   consistency only (no proximity row), as before. With proximity
   established, item 2 applies with the decoded weight rows.

Total error of an opening = sum over levels of (Ligero query error of that
level with its own t, blowup, PoW) + O((E log G' + log(G'C) + n_claims)/|F|).
Reported bits (`Params.provenBits`/`conjecturedBits`) are the minimum over the
outer and inner parameter sets.

### Adversarial tests

* `pcs2.zig`: depth 0/1/2 roundtrips; rejection of a wrong claimed value,
  wrong root, and for **every level**: tampered opened column value, tampered
  multiproof sibling, tampered final row, tampered limb value, tampered inner
  root, tampered sumcheck round, wrong PoW nonce. Multiproof: tampered leaf,
  missing sibling, wrong position. A committed table that is not a codeword
  (half the encoded columns of a row corrupted, Merkle tree rebuilt) is
  rejected by the proximity check.
* `size_tests.zig`: MLP (depth 1 and 2) and product under pcs2, tampered
  witness value, weight value, column values and limb values of both the
  witness and the weight opening, wrong weight root, a verifier configured
  with a different depth, and the flat verifier given a pcs2 proximity proof
  are all rejected.

## 3. Measurements (M4 Max, AC power)

Small sizes measured in this stream (the coordinator runs the big ones).
Flat = legacy `pcs`, pcs2 dX = recursive PCS with X committed-row levels;
inner params `32 queries, blowup 2^4, PoW 20` unless stated.

| case | config | proof | prove | verify |
|---|---|---|---|---|
| product 2^20, 1 thread | flat 54q lb2 (conj. 128) | 323 352 B | 0.333 s | 1.52 ms |
| | pcs2 d1 | 115 120 B | 0.419 s | 0.62 ms |
| | pcs2 d2 | 90 328 B | 0.441 s | 0.57 ms |
| product 2^20, proven 128 | flat 160q lb2 | 697 320 B | 0.319 s | 2.78 ms |
| | pcs2 d1, inner 119q lb4 | 261 744 B | 0.407 s | 1.42 ms |
| | pcs2 d2, inner 119q lb4 | 235 960 B | 0.559 s | 1.38 ms |
| MLP t=2^8 D=2^10 F=2^11, 8 thr | flat 64q | 1 966 288 B | 0.166 s | 7.2 ms |
| | pcs2 d1 | 304 064 B | 0.204 s | 1.83 ms |
| | pcs2 d2 | 230 832 B | 0.248 s | 1.51 ms |

(prove-time overhead is addressed in the next section.)
