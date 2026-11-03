# Tensor frontend: proven security and proof format (stream `r2-sec`)

Branch `codex/tensor-r2-sec` (base `61ba1ce6c`). New: `src/tensor/security.zig`
(soundness calculator). Protocol changes are opt-in (`pcs2.Params.ood`,
`pcs2.Params.deep`, `Config.weight_outer`, `Config.key_outer`); with the
defaults, proofs are unchanged except that the duplicated weight values are
gone (see 5).

## 1. The calculator

`security.accountProof(a, cfg, st, key, proof, key_proof)` runs the verifier
(`protocol.verifyInfo` records the shapes it checked; a rejected proof is not
accounted). It then lists **every challenge of the protocol with its error
term**. The bench prints the result as `"security"` for `product`, `mlp` and
`layer`:

```
TENSOR_OOD=1 TENSOR_DEEP=76,3,20 \
  tensor-bench product 20 1 122 2 20 2 76 3 20 2 2      # toy, proven config
TENSOR_BATCH_MATMULS=1 TENSOR_OOD=1 TENSOR_DEEP=76,3,20 TENSOR_WEIGHT_Q=66 TENSOR_KEY_Q=900 \
  tensor-bench mlp 10 12 13 12 122 2 20 2 76 3 20 3 2   # MLP 1024, proven config
```

(positional pcs2 arguments as before: `depth inner_q inner_lb inner_pow
work_shift prox_rows`; `TENSOR_DEEP=q,lb[,pow]` sets the levels >= 2;
`TENSOR_WEIGHT_Q=q[,pow]` sets the per-batch weight openings and
`TENSOR_KEY_Q=q[,pow]` the weight-key proof, both at the outer blowup.)

The report gives these figures, in FlashProve's style:

| figure | meaning |
|---|---|
| `sum_with_work` / `sum_without_work` | -log2 of the sum of all terms. With work, every query term is divided by 2^pow. This is the **whole bound** (FlashProve: 126.21 with work / 96.23 without). |
| `round_with_work` / `round_without_work` | -log2 of the largest single term (FlashProve's "largest round error"). |
| `compiled` | FlashProve's compiled level for `round_with_work` (the largest L with 2^-L >= 2^-w + 8.5 * 2^(L-256)); it gives 126.21 at w = 128, as theirs does (tested). |
| `request` / `key` / `total` | the per-batch proof, the one-time weight-key proof, and both together (a client checks both). |
| `largest` | the six largest terms, each as `[name, bits, pow, count]`. |

## 2. Error terms

|F| = |QM31| = (2^31 - 1)^4 ~ 2^124. E = 2^(lc+lb) is the code length and
rho = 2^-lb the rate (a circle code of dimension C enters with k = C, as in
FlashProve's `codes.h`). R is the number of committed rows of a table, t the
number of queries, and k the number of proximity rows.

| term | bound | source / argument |
|---|---|---|
| LogUp (alpha, beta) | 2 * max(arity, 2) * D / \|F\|, with D = keys + table rows over all relations | The fractional-sum identity of a relation, cleared of denominators, is a nonzero polynomial in (alpha, beta) of total degree <= D (arity - 1) + D; add a zero denominator. Also requires D_rel < p (reported as `logup_below_p`). |
| GKR, per layer | (2 n + 1)/\|F\| for instance batching, deg/\|F\| per round, n/\|F\| for the mask fold | Schwartz-Zippel on stwo's batched LogUp-GKR; n = instances active at the layer. |
| sumchecks (op, ext, batch, class) | deg/\|F\| per round, plus (rounds + 1)/\|F\| for the claim's own randomness (zero-check point, batching xi or gamma) | Schwartz-Zippel / LFKN. |
| PCS: claim gammas | 1/\|F\| per group | independent coefficients |
| PCS: proximity | (R * count / \|F\|)^k | k independent rows drawn in one challenge (3.2). count = E + 1 in unique decoding (BCIKS20 Thm 1.6, plus one for the circle subcode). Johnson: count = (2 M^5 + 3 M delta rho)/(3 rho^1.5) E + M/sqrt(rho) + L with M = m + 1/2 (BCHKS25 Thm 4.6 with M = 1, which FlashProve machine-checks as its Lemma 5.13, plus a list size for the circle subcode). The factor R is the conservative reduction from a line to a uniform combination of R rows (ePrint 2026/680 Lemma 4.7; FlashProve argues that the factor is not needed). |
| PCS: OOD collision (Johnson only) | binom(L, 2) * n_vars / \|F\| | Two distinct members of the list have distinct MLEs, which agree at a random point with probability <= n_vars/\|F\|. L is the Johnson list bound (a - rho)/(a^2 - rho) with a = 1 - delta. |
| PCS: lambda | t * log G' / \|F\| | 3.3: the mean value over the t queried positions. |
| PCS: inner batch + sumcheck | 1/\|F\| + 2 (log G' + lc)/\|F\| | as in size.md 4.1(3) |
| PCS: queries | a^t / 2^pow, with a = 1 - delta for a fresh table and a = rho + delta_key for per-batch weight openings | 3.2 and 4 |

The calculator chooses the regime per level: unique decoding, delta E =
floor((E - C - 1)/2); or, for a table with an OOD sample, the Johnson
regime 1 - delta = sqrt(rho)(1 + 1/m), with m chosen to minimise the
level's total. It picks delta_key to balance the weight key's level-0
query term against the per-batch weight term. These choices are analysis
only: the verifier does not depend on delta, and the bounds hold for every
delta that is fixed from public parameters.

## 3. Soundness argument for the PCS changes

### 3.1 Setting

At one pcs2 level a table T* (R rows of E symbols) is committed by a
Merkle root. The opening has k proximity rows with uniform coefficient
vectors beta_1..beta_k (one challenge), claim groups g with coefficient
vectors a_g (fixed before beta), the committed combined rows U = (u_g)
(proximity rows first), then lambda = eq(rho, .), PoW, and t positions j.
At position j the verifier checks sum_g lambda_g Enc(u_g)[j] =
(sum_g lambda_g a_g) . T*[j]. Write e_g = Enc(u_g) - a_g T* (with a_g =
beta_i for the proximity rows) and Z for the positions where every e_g
vanishes. "u_g" means the decoded rows of U (3.4).

### 3.2 Proximity and binding with k rows (both regimes)

*Mutual correlated agreement (MCA)* for a uniform combination: except with
probability eps = R * count / |F| over beta, every set S of at least
(1 - delta) E positions on which beta T* agrees with a codeword is a
correlated-agreement set of T*: some codeword table C^S equals T* on S.
The k proximity rows are independent, so all k combinations are bad with
probability <= eps^k. In this one-challenge form the bound is also a
round-by-round bound. Fix a good row beta = beta_i.

* If |Zero(e_beta)| < (1 - delta) E, then Z is contained in Zero(e_beta),
  and a query lands in Z with probability < 1 - delta.
* Otherwise S = Zero(e_beta) is a correlated-agreement set: T* = C^S on S,
  and beta C^S = Enc(u_beta) on S. Both are codewords and |S| > rho E, so
  u_beta = beta M^S, and C^S is in the list Lambda(T*) at delta. Suppose
  some row has d_g = u_g - a_g M^S != 0. On S, e_g = Enc(d_g), a nonzero
  codeword with at most rho E zeros. So Z is contained in S and in
  zeros(Enc(d_g)), and |Z| <= rho E.

So a query lands in Z with probability <= max(1 - delta, rho) = 1 - delta,
unless every row is consistent with one member C* = C^S. Outside Z, the
lambda-combination vanishes with probability <= log G'/|F| per position
(3.3). Hence, except with eps^k + (1 - delta)^t 2^-pow + t log G'/|F|, all
rows (proximity and claim rows alike) are the rows of one list member C*.
The evaluation checks then give, for each group, sum_c gamma_c C*~(z_c) =
sum_c gamma_c v_c, so every claim holds for C* except with 1/|F| per group.

In unique decoding the list has one member (L = 1), which is the decoded
table. Beyond unique decoding the adversary might pick C* from the list.
The OOD sample removes that choice (3.4).

This replaces size.md 4.1(2)/(4). The query term is now (1 - delta)^t at
any delta, rather than (rho + delta)^t, which is useless in the Johnson
regime. With k rows the proximity term really is eps^k: all rows enter the
same lambda check, and one good row suffices. (size.md's
`prox_rows = 2 squares it` holds; this note states the argument.)

### 3.3 Lambda (mean value)

U is fixed before rho, and the positions are drawn after rho. For a position
j outside Z, the vector (e_g[j])_g is nonzero, and sum_g eq(rho, g) e_g[j]
is a nonzero multilinear polynomial in rho. It vanishes with probability
<= log G'/|F|. With N_rho such positions, Pr[pass] <= E_rho[(|Z|/E +
N_rho/E)^t] <= (|Z|/E)^t + t E[N_rho]/E <= (|Z|/E)^t + t log G'/|F|. This
interactive mean-value bound is not a round-by-round bound. A Markov split
gives an RBR form (lambda round log G'/(tau |F|), query round (a + tau)^t);
the calculator reports the mean-value form.

### 3.4 OOD samples (pcs2 `ood`, witness OOD)

Right after a root, and before any challenge that later claims depend on,
the verifier draws zeta. The prover answers with the table's MLE at zeta
(witness: `Proof.witness_ood`; committed rows: `LevelProof.ood_value`,
which is the MLE of the limb table V). The answer is a claim of its own
group, opened in the same opening (witness) or at the next level (inner
tables). Except with binom(L, 2) n_vars / |F|, at most one member of
Lambda(T*) matches the answer. Call it D, the decoded table; it is fixed
when the answer is sent. By 3.2, every accepted claim holds for C*. The
OOD claim is one of them, so C* = D. So the claims of the whole protocol
are about a table fixed at commitment time, the same footing as unique
decoding. For an inner table this D is the U* of the level above, fixed
before rho, as 3.2 needs. Inner OOD values are computed from the limb MLEs
(`oodValue`, tested against a direct MLE of V). OOD claims are separate
groups, not batched into an earlier sumcheck: batching them would multiply
that sumcheck's error by L.

### 3.5 Level-specific parameters

`Params.deep` sets the parameters of levels >= 2. The argument is per
level with that level's (t, rho, pow), so nothing changes. The size model
reads the same function on both sides. Note that the inner work bound
(`inner_work_shift`) narrows the level above when the deep blowup is high:
lb 6 there made proofs larger. lb 3 is the measured optimum.

## 4. Weights: proximity once at a small distance

The weight key proves proximity of the weight table once, at level 0 with
k proximity rows, `key_outer` queries and distance delta_key, which is far
inside unique decoding. Except with eps^k + (1 - delta_key)^t_key 2^-pow, the
table agrees with a unique codeword table D_w on a set S_D of at least
(1 - delta_key) E columns. D_w is fixed by the key.

A per-batch weight opening has no proximity row (as before). If a
committed row u_g != a_g M^{D_w}, then sum_g lambda_g Enc(d_g) is a nonzero
codeword, except with log G'/|F|. On S_D the check at j passes only where
that codeword is zero. The passing positions therefore number at most
(rho + delta_key) E, and the per-batch term is (rho + delta_key)^t_w 2^-pow +
t_w log G'/|F|. At delta_key = 0.07 and rho = 1/4, a query costs 1.66 bits,
against 0.68 bits in the unique-decoding radius used before. The price is
paid once, offline: about 900 key queries (key proof 1.9 MB instead of
0.5 MB). The blowup of `weight_outer` / `key_outer` must equal the commitment's
(`error.ConfigBlowup`).

## 5. Proof-format trims

* **weight_values dropped.** The weight claims' values are the matmul
  finals W(r, rho_n), already in the proof and in the transcript. The
  verifier now builds the weight claims from the finals it collected
  (`expected_w`). The transcript is unchanged and the soundness is
  unchanged: the opened values are exactly the values the old verifier
  forced equal. This saves 16 B per matmul (48 B on the MLP; ~300 KB of the
  18.8K-matmul Maverick window). Tests now tamper every op final instead.
  The MLP golden digest changed only because the digest no longer hashes
  the duplicate.
* **GKR instance merging per table**: not done (see 7).

## 6. Measurements

M4 Max on AC power. The host was shared with other agents (load average 7-11
during these runs), so times vary by about +-20% between identical runs.
Sizes and bits are deterministic. Toy: `product 20`, 1 thread, best of 3.
MLP: 1024 x 4096 x 8192, 12 threads, `TENSOR_BATCH_MATMULS=1`. "Bits" are the
calculator's `total` (request + key): sum with work / sum without / largest
round with work / without.

| config | bytes | prove s | verify ms | sum w/ | sum w/o | round w/ | round w/o | key bytes |
|---|---|---|---|---|---|---|---|---|
| toy base conj (54/54, d2) | 117 976 | 0.14-0.20 | 0.7 | 55.0 | 35.0 | 56.5 | 36.5 | |
| toy base "proven-query" (160/160, d2, 1 prox) | 250 456 | 0.16-0.19 | 1.5 | 100.3 | 100.3 | 100.4 | 100.4 | |
| toy UD, 2 prox (160/160) | 299 160 | 0.21 | 2.0 | 114.3 | 106.9 | 115.7 | 108.4 | |
| **toy Johnson+OOD** (122 lb2 / 76 lb3 / 76 lb3, 2 prox) | **246 920** | 0.19 | 1.45 | **113.5** | 96.8 | 115.7 | 97.1 | |
| toy Johnson+OOD (97 / 61 lb3 / 61 lb3) | 202 824 | 0.20 | 1.2 | 107.8 | 88.6 | 109.7 | 89.7 | |
| MLP base conj (64/54) | 423 296 | 1.08-1.36 | 3.4-4.4 | 54.6 | 34.6 | 56.6 | 36.6 | 246 568 |
| MLP base "proven-query" (160/160) | 914 848 | 1.05-1.28 | 6.4 | 93.7 | 93.7 | 95.0 | 95.0 | 514 024 |
| **MLP Johnson+OOD, balanced** (97 / 61 lb3 / 61 lb3, weights 53, key 900) | **640 116** | 1.07 | 4.6 | **94.5** | 86.1 | 95.0 | 88.1 | 1 891 208 |
| MLP Johnson+OOD (122 / 76 / 76, weights 66, key 900) | 763 672 | 1.08-1.55 | 6.2 | 94.5 | 93.5 | 95.0 | 95.0 | 1 931 048 |
| layer 256 tok, D 512, F 1024, 8q/2kv heads, conj (54/54) | 321 816 | 0.26 | 5.2 | 54.0 | 34.0 | 56.5 | 36.5 | |
| layer, base "proven-query" (160/160) | 705 152 | 0.28 | 7.2 | 98.0 | 98.0 | 98.6 | 98.6 | |
| layer, Johnson+OOD balanced (97 / 61 lb3 / 61 lb3, weights 53, key 900) | 518 996 | 0.27 | 6.2 | 98.6 | 86.8 | 98.6 | 88.1 | |

Layer rows: `tensor-bench layer 8 9 10 3 12 <q> 2 20 1 1 0 8 1 2 ...`; bits are
the request only (the layer bench makes no key proof). The 1024-token layer
command from the brief (`layer 10 11 12 4 12 54 2 20 2 1 0 10 1 2 54`) fails
with `error.ExtStatement` on the base branch `61ba1ce6c` as well. That is
pre-existing and was not investigated in this stream.

FlashProve's CPU toy on this machine: 341 KB, 8.37 s, 14 ms. Its printed
accounting: 128 (largest round, work counted) / 96.23 (without work); its
theorem: about q/2^124 + 2^-101.

Reading the table:

* The base "proven-query 128" configs are about 100 bits (toy) and 94
  bits (MLP) once every term is counted. A single proximity row with
  R x E/|F| and LogUp, respectively, are the limits.
* **Toy:** 247 KB at 113.5 proven bits (whole bound with work), 28% below
  FlashProve's 341 KB, with 115.7 bits for the largest round. 203 KB still
  gives 107.8 bits, above the old 250 KB config. Without work, 97 bits,
  comparable to FlashProve's 96.23. Against the unique-decoding config with
  the same bits (299 KB), Johnson + OOD saves 17%.
* **MLP:** the whole bound is capped at ~94.5 bits by LogUp: the weight
  key's 2^27-key range proof (2^-95.0) and the per-batch LogUp over ~2^25
  fractions (2^-96.2). Every PCS term is now >= 113 bits (122/76 config).
  The balanced config puts them just above that floor at 640 KB, 30% below
  the old 915 KB, with no loss of proven bits.
* Prover cost: the extra rows (2 proximity rows + an OOD group) and the OOD
  MLE add ~0.05-0.15 s to the MLP openings. On this loaded host that is
  within the run-to-run noise of the total; the stage timers show
  witness_open + weight_open going from ~0.10 s to ~0.12-0.24 s.

## 7. Caveats and not done

* **QM31 caps every whole bound at ~114 bits.** About 100 sumcheck/GKR
  rounds at 2-3/|F|, the lambda terms (t log G'/|F| ~ 2^-116) and the OOD
  collisions (~2^-114 to 2^-116) add up there. A largest round above ~122
  bits is impossible with a 2^124 field. Reaching 120+ for the whole bound
  needs a larger challenge field, or repeated sumchecks.
* **LogUp is the MLP floor (~95 bits).** The fix is two independent alpha
  (two GKR runs: the key proof is offline and could afford it; per batch
  it costs ~25% prover time), or alpha in a degree-2 extension of QM31.
  Not done. At Maverick scale (~9e9 keys per request), D exceeds p =
  2^31 - 1 and the LogUp multiplicity argument over M31 does not apply as
  stated. The calculator flags this (`logup_below_p`). Relations must be
  split below p, or the multiplicities checked another way.
* The lambda term uses the interactive mean-value bound (3.3), so the
  `round_*` figures are not a round-by-round proof. They are also neither
  machine-checked nor refereed. The Johnson count (BCHKS25 Thm 4.6) is taken
  as given; FlashProve machine-checks it for lines (its Lemma 5.13). We
  use the conservative R factor for combinations of R rows.
* Not done: the RBR (Markov) form of the lambda term in the report;
  independent lambda coefficients (saves log G' in that term); GKR
  instance merging per lookup table; a second OOD point for tables with
  long lists (it would square the collision term at the cost of one group).
* Metal: the OOD MLEs run on the CPU (`pcs.combineRows`, exact integer
  arithmetic), so proofs stay bit-identical (`test-metal` 10/10).

## 8. Tests

* `pcs2.zig`: OOD roundtrips at depth 1, 2 and 3 with deep params. At every
  level, a wrong and a missing OOD answer are rejected, and the OOD value
  equals a direct MLE of the limb table.
* `size_tests.zig`: MLP at depth 1, depth 2 and batched in the
  beyond-unique-decoding config. Rejected: a wrong witness OOD answer, a
  wrong inner OOD answer at every level of both openings, a verifier
  without OOD, other `key_outer` / `weight_outer` params, a blowup mismatch,
  and every op final (now the only copy of the weight values) in both MLP
  tests.
* `security.zig`: the compiled level (126.21 at w = 128), the unique and
  Johnson parameters, the sum/max arithmetic, and an end-to-end product
  account: more queries give > 20 more bits, and a tampered proof is
  refused.
