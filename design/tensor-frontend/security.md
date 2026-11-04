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
TENSOR_BATCH_MATMULS=1 TENSOR_OOD=1 TENSOR_DEEP=61,3,20 TENSOR_WEIGHT_Q=53 TENSOR_KEY_Q=900 TENSOR_KEY_ALPHAS=2 \
  tensor-bench mlp 9 11 12 12 97 2 20 2 61 3 20 3 2     # MLP 512 x 2048 x 4096, balanced
```

(positional pcs2 arguments as before: `depth inner_q inner_lb inner_pow
work_shift prox_rows`; `TENSOR_DEEP=q,lb[,pow]` sets the levels >= 2;
`TENSOR_WEIGHT_Q=q[,pow]` sets the per-batch weight openings and
`TENSOR_KEY_Q=q[,pow]` the weight-key proof, both at the outer blowup;
`TENSOR_KEY_ALPHAS=2` gives the weight-key LogUp two independent alpha, 4.1.)

The report gives these figures, in FlashProve's style:

| figure | meaning |
|---|---|
| `sum_with_work` / `sum_without_work` | -log2 of the sum of all terms. With work, every query term is divided by 2^pow. This is the **whole bound** (FlashProve: 126.21 with work / 96.23 without). |
| `round_with_work` / `round_without_work` | -log2 of the largest single term (FlashProve's "largest round error"). |
| `compiled` | FlashProve's compiled level for `round_with_work` (the largest L with 2^-L >= 2^-w + 8.5 * 2^(L-256)); it gives 126.21 at w = 128, as theirs does (tested). |
| `rbr_round_with_work` / `rbr_round_without_work` / `rbr_compiled` / `rbr_worst` | the largest single term with each inner level's lambda/query pair in its round-by-round (Markov) form (3.3). Every other term is already a per-round bound, so these are the round-by-round figures. |
| `request` / `key` / `total` | the per-batch proof, the one-time weight-key proof, and both together (a client checks both). |
| `largest` | the six largest terms, each as `[name, bits, pow, count]`. |

## 2. Error terms

|F| = |QM31| = (2^31 - 1)^4 ~ 2^124. E = 2^(lc+lb) is the code length and
rho = 2^-lb the rate (a circle code of dimension C enters with k = C, as in
FlashProve's `codes.h`). R is the number of committed rows of a table, t the
number of queries, and k the number of proximity rows.

| term | bound | source / argument |
|---|---|---|
| LogUp (alpha, beta) | 2 sum_rel g_rel D_rel / \|F\| with g_rel = max(arity - 1, 1) of the relation (its table kind and its keys; ext tables counted as arity 3), D_rel = its keys + table rows. Weight key: (2 D / \|F\|)^k with k = `key_alphas` | A key of arity a enters as alpha - (v_0 + beta v_1 + ... + beta^(a-1) v_(a-1)): total degree g. Distinct keys give distinct denominators that are monic in alpha, hence coprime. If the multiset identity fails (a net multiplicity c_s != 0 mod p), sum_s c_s/d_s is a nonzero rational function, whose numerator over the common denominator has total degree <= (N - 1) g for N <= D distinct keys (Schwartz-Zippel), plus N g/\|F\| for a zero denominator. Needs D_rel < p (reported as `logup_below_p`). The verifier checks each relation's sum separately (`LogUpSumNonZero` per table), so the union bound runs per relation (dddb8387c). Until 0f1f577ec the calculator used 2 max(arity, 2) D with the global maximum arity, which added the alpha- and beta-degrees (1 bit loose for arity <= 2, 0.6 bit for arity 3). |
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

### 3.3 Lambda (mean value and round-by-round)

U is fixed before rho, and the positions are drawn after rho. For a position
j outside Z, the vector (e_g[j])_g is nonzero, and sum_g eq(rho, g) e_g[j]
is a nonzero multilinear polynomial in rho. It vanishes with probability
<= log G'/|F|. With N_rho such positions, Pr[pass] <= E_rho[(|Z|/E +
N_rho/E)^t] <= (|Z|/E)^t + t E[N_rho]/E <= (|Z|/E)^t + t log G'/|F|. This
interactive mean-value bound is not a round-by-round bound. The sums use
it. For the round-by-round figures (`rbr_*`) the calculator also gives the
Markov form: the lambda round is bad when N_rho >= tau E, which has
probability <= E[N_rho]/(tau E) <= log G'/(tau |F|); in a good state a
query passes with probability <= a + tau, so the query round is
(a + tau)^t / 2^pow. tau = 2^-x is fixed from public parameters (any
fixed tau gives a valid bound); the calculator picks x on a 1/32 grid in
[1, 60] per level, separately for the with-work and without-work maxima.
On the toy's witness L1 (log G' = 3, 76 queries at a = 0.412, 20 bits of
work) this gives 115.3 bits with work (tau = 2^-7.1) against 117.2 for the
query term alone, and 97.2 without work (unchanged to 0.01 bit).

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

### 4.1 Weight-key LogUp with two alpha (`key_alphas = 2`)

The key's range proof (2^n weights against the 256-entry table) is one
LogUp relation of arity 1, error 2 D/|F| (2^-98.0 at MLP 512, 2^-97 at MLP
1024): the largest term of every proven MLP config. With `key_alphas = 2`
the verifier draws alpha_1 and alpha_2 back to back after the histogram,
with no prover message between them, and the GKR batch proves the keys and
table sums for both (4 instances, one output point rho). The verifier
checks both sums, every terminal claim, and that alpha_j - den_j(rho) - 128
is the same W(rho) for j = 1, 2; that value is the single opened claim. The
weights and the histogram are fixed before the round, and the two alpha are
independent, so both identities hold for a bad table with probability <=
(2 D/|F|)^2. Because both alpha come from one round, this is also the
round-by-round error, so it holds under Fiat-Shamir. A second alpha drawn
after the first GKR would be a separate round, and a grinding prover could
attack the two rounds one after the other. Cost (MLP 512): key prove 0.29
-> 0.47-0.49 s, once per model, offline; key proof +2.4 KB; key verify
unchanged (~7 ms). The request proof does not change. The request LogUp
(per batch) keeps one (alpha, beta). Doubling it would cost a second
per-batch GKR, about +25% prover time.

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

M4 Max on AC power, binary at `0f1f577ec` (ReleaseFast), host shared with
other agents (load average 4-11), so times vary by about +-20% between
identical runs and are quoted as ranges over 2-3 runs. Sizes, digests and
bits are deterministic. Every run goes through `memguard` (6 GB; peak RSS
0.3 GB toy, 2.6 GB MLP). "Bits" are the calculator's `total` (request +
key): whole bound (sum) with / without work, largest round with / without,
and the round-by-round largest round with / without (`rbr_*`, 3.3).

### 6.1 Toy: `product 20`, 1 thread, best of 3 (prove and verify)

| config | command (after `tensor-bench`) | bytes | prove s | verify ms | sum w/ | sum w/o | round w/ | round w/o | rbr w/ | rbr w/o |
|---|---|---|---|---|---|---|---|---|---|---|
| base conj (54/54, d2) | `product 20 1 54 2 20 2 54` | 117 976 | 0.14-0.19 | 0.6-0.7 | 55.0 | 35.0 | 56.5 | 36.5 | 56.5 | 36.5 |
| base "proven-query" (160/160, d2, 1 prox) | `product 20 1 160 2 20 2 160 2 20 2` | 250 456 | 0.14-0.21 | 1.3-1.7 | 100.3 | 100.3 | 100.4 | 100.4 | 100.4 | 100.4 |
| unique decoding, 2 prox (160/160) | `product 20 1 160 2 20 2 160 2 20 2 2` | 299 160 | 0.16-0.24 | 1.7-2.5 | 114.3 | 106.9 | 115.7 | 108.4 | 117.9 | 108.4 |
| **Johnson+OOD** (122 lb2 / 76 lb3 / 76 lb3, 2 prox) | `TENSOR_OOD=1 TENSOR_DEEP=76,3,20` `product 20 1 122 2 20 2 76 3 20 2 2` | **246 920** | 0.16-0.21 | 1.3-1.5 | **113.5** | 96.8 | 115.7 | 97.1 | 115.6 | 97.1 |
| Johnson+OOD (97 / 61 lb3 / 61 lb3) | `TENSOR_OOD=1 TENSOR_DEEP=61,3,20` `product 20 1 97 2 20 2 61 3 20 2 2` | 202 824 | 0.16-0.17 | 1.1-1.2 | 107.8 | 88.6 | 109.7 | 89.7 | 109.6 | 89.7 |

The toy has no lookups and no weight key, so the LogUp change (0f1f577ec)
does not move it. Digest of the proven config: `eaa5aa01ffec...` (same
as at `1cd11fb72`).

### 6.2 MLP 512 x 2048 x 4096 (`mlp 9 11 12`), 12 threads, `TENSOR_BATCH_MATMULS=1`

All rows: `mlp 9 11 12 12 <q> 2 20 2 <inner q> [3 20 3 2]`. The Johnson
rows add `TENSOR_OOD=1 TENSOR_DEEP=<q>,3,20 TENSOR_WEIGHT_Q=<w> TENSOR_KEY_Q=<k>`,
and every row except base conj adds `TENSOR_KEY_ALPHAS=2` (4.1). Binary at
04491c33f. Weight-key proof, once per model (offline): prove 0.47-0.49 s
with 2 alpha (0.28-0.34 s with 1), verify 2.3 ms (160 queries) to 7.3 ms
(900 queries).

| config | bytes | prove s | verify ms | sum w/ | sum w/o | round w/ | round w/o | rbr w/ | rbr w/o | key bytes |
|---|---|---|---|---|---|---|---|---|---|---|
| base conj (64/54), 1 alpha | 328 704 | 0.29-0.46 | 2.8-3.5 | 54.0 | 34.0 | 56.6 | 36.6 | 56.6 | 36.6 | 191 368 |
| base "proven-query" (160/160, 1 prox) | 731 072 | 0.27-0.29 | 4.8-5.1 | 96.7 | 96.7 | 97.4 | 97.4 | 97.4 | 97.4 | 412 264 |
| **Johnson+OOD, balanced** (97 / 61 lb3 / 61 lb3, weights 53, key 900) | **522 588** | 0.29-0.34 | 3.7-4.2 | **99.5** | 86.1 | 99.5 | 88.1 | 99.5 | 88.1 | 1 782 152 |
| Johnson+OOD (122 / 76 / 76, weights 66, key 900) | 632 200 | 0.28-0.43 | 4.3-4.6 | 99.5 | 95.1 | 99.5 | 97.1 | 99.5 | 97.1 | 1 815 560 |
| Johnson+OOD, lean (85 / 53 / 53, weights 46, key 800) | 464 748 | 0.29-0.34 | 3.5-4.9 | 95.1 | 75.2 | 96.8 | 76.8 | 96.8 | 76.8 | 1 589 320 |

The request alone (what one batch carries) gives: balanced 99.5 / 86.8,
122/76 99.5 / 95.6, proven-query 98.1 / 98.1 (sum with / without work). The
Johnson configs are now capped by the request LogUp (2^-99.5, per-relation
degree). The key's LogUp with 2 alpha is ~2^-196. Every PCS term of the
122/76 config is >= 113 bits. Proven-query is capped by its single
unique-decoding proximity row on the key (2^-97.4). Progress for the
balanced config over this session: 96.49 (start) -> 97.35 (LogUp total
degree) -> 97.56 (per-relation degree) -> 99.50 (2 key alpha); proof
bytes unchanged. Request proof digests are unchanged throughout, and the
1-alpha key digest is unchanged.

### 6.3 Earlier runs (previous session, calculator before 0f1f577ec)

MLP 1024 x 4096 x 8192 (`mlp 10 12 13 12 ...`, same parameters as 6.2) and a
decoder layer (256 tokens, D 512, F 1024, 8q/2kv heads, `layer 8 9 10 3 12
<q> 2 20 1 1 0 8 1 2 ...`, request only). These are not re-run here (the
1024-token MLP is reserved for the coordinator's final runs). Their bits
used the old LogUp bound and one key alpha. With the current calculator,
the request LogUp is per-relation (+0.7 bit at MLP 512) and the key LogUp
is squared with `TENSOR_KEY_ALPHAS=2`, so the LogUp-capped figures below
are underestimates. Expect the MLP 1024 Johnson rows near the request
LogUp, about 98.5 bits. That is an extrapolation, not a measurement. The
rbr figures were not reported then. For the coordinator: the 6.2 commands
with `mlp 10 12 13` reproduce these rows.

| config | bytes | prove s | verify ms | sum w/ | sum w/o | round w/ | round w/o | key bytes |
|---|---|---|---|---|---|---|---|---|
| MLP 1024 base conj (64/54) | 423 296 | 1.08-1.36 | 3.4-4.4 | 54.6 | 34.6 | 56.6 | 36.6 | 246 568 |
| MLP 1024 base "proven-query" (160/160) | 914 848 | 1.05-1.28 | 6.4 | 93.7 | 93.7 | 95.0 | 95.0 | 514 024 |
| MLP 1024 Johnson+OOD, balanced | 640 116 | 1.07 | 4.6 | 94.5 | 86.1 | 95.0 | 88.1 | 1 891 208 |
| MLP 1024 Johnson+OOD (122 / 76 / 76) | 763 672 | 1.08-1.55 | 6.2 | 94.5 | 93.5 | 95.0 | 95.0 | 1 931 048 |
| layer conj (54/54) | 321 816 | 0.26 | 5.2 | 54.0 | 34.0 | 56.5 | 36.5 | |
| layer base "proven-query" (160/160) | 705 152 | 0.28 | 7.2 | 98.0 | 98.0 | 98.6 | 98.6 | |
| layer Johnson+OOD balanced | 518 996 | 0.27 | 6.2 | 98.6 | 86.8 | 98.6 | 88.1 | |

The 1024-token layer command from the brief (`layer 10 11 12 4 12 54 2 20 2
1 0 10 1 2 54`) fails with `error.ExtStatement` on the base branch
`61ba1ce6c` as well. That is pre-existing and was not investigated in this
stream.

FlashProve's CPU toy on this machine: 341 KB, 8.37 s, 14 ms. Its printed
accounting: 128 (largest round, work counted) / 96.23 (without work); its
theorem: about q/2^124 + 2^-101.

### 6.4 Reading the tables

* The base "proven-query 128" configs are about 100 bits (toy) and 96
  bits (MLP 512) once every term is counted. A single proximity row with
  R x E/|F| (toy, and the MLP key) and LogUp are the limits.
* **Toy:** 247 KB at 113.5 proven bits (whole bound with work), 28% below
  FlashProve's 341 KB, with 115.7 bits for the largest round (115.6
  round-by-round). 203 KB still gives 107.8 bits, above the old 250 KB
  config. Without work, 97 bits, comparable to FlashProve's 96.23. Against
  the unique-decoding config with the same bits (299 KB), Johnson + OOD
  saves 17%. Prove 0.16-0.21 s vs FlashProve's 8.37 s; verify 1.3-1.5 ms
  vs 14 ms.
* **MLP 512:** the balanced config is 523 KB at 99.5 bits, 29% below the
  731 KB proven-query config at 96.7 bits, so it is smaller and has more bits. The
  122/76 config keeps ~95 bits without work at 632 KB (-14%). The lean
  config shows the trade-off below the LogUp cap: 465 KB at 95.1 bits.
* Prover cost: the 2 proximity rows, the OOD groups and the OOD MLEs add
  ~0.005-0.03 s to the openings of MLP 512 (witness_open + weight_open
  0.039 s base vs 0.043-0.066 s Johnson), within the run-to-run noise of
  the total (0.28-0.33 s). The key proof with 900 queries is 1.8 MB, once
  per model.

## 7. Caveats and not done

* **QM31 caps every whole bound at ~114 bits.** About 100 sumcheck/GKR
  rounds at 2-3/|F|, the lambda terms (t log G'/|F| ~ 2^-116) and the OOD
  collisions (~2^-114 to 2^-116) add up there. A largest round above ~122
  bits is impossible with a 2^124 field. Reaching 120+ for the whole bound
  needs a larger challenge field, or repeated sumchecks.
* **The request LogUp is the MLP floor (99.5 bits at MLP 512, about 1 bit
  lower at 1024 tokens).** The key's LogUp is fixed by `key_alphas = 2`
  (4.1). For the request, the same one-round trick needs a second
  per-batch GKR (~+25% prover time), or alpha in a degree-2 extension of
  QM31. Not done. At Maverick scale (~9e9 keys per request), D exceeds p =
  2^31 - 1 and the LogUp multiplicity argument over M31 does not apply as
  stated. The calculator flags this (`logup_below_p`). Relations must be
  split below p, or the multiplicities checked another way.
* The sums and `round_*` use the interactive mean-value bound for lambda
  (3.3); `rbr_*` are the round-by-round figures (Markov form). None of
  these arguments is machine-checked or refereed. The Johnson count (BCHKS25 Thm 4.6) is taken
  as given; FlashProve machine-checks it for lines (its Lemma 5.13). We
  use the conservative R factor for combinations of R rows.
* Done in the resumed session: the RBR form (`rbr_*`, 445111163), the
  LogUp total degree (0f1f577ec) and per-relation degree (dddb8387c), all
  calculator-only (proofs byte-identical), and the 2-alpha weight key
  (04491c33f, opt-in; the default key proof is byte-identical).
* Not done: independent lambda coefficients (saves log G' in that term); GKR
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
  account: more queries give > 20 more bits, the rbr fields are present,
  and a tampered proof is refused. The RBR pair of the toy's witness L1
  (115.3 bits with work; the query term without work to 0.01 bit) and the
  LogUp term (2D for arity 1 and 2, 4D for arity 3) are pinned. The
  calculator refuses a weighted LogUp count outside [D, g_max D].
* `weight_key.zig`: the 2-alpha key verifies. It is rejected by a 1-alpha
  and a 3-alpha verifier, and with a tampered histogram, a tampered value,
  or any tampered output claim of the second alpha's instances. The 1-alpha
  proof keeps 2 instances.
* 55/55 tests (ReleaseFast and ReleaseSafe), `test-metal` 10/10.

## 9. Verifier input hygiene and prover bounds (review A: KERN-1..4, PROTO-3, PCS-4)

* **Canonical encodings (KERN-1).** The soundness argument is over field
  elements, but the verifier receives limbs. The field kernels are only
  correct on limbs in [0, P): `M31.sub` computes (a + P) - b, which wraps by
  2^32 = 2 (mod P) when b >= P, while the transcript hashes the raw limbs.
  A non-canonical s(0) in a sumcheck round therefore hashes as one value and
  acts as another. The review forged a false sumcheck claim this way under
  ReleaseFast (a verifier panic under ReleaseSafe). Round polynomials,
  finals, claimed MLE values and GKR masks are not Merkle-bound, so no
  other check catches them. Every verifier entry point now runs
  `canonical.check` on the whole proof object before any arithmetic:
  `protocol.verify` / `verifyInfo`, `protocol.verifyWeightProximity`,
  `weight_key.verify`, `zk.verify` / `verifyPublic`,
  `zk.verifyWeightProximity` and `zk.verifyWeightLink`. `sumcheck.verify` and
  `zk_sumcheck.verify` also check their own proof, because they are called
  directly. `canonical.check` walks the proof type by comptime reflection
  (structs, tagged unions, optionals, arrays, slices) and checks every M31
  it reaches. Subtrees with no field element are pruned at compile time.
  A new proof field is therefore covered with no edit, and so is every
  existing class: sumcheck round evals, op/ext finals, `lookup_in_values`,
  witness value and OOD, flat rows and opened columns, pcs2 level
  `col_values` / `limb_vals` / `ood_value` / rows / inner sumchecks, GKR round
  polynomials, masks and output claims, and the zk sigma, hats, u_val, mus,
  rows, table values and GKR roots. The cost is one linear pass over the
  proof (unmeasurable next to the Merkle checks). With canonical inputs
  the residue map from limbs to field elements is injective, so a transcript
  value and the value the verifier computes with are the same field element.
  This is what the arguments of sections 3 and 4 assume. Any future
  byte decoder must build values with `field.fromLimbsChecked`.
  Regressions: `canonical_proof_test.zig` corrupts the first, middle and
  last limb of every class (to v + P and to exactly P) in a flat decoder
  layer, a pcs2 + OOD + batched layer, the weight-key proof, a zk MLP proof,
  the zk weight proximity and the zk weight link. Each corruption must give
  `error.NonCanonical`. The test also pins that the fixtures exercise each
  class. `review_kern_test.zig` replays the reviewer's sumcheck forgery.
* **Canonical-input contract (KERN-4).** `QM31.mul`'s base-field shortcut is
  wrong off-contract. The lazy path happens to reduce. The contract
  "kernels take canonical limbs" is documented at `field.fromLimbs` and is
  enforced at the trust boundary (above), not in the hot kernels. There is
  no separate soundness issue once KERN-1 holds.
* **Prover operand bounds (KERN-3).** `combineRows` / `colCombine` take a
  `bound_log2` that sets how many rows the i64 limb accumulators may sum
  before they reduce. The matmul prover passed a literal 8. A statement
  that validateStatement admits, a 20-bit range-keyed operand with K = 2
  at T = 2^13, overflowed: a panic under ReleaseSafe, and under ReleaseFast
  a wrong fold, so the honest proof was rejected. This was a completeness
  bug, not a soundness bug, because the verifier recomputes nothing from it.
  The bound table is now one function, `fillBounds`, shared by
  validateStatement and `protocol.operandBoundLog2`. All three call sites
  pass the relation-proved bound: per-matmul, batched shape class, and
  `zk.zig`. Unbounded and exact-einsum operands get 31, which is exact for
  any i32. `matmulAcc` falls back to i64 row sums when max|x| * 128 * K
  >= 2^31. Proofs are unchanged for the int8 operands that every shipped
  builder produces. The golden digests did not move.
* **Batched matmul order (PROTO-3).** This was already fixed in this base:
  the `vclass_done` skip runs before the `op_sumchecks` length check, and a
  trailing `op_i != len` check rejects extra sumchecks. The reviewer's R1
  test is kept as a regression test (`review_proto3_pcs4_test.zig`).
* **Opening claim shapes (PCS-4).** `pcs.verifyOpening` now checks every
  claim point length before `groupCoeffs` slices it, in the same order as
  `pcs2.verifyRec` and `zk_pcs.verifyOpening`. No verifier-built point could
  reach this path, so this is hardening only.
* **Metal (KERN-2).** See metal.md: the fp32 matmul gate is x in [-128, 127].
