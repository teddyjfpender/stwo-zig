# Tensor frontend: proven security and proof format (stream `r2-sec`)

Branch `codex/tensor-r2-sec` (base `61ba1ce6c`). New: `src/tensor/security.zig`
(soundness calculator). Protocol changes are opt-in (`pcs2.Params.ood`,
`pcs2.Params.deep`, `Config.weight_outer`, `Config.key_outer`); with the
defaults, proofs are unchanged except that the duplicated weight values are
gone (see 5).

## 1. The calculator

`security.accountProof(a, cfg, st, key, proof, key_proof)` runs the verifier
(`protocol.verifyInfo` records the shapes it checked) and, when a key proof
is given, the key verifier `weight_key.verify` (review B SEC-2). A proof or
key proof that either verifier rejects is not accounted. It then lists
**every challenge of the protocol with its error term**. Without a key proof,
a proof that reads weights is reported as `conditional_on_key` (SEC-3): its
weight opening is only a consistency check against a table whose proximity
the key proof proves, so the sum is a bound only given a verified key proof
at `delta_key`, and the JSON prints it as `total_conditional_on_key`, not
`total`. `security.accountServe(...)` does the same for one request of a
served batch (1.2). The bench prints the result as `"security"` for
`product`, `mlp` and `layer`. The layer bench proves the key only with
`TENSOR_LAYER_KEY=1`, because its GKR over every layer weight sets the
memory peak.

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

### 1.1 The figures, and which FlashProve number each one matches

Until review B (SEC-1) this section called `sum_*` the "whole bound" and
compared it with FlashProve's 126.21 / 96.23. That was the wrong row.
FlashProve (`docs/limits.md`, "the soundness figure"; `docs/figures.tsv`
rows `whole-bound-with-work` / `-without-work`) prints four readings of the
same rounds:

| FlashProve row | with work | without work | definition | our figure |
|---|---|---|---|---|
| the weakest single round | 128.00 | 96.23 | -log2 of the largest per-round error | `rbr_round_with_work` / `rbr_round_without_work` |
| the whole bound "as one number" (`cp_verify -plan accounting`) | 126.21 | 96.23 | the largest L with 2^-L >= 2^-w + 8.5 * 2^(L-256), w = the weakest round; read as "a cheater making N hash calls succeeds with probability <= N/2^L" | `rbr_compiled` (alias `compiled`) / `rbr_compiled_without_work` |
| all rounds of one key file's, leaf file's and request's proof, added | 119.38 | 92.42 | -log2 of the sum of every round's error | `sum_with_work` / `sum_without_work` |
| a cheater who computes no hashes, at the verifier's own hash count | 108.32 | 76.55 | the compiled bound times the verifier's own N | not computed (we do not count verifier hashes) |

| JSON field | meaning |
|---|---|
| `sum_with_work` / `sum_without_work` | -log2 of the sum of all terms; with work, every query term is divided by 2^pow. **FlashProve's "all rounds added" (119.38 / 92.42).** It sums the mean-value lambda form (3.3), which is an interactive bound. |
| `round_with_work` / `round_without_work` | -log2 of the largest single term with the mean-value lambda form. A diagnostic only: it is not a per-round bound (3.3). |
| `rbr_round_with_work` / `rbr_round_without_work` / `rbr_worst` | -log2 of the largest per-round error, with each inner level's lambda/query pair in its round-by-round (Markov) form (3.3). Every other term already is a per-round bound. **FlashProve's "weakest single round" (128.00 / 96.23).** |
| `rbr_compiled` (= `compiled`) / `rbr_compiled_without_work` | FlashProve's compiled level (c_h = 8.5, 256-bit digests) of `rbr_round_*`. **FlashProve's "whole bound as one number" (126.21 / 96.23)**; tested at 126.21 for w = 128. Until SEC-6, `compiled` was taken from `round_with_work` (the mean-value maximum), which is not the per-round error the Fiat-Shamir compilation needs; it overstated the toy by 0.1 bit. Below ~120 bits the 8.5 * 2^(L-256) term is negligible, so `rbr_compiled` = `rbr_round_with_work` to 0.01 bit on every config here. |
| `request` / `key` / `total` (or `total_conditional_on_key`) | the per-batch proof, the one-time weight-key proof, and both together (a client checks both). |
| `batch`, `n_requests` (serving only) | the joint reading of a served batch (1.2). |
| `largest` | the six largest terms, each as `[name, bits, pow, count]`. |

The `proven_bits` JSON field of `printTl` / `tensor-verify` / `zk_bench` is
now `query_bits_unique` (SEC-8): -t log2(1 - delta_ud) + pow of the PCS
query rounds alone, which is not a soundness bound.

### 1.2 Serving: per-request and batch readings (`accountServe`, SEC-7)

`security.accountServe(a, cfg, st, key, rp, shared, index, key_proof)` runs
`serve.verifyRequestInfo` and adds, to the request's own terms (the same
terms as a single proof, without its weight opening), the shared ones:

* the cross-request combination: n_all independent gamma. A false slot
  claim gives a nonzero linear form in the gammas, which vanishes with
  probability 1/|F|.
* the reduction sumcheck: degree 2 over log|W| variables, 2 log|W|/|F|
  (with its claim term).
* one weight opening at the reduced point (one group), at `delta_key`.

`request` is the **per-request reading**: verifier i accepts a false
statement i. `batch` is the **joint reading**: some request of the batch is
false and its verifier accepts. Each request's own rounds run on its own
transcript T_j, so the union over the batch charges them log2(n_requests)
bits each, as FlashProve's printout says for a joint count ("each round of
a request's own chains reads log2(N) bits less"). The shared rounds run once
on the batch transcript, after every slot is fixed, so they are charged
once. FlashProve argues that step only in its report (row SO-1.4). Here it
is the plain union bound over the n transcripts, which only the request
rounds need. The tests pin both readings: logup + 2 bits at 4 requests, and
the weight-opening terms are unchanged.

## 2. Error terms

|F| = |QM31| = (2^31 - 1)^4 ~ 2^124. E = 2^(lc+lb) is the code length and
rho = 2^-lb the rate (a circle code of dimension C enters with k = C, as in
FlashProve's `codes.h`). R is the number of committed rows of a table, t the
number of queries, and k the number of proximity rows.

| term | bound | source / argument |
|---|---|---|
| LogUp (alpha, beta) | 2 sum_rel g_rel D_rel / \|F\| with g_rel = max(arity - 1, 1) of the relation (its table kind and its keys; ext tables counted as arity 3), D_rel = its keys + table rows. Weight key: (2 D / \|F\|)^k with k = `key_alphas` | A key of arity a enters as alpha - (v_0 + beta v_1 + ... + beta^(a-1) v_(a-1)): total degree g. Distinct keys give distinct denominators that are monic in alpha, hence coprime. If the multiset identity fails (a net multiplicity c_s != 0 mod p), sum_s c_s/d_s is a nonzero rational function, whose numerator over the common denominator has total degree <= (N - 1) g for N <= D distinct keys (Schwartz-Zippel), plus N g/\|F\| for a zero denominator. Needs D_rel < p (reported as `logup_below_p`). The verifier checks each relation's sum separately (`LogUpSumNonZero` per table), so the union bound runs per relation (dddb8387c). Until 0f1f577ec the calculator used 2 max(arity, 2) D with the global maximum arity, which added the alpha- and beta-degrees (1 bit loose for arity <= 2, 0.6 bit for arity 3). |
| GKR, per layer | (2 n + 1)/\|F\| for instance batching, 3/\|F\| per round, n/\|F\| for the mask fold | Schwartz-Zippel on stwo's batched LogUp-GKR; n = instances active at the layer. Every round is charged the verifier's maximum degree 3 (`verifier_kernel.MAX_DEGREE`), not the degree of the polynomial the proof sends (SEC-5): a cheating round polynomial of lower degree still differs from the true degree-3 one, and agrees with it at up to 3 points. Honest LogUp layers have degree 3, so no figure moves. |
| sumchecks (op, ext, batch, class) | deg/\|F\| per round, plus (max(rounds, claim_dim) + 1)/\|F\| for the claim | Schwartz-Zippel / LFKN. The claim of an op sumcheck is an identity checked at a random point: the matmul accumulator acc~(rho) = r~ + 2^s y~ - sum_k X~ W~ at the GKR point over lt + ln variables (not the lk rounds); requant and plain einsums at n_out variables; the class batching xi adds one degree (SEC-4). The op bound uses the largest matmul/hadamard output (conservative across shape classes). |
| ext lineq | n/\|F\| per linear equation | expr~(rho) = 0 at a fresh rho of n variables, with no sumcheck: a nonzero multilinear polynomial (SEC-4). These terms were missing before. |
| serving: shared reduction | 1/\|F\| (gamma) + 2 log\|W\|/\|F\| (rounds) + (log\|W\| + 1)/\|F\| (claim) | 1.2 |
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

## 4. Weights: proximity once at a small distance (`weight_proximity = false`)

> Since 4.2 (review PCS-1) this is the opt-in mode. The default runs a
> proximity test in every batch's weight opening, and the key's OOD claim
> pins the decoding.

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

### 4.2 Binding every batch to the key's decoding (review PCS-1, PCS-2, P7)

**The gap.** Without an OOD sample a word can be close to several
codewords, and a consistency-only opening binds only up to the distance the
key proved. The review built a table that equals Enc(M1) on a random half of
the columns and Enc(M2) on the rest. Its key proof (for M1) passed with
probability ~(1/2)^t_key, and a batch proof for M2 (the down projection
negated, a valid int8 model) passed with ~(1/2)^t_w. The two proofs are
ground separately. At the default 54/54 queries this is about 2^74 work, not
the "conjectured 128". The proven accounting of section 4 was already right:
it charges (rho + delta_key)^t_w, and for the hybrid delta_key = 1/2. The
conjectured figure was the problem. A capacity-style proximity conjecture
says nothing about which codeword a later consistency opening decodes to.

**The fix (proof format change; digests repinned).**

1. *Layout.* `protocol.mixWeightLayout` mixes the root, every tensor's dims,
   every offset, and (log_rows, log_cols, rows_used). It mixes them into the
   key transcript (`keyTranscript`) and into every batch transcript
   (`mixStatement`). `checkKeyLayout` makes `weight_key.verify`, `prove` and
   `verify` reject a key that is not the canonical `layout(st.weights)`, with
   `error.WeightKeyShape`: other lengths, other dims, non-canonical or
   misaligned offsets, a wrong split, or a wrong rows_used. Before, these were
   panics or a silent reshape. `fullPoint` returns `error.ClaimShape` instead
   of underflowing.
2. *Key OOD.* The key transcript draws z_ood (log_rows + log_cols QM31
   coordinates) right after the layout, before any prover message. The
   committer publishes v_ood = W~(z_ood) as `WeightKey.ood_value`, computed in
   `commitWeights`. The key proof mixes v_ood and opens the two claims W(rho)
   and (z_ood, v_ood) with proximity. Except with binom(L, 2) n / |F| (L =
   the list size at the key's delta), at most one member D of the list
   Lambda(T*) matches v_ood, and by 3.2 the range proof is about D.
3. *Batch OOD claim.* Every batch's weight opening holds the matmul claims and
   the claim (z_ood, v_ood), grouped by column point (`pcs2.groupByColumn`,
   now in the flat PCS too).
4. *Per-batch proximity (`Config.weight_proximity`, default true).* Each
   batch's weight opening also runs its own proximity test (prox_rows rows at
   level 0). By 3.2 every accepted claim of that opening holds for one list
   member C*. The OOD claim is one of them, so C* = D: the same table the key
   proved in range, in any regime the PCS argument covers (unique, or Johnson
   with this OOD sample). This is FlashProve's online proof ("folds the
   table's rows at a sampled point ... compares the fold with them and with
   the OOD answers", paper.txt 957-958). The opening is accounted as a fresh
   table with an OOD sample (`security.zig`: `weights L0 proximity`, Johnson
   when better), and so is the key's level 0.

   With `weight_proximity = false`, the binding is section 4's: the key's MCA
   set S_D (|S_D| >= (1 - delta_key) E, T* = D there) gives (rho +
   delta_key)^t_w per batch. The batch OOD claim is then redundant, but it is
   cheap and keeps one format. This mode is cheaper per query (1.66 bits vs
   ~0.9 at rho = 1/4) but needs ~900 key queries. It has **no conjectured
   reading**: under the capacity conjecture, delta_key -> 1 - rho and the
   per-batch term becomes 1. `tensor-bench` prints `"conjectured_bits":null`
   for such a configuration. `security.zig` never computes a conjectured
   figure; it only sums proven terms for the binding the verifier checks
   (`"weight_binding"` in the report).

**Why per-batch proximity is the default.** It makes each batch
self-contained: the batch's security does not depend on the key's
query count, so a client never has to trust a 1.8 MB key proof's
distance. It is also the only mode in which the bench's conjectured figure
means anything. It costs +7% bytes at the conjectured config and +22% at
the balanced proven config (6.5 below), and in exchange the key proof
shrinks from 1.8 MB to 0.4 MB. Deployments that verify the key once, and
care about request bytes, can set `weight_proximity = false` and the
section-4 key parameters.

**LogUp counts below p (P7, PROTO-6).** The multiplicity argument needs every
relation's fractions below p: with p copies of an off-table key, p/(alpha -
v) = 0. `weight_key.checkCount` rejects 2^n + 256 >= p (n >= 31), before
the histogram check. `protocol.checkLogUpCounts` (in prove and verify)
rejects any request relation whose keys + table rows reach p, or any key of
log size >= 31, with `error.LogUpCountAboveP`. Maverick-scale relations must
be chunked below p (section 7); the projection is out of scope until that is
done.

**PCS-3, PCS-4.** Flat weight openings group claims by column point, so
`weight_log_cols > min log N` is complete (before, honest proofs failed with
`OpeningGroupMismatch`). `pcs.verifyOpening` checks every point's length
before slicing it (`error.OpeningShape`, not a panic).

**Regression tests** (`review_pcs_test.zig`, copied from the review's
rev-pcs worktree; the attack tests now assert rejection): the swapped-layout
key is rejected by the key verifier, the prover and the batch verifier, and
seven malformed keys give errors; flat `weight_log_cols = 5 > log N = 4`
verifies in both modes; the end-to-end hybrid (key for M1, batch for M2,
flat and pcs2, both modes, 40 seeds) is never accepted, while the key half
still passes 5-12 of 40 seeds at t = 2; short and long points are rejected;
2^31-weight keys and request relations with >= p fractions are rejected.
`security.zig` checks the accounting of both modes.

**Not done / follow-ups.** zk.zig has the same structure (`verifyWeightProximity`
once, per-batch `zkp.verifyOpening(..., null, ...)` without proximity, and no
OOD). There a published v_ood would leak a linear form of the weights. It
needs FlashProve's masked OOD answers (paper Definition 4.3) and is left to
the zk stream. In proximity mode the per-batch weight query count is not yet
re-tuned: 97 queries at Johnson is more than needed for the request's
LogUp-capped 99.5 bits.

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

> 6.1-6.4 were measured before the PCS-1 fix (4.2). Proof formats and
> digests have changed since; 6.5 gives the fix's cost on the same runs.

M4 Max on AC power, binary at `0f1f577ec` (ReleaseFast), host shared with
other agents (load average 4-11), so times vary by about +-20% between
identical runs and are quoted as ranges over 2-3 runs. Sizes, digests and
bits are deterministic. Every run goes through `memguard` (6 GB; peak RSS
0.3 GB toy, 2.6 GB MLP). "Bits" are the calculator's `total` (request +
key): all rounds added (`sum_*`, FlashProve's 119.38 / 92.42 row) with /
without work, largest round with / without, and the round-by-round largest
round with / without (`rbr_*`, 3.3). The compiled single number is 6.0.

### 6.0 Corrected comparison with FlashProve (review B, calculator at `codex/tensor-secfix`)

Re-run after the review-B fixes (SEC-1..8): M4 Max on AC power, ReleaseFast,
every run through `memguard`, one job at a time, one run each (times are
single samples; bits, bytes and digests are deterministic). The proofs are
byte-identical to 6.1 / 6.2: the fixes change the calculator, not the
protocol. The product Johnson digest is still `eaa5aa01ffec`, and the MLP
sizes are unchanged. "All rounds added" = `sum_*`, "weakest round" =
`rbr_round_*`, "compiled" = `rbr_compiled` / `rbr_compiled_without_work`
(definitions in 1.1). Every column is our `total` (request + key) where the
config has a key, `request` otherwise.

| config | bytes | prove s | verify ms | all rounds added w/ / w/o | weakest round (rbr) w/ / w/o | compiled w/ / w/o | weakest term |
|---|---|---|---|---|---|---|---|
| **FlashProve CPU toy** (its printout, `docs/limits.md`) | 341 KB | 8.37 | 14 | **119.38 / 92.42** | 128.00 / 96.23 | **126.21 / 96.23** | smallness test |
| product 20, base conj (54/54, d2) | 117 976 | 0.14 | 0.6 | 54.98 / 34.98 | 56.49 / 36.49 | 56.49 / 36.49 | witness L2 queries |
| product 20, unique decoding, 2 prox (160/160) | 299 160 | 0.15 | 1.7 | 114.26 / 106.86 | 117.90 / 108.40 | 117.90 / 108.40 | witness L1 queries |
| product 20, **Johnson+OOD** (122 / 76 lb3 / 76 lb3, 2 prox) | 246 920 | 0.16 | 1.3 | **113.47 / 96.76** | 115.56 / 97.10 | **115.56 / 97.10** | witness L1 lambda (rbr) |
| mlp 9 11 12, base conj (64/54), 1 alpha | 328 704 | 0.27 | 2.6 | 53.99 / 33.99 | 56.56 / 36.56 | 56.56 / 36.56 | witness L2 queries |
| mlp 9 11 12, **Johnson+OOD balanced** (97 / 61 / 61, weights 53, key 900, 2 alpha) | 522 588 | 0.28 | 3.6 | **99.50 / 86.14** | 99.52 / 88.13 | **99.52 / 88.13** | request LogUp |
| layer 9 11 12, base conj (54/54), with key (`TENSOR_LAYER_KEY=1`) | 451 312 | 1.18 | 17.4 | 53.43 / 33.43 | 56.56 / 36.56 | 56.56 / 36.56 | weights L2 queries |
| layer 9 11 12, **Johnson+OOD balanced**, with key | 682 624 | 1.31 | 18.8 | **96.55 / 86.14** | 96.55 / 88.13 | **96.55 / 88.13** | request LogUp |
| layer 9 11 12, Johnson+OOD balanced, no key (default) | 682 624 | 1.25 | 18.6 | 96.55 / 86.84 *(conditional on key)* | 96.55 / 88.13 | 96.55 / 88.13 | request LogUp |

Commands (after `tensor-bench`; mlp and layer at 4 threads, which does not
change bits or bytes): the 6.1 / 6.2 rows, and for the layer `layer 9 11 12 3
4 54 2 20 1 1 0 9 1 2 54` (conj) and `TENSOR_OOD=1 TENSOR_DEEP=61,3,20
TENSOR_WEIGHT_Q=53 TENSOR_KEY_Q=900 TENSOR_KEY_ALPHAS=2 layer 9 11 12 3 4 97
2 20 1 1 0 9 1 2 61 3 20 3 2`. The layer key proof takes the peak RSS from
5.7 GB to 9.9 GB, which is why it is opt-in.

Like for like:

* **Toy against FlashProve's toy.** All rounds added: 113.47 vs 119.38 with
  work (5.9 bits below), and 96.76 vs 92.42 without work (4.3 bits above).
  Compiled single number: 115.56 vs 126.21 with work (10.7 bits below), and
  97.10 vs 96.23 without work (0.9 bit above). Our proof is 28% smaller
  (247 KB vs 341 KB). The with-work gap is the QM31 field. Our weakest round
  with work is a field term (lambda, OOD collision, at ~2^-116), which proof
  of work cannot raise, so neither number with work can reach FlashProve's
  128 / 126.21 with a 2^124 field (7). Without work the PCS query rounds
  set both numbers, and ours are higher.
* The old 6.4 compared the 113.5 sum with 126.21. That compared our "all
  rounds added" with FlashProve's compiled number, which understated us by
  the 6.8-bit gap between FlashProve's own two rows. The corrected
  comparison is the two bullets above.
* MLP and layer have no FlashProve counterpart at this size. Both are capped
  by the request LogUp (2^-99.5 at MLP 512, 2^-96.6 at layer 9 11 12), the
  same in every reading.
* The review-B term changes (SEC-4 claim dimensions and lineqs, SEC-5 GKR
  degree 3) move no figure at 0.01-bit precision. Each new or increased term
  is ~2^-120, against sums of ~2^-99 to 2^-113.

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
* **Toy:** 247 KB at 113.5 bits with all rounds added and work counted
  (FlashProve 119.38), or 115.6 as a compiled single number (FlashProve
  126.21). Without work: 96.8 all rounds added (FlashProve 92.42) and 97.1
  compiled (FlashProve 96.23), so both are above FlashProve's. Corrected in
  review B (SEC-1); see 6.0. 203 KB still gives 107.8 bits (all rounds
  added), above the old 250 KB config. Against the unique-decoding config
  with the same bits (299 KB), Johnson + OOD saves 17%. Prove 0.16-0.21 s vs
  FlashProve's 8.37 s; verify 1.3-1.5 ms vs 14 ms.
* **MLP 512:** the balanced config is 523 KB at 99.5 bits, 29% below the
  731 KB proven-query config at 96.7 bits, so it is smaller and has more bits. The
  122/76 config keeps ~95 bits without work at 632 KB (-14%). The lean
  config shows the trade-off below the LogUp cap: 465 KB at 95.1 bits.
* Prover cost: the 2 proximity rows, the OOD groups and the OOD MLEs add
  ~0.005-0.03 s to the openings of MLP 512 (witness_open + weight_open
  0.039 s base vs 0.043-0.066 s Johnson), within the run-to-run noise of
  the total (0.28-0.33 s). The key proof with 900 queries is 1.8 MB, once
  per model.

### 6.5 Cost of the PCS-1 fix (key OOD, batch OOD claim, per-batch proximity)

M4 Max on AC power, ReleaseFast, 3 runs each, other agents on the host
(times +-20%). base = `16ce61448`, fix = this branch. Sizes and bits are
deterministic. mlp: 12 threads, `TENSOR_BATCH_MATMULS=1`. Bits are the
request account (sum with / without work); `tensor-bench mlp` accounts
the key separately.

| run | config | bytes | prove s | verify ms | weight_open s | key bytes | key verify ms | bits |
|---|---|---|---|---|---|---|---|---|
| product 20, 1 thread | base, `54 2 20 2 54` | 117 976 | 0.137-0.139 | 0.64-0.66 | - | - | - | 55.0 / 35.0 |
| | fix | 118 296 | 0.131-0.132 | 0.63 | - | - | - | 55.0 / 35.0 |
| mlp 9 11 12, conj | base, `64 2 20 2 54 2 20` | 328 704 | 0.157-0.159 | 2.71-2.72 | 0.019-0.023 | 191 368 | 1.1-1.2 | 54.6 / - |
| | fix, per-batch proximity | 350 464 (+6.6%) | 0.166-0.213 | 2.88-2.90 | 0.030-0.036 | 205 416 | 1.2 | 54.6 / - |
| | fix, `TENSOR_WEIGHT_PROX=0` | 343 968 (+4.6%) | 0.180-0.197 | 2.78-2.82 | 0.028-0.031 | 205 416 | 1.2 | 54.6 / - (conj: null) |
| mlp 9 11 12, balanced (6.2) | base, weights 53, key 900 | 522 588 | 0.169-0.173 | 3.77-3.81 | 0.030-0.032 | 1 782 152 | 7.4-7.5 | 99.51 / 86.14 |
| | fix, `TENSOR_WEIGHT_PROX=0`, weights 53, key 900 | 553 660 (+5.9%) | 0.160-0.196 | 3.92-4.05 | 0.021-0.023 | 1 770 920 | 7.4 | 99.51 / 86.14 |
| | fix, per-batch proximity, weights 97, key 122 | 640 028 (+22%) | 0.178-0.180 | 4.55-4.60 | 0.033-0.034 | 404 648 | 2.2-2.3 | 99.51 / 87.00 |

* The product toy opens no weights. Its proof changes only through the
  transcript: other query positions give +320 B of multiproof siblings.
  Prove and verify times are unchanged.
* The MLP cost is the OOD claim group (one more group, so a row at the
  final level), plus in proximity mode the proximity row and its inner
  level. weight_open grows by ~0.01 s, verify by 0.1-0.8 ms, and commit by
  the OOD MLE (one row combination, within noise of commit_weights ~0.14 s).
* With per-batch proximity the request is self-contained. The key falls
  from 1.78 MB to 0.40 MB and its verify from 7.4 to 2.2 ms at the same
  request bits. Re-tuning the per-batch weight queries (97 here) is a
  follow-up.
* The conjectured config's bench JSON now prints `"conjectured_bits":null`
  with `TENSOR_WEIGHT_PROX=0`. Its proven account is unchanged (~54-55 bits:
  that config was never proven 128).

## 7. Caveats and not done

* **QM31 caps the all-rounds-added sum at ~114 bits** (and every per-round
  figure at ~116). About 100 sumcheck/GKR
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

### 7.1 Review B notes: soundness and zero knowledge

* **SEC-1 (naming).** Labels and the comparison only (1.1, 6.0). No bound changed.
* **SEC-2 (key proof verified before it is accounted).** `accountKey` runs
  `weight_key.verify(a, cfg, key, kp)` first. Soundness: the key terms are
  read from `keyConfig(cfg)` and the GKR shape, which is valid only for an
  accepted proof whose parameters are cfg's. `weight_key.verify` checks
  exactly that. Before the fix, a tampered key proof was reported at 12.05
  bits (review test). The only bench caller already verified first.
* **SEC-3 (no key proof).** `conditional_on_key` and
  `total_conditional_on_key`, as in 1. The per-batch weight term
  (rho + delta_key)^t is valid only if the table is delta_key-close, and
  only a verified key proof gives that.
* **SEC-4 (claim dimensions, lineqs).** See the section 2 rows. Each
  missing term was ~2^-120.
* **SEC-5 (GKR rounds).** 3/|F| per round from `round_polys.len`. The old
  `coeffsSlice().len - 1` underflowed on an empty round polynomial (pinned
  by a test that aborted on the old code).
* **SEC-6 (compiled).** `compiled` = `rbr_compiled`.
* **SEC-7 (serving).** 1.2. The joint reading charges log2(n) bits on each
  request's own rounds. The shared rounds are charged once.
* **SEC-8 (hiding mode).** zk_bench's `proven_bits` is now
  `query_bits_unique`. It omits the R (E + 1)/|F| proximity term (2^-97 to
  2^-100 with one row) and all protocol terms. The calculator does not cover
  hiding openings yet (zk.md 3.5, "So `security.zig`").
* **Zero knowledge.** Every review-B change is to the calculator,
  bench labels or docs. No prover message, transcript or opening changes,
  so hiding-mode proofs and their simulators (zk.md) are untouched, and no
  proof digest moves. Nothing was repinned.

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
* `security_regress_test.zig` (review B; each failed on the old calculator):
  a rejected key proof is refused (SEC-2), a request without a key proof
  reports `total_conditional_on_key` (SEC-3), and the matmul claim is charged
  at least lt + ln (SEC-4). `security.zig` adds: compiled from the RBR
  maximum (SEC-6), GKR rounds at degree 3 including an empty round
  polynomial (SEC-5), lineq n/|F| (SEC-4), and a 4-request served batch with
  the reduction terms, the +2-bit joint reading of the request rounds, the
  shared weight terms counted once, and a slot mismatch refused (SEC-7).
* 55/55 tests (ReleaseFast and ReleaseSafe), `test-metal` 10/10 (at the
  r2-sec merge); 111/111 tensor tests after review B.

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

## 10. Selectable security levels: 128 and 160 bits (degree-8 challenge field)

Branch `codex/tensor-sec128`. `Config.security` picks a level:
`.custom` is the default, with the parameters given in Config, so every
existing proof and pinned digest is unchanged. `.bits128` and `.bits160` fix
every soundness parameter (`proto.securityConfig`). Prover and verifier refuse
a config whose parameters do not match its level (`proto.checkSecurity`:
`error.SecurityParams`) or whose level needs a larger field than the build has
(`error.ChallengeFieldTooSmall`).

**Why a bigger field.** Over QM31 (|F| = 2^124), every field-limited round
costs at least 1/|F|. Examples are a sumcheck round, a LogUp alpha/beta, a GKR
layer, an OOD collision and a pcs2 lambda. A model-layer proof adds
100-400 such rounds, so "all rounds added" stops at about 113-116 bits with
work, whatever the PCS does. The QM31 rows of the table below show this:
raising queries to the 128-bit preset over QM31 moves the toy from
113.5 / 96.8 to only 114.1 / 104.3. So 128 bits needs either a larger field
or repetition.

* **Chosen: degree-8 challenge field.** OM31 = QM31[v]/(v^2 - u), from
  `core/fields/om31.zig`. It is irreducible because Norm(u) = 5 is a
  non-square mod p. |F| = 2^248. The choice is made at build time:
  `zig build -Dchallenge=om31` builds `tensor-bench-om31` /
  `tensor-verify-om31`. Every challenge is then drawn from OM31, and every
  prover message over the secure field is OM31: sumchecks, LogUp-GKR (the
  engine's `gkr_prover_fast.ForField(OM31)`, which already had packed OM31
  lanes), the pcs2 combined rows and the OOD values. Commitments stay over
  M31. A combined pcs2 row of C felts is committed as 8 x C M31 limbs instead
  of 4 x C.
  `field.QM31` is an alias, Q4 in the default build and OM31 in the om31
  build. The frontend keeps every `f.QM31` name.
  `OM31.fromU32Unchecked(a,b,c,d)` builds the QM31-subfield element, so every
  constant in the code keeps its meaning. The default build compiles the same
  code with the alias set to QM31, and its outputs are unchanged: the full
  default suite passes, including the pinned digests.
* **Not chosen: repetition** (k independent challenge sets for the
  field-limited checks). This alternative was argued, not measured.
  Repetition inside one Fiat-Shamir transcript does not amplify
  round-by-round soundness. A grinding prover can let one copy escape in
  round i and the other in round j, at a cost of about 2/eps. So the FS bound
  stays near eps, not eps^2. Repetition across independent transcripts gives
  (N / 2^L)^2 against an N-query attacker, not N / 2^(2L). That is below
  128 bits for N > 2^64 when L is about 96. Either way, repetition doubles
  the sumcheck and GKR prover work, and every round's messages. The field
  extension has neither soundness problem, and its cost is measured below.

**Parameters** (`securityConfig`). pcs2 depth 2 in the Johnson regime, with
OOD samples on every table and 2 proximity rows. The outer level runs at rate
1/4 and the committed-row levels (inner and deep) at rate 1/8. Each query
phase is preceded by 20 PoW bits, which count only in the with-work reading.
Weight openings run their own proximity test with the outer parameters. The
key uses one LogUp alpha. The larger field also helps the Johnson parameter:
m can grow to about 2^14 (the correlated-agreement count is ~m^5 n / |F|).
The agreement then sits at sqrt(rho)(1 + 1/m), about 0.500 at rate 1/4 and
0.354 at rate 1/8: 1.0 and 1.5 bits per query.

| level   | outer queries (lb 2) | inner/deep queries (lb 3) | PoW |
|---------|----------------------|---------------------------|-----|
| bits128 | 136                  | 90                        | 20  |
| bits160 | 168                  | 112                       | 20  |

**Binding.**
* Wire format: a degree-8 build writes VERSION 2, with header
  MAGIC, 2, kind, degree (8), level (0 for keys). Each build decodes only its
  own version. A QM31 verifier given an OM31 file, or the reverse, fails
  with `error.ChallengeFieldMismatch`. A proof whose header level is not the
  statement config's fails with `error.SecurityLevelMismatch`. The
  statement's level comes from its header.
* Transcript (degree-8 builds only): initDomain mixes ("OM31", 8), and
  proveCore / verifyCore / the weight key mix the level. A proof made at one
  level fails at another even if the parameters were made to coincide.
  QM31 transcripts are untouched.
* ZK (hiding) mode is QM31-only. An om31 build, or a non-custom level,
  returns `error.Unsupported` from zk.prove / zk.verify.

**Accounting.** `security.LOG2_F` is the build's log2 |F| (124 or 248). The
calculator is otherwise unchanged. All three benches print `security_level`
and `challenge_degree`, and `tensor-bench-om31 ... --security bits128`
applies the preset; the query arguments are then ignored except the pcs2
work shift. "All rounds added without work" is FlashProve's 92.42-bit row
reading: -log2 of the sum of every term with no PoW credit. The compiled
reading (N/2^L, digest 256 bits, c_h = 8.5) is capped near 126.4 bits by the
hash, for any field. FlashProve's 126.21 sits at the same cap. The levels
claim the all-rounds-added number, not the compiled one.

**Measured** (M-series laptop on AC power, best of 3 prove runs, memguard,
one job at a time). Bytes are the encoded wire proof. Bits are sum with /
without work, then compiled with work.

| bench | config | field | prove s | verify s | proof bytes | bits (all rounds) | compiled |
|-------|--------|-------|---------|----------|-------------|-------------------|----------|
| toy 2^20, 1 core | johnson (122/76) | QM31 | 0.162 | 0.0013 | 249,192 | 113.47 / 96.76 | 115.56 |
| toy 2^20, 1 core | 128-bit queries (136/90) | QM31 | 0.165 | 0.0014 | 276,872 | 114.14 / 104.34 | 117.25 |
| toy 2^20, 1 core | **bits128** | OM31 | 0.270 | 0.0022 | 443,066 | **153.67 / 133.67** | 126.46 |
| toy 2^20, 1 core | bits160 | OM31 | 0.297 | 0.0032 | 535,194 | 186.40 / 166.40 | 126.46 |
| MLP 1024 tok, d=2^10 f=2^11, 12 thr | johnson | QM31 | 0.203 | 0.036 | 590,378 | 98.74 / 94.40 | 99.52 |
| MLP 1024 tok, d=2^10 f=2^11, 12 thr | **bits128** | OM31 | 0.367 | 0.055 | 1,026,844 | **152.08 / 132.08** | 126.46 |
| MLP 1024 tok, d=2^12 f=2^13, 12 thr | johnson | QM31 | 0.798 | 0.132 | 897,073 | 95.57 / 93.92 | 96.00 |
| MLP 1024 tok, d=2^12 f=2^13 | bits128 | OM31 | round 3: killed by memguard at 13.8 GB peak (8 GB reservation) | | | | |
| MLP 1024 tok, d=2^12 f=2^13, 12 thr | **bits128** (round 4) | OM31 | 1.580 | 0.195 | 1,553,419 | **152.08 / 132.08** | 126.46 |
| layer 512 tok (decoder layer, 12 thr) | johnson | QM31 | 0.789 | 0.048 | 911,810 | 96.43 / 94.59 | 96.43 |
| layer 512 tok (decoder layer, 12 thr) | **bits128** | OM31 | 1.618 | 0.071 | 1,574,644 | **152.67 / 132.67** | 126.46 |

MLP weight key (one-time, d=2^10): 0.100 s / 292 KB (johnson) vs
0.196 s / 519 KB (bits128). The layer rows are conditional on the key
(`conditional_on_key`), because the layer bench does not prove one; this is
the same reading the earlier tables use. Cost split on the toy, with the PCS
parameters held fixed (rows 2 and 3): the degree-8 field costs about 1.6x
prove time, 1.6x bytes and 1.5x verify time. The extra queries cost about 2%
prove time and 11% bytes. On the MLP and the layer the total cost is about
1.8-2.0x prove time and about 1.7x bytes.

**Not done / caveats.**
* ~~The peak memory of the large MLP (d=2^12) roughly doubles in the om31
  build~~ - profiled and cut in round 4 (`codex/tensor-sec2`), see
  "Round 4" below. The D 4096 MLP at bits128 now runs under the 8 GB
  reservation.
* No Metal path for OM31: the build disables Metal (CPU only, so proofs
  are the CPU prover's by construction). No ZK mode. See "Round 4".
* The OM31 kernels are the generic Karatsuba ones (`packed_om31`). No
  OM31-specific tuning of the sumcheck, eqsum or pcs2 limb kernels was done
  (still true after round 4).
* The levels are proven bounds under the calculator's definitions (Johnson
  regime per BCHKS25, the same terms as sections 2-4). They inherit that
  argument and are not separately machine-checked.
* Tests: `sec128_test.zig`, in the om31 suite
  (`zig build test -Doptimize=ReleaseSafe -Dchallenge=om31`: 58 passed,
  3 skipped). The 3 skips are QM31 digest/number pins. For product and MLP
  at bits128, plus MLP at bits160, it checks: a byte-exact wire round trip,
  the full decode-and-verify pipeline, rejection of header tampering
  (version, degree, level), random bit flips, an OM31-half value tamper,
  and a level relabel. It also checks that `checkSecurity` refuses
  mismatched parameters. The om31 suite also runs the field, sumcheck, pcs,
  pcs2, batch-sumcheck, eqsum, prep, canonical, weight-key, security and
  wire_test suites (the last includes the wire fuzzer: 4,500 mutated
  product / MLP / decoder-layer proofs and keys at the `.custom` level over
  OM31, 0 accepted). After the independent check this suite is 71 passed,
  4 skipped (the 4th skip is the QM31 decoder-layer digest pin); before it,
  only field / sumcheck / pcs / pcs2 / sec128 ran (58 passed), and the
  weight-key and wire suites were not run in the om31 build.
* `tensor-verify[-om31]` prints `security_level` and `challenge_degree`.
  The level comes from the statement file's header, so a verifier that does
  not pin `statement_digest` must check these: a `.custom` statement accepts
  a `.custom` proof. Tampering with the level byte of the proof, the
  statement, or both was checked on emitted MLP files: every case is
  rejected (SecurityLevelMismatch, SecurityParams, NonCanonical, or a
  transcript failure when both are relabelled to `.custom`).
* The compiled (N/2^L) reading of both levels is 126.46 bits, below 128:
  the 256-bit hash caps it. "bits128" names the all-rounds-added,
  without-work number only.
* Peak RSS of the 512-token decoder layer at bits128 is about 9.7 GB
  (measured in the independent check), close to this host's memory limit.

### Round 4 (branch `codex/tensor-sec2`)

**1. Memory: the weight-key LogUp-GKR, profiled and cut.** A phase trace
(`TENSOR_RSS_TRACE=1 tensor-bench[-om31] mlp ...` prints the peak RSS after
commit / key proof / key verify / forward / prove / verify) at d=2^11
f=2^12, 1024 tokens, gave:

| phase (peak RSS, MB) | commit | key proof | forward | prove |
|---|---|---|---|---|
| johnson, QM31 | 829 | 2,065 | 2,085 | 3,339 |
| bits128, OM31, before | 650 | 3,585 | 3,602 | 4,877 |
| bits128, OM31, after | 650 | 2,051 | 2,140 | ~4,600 |

The growth was the key proof: one LogUp singles instance over the whole
weight table (n = 2^25 here, 2^27 at D 4096), held as the input column
(n|F|) plus every generic layer (~2n|F|), about 3n|F| = 12 GB at 32-byte
felts for D 4096. Fix (engine `gkr_prover_fast`, `Input.regen`): a singles
input can be given as a function `den(i)` instead of a column. The prover
builds layer n-2 straight from the function (a 2 KiB stack window per task),
keeps the lower layers in one block of 2^n entries, and refills that block
with layer n-1 for the step that reads it and then with the input column
for the last step. Peak layer memory ~3n|F| -> ~n|F| (plus eq tables),
whatever the allocator caches. Values are recomputed with the same field
operations, so proofs are byte-identical: the proof and key digests of the
MLP bench are unchanged in both builds, every pinned digest still passes,
and `gkr_regen_test.zig` compares regen vs materialised GKR proofs and
artifacts for 7 shapes (n = 2..2^13, the small path n < 3, mixed instance
sizes) at 1 and 4 threads, in both builds. `weight_key.prove` uses it on the
CPU path (`cfg.accel == null`); a device prover still gets the column.
The bench also trims its recycling allocator after the (offline, one-time)
key proof, so the batch proof does not add its peak to the key's cache.

Full size, MLP 1024 tok, D 4096, F 8192, 12 threads, `memguard --gb 8`
(kill at 10.4 GB), one prove run each (no best-of-3; other agents were
running, so the times are indicative):

| config | field | peak RSS | key proof | prove s | verify s | proof bytes | key bytes | bits (all rounds) |
|---|---|---|---|---|---|---|---|---|
| johnson (round 4 build) | QM31 | 6.88 GB (was 9.4) | 0.94 s | 0.846 | 0.130 | 897,073 | 504,080 | 95.6 / 93.9 |
| **bits128** (round 4) | OM31 | **9.55 GB** (was > 13.8, killed) | 2.22 s | 1.580 | 0.195 | 1,553,419 | 858,834 | **152.08 / 132.08** |

Phases of the bits128 run (peak RSS): commit 2.6 GB, key proof 8.1 GB,
prove 9.1 GB, end 9.55 GB. The key proof is still the largest phase:
the 4 GB GKR block plus eq tables (1 GB at the last step) on top of the
2.6 GB weight commitment. The peak after it is the batch proof (+1 GB) and
the wire encoding / accounting. Cost ratio at this size: prove 1.87x,
verify 1.50x, proof bytes 1.73x, key proof 2.4x. The johnson digest
(proof bytes 897,073) is the round-3 one: the change is memory only.

**3. Runtime level check, key level.** `SecurityLevel.targetBits()` is 128
/ 160 (0 for `.custom`). `security.checkLevel(report, level)` refuses
(`error.SecurityBelowLevel`) a report whose all-rounds-added,
without-work number is under the target, whose LogUp count reaches p, or
that is conditional on an unaccounted weight key.
`security.verifyAtLevel` = verify + account (with the key proof) + check.
`tensor-verify[-om31]` runs it after `proto.verify` and prints
`level_target_bits`, `bits_all_rounds_without_work` and `level_check_s`.
The benches run it on the prover side (the layer bench, which has no key
proof, checks the request terms against the target). The key proof now
records its level (`KeyProof.security`, from `Config.security`), the key
file header carries it (byte 7 in degree-8 builds), and `wire.decodeKey`
and `weight_key.verify` refuse a key whose level is not the statement's
with `error.SecurityLevelMismatch` (before, a generic sumcheck failure).
Tests in `sec128_test.zig` (product and MLP at bits128 / bits160): key
header byte = level; `checkLevel` and `verifyAtLevel` pass; a bits128
report checked against bits160 is refused; an MLP report without its key
proof is refused; a key file relabelled to another level or to `.custom`
gives `SecurityLevelMismatch`, an unknown level byte `NonCanonical`; an
in-memory key proof with another level is refused by `weight_key.verify`
and `verifyAtLevel`. A statement relabelled to another level now fails at
key decode with `SecurityLevelMismatch` (it was `SecurityParams`).

**Not done in round 4.**
* OM31 arithmetic tuning (task 2): not started. The cost ratio vs johnson
  is the round-3 one (toy 1.6x prove; MLP / layer 1.8-2.0x).
* ZK under OM31: not done. Design note, from reading the code: two
  blockers. (a) The hiding PCS is 4-limb specific: `zk_pcs2.zig` keeps
  `limb_vals: [4]QM31`, `limbPoints` / `limbMles` return `[4]...`, and the
  committed limb rows are indexed `gc / 4`, `gc % 4`; `zk.zig` reaches an
  `unreachable` on the om31 build path (line ~1678). These become
  `[f.N_LIMBS]` (8 limb rows per combined felt, as the non-hiding pcs2
  already commits 8 x C limbs), with `f.FELT_BYTES` in the encoders.
  (b) The levels need OOD samples and deep levels, and `zk_pcs2` refuses
  both (`error.ZkOodUnsupported`, `error.ZkDeepUnsupported`): hiding OOD
  answers need their own masking term. (b) is the larger piece. Until both
  are done `zk.prove` / `zk.verify` return `error.Unsupported` in om31
  builds and `checkSecurity` refuses `hiding` at a level.
* Metal under OM31: the guard is the build itself (`-Dchallenge=om31`
  forces `use_metal = false`, so `--metal` gives `error.MetalNotBuilt` and
  every proof is the CPU prover's). A device path needs OM31 kernels for the
  GKR layer build / fold (8-limb Karatsuba over the existing QM31 kernel),
  the pcs2 combine (8 limbs per coefficient) and the eq table; the commit
  (M31 RS encode + Merkle) is field-independent and could run on the GPU
  unchanged. Not built.
