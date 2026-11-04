# Tensor frontend: integer transformer model and its proof

Status: implemented in `src/tensor/ext.zig` (generic ops) and
`src/tensor/transformer.zig` (builders, tests), hooked into
`src/tensor/protocol.zig`. Bench: `tensor-bench layer <log_t> <log_d> <log_f> <log_heads> [threads] [queries] [log_blowup] [pow] [log_kv_heads] [n_layers]`.

p = 2^31 - 1 (M31). All challenges are QM31 (|F| ~ 2^124).

## 1. Generic ops (ext.zig)

Tensors are addressed at **bit** granularity. A tensor with 2^n entries has n
index bits, MSB-first (the row-major layout of its dims). An op lives on a
variable space {0,1}^m; every operand carries one *label* per index bit naming
the variable that drives it. Labels express batching, transposes, broadcasts,
head grouping (GQA) and the RoPE pair-rotation without data movement.
Operands are committed witness tensors or **public** tensors (part of the
statement; the verifier evaluates their MLEs itself).

### einsum
`Y[o] = requant_s(sum_k A[la(o,k)] * B[lb(o,k)])` (s > 0) or exact
`Y[o] = sum_k A*B` (s = 0; `y = null` asserts the sum is identically 0).
Variables 0..n_out-1 are Y's bits, n_out..n_out+n_k-1 are contracted.
Validation: each label in range, no repeats within an operand, every output
var driven by A or B, every contracted var by both.

Reduction of a claim Y_acc(rho) (rho in F^n_out):

    Y_acc(rho) = sum_{b,k} eq(rho_B, b) * A'(b,k) * B'(b,k)

where B ("batch") = output vars present in both operands, and
A'(b,k) = sum_u eq(rho_u, u) A(u,b,k) folds A-only output vars u at rho
(likewise B'). eq factorises over disjoint variable sets, so this is an
identity of multilinear polynomials; A'(r) = A~(point) where point takes
rho on A-only vars and the sumcheck point r on batch/contracted vars.
Sumcheck degree 3 (degree 2 when there are no batch vars). Final check
`eq(rho_B, r_B) * A'(r) * B'(r)`; the two finals become witness claims, or are
recomputed by the verifier for public operands.

* requant (s > 0): exactly the core protocol's virtual-remainder scheme:
  LogUp keys `r = acc + 2^(s-1) - 2^s Y in [0, 2^s)` (virtual: GKR terminal
  value is derived, never committed) and `Y + 2^(ob-1) in [0, 2^ob)`.
  acc(rho) = r(rho) - 2^(s-1) + 2^s Y(rho) at GKR's terminal point.
* exact: rho is drawn after the commitment; the prover sends Y(rho) (a witness
  claim) or the claim is 0.

### key (LogUp)
Key column `in(x) + beta * out(x)`, x in {0,1}^n, where `in`/`out` are
**linear expressions**: `c0 + sum_t c_t * T_t[labels]` with integer
coefficients; a term's labels map its bits to key vars (unmentioned key vars
broadcast) or to `SUM` (the term is summed over that bit). Tables: range
`[0, 2^b)` (b <= 20) or a public lookup table `(i, values[i])`. The GKR
terminal claim is `alpha - key~(rho)`; the prover sends each witness term's
MLE value at its point (SUM bits evaluated at 1/2 and scaled by 2^#SUM, since
`sum_u T~(rho', u) = 2^|u| T~(rho', 1/2..1/2)`), the verifier recomputes public
terms and checks `alpha - den == in(rho) + beta * out(rho)`.

### lineq
`expr(x) == 0` for all x: rho drawn after commitment, prover sends witness term
values, verifier checks expr~(rho) = 0 (Schwartz-Zippel, error n/|F|).

### Protocol placement
Ext keys are appended after the core keys in the one batched LogUp-GKR;
range tables are shared with core relations. Transcript order: statement
(ext part mixed only if non-empty, so core transcripts are unchanged) ->
witness root -> alpha, beta -> GKR -> core terminal claims -> ext terminal
claims -> core op sumchecks -> ext ops (requant einsums at GKR's point;
exact einsums and lineqs at fresh points) -> one batch sumcheck over all
witness claims -> single witness opening. All prover messages are mixed
before the next challenge.

### Soundness of the generic ops
* Every witness claim produced by an ext op is discharged by the same batch
  sumcheck + PCS opening as core claims (binding to the committed table).
* einsum: sumcheck soundness (deg * #vars / |F|) + the fold identity above.
* key: LogUp soundness over QM31 with alpha, beta drawn after the witness and
  multiplicities are committed (total key count < p); the terminal check
  binds the key column MLE to the opened tensors. Hence every key value
  (as a *field* element pair) lies in the table.
* lineq: Schwartz-Zippel.
* Public operands are hashed into the transcript (values and shapes), so a
  proof for one mask / RoPE table / gamma does not verify for another (tested).
* Statements are validated before use (malformed labels / ids / table sizes
  -> error, never out-of-bounds).

**Range-to-integer lemma.** If an integer combination of bounded integers has
true value v with -(p - 2^b) < v < p and the protocol proves v mod p lies in
[0, 2^b), then v in [0, 2^b) as an integer. Every inequality below is used only
under bounds that satisfy this (section 4).

## 2. Integer decoder layer (transformer.zig)

Dims (powers of two): T = 2^lt tokens, D = 2^ld, F = 2^lf, H = 2^lh query
heads, Hkv = 2^lkv kv heads (GQA, lkv <= lh, group G = H/Hkv; query head
h = (hk, g) uses kv head hk = h >> lg), dh = D/H. Weights int8, committed once
(7 per layer: Wq [D,D], Wk/Wv [D,Hkv dh], Wo [D,D], Wg/Wu [D,F], Wd [F,D]).
`rq_s(a) = floor((a + 2^(s-1)) / 2^s)` (rq_0 = id). Shifts marked "chosen" are
picked by the builder as the smallest s making the output fit its range; they
are part of the public statement.

```
layer(x):                       x: [T, D], int8 for layer 0
  y1  = RMSNorm(x, gamma1)
  q   = rq(y1 Wq)  k = rq(y1 Wk)  v = rq(y1 Wv)        core matmul, int8
  qr  = RoPE(q)    kr = RoPE(k)                         9-bit
  S   = rq(qr kr^T) per head (GQA)                      int8, shift chosen
  o   = Softmax-PV(S, v)                                int8
  h   = x + rq(o Wo)                                    residual (lineq)
  y2  = RMSNorm(h, gamma2)
  out = h + rq(rq(silu(rq(y2 Wg)) * rq(y2 Wu)) Wd)      core SwiGLU
```

**RMSNorm(x, gamma)** (per token t, gamma public int8 in [48, 80]):
1. xs = x if x is int8 (range-checked), else xs = rq_{s0}(x) with s0 chosen
   (remainder key + int8 range key).
2. ss = sum_d xs^2 (exact einsum, contraction over d).
3. s1 = max(ld-8, 0), m1 = max(8-ld, 0), c = 2^s1, N = (ss + c) 2^m1.
   rt = max{ r >= 0 : r^2 2^s1 <= N } (so rt ~ 16 * rms(xs), rt >= 1).
   Proved by: rt in [0, 2^rt_bits) with 2 rt_bits + s1 <= 30; rt2 = rt*rt
   (exact einsum); N - 2^s1 rt2 >= 0 and 2^s1 (rt2 + 2 rt + 1) - 1 - N >= 0
   (range keys of gap_bits = s1 + ceil(log2(2 rtmax + 2)), limbs if > 16).
4. inv = floor(2^15 / rt): inv in [0, 2^16); pr = inv*rt (exact);
   2^15 - pr >= 0 and rt - 1 - (2^15 - pr) >= 0 (16-bit ranges).
5. u = rq_6(xs * inv) (broadcast over d; 16-bit signed) ~ 32 xs / rms.
6. y = rq_s(u * gamma[d]) (public operand), int8, s chosen.

**RoPE(x)** on x [T, heads*dh] with pairs (2i, 2i+1): public table
R[t, i, b', b] = 128 * [[cos, -sin], [sin, cos]] (theta = t * 10000^(-2i/dh),
rounded). `x'[t, h, i, b'] = rq_7(sum_b x[t, h, i, b] R[t, i, b', b])`, 9-bit
signed. One einsum (batch vars t, i; contracted b; x-only h; R-only b').

**Softmax-PV(S, v)** for every head h and query t (j = key position):
* Bias[t, j] = 0 if j <= t else -512 (public causal mask). Sm = S + Bias.
* m[h,t] = max_j Sm; sel[h,t,:] = one-hot of the first argmax.
* D = m - S - Bias (committed; lineq) in [0, 1024) (lookup domain).
* e = expT(D), expT(d) = round(256 exp(-d/16)) for d < 256, 0 otherwise
  (public 1024-entry lookup). Masked positions have D >= 257, so e = 0.
* den[h,t] = sum_j e (lineq with a SUM term) in [256, 256 T].
* acc[t, h, c] = sum_j e[h,t,j] v[j, hk(h), c] (exact einsum, contraction
  over j; |acc| <= 2^8 2^7 T = 2^(lt+15)).
* o[t, h, c] = round(acc / den) = floor((2 acc + den) / (2 den)), int8
  (range key), proved per entry by the division inequality
  `0 <= 2 acc + den - 2 o den < 2 den` with od = o * den an exact einsum
  (den broadcast over c; |od| <= 2^7 2^(lt+8)) and two range keys of lt + 9
  bits (limbs above 16 bits). o is a convex combination of int8 v rounded
  once, so rows are normalised up to one rounding per output.

  History (review-A EXT-1 / EXT-3, fixed): the layer used to prove a per-row
  reciprocal rden = floor(2^(lt+15) / den) with rden in [0, 2^(lt+8)) and
  pr = rden den exact, then P = rq_{lt+8}(e rden) and o = rq_s(P v). The
  integer rden den reaches 2^(2 lt + 16), which wraps mod p from lt = 8: a
  cheating rden' = floor((2^K + p) / den) passed every key and inflated P
  (the reviewer's test made O[T-1] = 64 instead of 1). Independently, P had
  1/128 resolution, so at T >= 512 a flat row rounded every P to 0 (sum 0
  instead of 1). The FlashProve-style division above removes both: every
  product is below 2^(lt+17) and there is no per-probability quantisation.

Constraints for the rowmax: sel in {0,1} (exact einsum sel * sel = sel, a
degree-3 zero-check; over the field x^2 = x iff x in {0,1}), sum_j sel = 1
(lineq), sum_j sel * D = 0 (exact einsum with y = 0).

**Residual**: z = x + y committed with a lineq (no range check needed: z is
an integer function of range-checked integers).

**Stack**: `buildStack` chains n_layers; layer l > 0 re-quantizes its input
for RMSNorm (step 1) but the residual uses the full-precision stream
(|x_l| <= 128 + 256 l).

**Fused QKV** (`fused_qkv`, bench default): one core matmul
qkv = rq(y1 W_qkv) with W_qkv [D, 2^ceil(log2(D + 2 Dkv))] = [Wq | Wk | Wv | 0]
(one shared requant shift for Q, K, V). RoPE reads Q and K, and PV reads V,
as fixed-bit column slices of qkv. Every matmul output is then >= D wide, so
the weight table's column count is 2^min(ld, lf) (capped at 2^13) instead of
2^logDkv: the weight opening (queries x rows) shrinks by D / Dkv. Cost: the
zero padding columns are committed weights ((2^ceil - D - 2 Dkv) x D).

**MoE (top-1)** (`log_experts > 0`), replacing the dense SwiGLU MLP:
* logits = rq(y2 Wr) (core matmul, int8). Wr has 2^max(le, wlc) columns so
  the weight-table column constraint holds; only the first E columns are
  used, selected with fixed-bit labels (FIX0 on the high column bits).
* Routing x*(t) = **first** argmax_x L[t, x]: Dr = m - L (lineq) in [0, 256),
  sel binary (sel^2 = sel), sum_x sel = 1, sum_x sel Dr = 0 (as for softmax),
  plus tie-breaking: pre[t, x] = sum_{x' > x} sel[t, x'] (exact einsum with
  the public triangle Tri[x', x] = [x' > x]) and Dr - pre >= 0, so every
  x < x* has L_x < m strictly.
* Dispatch Disp[x, c, t] in {0,1} (Disp^2 = Disp) with
  sum_c Disp[x, c, t] = sel[t, x] (each token in exactly one slot of its
  expert, none elsewhere) and occ[x, c] = sum_t Disp in {0,1} (a slot holds
  at most one token). Capacity C = 2^log_capacity slots per expert; a batch
  that overflows a capacity is outside the model (the prover errors).
* Expert x: Xe_x[c, d] = sum_t Disp[x, c, t] y2[t, d] (exact einsum on the
  FIX-labelled slice x of Disp), then the core SwiGLU on C slots with that
  expert's weights (weight work follows the dispatched tokens: E * C rows
  instead of E * T).
* MO[x, c, d] = mo_x[c, d] (lineq per expert, FIX-labelled slice of the
  stacked tensor); out[t, d] = sum_{x, c} Disp[x, c, t] MO[x, c, d] (exact
  einsum, degree 2).
* Semantics: out[t] = SwiGLU_{x*(t)}(y2[t]) (no gate-probability scaling;
  slot assignment does not affect the output since the expert MLP is
  row-wise). Uniqueness: Disp binary + row/slot sums pin a bijection between
  routed tokens and occupied slots of the right expert; combine reads exactly
  that slot back.

**Fixed-bit labels.** A label FIX0/FIX1 pins an operand bit to a constant
(slicing): the claim is made at a point with that coordinate 0/1, i.e. on the
MLE of the slice, and is discharged by the same batch opening.

## 3. What is proved

For a public statement (shapes, shifts, gammas, mask, RoPE table, exp/silu
tables) and the committed weight root, the verifier is convinced that the
committed witness is *the* output of the integer layer above on the committed
input: every intermediate is uniquely determined by the constraints (argmax
ties are irrelevant: m is unique; sel may pick any maximiser but nothing
downstream depends on which).

Uniqueness arguments:
* rowmax: sel in {0,1} (sel^2 = sel), sum sel = 1 over <= T < p terms => exactly one j*;
  D_j in [0,1024) and D_j = m - S_j - Bias_j as integers (bounds below) =>
  m >= Sm_j for all j; sum_j sel D = D_{j*} = 0 => m = Sm_{j*}. So m = max Sm.
* division: o int8 and od = o den exactly, with |2 acc + den - 2 od| <
  2^(lt+17) < p - 2^(lt+9) (range-to-integer lemma), so
  0 <= 2 acc + den - 2 o den < 2 den holds over the integers and, since
  den >= 256 > 0 (the argmax entry has D = 0, e = 256), o = round(acc / den)
  is unique. Range-checking o is essential: without it o could be
  (2 acc + den - r) / (2 den) mod p for any slack r.
* isqrt / reciprocal: same pattern; rt >= 0 range-checked so the square root
  is unique; rt >= 1 since N >= 2^s1.
* requant: core argument (remainder in [0, 2^s), output range).

## 4. Field-size bounds (no wrap-around)

Enforced by `LayerCfg.validate` (ld <= 14, lf <= 15, ldh <= 13, lt <= 12,
lh + 2 lt <= 26) and by builder assertions:

| quantity | bound |
|---|---|
| ss = sum xs^2 | D 2^14 <= 2^28 |
| 2^s1 rt2, N | < 2^30 (2 rt_bits + s1 <= 30), N <= 2^28 + 2^14 |
| pr = inv rt | < 2^16 2^12 = 2^28 |
| u acc = xs inv | < 2^23; y acc = u gamma < 2^22 |
| RoPE acc | < 2^17 |
| score acc | dh 2^16 <= 2^29 |
| D, m - S - Bias | |.| < 2^11 |
| den | <= 2^(lt+8) |
| acc = sum_j e v | <= 2^(lt+15) <= 2^27 |
| od = o den | <= 2^(lt+15) <= 2^27 |
| 2 acc + den - 2 od (slack) | < 2^(lt+17) <= 2^29 |
| core matmul acc | K 2^14 <= 2^29 |

All inequality operands therefore satisfy the range-to-integer lemma.

### Statement-level bounds (verifier side; `src/tensor/bounds.zig`)

The table above is a property of the honest builder. Since review-A
(PROTO-1, PROTO-2, PROTO-4, EXT-2), `verify` no longer trusts it:
`validateStatement` re-derives, from the public statement alone, a bound
`|t| <= 2^b` for every witness tensor it can, and rejects the statement
unless every multiplication and relation is wrap-free:

* bound sources: core op outputs / lookup / range8 (int8); requant einsum
  outputs (`ob - 1`); a key whose input (or lookup output) is a single +-1
  term over plain, pairwise-distinct variable labels covering **every** bit
  of the tensor (a SUM, FIX or repeated label covers only a reduction or a
  slice and bounds nothing: PROTO-1 / EXT-2); boolean selectors `y = y (.) y`
  with identity labels (bound 0); exact einsums `bound(a) + bound(b) + n_k`
  (PROTO-2: replaces the old `EXT_EXACT_BOUND` exemption), or `bound(b)`
  alone when `a` is a proved boolean selector one-hot over the contracted
  bits (`sum_S a = 1`, or `sum_S a = s` with `s` boolean, nested through
  `s`'s own one-hot sets); lineqs solved for a +-1 term (FIX-labelled slices
  count once all slices of the tensor are covered). Derived to a fixpoint.
* checks: core matmul `bx + 7 + log K <= 30`, hadamard `ba + bb <= 30`;
  requant einsum accumulator `<= 2^29` and `shift + out_bits <= 30`; exact
  einsum / zero-check `<= 2^29 < p/2`; every key expression that is not a
  bound source has bounded terms with `|expr| + table size < p`; every
  lineq whose terms are all bounded has `|expr| < p` (an integer identity).
  Unbounded operands fail closed with `StatementUnboundedOperand`.
* shapes, ids, table ids and `n_dims` are checked before any indexing
  (PROTO-4: the old pass indexed `bound[y]` and `tables[id]` raw).

MoE stays valid structurally: Disp is boolean and one-hot over tokens
(`occ = sum_t Disp`, `occ` boolean), so `Xe = Disp . y2` has bound 7, and
Disp is one-hot over `(c, x)` (`sum_c Disp = sel`, `sum_x sel = 1`), so the
combine output has the bound of the stacked expert outputs (7, from the
per-expert FIX-slice lineqs). Removing `Disp^2 = Disp` makes the expert
matmuls fail validation (tested).

## 5. Tests (src/tensor/transformer.zig)

* full layer (T=8, D=32, F=64, 4 heads, 2 kv heads) and a 2-layer stack
  prove and verify;
* the witness matches an independent direct-index integer reference for
  RoPE, GQA scores, causal softmax, PV and RMSNorm;
* tampering of every ext sumcheck (first round), sampled finals, first/last
  ext values, statement (mask, shift, labels) -> rejected;
* test-only unchecked prover (`ext.test_unchecked_prover`) with invalid
  witnesses: moved argmax selector, lowered rowmax (consistent D), acc + 1,
  wrong rt, residual, exp value, masked-position exp leak,
  score, sum of squares -> all rejected by the verifier;
* honest prover refuses an invalid witness (error, no proof);
* fused QKV (GQA and MHA padding cases): RoPE reads the right slice
  (direct reference) and the layer proves/verifies with the wider table;
* MoE: routing / dispatch / combine match a direct reference; prove/verify
  (also with tied router columns); unchecked-prover cheats rejected: wrong
  expert in sel, dropped token, duplicated slot, combine output, and a fully
  consistent last-maximiser routing on tied logits (only Dr - pre >= 0 fails).

## 6. Not covered / caveats

* MoE: no gate-probability scaling (top-1 output = expert output); router
  columns padded to the weight-table width (padding weights are committed).
* Weight gammas are public, not committed.
* Prover kernels for ext ops: GEMM-shaped einsum accumulators, parallel
  expression evaluation and split-eq einsum sumchecks (CPU and Metal) are in
  `speed.md`; einsums with folded operand-only output vars still use the
  generic fold + sumcheck.
* Non-hiding (zero-knowledge is a separate stream).
