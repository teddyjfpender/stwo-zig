# Accuracy of the proved integer model vs the float model

FlashProve reports that its integer model's greedy token differs from the
float32 evaluation of the 16-bit weights at 6.81 % of token positions (Llama 4
Maverick, 12-bit activations, 16-bit residuals, WikiText-2; paper.txt §"The
integer model"). Before this study we had no such measurement. This page
describes a reproducible harness and what it measured. **Scope: one tiny public
model and one text domain. Read the numbers as a study of the mechanisms, not
as a prediction for a large model.**

## Setup

* **Model**: `stories260K` (karpathy/tinyllamas, llama2.c format): Llama
  architecture with GQA (8 query heads, 4 KV heads, head dim 8), RMSNorm, RoPE
  (theta 10000, interleaved pairs, which is our RoPE layout as is), SwiGLU
  (hidden 172, zero-padded to 256), 5 layers, dim 64, vocab 512, shared
  embedding / classifier. 264K parameters. We picked it because its dims are
  powers of two (or pad exactly) and it is small enough to **prove** within
  this host's limits. SmolLM2-135M was not used: dim 576 and 9 heads are not
  powers of two (padding heads needs a zero-head GQA mapping), and its vocab
  (49152, padded to 65536) makes the LM head and embedding 2^26 weights each,
  far above the 2^20-element bench limit on this host. Not done.
* **Text**: the first 63 stories of TinyStories-valid (the model's own
  domain), tokenized with the checkpoint's `tok512.bin` (llama2.c `encode`
  reimplemented in Python), BOS per story, concatenated into a stream cut into
  windows of T = 64 tokens: 64 calibration windows, then 256 disjoint
  evaluation windows (16384 positions).
* **Float reference**: float32 numpy forward with llama2.c `run.c` semantics
  (RMSNorm eps 1e-5). Its next-token accuracy on the eval text is 59.7 % and
  cross-entropy 1.459 nats, a sanity check that the checkpoint is parsed
  correctly. An independent token-by-token re-implementation of `run.c`
  (KV cache, float32 RoPE as run.c computes it) matches its logits to within
  1.4e-5 on 4 eval windows, and its greedy continuation of BOS is "Once upon
  a time, there was a little girl named Lily. ..." (review check, not in the
  harness).
* **Integer model**: exactly `lm.buildModel` (dense layers, unfused QKV,
  `log_out = 0`). `scripts/tensor_accuracy.py` holds a numpy emulation of
  it. `tensor-accuracy` (`src/tensor/accuracy_cli.zig`) replays the same
  quantized model file through the Zig builder. **The emulation is checked
  bit for bit against Zig**: final residual stream [T, D] and the head's int8
  logits, on all 256 eval windows for each Zig config below, plus agreement on
  which windows are refused. Results: 238 identical + the same 18 refused
  (matched-s13-h0), and 256/256 identical for each lmcal config.
* **Metrics** (over all positions of the non-refused eval windows; the proved
  statement checks only the last position, and for each window the integer
  model at position t is the same function of tokens 0..t):
  top-1 agreement (least maximiser of the int8 logits, as the greedy check
  proves, vs float argmax); top-5 overlap; KL(float || int) with the int8
  logits dequantised by their known scale; centred logit cosine; per-layer
  relative L2 error of the residual stream; refusal rate. A window is
  *refused* when a value leaves the plan's ranges. The prover then refuses
  the request (`error.RequantOverflow`), because the model is undefined there.
  **Refused windows are left out of every metric except the "all windows"
  column**, and they are harder than the rest (float next-token accuracy
  55.7 % on the 19 windows matched-s13-h0 refuses vs 60.0 % on the others).
  The "all windows" column counts every position of a refused window as a
  disagreement (the prover gives no token there). Quote that column when
  comparing with a system that does not refuse. The float baseline also moves
  with the window set (59.7 % on all 256 windows, 60.0 % on the 237 that
  matched-s13-h0 keeps), so compare int vs float accuracy within a row.

## Quantization: why the plan must be scale-matched

`lm.calibrate` (the shipped path) chooses every requant shift from the data
(the smallest that fits int8). That is correct for a model defined by its
integer weights (the random-weight benches). For a model quantized from float
weights it breaks the meaning of the model in three places:

1. The residual adds `x + rq(o Wo)` and `h + rq(hm Wd)`. With data-chosen
   shifts every increment has its own power-of-two scale, unrelated to the
   residual's.
2. The scores `S = rq(Qr Kr)` feed an exp table with a fixed scale of 1/16
   nat (`exp(-d/16)`), so the softmax temperature is set by whichever shift
   the data picked.
3. The SiLU table reads its int8 input at scale 1/16.

The **scale-matched** plan keeps the integer model unchanged and chooses
weight scales and shifts together. The weights are per-tensor int8 at a free
real scale, the shifts are integers, and the RMSNorm gains are folded into the
next weights' rows (the public gains are a constant 64). Then:

* the residual scale s_r is set by max(|emb|, |attn out|, |MLP out|) over the
  calibration set (x 1.05);
* `o Wo` and `hm Wd` are targeted to s_r: we pick the largest shift with the
  weights still within ±127, and the weight scale makes the output scale
  exactly s_r;
* `s_q s_k 2^sS = sqrt(dh)/16` exactly, so the softmax temperature is the float
  model's; the spare factor is split evenly between q and k;
* the gate output is targeted to 1/16;
* every other shift (RMSNorm s0 and y, v, up, Hadamard, logits) is
  data-chosen, stage by stage, with the Zig record rule, and `h` extra bits are
  added as headroom.

The plan is a valid `ModelDesc.shifts`; Zig replays it unchanged.

## Score width (implemented): `ModelCfg.score_bits`

The trained model's attention logits run from -172 to +25 nats (calibration
set). At the fixed 1/16-nat score scale, int8 scores cover only ±8 nats, so
the scale-matched int8 model **refuses every window** (matched-s8). The new
option `lm.ModelCfg.score_bits` / `tf.LayerCfg.score_bits` (default 8, range
8..14) widens S to sb bits and derives the rest from it. The mask bias becomes
2^sb + 256: masked D >= 256, so e = 0. The exp-table domain becomes 2^(sb+2),
because D < 2^sb + bias. At sb = 8 both are the old 512 / 1024, so the
statement is unchanged. `score_bits` is mixed into `ModelDesc.digest` and
`ModelConfig.digest` only when it is not 8, so **no pinned digest changes**. A
test proves and verifies a score_bits = 13 request, and checks that a verifier
holding the score_bits = 8 descriptor rejects it (`lm.zig`, "score_bits = 13").

Proof cost at this size: 4 requests (T = 64), batch prove 0.69 s with sb = 13
vs 0.75 s with sb = 8 (lmcal plans, same weights). That gap is timing noise,
not a cost. Proof bytes were not measured. The exp-table LogUp grows from 2^10
to 2^15 entries per layer. That cost is fixed per table and does not grow with T.

## Results (eval set: 256 windows x 64 positions)

| config | in Zig / proved | refused windows | top-1 agree (kept windows) | top-1 agree, all windows (refused = wrong) | top-5 overlap | KL nats | logit cos | int / float next-token acc (same windows) | resid rel-err L0 .. L4 |
|---|---|---|---|---|---|---|---|---|---|
| lmcal-h1: max-abs weights + `lm.calibrate` (headroom 1), int8 scores | yes / yes | 0 | **0.8 %** | 0.8 % | 3.4 % | 21.6 | 0.73 | 0.8 / 59.7 % | 0.66 .. 0.97 |
| matched-s8-h0: scale-matched, int8 scores | yes / n.a. | **256 (all)** | n.a. | 0 % | | | | | |
| **matched-s13-h0**: scale-matched, 13-bit scores | yes / yes | 19 (7.4 %) | **82.2 %** | **76.1 %** | 80.0 % | 0.104 | 0.995 | 58.3 / 60.0 % | 0.15 .. 0.25 |
| matched-s13-h1: same, 1 bit headroom | yes / not run | 9 (3.5 %) | 70.2 % | 67.7 % | 69.7 % | 0.286 | 0.989 | 53.2 / 59.7 % | 0.24 .. 0.37 |
| emu-s13-r16: + 16-bit residual increments | **emulation only** | 7 | 75.2 % | 73.1 % | 72.9 % | 0.215 | 0.991 | 54.8 / 59.7 % | 0.17 .. 0.36 |
| emu-a12-s13-r16: + 12-bit activations | **emulation only** | 13 | **93.3 %** | **88.5 %** | 91.9 % | 0.0128 | 0.9993 | 59.4 / 59.8 % | 0.04 .. 0.09 |
| emu-a16-s13-r16: 16-bit activations | **emulation only** | 15 | 93.4 % | 87.9 % | 92.0 % | 0.0126 | 0.9993 | 59.5 / 59.7 % | 0.04 .. 0.09 |
| **matched-a12-s13-r16-h0** (round 4): 12-bit activations, 16-bit residual | **yes / yes** | 6 (2.3 %) | **92.7 %** | **90.5 %** | 91.6 % | 0.0122 | 0.9994 | 59.5 / 59.6 % | 0.05 .. 0.08 |

At the last position (the one the proved statement greedy-checks),
matched-s13-h0 agrees at 84.8 % of kept windows and 78.5 % of all 256
windows; emu-a12-s13-r16 at 94.7 % and 89.8 %.

Also measured: lmcal-s13-h1 gives 0.8 % top-1, so a wider score does not
rescue the naive plan. With matched-s13-h0, the float top-1 token is in the
integer top 5 at 98.8 % of positions. On average 1.06 tokens tie at the
int8-logit maximum, and top-1 measured on the pre-requant accumulators is
82.4 %, so the int8 logits themselves cost about 0.3 points.

End to end (Zig, `tensor-accuracy --prove 4`): for each of matched-s13-h0,
lmcal-h1 and lmcal-s13-h1, 4 eval requests (T = 64, one greedy token each) were
decoded, proved as one served batch (`serve.proveRequests`, recommended
pcs2 config), and verified by `lm.verifyRequest`. The verifier builds the
statement itself from the descriptor and the tokens. All 4 verified, and all 4
were rejected with a wrong claimed token. Batch prove 0.63 to 0.75 s, verify
about 0.15 s for all 4.

## Findings

1. **The shipped calibration path does not preserve the float model's
   meaning.** lm.calibrate on max-abs-quantized weights agrees with the float
   model's top-1 token at 0.8 % of positions. The integer model there is
   context-free: on the 16384 eval positions its token is a function of the
   current input token alone (205 distinct input tokens, each always mapped to
   the same prediction), which is why lmcal-s13-h1 predicts exactly the same
   tokens. The data-chosen shifts fit each increment's calibration maximum, so
   the typical attention and MLP increments round to about 0 (mean |o Wo| 0.5
   to 0.7 and mean |hm Wd| below 0.01 in int8 units in layers 0 and 4, vs
   mean |emb| 23) and the
   residual stays the embedding. This is a property of how a float
   checkpoint must be mapped to the integer model, not a bug in the prover.
   (Bit-identity with Zig shows the emulation is not the cause.) The model a provider commits to has to come from
   a scale-matched quantizer such as `scripts/tensor_accuracy.py`.
2. **Int8 attention scores cannot hold a trained model's attention at its
   true temperature.** The fix (`score_bits`) is implemented and proved:
   82.2 % top-1 agreement with int8 weights and activations.
3. **Activation width is the remaining main loss, not residual width.**
   Widening only the residual increments to 16 bits does not help (75.2 %):
   RMSNorm then re-quantizes the residual to int8 before the norm. 12-bit
   activations with 16-bit residual increments reach 93.3 % on the windows
   they do not refuse, which is the same ballpark as FlashProve's 93.2 %
   (6.81 % disagreement). That comparison needs care: their model is 1000x
   larger, their reference is bf16 weights, and their figure is over all
   positions, while 13 of our 256 windows are refused. Counting those as
   disagreement gives 88.5 %. Round 4 proves it (matched-a12-s13-r16, section "Wide activations"). 16-bit activations add nothing over 12-bit here. The remaining
   ~6.6 % comes from the int8 per-tensor weights (with the gains folded in),
   the 7-bit RoPE table, the 1/16-nat exp table and roundings. Not separated.
4. **Refusal is the other cost.** Overflow refuses the request, so a plan
   calibrated on 64 windows refuses 7.4 % of held-out windows (h = 0).
   Headroom trades refusals for precision: h = 1 refuses 3.5 % but drops to
   70.2 %. A provable *saturating* requant (clamp plus a proven
   "clamped or exact" selector) would remove refusals at no precision cost.
   That is designed here, not implemented.
5. The q/k dynamic range is bounded by the fixed score scale and the
   requant shift >= 1: max|q| max|k| <= 127^2 sqrt(dh) / 32 (about 1426 at
   dh = 8). On this model the spare factor is 1.1 to 2.0 per layer, so q/k
   headroom cannot be bought by adding bits. A shift-0 score (exact einsum)
   would double the room.

## Wide activations / residuals (round 4: implemented and proved)

`lm.ModelCfg.act_bits` (A, 8..14) and `resid_bits` (R, 8..16), mirrored in
`tf.LayerCfg`, default 8 / 8. Both are mixed into `ModelDesc.digest` and
`ModelConfig.digest` only when not 8 (tagged), so **no pinned digest
changes**; the default model builds the identical statement (full suite green,
pinned proof digests unchanged).

What is wide (dense layers; MoE layers refuse A or R != 8 with BadConfig):

* **Core matmul output width**: `proto Op.matmul.out_bits` (8..16, default 8).
  The y-range LogUp key becomes Y + 2^(ob-1) in [0, 2^ob) (one 2^ob range
  table), everything else is the int8 op. Transcript and wire mix out_bits
  only when != 8 (transcript tag 7, wire tag 7; a tag-7 op with ob = 8 is
  NonCanonical), so int8 statements and proofs are byte-identical to before.
  `bounds.zig`: Y gets bound ob - 1; 8 <= ob <= 16 and shift + ob <= 30
  (2^s |Y| < p/2 in the remainder identity) are required. The hiding prover
  (`zk.zig`) refuses ob != 8 (error.Unsupported): not implemented there.
* **Inputs** need no new op: the core matmul's accumulator check was already
  |acc| <= 2^(bx + 7 + log K) <= 2^30 for any proved input bound bx. At
  A = 12 this allows K <= 2^12 (stories260K: K = 64 / 256). Larger K (Maverick
  d_model 5120) would need the int8-limb split X = 2^6 X_hi + X_lo or K
  splitting; **not implemented** - such a statement is rejected by
  `validateStatement` (test: wide_test.zig "wrapped accumulator").
* q / k / v / gate / up: A-bit outputs. o Wo and hm Wd: R-bit outputs. RoPE:
  A + 1 bits. Attention output O: A-bit range. SiLU: an ext lookup over
  2^A entries (`tf.siluTableWide`, input scale 2^-(A-4), same +-8 range), whose
  input key also range-checks g. Hadamard: a requant einsum with A-bit output
  and a symmetric data-chosen shift. Logits stay **int8** (the greedy check is
  unchanged; finding: int8 logits cost about 0.3 points).
* **Embedding at R > 8**: two committed int8 limbs, X = 2^8 rq_1(OH EmbHi) +
  rq_1(OH EmbLo) (EmbLo is a new weight after Emb, `embLoIndex`), each limb
  range-checked by its own core op, combined by an exact lineq; bounds derive
  |X| <= 2^16. Layer 0 then requantizes X like every other residual
  (`l0.rms1.s0` enters the plan).
* **RMSNorm at A > 8** (`tf.rmsParams`): s1 - m1 = ld + 2A - 27 so rt < 2^13
  for |xs| <= 2^(A-1); eps ceps = 2^(12 + s1 - m1) forces rt >= 64, so
  inv = floor(2^21 / rt) <= 2^15 fits its 16-bit range and inv * rt <= 2^29;
  u = rq_10(xs inv). Every product is below 2^29, re-derived by bounds.zig.
  The squared sum ss <= 2^(2(A-1) + ld) limits A = 12 to **D <= 2^7**
  (D = 2^8 is refused with BadConfig by the builder on both prover and
  verifier side; test "statement validation rejects shapes that could wrap").
  So Maverick-size D at 12 bits needs ss limb-splitting too: not done.

The numpy emulation (`--config matched-a*-s13-r16-*`, `Cfg.zig_wide`) uses
exactly these constants and is checked **bit for bit against Zig** on all 256
eval windows: 249 + 7 refused (a8), 252 + 4 (a10), 250 + 6 (a12-h0), 255 + 1
(a12-h1), 0 mismatches (summary.json "zig" -> "compare").

### Results (proved configs, same eval set)

| config | refused | top-1 kept | top-1 all windows | last pos kept / all | top-5 | KL | int / float next-tok |
|---|---|---|---|---|---|---|---|
| matched-s13-h0 (round 3, int8) | 19 | 82.2 % | 76.1 % | 84.8 / 78.5 % | 80.0 % | 0.104 | 58.3 / 60.0 % |
| matched-a8-s13-r16-h0 | 7 | 75.2 % | 73.1 % | 77.9 / 75.8 % | 72.9 % | 0.215 | 54.8 / 59.7 % |
| matched-a10-s13-r16-h0 | 4 | 91.7 % | 90.3 % | 91.7 / 90.2 % | 90.6 % | 0.016 | 59.5 / 59.7 % |
| **matched-a12-s13-r16-h0** | 6 (2.3 %) | **92.7 %** | **90.5 %** | 92.8 / 90.6 % | 91.6 % | 0.0122 | 59.5 / 59.6 % |
| matched-a12-s13-r16-h1 | 1 (0.4 %) | 88.9 % | 88.6 % | 88.2 / 87.9 % | 87.9 % | 0.025 | 59.0 / 59.7 % |
| emu-a12-s13-r16-h0 (round 3 emulation) | 13 | 93.3 % | 88.5 % | 94.7 / 89.8 % | 91.9 % | 0.0128 | 59.4 / 59.8 % |

The proved A = 12 model matches the round-3 emulation within 0.6 points on
kept windows and beats it on all windows (fewer refusals: the RMSNorm
reciprocal is coarser but the eps and int8 logits refuse less). FlashProve
reports 93.2 % agreement (6.81 % disagreement) on Maverick; the earlier
caveats apply (1000x smaller model, our figure excludes or counts refusals).
a8-r16 is identical to emu-s13-r16 (wide residual alone does not help).

### Proof cost (stories260K, T = 64, 4 requests per batch, recommended pcs2 config, this laptop)

| config | witness elems / request | committed bits / request | request proof bytes (wire, mean) | shared opening bytes | batch prove | verify (4) |
|---|---|---|---|---|---|---|
| matched-s13-h0 (int8) | 1,331,339 | 42.6 M | 371,037 | 1,350,796 | 0.71 s | 0.18 s |
| matched-a12-s13-r16-h0 | 1,378,963 (+3.6 %) | 44.1 M | 399,793 (+7.8 %) | 1,417,036 (+4.9 %) | 0.73 s | 0.18 s |

All proved requests verified (4/4 per config) and a wrong claimed token was
rejected (4/4). Prove-time difference is within run-to-run noise. The cost
comes from the 2^12 SiLU table, the 2^12 / 2^13 / 2^16 range tables and the
extra embedding limb, all fixed per table, not per token. **Not measured**:
the cost at the bench layer size (Maverick-like D) - it cannot be built there
at A = 12 (K and D limits above); proven / conjectured security bits were not
recomputed for these statements.

## Saturating (refusal-free) requant: designed, not implemented

Refusals are now 2.3 % (h0) / 0.4 % (h1) at A = 12. A saturating requant
y = clamp(rq_s(acc)) is provable with a committed selector pair
(hi, lo booleans, hi + lo <= 1) and the identity
  y = (1 - hi - lo) rq_s(acc) + hi (2^(ob-1) - 1) - lo 2^(ob-1),
where the remainder key applies only on the unclamped branch and the
clamped branches prove acc + 2^(s-1) >= 2^s 2^(ob-1) (resp. < -2^s 2^(ob-1))
with a range key on the slack. That needs the core remainder key to be
gated by the selector (a degree increase in the core LogUp leaf), which is a
protocol change we did not make in this round. Soundness sketch: the selector
booleans are forced by y = y (.) y einsums, and each branch's range key makes
the clamp exact; no value can wrap because acc is bounded as today.

## lm.calibrate and the scale-matched plan

`lm.calibrate` is unchanged and documented as such (doc comment): it chooses
shifts for a model defined by its integer weights. The scale-matched plan is
a joint choice of float weight scales and shifts and needs the float
checkpoint, which is not an input of the Zig prover; a provider must quantize
with the scale-matched quantizer (`scripts/tensor_accuracy.py`) and ship its
plan as `desc.shifts`. A Zig port of that quantizer (float weights in) is the
fix; not done this round.

## Reproduce

```
# downloads (data only, own directories): stories260K.bin + tok512.bin, TinyStories-valid head (2 MB)
cd src/tensor && memguard run --gb 6 -- zig build -Doptimize=ReleaseSafe
python3 -I scripts/tensor_accuracy_run.py --cache ~/Coding/ge-cache/accuracy \
    --out vectors/reports/tensor-frontend-20261103/accuracy
```

Outputs: `summary.json` (all of the above), per-config `<config>.json` (plan,
residual scale, weight clipping, refusal sites, per-layer errors), `meta.json`
(inputs). Everything is deterministic. Runtime is about 2 minutes on the
laptop. Peak RSS of the Zig prove run is 206 MB; Python RSS was not
measured.
