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
  correctly.
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

| config | in Zig / proved | refused windows | top-1 agree | top-5 overlap | KL nats | logit cos | int next-token acc (float 59.7 %) | resid rel-err L0 .. L4 |
|---|---|---|---|---|---|---|---|---|
| lmcal-h1: max-abs weights + `lm.calibrate` (headroom 1), int8 scores | yes / yes | 0 | **0.8 %** | 3.4 % | 21.6 | 0.73 | 0.8 % | 0.66 .. 0.97 |
| matched-s8-h0: scale-matched, int8 scores | yes / n.a. | **256 (all)** | n.a. | | | | | |
| **matched-s13-h0**: scale-matched, 13-bit scores | yes / yes | 19 (7.4 %) | **82.2 %** | 80.0 % | 0.104 | 0.995 | 58.3 % | 0.15 .. 0.25 |
| matched-s13-h1: same, 1 bit headroom | yes / not run | 9 (3.5 %) | 70.2 % | 69.7 % | 0.286 | 0.989 | 53.2 % | 0.24 .. 0.37 |
| emu-s13-r16: + 16-bit residual increments | **emulation only** | 7 | 75.2 % | 72.9 % | 0.215 | 0.991 | 54.8 % | 0.17 .. 0.36 |
| emu-a12-s13-r16: + 12-bit activations | **emulation only** | 13 | **93.3 %** | 91.9 % | 0.0128 | 0.9993 | 59.4 % | 0.04 .. 0.09 |
| emu-a16-s13-r16: 16-bit activations | **emulation only** | 15 | 93.4 % | 92.0 % | 0.0126 | 0.9993 | 59.5 % | 0.04 .. 0.09 |

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
   model's top-1 token at 0.8 % of positions, which is chance level. This is
   a property of how a float checkpoint must be mapped to the integer model,
   not a bug in the prover. The model a provider commits to has to come from
   a scale-matched quantizer such as `scripts/tensor_accuracy.py`.
2. **Int8 attention scores cannot hold a trained model's attention at its
   true temperature.** The fix (`score_bits`) is implemented and proved:
   82.2 % top-1 agreement with int8 weights and activations.
3. **Activation width is the remaining main loss, not residual width.**
   Widening only the residual increments to 16 bits does not help (75.2 %):
   RMSNorm then re-quantizes the residual to int8 before the norm. 12-bit
   activations with 16-bit residual increments reach 93.3 %, which is the same
   ballpark as FlashProve's 93.2 % (6.81 % disagreement). That comparison
   needs care: their model is 1000x larger and their reference is bf16
   weights. 16-bit activations add nothing over 12-bit here. The remaining
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

## Wider activations / residuals: design (not implemented)

This is not a small change in `transformer.zig`, for two reasons:

* Core matmuls take int8 inputs and produce int8 outputs: `checkInt8`,
  `model.chooseShift`, and the range8 / lookup keys of the core protocol. The
  accumulator no-wrap argument is |acc| <= 2^7 2^(a-1) 2^K < p/2 ~ 2^30. For
  a = 8 that allows K <= 16. For **12-bit activations it allows only K <= 12**,
  and Maverick's d_model is 5120 > 2^12. So 12-bit activations need either
  K-splitting (partial sums as committed tensors, then an exact add and a
  requant) or 2-limb activations (x = x_hi 2^6 + x_lo with int6 / uint6 limbs,
  two int8-style matmuls and an exact einsum combine). The limb route roughly
  doubles the matmul sumchecks and the activation commitments. The weight
  side (the expensive opening) is unchanged.
* 16-bit residual increments need the same for `o Wo` and `hm Wd` outputs:
  16-bit requant outputs (range keys at 16 bits, as `einsumRequant` already
  does with `out_bits`). Plus RMSNorm on a 12-bit `xs`: ss <= 2^(2*11 + ld)
  needs the rt / gap range bounds re-derived, and INV_BITS ~ 23 to keep the
  reciprocal's precision.

The emulated configs above use exactly these semantics (`Cfg.A`, `Cfg.R`,
SiLU table at A bits with the same ±8 range, INV_BITS = 15 + 2(A - 8),
u = 2^10 x / rms). Their accuracy is measured; their proof cost is not.

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
