# Witness ledger: committed bits per token per layer

The tensor frontend's equivalent of the per-opcode bits/gas table of the RV64
guest-efficiency work. The serving projection (serving.md section 4) found
that the Maverick gap is the **volume of committed witness**
(n_w ≈ 1e10 to 3e10 elements per request), not kernel speed. This ledger
breaks n_w down by committed tensor and op class, so that cuts can be ranked
the way bits/gas cuts were (virtualise derivable columns, pack the rest).

**Metric** (lower is better, soundness unchanged):
* committed bits per token per layer = 31 × committed elements / T / layers,
  separately for dense and MoE layers;
* prover ns per token per layer;
* projected Maverick committed elements and prove time per request.

## 1. Running it

```
TENSOR_LEDGER=1       tensor-bench layer ... | model ...   # ledger of the first proof
TENSOR_LEDGER=noprove tensor-bench layer ...               # forward pass + ledger, no proof
python3 -I src/tensor/ledger_project.py run1.jsonl [run2.jsonl ...]
```

The bench prints one JSON line per committed tensor (`"ledger":"tensor"`),
per LogUp key (`"key"`), per class (`"class"`) and a `"summary"` after the
bench line. `ledger_project.py` checks a closed-form element count for every
class against the measured one (they must match exactly) and evaluates the
same formulas at the Maverick shape.

* Labels: `transformer.Builder` records a label per witness tensor: scope
  (block: `rms1`, `attn.proj`, `rope`, `attn`, `residual`, `rms2`, `mlp`,
  `moe.route`, `moe.expert`, `embed`, `head`, `head.greedy`, `rms.head`) and
  name (`scores`, `sel`, `d`, `e`, `den`, `acc`, `o`, `od`, `div.slack_lo`,
  `gate`, `disp`, ...), plus layer index and dense/MoE. Labels never enter
  the statement or the transcript.
* Capture: `protocol.proveCore` hands the committed tensors (witness +
  multiplicity columns), the derived LogUp relations and the witness-table
  layout to `ledger.sink` after the witness opening. It reads only. The
  `"ledger: every witness tensor labelled, proofs unchanged with the ledger
  on"` test proves an MoE layer with and without the sink and checks that the
  full proof digests are equal, that every tensor has a block label, and that
  `protocol.witnessLedger` (the no-prove path) sees the same tensors.
* Columns of the class line: `elems`; `bits31` = elems × 31 (what the M31
  commitment encodes); `used_bits` = elems × ceil(log2(max − min + 1)) (a
  packing lower bound, data-dependent); `gkr_leaves_direct` (key leaf = a
  committed column, possibly shifted by a constant) and `gkr_leaves_virtual`
  (key leaf = an affine combination of committed columns or accumulators
  that is never committed, e.g. requant remainders); `opening_bytes` = the
  witness opening attributed by element share (each queried column of the
  witness table holds every committed row).

## 2. Measured (this Mac, 12 threads, synthetic weights)

| run | command | committed elems | table (padding) | used / 31 bits |
|---|---|---:|---:|---:|
| dense layer D 2048, F 4096, 16q/4kv, 1024 tok | `TENSOR_LEDGER=noprove tensor-bench layer 10 11 12 4 12 54 2 20 2 1 0 10 1 2 54` | 124,371,176 | 124,780,544 (409,368) | 24.9 % |
| same layer, 512 tok, proved | `TENSOR_LEDGER=1 tensor-bench layer 9 11 12 4 12 54 2 20 2 1 0 9 1 2 54` | 45,444,324 | 45,613,056 (168,732) | 25.4 % |
| LM: embed + dense + MoE (64 experts top-1, capacity fitted = 32) + head, 512 tok | `TENSOR_LEDGER=1 tensor-bench model t=9 d=8 f=10 fe=9 h=3 kv=1 layers=2 e=6 v=14 key=0 r=1` | 39,253,713 | 39,321,600 (67,887) | 14.3 % |

The 1024-token layer is ledgered without a proof: its proof needs ~12 GB
(speed.md), above this host's 8 GB per-job cap. The 512-token proof gives
the timings and opening bytes. The MoE stack keeps Maverick's tokens per
expert (T / E = 8; 64 experts is the frontend's limit, `LayerCfg.validate`);
the fitted capacity was 32 slots (max expert load 20). The formula check
matches every class of all three runs.

GKR leaves (dense 1024-token layer): 80.2M direct, 48.8M virtual, 72K table
rows. Witness opening (512-token proof): 175,400 bytes of a 469,104-byte
proof.

### Dense layer, per token per layer (T = 1024, D = 2048, F = 4096, H = 16, Hkv = 4)

| class | elems/token/layer | bits31/token/layer | max value bits | share | GKR leaves direct / virtual | opening bytes (T=512 proof) |
|---|---:|---:|---:|---:|---|---:|
| attn/scores | 16,384 | 507,904 | 8 | 13.49% | 16,777,216 / 16,777,216 | 16,129 |
| attn/sel | 16,384 | 507,904 | 1 | 13.49% | 0 / 0 | 16,129 |
| attn/d | 16,384 | 507,904 | 10 | 13.49% | 16,777,216 / 0 | 16,129 |
| attn/e | 16,384 | 507,904 | 9 | 13.49% | 0 / 0 | 16,129 |
| attn.proj/qkv | 4,096 | 126,976 | 8 | 3.37% | 4,194,304 / 4,194,304 | 8,064 |
| attn/div.slack_lo (2 limbs) | 4,096 | 126,976 | 16 | 3.37% | 4,194,304 / 0 | 8,064 |
| attn/div.slack_hi (2 limbs) | 4,096 | 126,976 | 16 | 3.37% | 4,194,304 / 0 | 8,064 |
| residual/residual (h, out) | 4,096 | 126,976 | 9 | 3.37% | 2,097,152 / 0 | 8,064 |
| mlp/gate | 4,096 | 126,976 | 8 | 3.37% | 4,194,304 / 4,194,304 | 8,064 |
| mlp/up | 4,096 | 126,976 | 8 | 3.37% | 4,194,304 / 4,194,304 | 8,064 |
| mlp/silu | 4,096 | 126,976 | 7 | 3.37% | 0 / 0 | 8,064 |
| mlp/glu | 4,096 | 126,976 | 8 | 3.37% | 4,194,304 / 4,194,304 | 8,064 |
| input/x | 2,048 | 63,488 | 7 | 1.69% | 2,097,152 / 0 | 4,032 |
| rms1/u, rms1/y, rms2/u, rms2/y | 2,048 each | 63,488 each | 7-8 | 1.69% each | 2,097,152 / 2,097,152 each | 4,032 each |
| rope/q_rot | 2,048 | 63,488 | 8 | 1.69% | 2,097,152 / 2,097,152 | 4,032 |
| attn/acc, attn/od | 2,048 each | 63,488 each | 18 | 1.69% each | 0 / 0 | 4,032 each |
| attn/o | 2,048 | 63,488 | 7 | 1.69% | 2,097,152 / 0 | 4,032 |
| attn.proj/wo, mlp/down | 2,048 each | 63,488 each | 7-8 | 1.69% each | 2,097,152 / 2,097,152 each | 4,032 each |
| rope/k_rot | 512 | 15,872 | 7 | 0.42% | 524,288 / 524,288 | 1,008 |
| logup multiplicities (all tables) | 70 | 2,170 | 7-22 | 0.06% | - | ~280 |
| attn/m, attn/den | 16 each | 496 each | 7, 16 | 0.01% each | 0 / 0 | 32 each |
| rms ss / rt / rt2 / inv / inv_rt | 1 each | 31 each | 3-21 | 0.00% | small | 2 each |
| **total** | **121,456** | **3,765,136** | | | | 175,400 |

The four H·T² attention tensors are 54 % of the dense layer at T = 1024. One
of them (`sel`) uses 1 of its 31 bits. Value bits come from synthetic
weights; the MoE run's synthetic activations partly collapse (some 0-bit
columns), so its used-bit figures are not representative.

### MoE layer, per token per layer (T = 512, D = 256, Fe = 512, E = 64, C = 32)

| class | elems/token/layer | formula (per request) |
|---|---:|---|
| attn/scores, sel, d, e | 4,096 each | H T² each |
| moe.route/disp | 2,048 | E C T |
| moe.expert/gate, up, silu, glu | 2,048 each | E C Fe each |
| moe.expert/xe.gather, down | 1,024 each | E C D each |
| attention T·D classes, rms, rope, qkv/wo, residual | as dense | as dense |
| moe.route/logits | 256 | T Nr (router padded to the 2^8-column weight table) |
| moe.route/sel, dr, pre | 64 each | T E each |
| moe.route/occ, m | 4, 1 | E C, T |
| moe.expert/combine | 256 | T D |
| request: embed/onehot | 16,384 per token (whole request) | T V |
| request: head/logits, head.greedy/dr | 64, 32 per token | 2 V, V |

The routed experts commit E · C = 2048 slot rows for 512 tokens: 4 × the
active rows (capacity padding to the max load, then to a power of two).

## 3. Formulas and the Maverick projection

Per request, T tokens, dh = D/H, Dkv = Hkv dh, Q = pow2(D + 2 Dkv) (fused
QKV), slack limbs λ = 2 if log2 T + 9 > 16 else 1:

* attention block (dense and MoE layers):
  rms1 + rms2: 6 T D (xs, u, y; xs only when the input is wider than the
  activations) + 10 T (+ 8 T isqrt limbs when log2 D + 5 > 16);
  qkv T Q; rope T D + T Dkv; scores + sel + d + e 4 H T²; m + den 2 H T;
  acc + o + od 3 T D; division slacks 2 λ T D; wo T D.
* dense MLP: 4 T F (gate, up, silu, glu) + T D (down) + 2 T D (residuals).
* MoE: routing T Nr + T + 3 T E + E C T + E C; experts E C (2 D + 4 Fe);
  combine T D; residuals 2 T D. Shared expert (Maverick; **not implemented
  here**): 4 T Fs + 2 T D.
* request: one-hot T V, gather T D, head 2 D + 3·2 D + 10 + 2 V,
  greedy V + 1, multiplicity columns ~1e5 (table sizes).

n_w = 24 × dense + 24 × MoE + request. Maverick: T = 1024, D = 5120,
40 q / 8 kv heads (dh = 128), F = 16384, Fe = Fs = 8192, E = 128, C = 32
(same tokens per expert and fitted capacity as the measured MoE run),
V = 202048.

| | model dims (ideal) | power-of-two dims (as stwo-zig builds it: D 8192, 64 heads, V 2^18, Nr 2^13, Q 16384) |
|---|---:|---:|
| dense layer, elems / token | 329,826 | 492,690 |
| dense layer, bits31 / token | 10.2 M | 15.3 M |
| MoE layer, elems / token | 483,943 | 685,591 |
| MoE layer, bits31 / token | 15.0 M | 21.3 M |
| **n_w per request** | **2.02e10** | **2.92e10** |
| committed bytes at 31 bits | 72.9 GiB | 105.5 GiB |

This sits inside serving.md's 0.93e10 to 2.6e10 range (its central 2.0e10
agrees with the ideal-dims figure); the power-of-two padding alone adds 45 %.

### Ranking by share of committed bits (Maverick, model dims)

| family | elements | share |
|---|---:|---:|
| MoE: routed experts (E·C slot stacks) | 4.35e9 | 21.5 % |
| dense: attention T² (scores/sel/d/e) | 4.03e9 | 19.9 % |
| MoE: attention T² (scores/sel/d/e) | 4.03e9 | 19.9 % |
| dense: MLP (gate/up/silu/glu/down) | 1.74e9 | 8.6 % |
| MoE: shared expert (projected, not implemented) | 1.06e9 | 5.2 % |
| dense / MoE: attention T·D (acc/o/od/slack limbs, m/den) | 0.88e9 each | 4.4 % each |
| dense / MoE: RMSNorm parts | 0.76e9 each | 3.7 % each |
| dense / MoE: attention projections (qkv, wo outputs) | 0.30e9 each | 1.5 % each |
| dense / MoE: residual stream | 0.25e9 each | 1.2 % each |
| request: one-hot embedding | 0.21e9 | 1.0 % |
| dense / MoE: RoPE outputs | 0.15e9 each | 0.75 % each |
| MoE: routing (logits/sel/dr/pre/disp/occ) | 0.11e9 | 0.6 % |
| request: gather, LM head + greedy, head RMSNorm | 6e6 | 0.03 % |

With power-of-two dims, attention T² rises to 44 % (64 padded heads) and the
router logits (padded to 2^13 columns for 128 experts) to 1.1 %.

### Prover time

| run | prove | ns / committed element | ns / token / layer |
|---|---:|---:|---:|
| dense layer, 512 tok (proof) | 0.893 s | 19.6 | 1.74 M |
| LM, 2 layers + head, 512 tok (proof) | 1.067 s | 27.2 | 1.04 M (incl. head) |

**Both timings were taken on battery power** (pmset: "Battery Power"); they
are indicative only and must be re-run on AC before quoting. At 20 to 27
ns/element, Maverick's 2.02e10 elements are 400 to 550 s of proving per
request on this CPU, before the weight fold and the shared opening, and
assuming ns/element does not grow with size (it did between T = 256 and
512, serving.md). Per token per layer: dense 6.5 to 9.0 ms, MoE 9.5 to
13.2 ms.

## 4. What the ledger points at (candidates, not implemented)

Savings below are from the formulas at Maverick model dims (n_w 2.02e10).
None of them is implemented or measured. Each needs its own soundness
argument and adversarial tests before it lands.

| lever | removes | est. share |
|---|---|---:|
| capacity padding: expert stacks at T slots (sorted / ragged dispatch) instead of E · C = 4 T | 3/4 of the routed-expert rows | ~16 % |
| causal half: commit scores / sel / e for j ≤ t only (on the masked half, sel = 0 and e is the exp table at the masked bias; needs a triangular layout and a proof that the mask is honoured) | ~half of 3 H T² | ~15 % |
| `d` virtual: the exp key's input is the expression m − S − bias (already a lineq), not a committed column | H T² per layer | ~10 % (**implemented**, section 6) |
| fused glu (`Op.glu`, one triple lookup) in the transformer MLPs and expert stacks: drops the committed SiLU output | T F, E C Fe, T Fs | ~7 % |
| division slacks as virtual keys into one 2^20 range table (instead of 16-bit limb pairs) | 4 T D per layer | ~5 % |
| residual stream as expressions (lineq sums) where consumers accept expressions | 2 T D per layer | ~2.5 % (needs checking) |
| one-hot embedding as a public input to the gather (verifier evaluates its sparse MLE) | T V | ~1 % |
| together | | ~56 % → n_w ≈ 8.8e9 |

Packing: the dense layer uses 25 % of its committed bits (`sel` and `disp`
1 bit of 31, activations 7 to 8 bits). Packing several narrow values per
field element is the second lever after virtualisation, as in the bits/gas
work. It changes the PCS encoding, so it is a protocol change, not a tweak.

## 5. Caveats

* The rms `xs` tensor is data-dependent: it is not committed when the input
  already fits the activation width (the formula counts it).
* Maverick's shared expert is not implemented. It is projected as a dense
  SwiGLU of width Fs plus one add.
* C = 32 assumes Maverick's max expert load fits 32 slots, as in the 64-expert
  run (max load 20 at 8 tokens per expert on average).
* Wide activations (accuracy.md: A = 12, R = 16) were not ledgered at D 2048.
  They cannot be built there, and MoE layers refuse A or R ≠ 8. Width changes
  used bits and the range-table sizes, not the element counts (except
  embedding limbs).
* Fix made while ledgering: `ext.gatherPacked` started its last chunks past
  the end when n_ch × chunk > len, which panicked in ReleaseSafe and crashed
  in ReleaseFast. The model bench at E = 64, T = 512 hit this. Chunk
  starts are now clamped. Outputs for every shape that ran before are
  identical, so no digests change.

## 6. Implemented levers

### 6.1 attn-virtual-d-sel (branch `codex/tensor-wv-attn-virtual-d-sel`)

Two commits, both in `transformer.attention` (statement and soundness:
transformer.md sections 2 and 3):

1. **D virtual.** `attn/d` (H T²) is no longer committed. The exp key's input
   is the expression m − S − Bias; the D lineq is gone. Attainment moves from
   Σ_j sel·D = 0 to z1 = Σ_j sel·S and z2 = Σ_j sel·Bias (committed, H T
   each) with m − z1 − z2 = 0, and m gets its own signed score_bits range key.
2. **Factored selector** (log_t ≥ `FACTORED_SEL_MIN_LOG_T` = 4; toy
   statements keep sel). sel[h,t,j] (H T²) becomes A[h,t,jh] and B[h,t,jl]
   (j = jl + 2^⌊lt/2⌋ jh), each boolean (zero-check) and one-hot (sum lineq),
   with partial sums PS = Σ_jl B·S and PB = Σ_jl B·Bias (committed,
   H T 2^⌈lt/2⌉ each) and z1 = Σ_jh A·PS, z2 = Σ_jh A·PB. bounds.zig's
   existing one-hot rule covers both einsum levels (no bounds.zig change).

Measured (this Mac, 12 threads, **battery power**, single runs; timings are
indicative only):

| run | before | after commit 1 | after commit 2 |
|---|---:|---:|---:|
| dense layer D 2048, F 4096, 16q/4kv, 1024 tok (noprove): committed elems | 124,371,176 | 107,626,728 | 92,946,664 |
| same, elems / token / layer (incl. the input) | 121,456 | 105,104 | 90,768 (−25.3 %) |
| same, bits31 / token / layer | 3.77 M | 3.26 M | 2.81 M |
| same, GKR leaves direct / virtual | 80.2 M / 48.8 M | 63.5 M / 65.5 M | 63.5 M / 65.5 M |
| dense layer, 512 tok (proof): committed elems | 45,444,324 | | 37,989,604 (−16.4 %) |
| same, prove (ns / committed elem) | 0.914 s (20.1) | | 0.845 s (22.2) |
| same, proof bytes (witness opening) | 469,104 (175,400) | | 466,216 (169,168) |
| LM embed + dense + MoE (E 64, C 32) + head, 512 tok: committed elems | 39,253,713 | | 31,798,993 (−19.0 %) |
| same, dense layer / MoE layer elems per token | 25,434 / 34,335 | | 18,154 / 27,055 |
| same, prove per request (ns / elem) | 1.300 s (33.1) | | 1.163 s (36.6) |
| same, request bytes (per-request total) | 532,792 | | 539,216 |

The formula check (`ledger_project.py`) matches every class of every run.
Commit-1 elements were measured on a separate build of the commit-1 tree.
Proof bytes barely move: the witness opening shrinks with the committed
columns (−6 KB), and the new einsum sumchecks and ext claims add about the
same. ns/element rises because the H T² exp-key work (now a 3-term virtual
expression), the sel·S einsum (now B·S at H T²) and the scores stay while
committed elements fall; the prove time still falls by 8 to 11 %.

Maverick projection (formulas, section 3):

| | before | after |
|---|---:|---:|
| model dims: dense / MoE elems per token per layer | 329,826 / 483,943 | 253,106 / 407,223 |
| model dims: bits31 per token per layer | 10.2 M / 15.0 M | 7.85 M / 12.6 M |
| model dims: n_w per request | 2.02e10 | 1.64e10 (−18.7 %) |
| power-of-two dims: n_w per request | 2.92e10 | 2.32e10 |

Per token per layer at model dims (H = 40): d −40,880 and sel −35,840 in
both layer kinds. At 22 to 37 ns per element (the battery-power figures
above), 1.64e10 elements are 365 to 600 s of proving per request on this
CPU, against 406 to 669 s for 2.02e10 at the "before" ns/element; to be
re-measured on AC (`TENSOR_LEDGER=1`) before quoting.

Soundness: the exp-table membership of the virtual D_j proves
m ≥ S_j + Bias_j as integers (|m| < 2^(sb−1) from m's range key,
|S| < 2^(sb−1), |Bias| ≤ 2^sb + 256, so the expression plus the 2^(sb+2)
domain is far below p: `bounds.exprCheck`); one-hot A ⊗ B (or sel) with the
exact einsums gives m = S(j*) + Bias(j*). security.zig accounts ext ops
generically (`accountExt`): commit 1 removes one lineq over n3 and adds two
einsum sumchecks over n2, one lineq over n2 and one range relation; commit 2
removes an n3 zero-check and an n2 lineq, adds two zero-checks over
n2 + lt/2, two lineqs and four einsum sumchecks, each term far below
2^−100 over QM31. Adversarial tests (unchecked prover, all rejected): plain
selector `m_lowered`, `m_raised`, `sel_moved`, `sel_nonbinary`; factored
selector `m_lowered` (A, B, PS, PB, z1, z2 and e consistent), `m_raised`,
`a_not_one_hot` (2 and −1, sum 1), `b_two_hot`, `a_moved` (z1, z2 following
PS, PB), `ps_forged`.

Digests repinned: golden decoder layer flat 837b19ac → 8424c4b6 (commit 1)
→ a2bcc5c7 (commit 2), pcs2_moe 0d99b4e3 → 79360fbd → 4dd28279, and the
CUDA-emu and Metal CPU-golden pins with flat.
