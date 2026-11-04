# Serving: per-request proofs, LM head, model-scale bench

Stream `codex/tensor-r2-serve`. This doc covers what is built, what was
measured on this machine, the scaling law fitted to those measurements, and a
conservative extrapolation to Llama 4 Maverick.

Code: `src/tensor/serve.zig` (proveRequests / BatchProver / verifyRequest),
`src/tensor/lm.zig` (model stack, LM head, greedy check),
`src/tensor/bench.zig` (`tensor-bench model`), and the batched matmul in
`src/tensor/protocol.zig` (`proveMatmul3`).

## 1. What is built

### 1.1 Per-request proofs sharing one weight opening

A batch of R requests is proved as R independent request proofs plus one
`SharedOpening` that every request's verifier checks.

* Request j runs `proto.proveCore` on its own transcript,
  `T_j = H(REQ_DOMAIN, salt_j, statement_j, ...)`. That covers the witness
  commitment, LogUp-GKR, the op sumchecks, the claim batching and the witness
  opening. The output is the request's weight claims `(w, local point, value)`
  and its final digest `d_j`. The salt goes first into the transcript and is
  sent only in request j's own proof. It must be 256-bit uniform, **secret**
  (known to the server and client j only) and **never reused**. By default
  (`Request.salt = null`) `BatchProver.add` draws it from `std.crypto.random`;
  an explicit salt (`testSalt`) is for tests and reproducible runs only
  (SERVE-2).
* The batch transcript absorbs the weight root, R, and then, for each request
  in order, its digest, its distinct claim points and its claims as
  `(w, point index, value)`.
* **Cross-request reduction.** The challenges `gamma_c` are drawn only after
  every slot has been absorbed. Then one degree-2 sumcheck over the whole
  weight table proves
  `sum_c gamma_c v_c = sum_x W(x) E(x)`, where `E(x) = sum_c gamma_c eq(z_c, x)`
  and `z_c` is claim c's full table point. The sumcheck ends at
  `W~(r) E~(r)`. The verifier evaluates `E~(r)` itself, at
  O(claims * log|W|) cost, and `W~(r)` is opened once against the committed
  weight root. The opening therefore has a single point, whatever R is.
* `verifyRequest(i)` does four things. It replays T_i and checks the request's
  own part (`verifyCore`). It checks that `d_i` equals slot i's digest. It
  **rebuilds slot i itself** from the claims T_i derived (`claimSet`, as the
  prover does; each full point is split into weight id and local point by
  its block prefix) and requires byte-for-byte equality: points in
  first-use order, `point_of`, `w`, values. Finally it checks that every
  slot is canonical, replays the batch transcript and checks the reduction
  and the opening, covering all slots.
* **Canonical slots (SERVE-1).** Every slot must have each point referenced
  by a claim, its points pairwise distinct and in first-use order, and each
  claim's point of its weight's size. A slot is therefore the unique
  encoding of its claim list: no unreferenced data reaches the batch
  transcript, and a `SharedOpening` is unique for given request proofs.
  Before this, a server could pad any slot with junk points (a free knob on
  the batch transcript and non-unique accepted openings); soundness was not
  affected, since the full-point equality already pinned the claims.
* **Bounds (SERVE-3).** Before any per-claim allocation the verifier
  requires `<= max_claims_per_weight * |weights|` claims per slot (4 per
  weight; an honest request makes at most one per weight per matmul class)
  and `<= max_slots` (2^16) slots. Verifier memory and work are
  O(sum of slot sizes * log|W|): linear in the bytes downloaded, never more.

**Soundness for request i.** It does not depend on the other slots being
honest.
1. Slot i is pinned to T_i's claims.
2. Every slot is fixed in the batch transcript before gamma is drawn. A false
   claim anywhere survives the random combination with probability 1/|F|.
3. The reduction sumcheck adds 2 log|W| / |F|.
4. The opened value binds W~(r) to the committed root.

Here |F| = 2^124 (QM31) and log|W| <= 39 for Maverick. The prover can choose
the other slots freely and so grind the batch transcript, at one hash per
attempt. That is the same Fiat-Shamir grinding exposure as any single proof:
2^k attempts multiply the per-attempt error by 2^k. The PCS query and PoW
parameters are those of the single-batch protocol.

**Single-batch protocol is unchanged.** It is the R = 1 case of the same
`proveCore` / `verifyCore` split, with one weight-claim group. Its golden
proof digests still pass.

**On the security-stream protocol (integration).** Serve was written before
the r2-sec changes and was re-expressed on top of them:
* `Proof.weight_values` no longer exists. The single-proof verifier takes the
  weight claim values from the op finals (`VerifierWeightClaims.values`), and
  a request slot is checked against those same verifier-derived values. The
  slot itself still carries its values: they are absorbed by the batch
  transcript before gamma is drawn (the other clients need them to replay
  the reduction).
* `openWeightClaims` / `openWeightFull` / `verifyWeightOpening` use
  `weightOpenConfig(cfg)`, so the shared opening runs with the per-batch
  `weight_outer` parameters; the flat (one-level) PCS keeps one claim group
  for all claims, pcs2 one group per distinct column point (the shared
  opening has a single point, hence one group).
* `proveCore` takes the ext-einsum accumulators (`Request.ext_acc`); the
  single proof still goes through `proveWithAllAccumulators`. The witness OOD
  sample (pcs2 with `ood`) is part of `proveCore`, so every request proof has
  it.
* `verifyRequestInfo(..., ?*VerifyInfo)` fills the same accounting as
  `proto.verifyInfo`: the request's witness and LogUp shapes, and the shared
  opening's weight shape with `weight_groups = 1`. The calculator
  (`security.accountProof`) does not yet add the cross-request terms (the
  gamma combination, 1/|F|, and the reduction sumcheck, 2 log|W| / |F|);
  both are far below the PCS terms.

**Leakage between clients.** v1 is non-hiding, so a request's own proof leaks
its activations to its own verifier. Every client also receives the other
slots, which hold their digests, claim points and weight-claim values:
* The points and digests depend on the other request's salt, so they are
  pseudo-random to this client.
* The values are evaluations of the weights at those points. They carry
  information about the weights, not about the other request's prompt.
* **The slot's shape is visible.** The MoE expert capacity is a per-request
  statement parameter, fitted to the request's routing. A slot's point
  dimensions therefore reveal the other request's log-capacity, which says
  something about its routing balance. A fixed `cap=` closes this, at the cost
  of padding.

* **This needs secret salts (SERVE-2).** With a known salt, the digest and
  points are a deterministic function of the request's statement, so a
  client could confirm a guess of another client's prompt by replaying it.
  The pre-fix bench used `testSalt(seed * 1000 + j)`, a public function of
  the index; it now uses the default random salt. FlashProve's longer-term
  fix applies here too: commit the slots as salted leaves of a batch tree,
  derive gamma from its root, and send each client its leaf, a path and the
  aggregates the reduction needs, so no client sees another slot in the
  clear.

**Availability coupling (by design, SERVE-3).** The batch is accepted or
rejected as a whole: one false or malformed slot makes every client's
verifier reject, and a client cannot tell "my request was false" from "some
other slot was bad". Conversely, R and batch membership are not attested: a
server may add true slots with arbitrary digests (no client behind them)
and every verifier accepts. Neither affects soundness for request i.

Zero knowledge (the `codex/tensor-zk` stream) does not cover the serving split
yet. ZK note for these fixes: the canonical-slot and own-slot checks add no
prover messages (the slot was already sent), and the default salt is the
only secret the leakage argument above needs; a hiding serving split would
additionally have to hide the slot values (weight evaluations at
request-dependent points), which the salted-tree layout would do.

Adversarial tests (`serve.zig`) are rejected for every verifier unless noted:
* a wrong slot index, a wrong salt, or a tampered own part;
* a changed value, point or digest in the request's own slot;
* another request's false claim or digest;
* a malformed, swapped or dropped slot, or a redirected point index;
* an unreferenced, duplicated or out-of-order point in any slot, and a slot
  over the claim cap (`review_serve_test.zig`);
* a tampered opening, a tampered reduction round, or a tampered reduced value;
* a wrong key root.

### 1.2 Model stack, LM head and greedy output statement (`lm.zig`)

* **Layers.** N decoder layers, dense and MoE interleaved (`moe_every = 2`,
  as in Maverick). Experts have their own width (`fe`). MoE layers are
  *stacked*: Xe `[E, C, D]` is gathered with one exact einsum, gate, up and
  down are batched matmuls over the `[E, C, .]` stacks, and the combine reads
  the stacked output.
* **Batched matmul.** `acc~(rho_e, rho_t, rho_n)` is reduced by a single
  sumcheck over (e, k) of `eq(rho_e, e) X~(e, rho_t, k) W~(e, k, rho_n)`, of
  degree 3. This produces one X claim and **one weight claim for the whole
  expert stack**.
* **Input (LM-1).** The public input is the window's **tokens**: window =
  prompt `x` (T - P + 1 tokens) `|| y[0..P-1)`. The token embedding
  `Emb [V, D]` is a committed weight (after the LM head). The verifier builds
  `OH = 2 * onehot(window)` `[T, V]`; a lineq binds it to the committed
  matmul input, and `X = rq_1(OH . Emb)` (fixed shift 1) equals
  `Emb[window]` exactly. For P > 1 the honest prover finds the
  self-consistent y by fixed-point iteration (`decodeGreedy`). Before this
  fix X was a prover-chosen public that nothing related to the tokens.
* **Model descriptor (LM-3).** `ModelDesc { cfg, gains }` holds every
  learned parameter that is not in the weight table: the RMSNorm gains, 2
  per layer + the final norm, int8 in [1, 127]. `buildModel` takes them from
  the descriptor (they used to come from a per-call seed, so a server could
  change them per request under one key).
* **What key.root covers.** key.root is the Merkle root of the committed
  int8 table: every layer weight (attention, MLP or router + expert stacks),
  `W_lm` and `Emb`. The verifier-held key also carries the weight shapes
  (`key.infos`, checked against the descriptor's `weightInfos`). The
  descriptor (configuration and gains) is **not** in key.root: a client
  pins `(key.root, key.infos, ModelDesc.digest())` together as the model
  identity. The digest omits `log_capacity`, a per-request statement
  parameter. Fixed tables (RoPE, causal mask, exp, SiLU, MoE triangle) are
  functions of the configuration.
* **Verifier entry point.** `lm.verifyRequest(key, desc, prompt, y, st, ...)`
  rebuilds every public (RoPE, mask, gains, MoE triangle, OH, Sel, Lt), the
  core and ext tables and the weight shapes from (key, descriptor, prompt
  tokens, claimed output tokens), as FlashProve builds its request instance
  from the tokens, and rejects (`error.StatementMismatch`) unless the
  prover's statement carries exactly those. It also requires the Emb op's
  shift to be 1. Tokens >= V are rejected before anything is built
  (`error.BadToken`, LM-2): for y >= V the verifier's Sel = 0 and Lt = 1
  would make the zero einsum vacuous.
* **Residual (not closed here).** The statement's *structure* (its op
  list, witness shapes and the data-chosen requant shifts) is still the
  prover's. That is the statement-bounds / ModelConfig work of phase A; with
  it the verifier can build the whole statement, not only its publics.
* **LM head and greedy check.** The last 2^log_out positions are sliced with
  fixed-bit labels, then go through the final RMSNorm and the LM head
  (`W_lm [D, V]`, committed). The greedy check on the public output tokens
  y uses three relations:
  `Dr = m - logits` (lineq), `Dr - [v < y] in [0, 256)` (range key), and
  `sum_v [v = y] Dr = 0` (zero einsum).
  Together they imply that y is the **least** maximiser. The selector is
  public, so no binary, one-hot or V x V tie-break check is needed.
* **Tests.** Through `lm.verifyRequest`: a different output token or prompt
  is rejected, and so is a statement over a window whose tail is not y, other
  gains, a two-hot Sel or an inconsistent Lt, an out-of-vocab prompt or
  output token, and a key without Emb (`review_lm_test.zig`). Greedy ties
  are accepted. At the gadget level, for a later tie or a non-maximum the
  honest prover refuses and an unchecked prover's proof is rejected; an
  out-of-vocab token is refused by the verifier-side builder. X equals
  `Emb[window]` (direct reference) and the stacked-MoE output equals a
  direct integer reference.
* **Soundness note.** With the publics the verifier's own, the greedy
  relations bind y to the least maximiser of the committed model's logits
  on `Emb[window]` (subject to the residual above). ZK note: the request
  is non-hiding; the prompt and output tokens are public by design (as in
  FlashProve), so the verifier-built publics leak nothing new.
* **Cost of the one-hot input.** The embedding matmul adds T V witness
  entries (OH) and a T V D forward product, and the verifier evaluates the
  T V public. Measured (`tensor-bench model t=6 d=7 f=8 e=1 fe=7 layers=2
  h=1 kv=0 r=2 q=20 iq=20 pow=8 ipow=8 key=0`, before -> after): v=8:
  0.058 -> 0.056 s/request, 194.6 -> 198.1 KB per request, verify 3.1 -> 3.7
  ms; v=12: 0.057 -> 0.073 s/request, 201.1 -> 214.2 KB, verify 3.6 -> 8.5 ms,
  witness elements +43%. At real vocabularies (V ~ 2^17) a lookup of the
  window's rows against the committed Emb (O(T D)) and a succinct OH
  evaluation (O(T log V)) are needed; not done.

### 1.3 Bench (`tensor-bench model`)

* **Setup.** The N-layer stack takes a public token window (X = Emb[window]
  from the committed Emb) and ends with the LM head and greedy check. Bench
  windows are random tokens and the output is their greedy tokens (cost
  measurement only; not a decoded continuation), verified with
  `serve.verifyRequest`.
* **Proving.** R requests go through the streaming `BatchProver`, and each
  request's witness is dropped after its proof. One shared opening follows.
  Every request is then checked by a single-thread `verifyRequest`.
* **Weights.** The synthetic weights have zero router padding columns and an
  offline router calibration, so that MoE routing is balanced. Untrained
  random weights send every token to expert 0.
* **Cost accounting.** `s_per_request` is forward + per-request prove + shared
  opening, divided by R. The untimed capacity probe is excluded.

## 2. Measurements (this machine)

**Machine and settings.**
* Apple M-series laptop with 36 GB, on AC power. 12 threads, CPU unless noted.
  ReleaseFast. Every run went through `memguard --gb 8`.
* PCS: pcs2, depth 2, 54 queries, log blowup 2, 20 PoW bits, giving
  **128 conjectured / 56.6 proven bits**. Non-hiding.
* Model: D = 1024, F = 4096, 8 query heads and 2 KV heads, E = 8 experts with
  expert width 2048, V = 32768, one checked output position. Layers alternate
  dense and MoE.

Commands, run from `src/tensor`:

```
zig build -Doptimize=ReleaseFast
memguard run --gb 8 --label serve-l2-r4 -- ./zig-out/bin/tensor-bench model layers=2 r=4 key=0
memguard run --gb 8 --label serve-l4r1  -- ./zig-out/bin/tensor-bench model r=1 key=0
memguard run --gb 8 --label serve-metal -- ./zig-out/bin/tensor-bench model layers=2 r=4 key=0 --metal
```

`key=0` skips the offline weight-key proof. Its peak RSS exceeds the 8 GB
budget at 4 layers. It is measured separately at 2 layers below.

### 2.1 R scaling: 2 layers (1 dense + 1 MoE), T = 256

* 103.8M weights, 59.8M of them active per token.
* 22.5M witness elements per request.
* 12 weight claims per request, reduced over 6 distinct points.

The table gives the median of runs b and c. The first sweep ran while the host
was busy and was 5-20% slower; it is in the raw logs.

| R | forward/req | prove/req | shared opening | **s/request** | **tokens/s** | verify/req | peak RSS |
|---|---|---|---|---|---|---|---|
| 1 | 0.14 s | 0.96-1.06 s | 0.41 s | **1.51-1.61** | **159-170** | 17.7-18.4 ms | 6.2-6.4 GB |
| 2 | 0.14 s | 0.88-0.92 s | 0.44 s | **1.24-1.28** | **200-206** | 17.8 ms | 6.2-6.5 GB |
| 4 | 0.14 s | 0.87-0.88 s | 0.50 s | **1.13-1.14** | **224-227** | 17.6-17.9 ms | 7.2-7.3 GB |

Bytes per request:

| R | own part | own slot (claims) | shared opening (once per batch) | download for one request | amortised over the batch |
|---|---|---|---|---|---|
| 1 | 320.5 KB | 3.3 KB | 204.9 KB | 528.7 KB | 528.7 KB |
| 2 | 319.5 KB | 6.5 KB (all slots) | 204.7 KB | 530.7 KB | 425.1 KB |
| 4 | 319.9 KB | 13.1 KB (all slots) | 205.3 KB | 539.5 KB | **374.5 KB** |

* A client downloads its own part, every slot (about 3.3 KB per request in
  the batch) and the shared opening.
* The own part splits as GKR 131 KB, op sumchecks 35 KB, ext 29 KB and
  witness opening 154 KB.
* The shared opening is constant in R.

### 2.2 Depth and T scaling (R = 1)

| config | weights | witness/req | forward | prove | shared | s/req | tok/s | own bytes | verify | peak RSS |
|---|---|---|---|---|---|---|---|---|---|---|
| L=2, T=128 | 103.8M | 10.0M | 0.05 s | 0.55 s | 0.50 s | 1.10 | 117 | 288 KB | 14.0 ms | 6.0 GB |
| L=2, T=128, R=4 | | | 0.07 s | 0.54 s | 0.56 s | 0.75 | 171 | 288 KB | 11.2 ms | 6.7 GB |
| L=2, T=256 | 103.8M | 22.5M | 0.14 s | 0.96-1.06 s | 0.41 s | 1.51-1.61 | 159-170 | 320 KB | 18 ms | 6.2 GB |
| L=2, T=512 | 103.8M | 55.8M | 0.43 s | 2.59 s | 0.55 s | 3.57 | 143 | 367 KB | 33.8 ms | 8.0 GB |
| L=4, T=256 (2 runs) | 174.1M | 45.1M | 0.27 s | 1.84-1.86 s | 0.77-0.79 s | 2.88-2.92 | 88-89 | 481 KB | 24.3-25.4 ms | 10.1 GB |
| L=4, T=256, R=2 | | 55.8M (*) | 0.34 s | 2.02 s | 0.94 s | 2.83 | 91 | 486 KB | 25.4 ms | 11.3 GB |

(*) One request's routing needed capacity 2^7 instead of 2^6, which grew its
MoE stacks. The expert capacity is fitted per request.

The rows above were measured before commit `5f77f7d2a`. After it, the
reduction reads the committed i8 table directly; before it, the table was
first widened to an i32 copy at 4 B per entry. Proofs are unchanged. The
re-measured points are below; the host load average was about 6 from other
jobs, so the prove times are noisier.

| config | shared opening | peak RSS |
|---|---|---|
| L=4, T=256, R=1 | 0.77-0.79 -> **0.68 s** | 10.13 -> **9.43 GB** |
| L=4, T=256, R=2 | 0.94 -> 0.92 s | 11.31 -> **10.50 GB** |
| L=2, T=256, R=1 / R=4 | 0.41 / 0.50 -> 0.36 / 0.47 s | about 6.3 / 7.4 GB (the request phase sets the peak here) |

### 2.2b Width scaling (L=2, T=256, R=1)

D, F and the expert width are all halved (`d=9 f=11 fe=10`), with the head
count unchanged:

| config | weights | witness/req | prove | shared | s/req | tok/s | own bytes | shared opening bytes | verify | peak RSS |
|---|---|---|---|---|---|---|---|---|---|---|
| D=512, V=32768 | 34.3M | 14.2M | 0.58 s | 0.17 s | 0.80 | 319 | 306 KB | 156 KB | 12.8 ms | 3.2 GB |
| D=512, V=16384 | 26.0M | 14.1M | 0.62 s | 0.10 s | 0.78 | 328 | 305 KB | 143 KB | 12.1 ms | 2.4 GB |
| D=1024 (from 2.1) | 103.8M | 22.5M | 0.96-1.06 s | 0.41 s | 1.51-1.61 | 159-170 | 320 KB | 205 KB | 18 ms | 6.2 GB |

Split the witness into an attention-pair term and a width-linear term. The
pair term is about 40 per token pair per layer at 8 heads, which is 5.2M at
L=2 and T=256, and it does not depend on width. The width-linear part then
goes from 8.9M to 17.3M, a ratio of 1.94 when the widths double, so it scales
linearly with width. The prove cost per element stays at 41 ns.

**L=4, R=4 was not run.** The R=2 run's peak RSS, 11.3 GB, was already above
memguard's 1.3 x 8 GB kill line. memguard samples RSS and missed that peak.
The R=4 attempt was killed at 11.0 GB.

### 2.3 Offline weight key (L=2)

* The weight-key proof takes 1.57 s and is 248 KB. It verifies in 1.5 ms.
* Peak RSS after the key proof is 8.5 GB.
* At L=4 the key proof exceeds the 10.4 GB memguard cap, so it was not
  measured.
* The weight commit takes 0.64-0.80 s at L=2 and 1.2 s at L=4. Router
  calibration takes 1.1 s at L=2 and 2.6 s at L=4. Both are offline.

### 2.4 Metal (L=2, T=256, single runs)

| R | prove/req | shared | s/req | tok/s | peak RSS (CPU-visible) |
|---|---|---|---|---|---|
| 1 | 0.95 s | 2.02 s | 3.11 | 83 | 2.9 GB |
| 4 | 1.03 s | 0.53 s | 1.32 | 195 | 4.1 GB |

* **No gain over CPU at this size.** Per-request proving takes the same time
  as on CPU.
* **R = 1 shared-opening outlier.** At R = 1 the shared opening on Metal took
  2.0 s, against 0.53 s at R = 4. This looks like a one-off device-path cost
  (the first large reduction), but it was not investigated.
* **RSS undercounts memory.** Metal buffers are unified memory, which RSS
  does not count.
* **Verification.** test-metal includes a per-request batch of the
  dense + MoE model with LM head. The device output equals the CPU output bit
  for bit.

## 3. Scaling law (fitted to section 2)

Batch time for R requests, where `n_w` is witness elements per request and
`|W|` is the total committed weights:

```
B(R) = R * (f * n_w + p * n_w + c * |W| + s1) + S0 * |W|
s/request(R) = (f + p) * n_w + c * |W| + s1 + S0 * |W| / R
```

| coefficient | value (12 threads, CPU) | from |
|---|---|---|
| p: prove per witness element | 39-41 ns (T=256); 46 ns (T=512); 54 ns (T=128, fixed costs) | L=2 and L=4 prove / n_w |
| f: forward per witness element | 6-8 ns | forward / n_w |
| c: per-request weight fold per **total** weight | 0.15 ns | `weight_fold` stage: 15.6 ms / 103.8M, 25.2 ms / 174M |
| S0: shared opening per weight, per batch | 3.7-4.8 ns (before `5f77f7d2a`; about 10% lower after) | 0.38 s / 103.8M, 0.74 s / 174M, 0.17 s / 34.3M |
| s1: shared opening per request | ~0.03 s at 12 claims (grows with claims per request) | slope of shared(R) |
| own proof bytes | ~80 KB / layer + ~160 KB; +~15% per doubling of T | L=2 vs 4, T=128-512 |
| shared claim bytes per request | ~0.7 KB / layer + ~1.9 KB | 3.3 KB (L=2), 4.7 KB (L=4) |
| shared opening bytes per batch | ~205-212 KB, logarithmic in |W|, flat in R | |
| verify per request (1 thread) | ~3.5 ms / layer + ~11 ms, flat in R; ~+80% from T=256 to 512 | |
| witness elements per token, per layer | ~34K * (D/1024) + ~40 * T * (heads/8) | T fit at T=128/256/512 and width check at D=512 (L=2); the head scaling is assumed |

Check: at L=2, T=256 the model gives s/request(4) = 1.056 + 0.38/4 = 1.15 s,
against 1.13-1.14 s measured. As R grows, it tends to about 1.06 s per request,
which is about 240 tokens/s.

## 4. Maverick extrapolation (conservative, this machine's coefficients)

**This is a compute-only extrapolation.** It does not describe a run that is
possible on this host. No H100 or other cross-hardware figure is claimed. The
inputs are stated so that each can be swapped out.

Maverick shape, from its public configuration as recalled (verify before
quoting):
* 48 layers, D = 5120, 40 query heads and 8 KV heads.
* MoE every other layer (24 layers), each with 128 routed experts (top-1)
  plus one shared expert. Expert width 8192; dense FFN width 16384.
* Vocab about 202K.
* 400.7B total weights (as in size.md) and about 17B active.

The request is 1024 tokens.

**Witness per request, n_w.**
* Fit, scaled (upper estimate). The per-token linear term is
  34K x 6.25 per layer: widths are about 5x, and the shared expert adds about
  25%. The attention-pair term is 40 x 5 per pair per layer (40 heads against
  8). Then 48 x (213K x 1024 + 200 x 1024²) = **2.0e10**. If MoE capacity
  padding is 1.5x worse at 128 experts than at 8 (it is 2x at E=8 in our
  runs), this becomes 2.6e10.
* size.md's bottom-up estimate (lower): 9M per token, which gives **9.3e9**.

**Per-request cost on this Mac (12 CPU threads), at R = 24:**

| term | low | central | high |
|---|---|---|---|
| prove, p * n_w | 9.3e9 x 40 ns = 370 s | 2.0e10 x 50 ns = 1000 s | 2.6e10 x 55 ns = 1430 s |
| forward, f * n_w | 60 s | 140 s | 210 s |
| weight fold, c * 400.7B (whole expert stacks, every request) | 60 s | 60 s | 120 s |
| shared opening, S0 * 400.7B / 24 | 62 s | 67 s | 80 s |
| **s/request** | **~550 s** | **~1270 s** | **~1840 s** |
| **tokens/s (1024 tokens per request)** | **~1.9** | **~0.8** | **~0.56** |

Proof bytes per request:
* Own part: 48 layers x 80-110 KB, plus witness-opening growth. That is about
  **4-6 MB**, dominated by GKR, because GKR instances are not yet merged per
  table (size.md section 5).
* Slot: about 35 KB.
* Shared opening: about 0.3 MB once per batch, which is negligible when
  amortised.
* For reference only (different hardware and implementation), FlashProve
  reports 18.78 MB.

Verify per request: about 0.2-0.3 s on one thread.

**Why this cannot run here.**
* The weight store costs about 30 B per weight (5.45 GB for 174M), which is
  about 12 TB at 400B.
* The shared-opening table E is materialised at 16 B per weight.
* The working set per request is about 130 B per witness element
  (3 GB for 22.5M), which is about 2.7 TB at 2e10.
* All of these would need to be streamed per layer and per tensor; none of
  that is built.

**Errors that could break this extrapolation.**
* p is assumed constant per element. It rose from 40 to 46 ns between T = 256
  and T = 512, and at log n_w ≈ 34 it is likely higher. The 55 ns column is a
  guess, not a measurement.
* The weight fold is O(total weights) per request, because a batched matmul
  folds the whole `[E K, N]` stack. Fewer tokens per request still pay for all
  of it.
* Width scaling was checked at only one point, D=512 against D=1024, and
  only downward. The heads-scaling of the attention-pair term (x5 for 40
  heads) is assumed, not measured.

## 5. Not done

* The statement structure (ops, shifts) is still prover-supplied; the
  verifier builds only the publics, tables and shapes (section 1.2).
* The one-hot embedding input is O(T V D) forward and O(T V) verifier work;
  a lookup against Emb is needed for real vocabularies (section 1.2).
* key.root does not cover the model descriptor; the client pins its digest
  separately.
* Sections 2-4 were measured before the committed Emb, the descriptor and
  the slot checks.

* Memory: the shared-opening table E (16 B per padded table entry) is not
  streamed. The i32 widened copy is gone (`5f77f7d2a`). Peak RSS still grows
  with R, by about 1 GB from R = 1 to R = 4 at L = 2. It looks like
  allocator retention rather than a leak: an earlier L=4, R=24 run peaked at
  10 GB. That was not investigated further. L = 4 with R >= 4 does not fit
  under the 8 GB budget.
* The serving split has no zero-knowledge treatment (`codex/tensor-zk`), and
  capacity leaks through slot shapes (section 1.1).
* The per-request weight fold costs O(total expert weights), even though
  only the routed experts are touched.
* GKR instances are not merged per table. This dominates the own-part bytes
  at depth.
* The Metal shared-opening outlier at R = 1 was not investigated, and Metal
  gives no speedup at these sizes.
* Large runs (R = 24, 1024 tokens) are left to the coordinator's end-of-campaign
  benchmark run, so no such numbers appear here. An earlier session measured
  R = 24 at L = 4: shared opening 1.62 s, 814 KB per request, verify
  23-25 ms. Those runs predate this session's memory rules.
