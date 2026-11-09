## Area: core protocol (protocol.zig prove/verify/proveWithAccumulators, sumcheck.zig, eq

### Parity
FlashProve parity for the core protocol: weight range is unproven in both (parity). Statement well-formedness: our validateStatement goes beyond FlashProve's fixed configs, but its bound inference is unsound for ext keys with SUM/FIX labels (PROTO-1) and for exact einsums (PROTO-2), so it does not yet deliver the 'every operand bounded by a proved relation' guarantee it documents. Virtual remainders, implied-range elision and the glu triple are sound. Batched matmuls are sound, but the verifier rejects honest proofs in some layouts (PROTO-3).

### Report corrections
Only new files in the worktree: ~/Coding/ge-wt/rev-proto/src/tensor/review_proto_test.zig, plus a local edit of ~/Coding/ge-wt/rev-proto/src/tensor/mod.zig (one import line). Nothing committed or pushed. R5 is skipped by default and runs only with REVIEW_PANIC=1.

### Checked OK
- deriveRelations: prover and verifier derive the same key and table lists. A remainder key is always followed directly by its y_range key (same op). lookup_in_values are consumed in key order on both sides and the total length is checked (lk_i == len).
- GKR suffix convention: both sides use pt = ood[L - log_size ..]. n_variables_by_instance is checked for every key and table. Key numerators are checked to be 1. Each table denominator is checked against alpha - tableKeyMle. The LogUp sum is checked per table with nonzero denominators.
- Virtual remainders: sound. den(rho) = alpha - (acc + 2^(s-1) - 2^s y)(rho) is linear in the MLEs. acc(rho) is then reduced by the matmul/hadamard sumcheck to committed X/W (or A/B) claims. R4 cheating provers, which shift acc with a consistent y and consistent multiplicities, are rejected for both matmul and hadamard.
- Implied-range elision: y(rho) is sent, mixed and bound as a witness claim on y at the same pt. The lookup/glu keys range-check every entry of y; equal log sizes are validated for lookup in/out and for glu g/u/h. Tamper tests in model.zig and R4 confirm.
- glu triple: the key g + beta*u + beta^2*h is computed the same way in keyValues, tableDen and tableKeyMle. The table index (vg = idx>>8, vu = idx&255) matches identityMle MSB-first applied to point[0..8] and point[8..16]. Clamp and requant live in the public table (gluValue). Shift is validated to 1..22, so shiftHalf never underflows.
- Accumulator overflow vs p (core-bounded operands): bounds keep |acc| ≤ 2^30 and |r - 2^(s-1) + 2^s y| < 2^29.1 for s ≤ 22, so the requant identity mod p is an integer identity. Weights are assumed int8 but not proven so, the same as FlashProve (paper: weights are not 'shown to meet the model's range conditions').
- Batched matmul classes: all members share rho (same y log size, so the same ood suffix). xi is drawn after every acc(rho) input is fixed. accValue matches the unbatched formula. The finals are mixed. The size_tests tamper suite rejects modified finals, weight values and rounds. Only the verifier loop-order bug (PROTO-3) was found.
- Batching sumcheck: the verifier recomputes E(z*) as sum gamma_c eq(fullPoint(offset_c, z_c), z*). The layout is gap-free (sizes sorted descending, offsets aligned). Prover entries at or beyond lay.used are zero and never read. Claim values are mixed before the gammas are drawn.
- Byte-identity of perf kernels: split-eq eqsum matches proveActive, including the rho_k=0 path and wrong claims (eqsum tests). proveBaseTimesExt matches proveActive across active lengths. The active-length prover matches a zero-padded one. The Fq-in-E-upper-half aliasing in fold0Chunk reads before it writes and is safe. The fused fold+round ownership in sumcheck.zig covers every folded position exactly once.
- Fiat-Shamir: the Blake2s channel chains one hash per mix call, so the statement encoding is unambiguous even without a table count. witness_root is mixed before alpha and beta. The GKR proof goes through partiallyVerifyBatch. Each lookup/y value is mixed before the next challenge. Sumcheck rounds are mixed before each r. Op finals are mixed. The pcs mixes claim values (pcs.zig:444). witness_value and weight_values are fixed by earlier checks, so they cannot be chosen adaptively. The unused evals[2] of degree-2 rounds is excluded from both digests.
- Proof reuse (R4, passes): the verifier rejects the honest proof under another same-shape weight id, a changed hadamard shift, a different weight commitment, and swapped y tensors.
- prep.zig: parallel countInto is deterministic and reports the lowest failing range. Remainder denominators subtract v < 2^22 only from the c0.a limb, which is correct.
- Observation: under `zig build test`, 'while executing test zk plan ... failed' appears only because the binary exits nonzero after my 4 failing tests (58+4+1 = 63, all ran). Running the binary directly shows no crash. Not a zk finding.

## Area: FlashProve parity and benchmark fairness (worktree ~/Coding/ge-wt/rev-parity @ 4

### Parity
Legend: BETTER / EQUAL / WORSE / MISSING. FP = FlashProve (~/Coding/ge-cache/flashprove/fp). Ours = merged 4cd5cf51e unless marked [r2-X unmerged].

1. Statement: greedy token(s) over a 1,024-token window, public prompt, commitment ID
   - FP: exact match (C,θ,cap)=(256,256,0); positions i0..i1 plus y+ after the window. Sources: paper §3.2, Def 3.4, 3.11; guide/what-is-proved.md.
   - Ours (non-hiding): MISSING. No I/O in Statement (protocol.zig:86-93); test P1.
   - Ours (zk): partial. Public input/output tensors exist, but there is no LM head or greedy check.
   - [r2-serve]: LM head plus greedy least-maximiser over int8 logits, last 2^log_out positions, public embeddings (lm.zig).
   - Verdict: WORSE, even counting r2-serve.

2. Clipped-gap policy
   - FP: implemented; Lean proves only that the reply meets the policy.
   - Ours: MISSING (low priority).

3. Integer model fidelity
   - FP: 12-bit activations with clamps, 16-bit residual stream, wide logits. Model parameters are fixed in public files. 48 layers, 202K vocabulary. 6.81% top-token disagreement measured against bf16 on real weights. Sources: docs/model.md, paper Table 2.
   - Ours: int8 everywhere, undefined outside range, data-dependent shifts (P2), public RMSNorm gains, synthetic weights only, no fidelity measurement.
   - Verdict: WORSE.

4. Weight commitment
   - FP: masked RS over Goldilocks with a cubic extension, ℓ≈4e8, |D|=2^32, OOD sample, salted BLAKE2b, one-time key proof (range plus proximity).
   - Ours: Ligero/Brakedown over M31 with circle codes (pcs.zig, pcs2.zig recursive), Blake2s, weight_key.zig (range plus proximity). LogUp count < p is unenforced (P7).
   - [r2-sec]: OOD, Johnson regime, 2-alpha key.
   - Verdict: EQUAL in structure, WORSE at scale.

5. Weight hiding, opening budget, copies and links
   - FP: budget t=44,040,191 columns; 688,127 batches per copy; 710,324 copies linked to T0. The counter is on disk. Proved ZK of the protocol in Lean.
   - Ours (zk.zig, zk_pcs.zig): masked circle code, budget S/2 columns enforced in process, about 17 proofs per commitment at the defaults, chain links (rerandomizeWeights).
   - Verdict: WORSE (P8).

6. Per-request proofs and batching
   - FP: up to 64 per batch, a proof per request, shared rounds (κ_bat 28-bit PoW), error N× per batch.
   - Ours: one proof per batch.
   - [r2-serve]: per-request proofs with one shared weight opening; non-hiding.
   - Verdict: WORSE merged; roughly EQUAL non-hiding once r2-serve merges; MISSING for ZK.

7. MoE
   - FP: 128 routed top-1 experts plus a shared expert, router shifts.
   - Ours: top-1, ≤64 experts (transformer.zig:407), no shared expert, no gate scaling, capacity overflow makes the prover refuse.
   - [r2-serve]: stacked experts, batched matmul.
   - Verdict: WORSE.

8. Soundness bound and accounting
   - FP: Lean-proved q/2^124 + 2^-101 (exact match). Printed 126.21 with work / 96.23 without, with honest caveats (figures.tsv:91-94).
   - Ours: query-term-only 'proven' number (P3).
   - [r2-sec]: full calculator. About 100 (toy) and 96-99 (MLP/layer) whole bound; best Johnson+OOD toy 113.5 with work / 96.8 without; QM31 caps the whole bound at about 114.
   - Verdict: WORSE (r2-sec without work ≈ FP's printed without-work figure; with work and in proven terms, worse).

9. Formal verification
   - FP: Lean soundness, completeness and ZK for the protocol; executable proved verifier (lean-verify); independent checker pass. Sources: lean/THEOREM.md, guide/what-is-proved.md.
   - Ours: none (formal/ covers only riscv-refinement).
   - Verdict: MISSING.

10. Verifier implementation
   - FP: C++ cp_verify plus the Lean executable verifier; they agree on every common file; both run on proof files.
   - Ours: one Zig verifier over in-memory structs, no wire format (P12).
   - Verdict: WORSE.

11. Tests of hiding
   - FP: five tests, including mask-loss fault injection (165 CPU / 130 GPU destroyed values) and audits with the key.
   - Ours: two statistical sanity tests, a 300-set slot-span rank test, and 'two proofs differ' (zk.md §4.5).
   - Verdict: WORSE.

12. Negative tests
   - FP: 57 full-size lying proofs, 249 altered copies, a malicious committer, altered stored tables.
   - Ours: per-field tamper tests in every module, unchecked-prover cheats for ext/MoE, serve slot attacks.
   - Verdict: EQUAL in breadth at small size; WORSE in that we have no full-size or cheating-prover corpus.

13. Speed (same toy, sequential CPU)
   - Ours: BETTER by about 25x at matched hiding (zk toy 0.327 s against 8.37 s at L=20). That is only a conjectured-security match (about 58 provable bits against FP's 128-per-round target), and FP's side is reference code.

14. Speed (model scale)
   - FP: 9.2 s per 1,024-token request for Maverick on an H100.
   - [r2-serve]: projects 550-1840 s per request on M4 CPU, compute-only, and not runnable here.
   - Verdict: no evidence of parity. Cross-hardware comparison is not possible.

15. Proof size
   - Toy: ours 247 KB at 113.5 bits (r2-sec Johnson+OOD) against FP 341 KB at 128 per round.
   - Model: ours estimated at 4-6 MB per request own part [r2-serve], against FP 18.78 MB.
   - Verdict: plausibly BETTER, but counted, not serialized (P12).

### Report corrections
CORRECTED WORDING

1. README line 7-11
   - Replace with: "It targets FlashProve's statement class (committed integer model, public prompt, claimed greedy tokens). Today only the hiding path binds public input and output, and no merged path proves greedy output tokens or fixes the model's scales at commit time (see Status)."

2. README 'Comparability rules'
   - Replace 'Same statement, same machine' with: "Same arithmetic relation as FlashProve's blocks/toy/product.h (a∘b=c over 2^L), on the same machine. FlashProve's figures come from its sequential plain-C++ reference engine (EngineCpu), not from cp_prove or its CUDA prover; 51% of that engine's time is ChaCha20 mask and salt generation."
   - Replace the two security regimes with: "Security is reported as the soundness calculator's whole bound with and without PoW. 'qc' configurations are sized by the capacity conjecture alone."

3. README Status
   - The weight range proof exists (weight_key.zig).
   - Attention, ZK and Metal are merged.
   - The non-hiding path proves an existential relation with no I/O.
   - Shifts are chosen per input.
   - LogUp requires fewer than p = 2^31-1 keys per relation, and this is not enforced.

4. Config names
   - 'conj128' → 'qc128 (54q, lb2, 20 PoW; ~55 provable bits)'.
   - 'proven128' → 'ud-query (160q; whole bound ~100 toy / ~97 MLP / ~98 layer)'.
   - Every bits figure gets the footnote: "QM31 challenges (|F|≈2^124) cap any whole bound at ≈114 bits; FlashProve's Lean bound is q/2^124+2^-101; its printed 126.21/96.23 are program accounting."

5. Toy table headline
   - Remove the 'prove speedup' column from the non-hiding table, or retitle the table "Non-hiding ours vs hiding FlashProve reference (not like-for-like)".
   - The like-for-like table is the hiding one.

6. MLP and layer tables
   - Title: "Existential relation (no public I/O, prover-chosen shifts): arithmetic throughput only."
   - Headline column: 'prove incl. forward'.
   - Compute MAC/s over prove+forward.
   - Report n and the range for every cell.

7. Serving and Maverick text [r2-serve]
   - Keep the 'compute-only, this machine, not runnable' wording.
   - Add: "outside the soundness scope until LogUp relations are split below p".
   - Never put our tokens/s beside FlashProve's 111.23 tok/s: different model (2-layer, 100M weights against 48-layer, 400.7B), hardware, ZK, statement and security.

TABLE STRUCTURE FOR THE FINAL REPORT

(A) Statement and feature parity: rows = items 1-12 of the parity matrix; columns = FP (source), ours merged (file), ours r2 (branch, unmerged), verdict.

(B) Security per config: config | queries/lb/PoW | whole bound with work | without work | largest round with/without | rbr | limiting term | proof bytes. FP rows: toy (its 128-per-round target, PoW 0 and 20) and full size (126.21 / 96.23 printed; Lean q/2^124+2^-101).

(C) Like-for-like toy (hiding only, PoW matched at 20): L | ours prove/verify/bytes | ours whole bound with/without | FP w20 prove/verify/bytes | FP bits per round | ratio. Mark FP as 'sequential reference'. Fill the missing FP w20 L=18 cell by running it. Medians of ≥3 reps, load average and AC status recorded.

(D) Non-hiding toy (informational, no ratio column).

(E) Throughput of the existential relation (MLP/layer): prove incl. forward, forward, commit (once), verify, bytes (computed, not serialized), threads (12 of 10P+4E), n and range.

(F) Model-scale projection (r2-serve), with every input listed and the soundness-scope caveat; no FP ratio.

MISSING TO BE "AT LEAST FLASHPROVE", BY IMPORTANCE

1. A statement that binds a public prompt and output, an LM head and a greedy-token check, merged on the main path (r2-serve, made the default).
2. Fixed model configuration (shifts, norm parameters, tables) bound to the commitment; the verifier builds the statement itself (P2).
3. Honest soundness accounting merged (r2-sec), a larger challenge field (or repetition) to clear 124+ bits per query, and LogUp count < p enforced, with relations split for large models (P3, P7).
4. ZK for per-request serving, with a FlashProve-size opening budget (long rows), links to T0, a persistent counter and fixed MoE capacity (P8).
5. Integer-model fidelity: 12-16-bit activations with clamps, committed gains and embeddings, 128 experts plus a shared expert, and a fidelity measurement on a public model (P9).
6. Full-window multi-layer completeness at FlashProve's shapes (1,024 tokens, D 5120); r2-sec reports ExtStatement at layer 10 11 12, not reproduced at small sizes.
7. Proof wire format, standalone verifier, hostile-input hardening, and a corpus of cheating-prover and lying proofs at size (P12).
8. Hiding tests beyond statistical sanity: mask-loss fault injection and an audit with the key.
9. Clipped-gap policy.
10. Machine-checked verifier soundness (Lean), longer term.

Tooling fix: tensor_compare.py layer arguments (P6), and fail loudly on missing rows.

### Checked OK
- Thread fairness of the toy rows: our toy runs use threads=1 ('product L 1 ...'), and FlashProve's EngineCpu is sequential. 1 core against 1 core is matched. No finding.
- The forward pass is shown separately in the MLP and layer tables as '(+forward)', and the weight commit and weight-key proof are excluded on both sides (FlashProve also excludes start-up and commit). Exclusion is matched, but see P5 for the MAC/s headline.
- The FlashProve published H100 figures in tensor_compare.py FP_PUBLISHED (111.23 tok/s, 9.206 s, 18.78 MB, 21.14 s verify, 2323.77 s commit, 126.21/96.23 bits) match docs/figures.tsv and guide/performance.md. No finding.
- The FlashProve CPU baseline's toy numbers (L16 0.49 s / 269 KB, L18 2.05 s / 251 KB, L20 8.37 s / 341 KB, deep, w0) match its logs (toy_L20_w0_deep.log: median 8.3680 s, 340520 B, ACCEPT). No transcription error.
- Layer completeness at T=1024: 'tensor-bench layer 10 5 6 1 4 54 2 20 0 1 0 10 1 2 54' and T=256/512 succeed, as do D=2048 at T=16 and D=512 at T=256. I could not reproduce r2-sec's report of error.ExtStatement at layer 10 11 12 at small sizes. The full-size run is beyond the memory rules and was not tried.
- The ZK re-randomization link exists in merged code (zk.zig:786-832) with tamper tests (zk.md §6). It is functionally present, but see P8 for the budget and chain-shape gap.
- The opening budget is enforced in the prover before release (zk_pcs Budget, error.OpeningBudgetExceeded), matching FlashProve's counter, but only in memory (P8).
- r2-serve per-request soundness argument (slot pinned to T_i, gamma after all slots, reduction sumcheck, single opening): the reasoning reads sound as written. Unmerged and not tested here.
- r2-serve greedy check (Dr = m - logits, Dr - [v<y] in [0,256), sum Sel*Dr = 0) correctly implies y is the least maximiser for int8 logits. The fidelity concern is in P9, not soundness.

## Area: transformer semantics (ext.zig, transformer.zig, model.zig, transformer.md), wor

### Parity
Feature, ours vs FlashProve (docs/model.md):
- RMSNorm: ours is isqrt + floor(2^15/rt), int8 output, public gamma. FlashProve uses Rc = round(2^M/sigma) with no gains and clamps to ±2047. Ours is roughly at parity; both are sound.
- RoPE: ours uses a 128-scale public table and a 9-bit output. FlashProve uses a 4096-scale table plus clamp. Same structure, lower precision in ours.
- GQA: same head mapping.
- Causal softmax: FlashProve shifts the keys by sh, uses a table, accumulates e·v, and divides once by Z. Ours uses per-entry P with 1/128 resolution through a reciprocal. Ours is WORSE: unsound for lt >= 8 (EXT-1) and not normalised (EXT-3).
- First-argmax ties: same in the MoE router. Softmax ties do not matter.
- MoE: FlashProve has a shared expert plus the routed top-1 expert with a sigmoid input scale. Ours has the routed top-1 expert only and no scale (less).
- Dispatch with capacity slots: an extra in ours (FlashProve evaluates the chosen expert per token).
- Embedding, final norm, output head, greedy argmax over public tokens: FlashProve has them; ours has none (less).
- Hiding: FlashProve yes; ours no (a separate zk stream).
- Weights: 13-bit vs int8 (benches use 4-bit values).
- Activations: 12-bit vs int8.

### Report corrections
Corrections to the existing docs:
- transformer.md §3 'division': the uniqueness argument ('with |2^K − pr| < 2^30 ... rden = floor(2^K/den)') is wrong for lt >= 8, because pr = rden·den itself can wrap mod p. Range-checking rden does not stop the wrap.
- transformer.md §4 table: the 'pr = rden den, 2^K − pr <= 2^(lt+15)' row bounds only the honest prover. A cheating rden < 2^(lt+8) gives a product up to 2^(2lt+16). So the claim 'All inequality operands therefore satisfy the range-to-integer lemma' is false at the configs the docs benchmark (T=256/512/1024).
- transformer.md §2 claims P ≈ 128e/den and 'tested against the exact quotient'. That holds per entry, but the rows are not normalised at long context (EXT-3).
- README.md's 'same statement class as FlashProve' does not hold for the layer and MoE benches (EXT-4).
- attn.md: 'adversarial coverage ... all rejected' is accurate for the 9+5 listed cheats, but none of them is a modular wrap.
All review tests are in /Users/theodorepender/Coding/ge-wt/rev-ext/src/tensor/review_ext_test.zig, wired into that worktree's mod.zig by a local edit. Nothing was committed.

### Checked OK
- Rowmax/argmax selector (softmax): sel·sel = sel (degree-3 zero-check, n_k=0, all vars batch) + sum_j sel = 1 (lineq SUM) + sum_j sel·D = 0 (exact einsum y=null) + D in [0,1024) via the exp lookup pin m = max_j Sm as an integer. m needs no range check: m = D_j + S_j + Bias_j as small integers. Selector on a masked position is impossible (it would need S_0 <= −385 with S int8).
- Causal mask: masked D >= 257 (m >= −128, Sm_masked <= −385) and D <= 767 < 1024, so e = expT(D) = 0 is forced by the lookup. The masked-exp leak is rejected (existing test).
- Exp table: 1024-entry public lookup (i, round(256·exp(−i/16)) for i<256 else 0). LogUp key D + β·e against i + β·v_i in its own table relation; per-table LogUp sums are checked separately (protocol.zig:1335-1355), so range-table entries cannot pay for (D, 0) lookup keys.
- den = sum_j e (lineq with SUM term; 2^|u|·T~(ρ,½) identity correct), den in [256, 256T].
- RMSNorm isqrt: rt < 2^rt_bits (rt_bits <= 12), rt2 = rt² < 2^24, 2^s1·rt2 < 2^30; both gap inequalities stay within the range-to-integer lemma; rt >= 1 forced since N >= 2^s1; the builder's floor(sqrt(floor(N/2^s1))) equals max{r : r²·2^s1 <= N}.
- RMSNorm reciprocal: inv < 2^16, rt < 2^12, so inv·rt < 2^28 (no wrap, unlike the softmax reciprocal). u = rq6(xs·inv) acc < 2^23; |u| <= ~2^12 at ld=14, so the honest prover does not overflow its 16-bit range. y = rq(u·γ) acc < 2^22.
- RoPE: labels map x[t, h, i, b] and R[t, i, b', b] correctly (batch t, i; contracted b; x-only h; R-only b'); table = 128·[[c, −s], [s, c]] with θ = t·10000^(−2i/dh) (interleaved-pair convention, matches FlashProve's p0 = C·A0 − S·A1, p1 = S·A0 + C·A1); |acc| <= 128·181, so the output fits 9 bits.
- GQA head mapping: query head h = (hk, g) with hk the MSB part, i.e. kv head = floor(h / G), the same as FlashProve's g = floor(h/(nh/ng)); score/PV labels checked bit by bit; existing direct-reference test agrees.
- Fused-QKV FIX slicing: sliceFix gives the Q block 0, K block 2^lg, V block 2^lg+1 with D a multiple of Dkv; FIX labels are handled consistently in einsumAcc/fixConst, foldOperand, operandPoint, termPoint, materialize; FIX points give the slice MLE and are discharged by the batch opening.
- MoE routing: Dr = m − L in [0,256), sel binary / sum 1 / sum sel·Dr = 0, and Dr − pre >= 0 with pre = sum_{x'>x} sel (Tri[x',x] = [x'>x], labels correct) enforce first-argmax ties, the same as FlashProve's 'ties to the lowest index'. Router padding columns are sliced off via FIX0 high bits.
- MoE dispatch/combine: Disp binary, sum_c Disp[x,c,t] = sel[t,x], occ = sum_t Disp binary, so each routed token sits in exactly one slot of its expert and each slot holds <= 1 token. So Xe = Disp·y is int8, which justifies the EXT_EXACT_BOUND exemption for the expert matmul. Combine out = sum Disp·MO reads exactly that slot.
- Residuals: z = x + y lineq; the bounds follow by induction (|x_l| <= 128 + 256l); layer>0 RMSNorm input requant uses remainder + int8 range keys.
- Einsum validity: labels in range, no repeats, every output var driven, every contracted var in both operands, FIX/SUM excluded from masks, SUM disallowed in einsums; the fold identity A'(r) = A~(ρ_u, r) is correct; final check eq(ρ_B, r_B)·A'·B'; requant acc claim = r − 2^(s−1) + 2^s·Y from the remainder/y_range GKR terminals at the shared ood suffix (the keys are consecutive in deriveKeys).
- Statement hashing: ext publics (log_size + values), lookup tables, every op (kind tag, y/shift/out_bits/n_out/n_k, refs incl. public bit, labels, expr coeffs and constants, table id) mixed after the witness/weight shapes and the weight root; empty ext leaves core transcripts unchanged. Prover messages (values, finals) are mixed before each challenge (ρ for exact einsums and lineqs is drawn after the commitment).
- Decoder-layer bench (bench.zig runLayer → buildStack) really includes 2×RMSNorm, (fused) QKV, RoPE on Q and K, GQA causal softmax-PV, Wo, both residuals, and SwiGLU or MoE; prove_s covers prove only (forward_s and weight commit reported separately).
- Baseline suite completeness: zig build test -Doptimize=ReleaseSafe reports 57/60 passed; the 3 failures are exactly the new review tests (the honest attention at T=256 proves and verifies inside the EXT-1 test).

## Area: commitments: pcs.zig, pcs2.zig, weight_key.zig, and how protocol.zig uses them (

### Parity
Commitments vs FlashProve:
- Weight commitment, committed once, opened per batch: stwo-zig yes; FlashProve yes (copies plus link proofs).
- Offline range proof of the weights: stwo-zig LogUp-GKR histogram; FlashProve offline proof πkey. Parity.
- Binding beyond unique decoding (OOD samples / masked linear forms at a root-derived point): FlashProve has it. stwo-zig has nothing, so the conjectured configs are unsound for weight binding (PCS-1). With unique-decoding query counts (about 160 at lb 2), stwo-zig is sound but the proof-size advantage shrinks (size.md §5 proven-query column: 2.08 MB weights, ~1.0 MB/request).
- Layout binding: FlashProve fixes it with a public layout file and a parameter check. stwo-zig takes key.offsets/infos on trust (PCS-2).
- Merkle multiproofs, PoW before queries, Fiat-Shamir order: parity.
- Hiding (masked encoding): out of scope here (zk_pcs).

### Report corrections
Corrections to the docs:
- design/tensor-frontend/README.md:86 ('conjectured: up to capacity') and size.md:20/219 present t*log_blowup + pow as a conjectured security level. For Ligero openings without OOD binding, test review_pcs_test.zig:330 refutes it: acceptance is about (1/2)^t, not rho^t. The FlashProve size comparison in size.md §5 should use the proven-query column, or OOD binding should be added first.
- pcs.zig:16-19 ('later openings only need consistency queries, because the decoded rows are already fixed') holds only within the unique-decoding radius.
- The README statement that the proximity proof 'is part of the weight key' omits that the key's layout fields are not authenticated (PCS-2).

All adversarial tests are in /Users/theodorepender/Coding/ge-wt/rev-pcs/src/tensor/review_pcs_test.zig, wired in through a one-line local edit of mod.zig. Nothing was committed or pushed.

### Checked OK
- Transcript order, flat pcs. Callers mix the root (mixStatement / startTranscript / proveWeightProximity). Then claim values are mixed, gammas drawn, proximity betas drawn, rows mixed, PoW nonce mixed into the channel (transcript.grind/verifyPow), and query indices drawn. Prover and verifier match; claim points come from the transcript.
- Transcript order, pcs2. Values, gammas, betas, combined rows, inner_root mixed, rho, PoW, queries, verifier-computed y_j mixed, gamma', sumcheck, limb_vals mixed (re-mixed by the next level's setup). The queries are drawn after U is committed and after rho; nothing the prover sends affects earlier challenges. Existing tamper tests plus test 7 confirm this.
- rows_used truncation. The verifier uses cf[0..RU] and columns of length RU, so rows ≥ RU are zero in its view. Test 'rows_used truncation' shows that garbage in the prover's matrix beyond RU is not committed, that a claim including it is rejected (OpeningEvalMismatch) for flat with and without proximity and for pcs2 depth 1, and that a verifier with the wrong rows_used rejects (OpeningShape). The inner U tables' rows_used = n_rows*4*C/2^lc exactly covers the real rows; padded U rows are zero, and W is evaluated on the full G'xC cube.
- Weight openings need no per-batch proximity: correct under unique decoding (per-query pass ≤ rho+delta = 1-delta with delta=(1-rho)/2, i.e. provenBits). Incorrect at the conjectured parameters; see PCS-1.
- Circle-basis factorisation. circleFactors uses the factors (y, x, pi(x), ...) in MSB-first fold order at domain.at(bitReverse(j)), which matches stwo's eval_at_point/fold. Test 1 checks evalCoeffs == encodeSecure (QM31, dyadic-extension path) at every j for log_c ∈ {1,2,3,4,6} and lb ∈ {1,2,3}, and checks that tensorEvalAt equals the MLE of tensorTable at random r.
- Multiproof. verifyMultiproof rejects duplicate, unsorted and out-of-range (aliasing) positions, extra and missing siblings, and empty leaves with siblings; it accepts all-leaves with 0 siblings (test 2). The verifier derives the positions itself (sortedUnique of its own drawIndices) and checks col_values.len == uq.len*RU.
- Merkle leaf/node confusion is not exploitable: path depth is fixed by log_ext (sibs.len checked), even when RU*4 == 64 bytes.
- Flat Ligero cheater (consistency only, as for weights). A combined row adjusted to satisfy the eval check for a false value is rejected with OpeningColumnMismatch (test 4).
- pcs2 limb_vals. A tamper in the kernel of (v_c) -> sum e_c v_c passes the level's sumcheck final check but is rejected by the next level's opening, at every level, with and without proximity (test 7).
- combineRows i64 accumulation. i8: 2^24 rows x 2^38 < 2^62. i32 limbs: chunk of 2 products ≤ 2(2^31-2)^2 + P < 2^63, including v = -2^31. No overflow.
- Weight-key range proof. The histogram counts the whole 2^n table including padding zeros; the verifier checks sum == 2^n (so every m_v < p), n_vars_by_instance == (n, 8), nonzero denominators, the cross-multiplied LogUp sum, num == 1, the table terminal claims (hist MLE and alpha - id) and the derived W(rho). The opening of W(rho) carries proximity under the same transcript. This is sound for range [-128, 128) up to O(N/|QM31|), subject to PCS-1 and PCS-2.
- Shape-dependent column choices. bestOuter, bestInner and innerShape are deterministic functions of public sizes, evaluated identically by prover and verifier; a finite option always exists (lc ≤ 10 never hits the budget bound). The verifier regroups weight claims from its own points (groupByColumn).
- Malformed proofs. Flat and pcs2 verifiers length-check rows, columns, paths, levels, sumcheck rounds and col_values before indexing; no panic from proof data was found (only the verifier-side issues in PCS-2 and PCS-4).

## Area: kernels and acceleration (field.zig, linalg.zig, core QM31.mul, accel.zig, metal

### Parity
Compared with FlashProve on the kernel side: like FlashProve, the int8 weights × QM31 limb folds are exact integer accumulation, and the CPU kernels are exact within their declared bounds. The Metal fp32 trick is exact up to 2^23 as claimed, except that +128 is packed wrongly. stwo-zig's extra Metal path promises bit-identity, which holds except at +128 (KERN-2). Hardening is needed beyond FlashProve's toy: canonical-limb validation at the verifier boundary (KERN-1), and bound plumbing for activations wider than int8 (KERN-3).

### Report corrections
Two of the documented claims are imprecise. metal.md says the fp32 path is exact for |x| <= 128, but +128 cannot be packed into char, so the safe bound is 127. CM31/QM31.fromU32Unchecked is not 'unchecked': it asserts canonical in safe builds and is UB in ReleaseFast for non-canonical input. Any decoder must build limbs with checks, not with this function.

All new tests are in /Users/theodorepender/Coding/ge-wt/rev-kern/src/tensor/review_kern_test.zig and /Users/theodorepender/Coding/ge-wt/rev-kern/src/tensor/metal/review_kern_metal_test.zig. They are wired in through local edits to src/tensor/mod.zig and src/tensor/metal/test.zig. Nothing was committed or pushed.

### Checked OK
- QM31.mul lazy reduction bounds (qm31.zig:186-218): for any u32 limbs pr(x,y) < 2^33+2^31, the subtracted side is at most 5 pr < 2^35.4, below bias 64p ≈ 2^37 (≡ 0 mod p); sums stay < 2^39 in u64; two Mersenne folds plus umin give a canonical output. Formula checked against u^2 = 2+i. Test 'QM31.mul lazy path is exact for extreme non-canonical limbs' (8^4 limb combinations of 0, 1, p-1, p, p+1, 2^31, 2^32-2, 2^32-1) passes in ReleaseSafe and ReleaseFast; the existing qmul_check_test 2M-sample differential passes in ReleaseFast.
- rowDots (linalg.zig:20-50): chunk = 2^(31-b) columns; |row| ≤ 2^b and plane < 2^31 give per-chunk |acc| < 2^62; tot stays in (-p,p). Exact at the bound: worst-case test (-128 × (p-1), 4096 cols) passes.
- combineRows (pcs.zig:316-371): reduction every 2^(31-b) rows; residual < p plus 2^62 < 2^63. Exact for i8 at b=7 and for i32 at b=30 (pcs2/zk_pcs callers), including -2^30 × (p-1) (test passes). Only the constant-8 callers are unsafe (KERN-3).
- Metal int32 matmul (tm_matmul_i32_i8): |x|<2^15, |w|≤128 give products < 2^22; flush every 8×32=256 terms gives < 2^30 < 2^31. Test at x=-(2^15-1), w=-128, K=2^8 matches CPU.
- Metal fp32 matmul exactness: |x·w| ≤ 2^14 with a flush every 16×32=512 terms keeps every partial < 2^23 < 2^24, so fp32 is exact. Test at K=2^12, x=w=-128 with odd -127 perturbations matches CPU. The only defect is the +128 packing (KERN-2).
- Metal combine / row_dots: field-exact qm_add/qm_mul_m31, per-chunk partials summed on the host. Existing test plus the i32 range up to p pass; tgsize 256 is a power of two, so the tree reduction is correct.
- Metal/CPU identity: the full test-metal suite (11 original tests + 2 of my 3 new ones) passes under ReleaseSafe; only the +128 test fails.
- ReleaseFast UB sweep: the baseline tensor suite (57 tests) passes under ReleaseFast and under ReleaseSafe, so ReleaseFast shows no extra miscompile or UB failures. All failures under ReleaseFast come from the new adversarial tests.
- Thread-pool chunking (field.zig Pool.parallelFor; sumcheck/eqsum/zk_sumcheck partial buffers): n_chunks ≤ ceil(work/ceil(work/target)) ≤ target < n_threads*4+2, so indexing by s/chunk stays in range. Partials are summed in fixed index order, and field addition is exact, so results are scheduling-independent. prep.zig caps tasks at MAX_POOL_TASKS.
- Determinism across thread counts: test 'proof digest independent of pool / GKR thread counts' (pool 1/2/3/7/16 × gkr 1..5, mlp 3 5 6) gives identical digests, and every proof verifies.
- Recycler: with dirty, poisoned reused blocks and a 4 KiB threshold, proofs are byte-identical to backing-allocator proofs and hits > 0, so no consumer reads uninitialised memory. A 6-thread concurrent alloc/fill/verify/free test showed no aliasing of live blocks. resize/remap keep a rounded-size invariant, alloc and free use the same isBig predicate and alignment, and trim frees with the alloc's size and alignment. Caveat: mutating the public `threshold` while blocks are live would mismatch frees; only tests do this, before allocating.
- accel.deviceRounds / proveFactors tail buffer: after device rounds active ≥ sc_min_work always holds, so the loop exits only when len < 2·sc_min_work ≤ tail_len, and the tail slices fit. head arrays [64] ≥ n.
- gpu.view wraps page-aligned spans that cover only mapped pages of the host allocation; writes are confined to [offset, offset+len).
- bench_prims.zig: no misleading claim in the area. Ops/s are computed over the work actually done (qm31 loops use ITER/4 and divide by N·ITER/4). Minor caveat: 3×4096 QM31 = 192 KiB is not L1-resident on M-series, so 'L1-resident' in the header is slightly inaccurate (not a finding).