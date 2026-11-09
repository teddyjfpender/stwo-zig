# Stream: transformer coverage (codex/tensor-attn)

Goal: make a full Llama-style decoder layer expressible and provable in the
tensor frontend. Full spec and soundness argument: `transformer.md`.

## Protocol changes (all additive)
* `Statement.ext` (ops, public tensors, lookup tables), `Proof.ext`.
* Ext LogUp keys appended after core keys in the single batched GKR; ext
  terminal claims after core terminal claims; ext op reductions after core op
  sumchecks; all resulting witness claims join the one batch opening.
* Empty `ext` => no transcript change (core proofs unchanged).

## Soundness summary
See transformer.md sections 1 (generic ops), 3 (uniqueness of every gadget)
and 4 (no-wrap bounds). Each new op reduces to sumcheck / LogUp / Schwartz-Zippel
with challenges drawn after the commitment, and all claims are bound by the
existing PCS opening. Inequalities are only used inside the bounds of the
range-to-integer lemma; `LayerCfg.validate` and builder assertions enforce them.

## Adversarial coverage
Proof tampering (sumcheck rounds, finals, values), statement tampering (mask,
shift, labels, malformed), and invalid witnesses through a test-only unchecked
prover (9 cheat classes) are all rejected. See transformer.zig tests.

## Measured (M4 Max, shared/loaded host, 8 threads, 64 queries, log_blowup 2, pow 20)

`tensor-bench layer <lt> <ld> <lf> <lh> 8 64 2 20 <lkv> <layers> <le> <lcap> <fused>`

| config | weights | prove | verify | proof (weight opening) |
|---|---|---|---|---|
| T=32 D=256 F=512 4h/2kv, unfused (first version) | 0.59M | 0.061 s | 6.0 ms | 1.40 MB (1.20) |
| T=128 D=1024 F=2048 8h/2kv, unfused | 8.9M | 0.27 s | 32 ms | 9.41 MB (8.94) |
| same, fused QKV | 8.9M | 0.27 s | 12.5 ms | 2.87 MB (2.40) |
| T=512 D=512 F=1024 8h/2kv, unfused, before ext parallelisation | 2.2M | 1.03 s | 29 ms | 5.38 MB (4.48) |
| same, fused QKV, parallel ext prover, sel zero-check | 2.4M | 0.86 s | 19 ms | 2.11 MB (1.21) |
| T=128 D=1024 F=2048, 2 layers, fused | 18.9M | 0.85 s | 24 ms | 5.42 MB (4.76) |
| T=128 MoE 8 experts cap 64, unfused | 53.2M | 0.73 s | 184 ms | 54.0 MB (53.2) |
| same, fused | 53.2M | 0.73 s | 53 ms | 14.4 MB (13.7) |
| T=256 MoE 8 experts cap 128, fused | 54.5M | 1.46 s | 59 ms | 14.7 MB (13.7) |

The remaining proof size is dominated by the weight opening
(queries x weight-table rows); the table width is now limited by min(D, F)
(2^10 here) rather than the K/V width. Raising it further needs the weight
PCS to support claims whose column point is not a common suffix (other stream).
