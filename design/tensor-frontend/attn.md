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
