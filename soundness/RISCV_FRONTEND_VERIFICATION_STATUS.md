# RISC-V frontend verification status and roadmap

**Status date:** 2026-07-31

**Claim owner:** the repository-wide RISC-V refinement gate

**Normative detailed contract:**
[`UNIVERSAL_AIR_SAIL_REFINEMENT.md`](UNIVERSAL_AIR_SAIL_REFINEMENT.md)

This file is the short claim ledger for the RISC-V frontend. It separates
what the checked artifacts establish from what remains an engineering plan.
If a receipt, issue, pull request, or older document makes a stronger claim,
this ledger and the machine-readable receipt take precedence.

The former **Team A / Team B** split was a temporary allocation of proof work.
It is not an ISA distinction, an AIR boundary, or a verification grade. New
public theorem names, receipts, gates, and roadmap entries are organized by
opcode family and verification layer instead.

Canonical entry points are:

- this file for claim status and roadmap;
- [`README.md`](README.md) for the soundness-document index;
- [`../formal/riscv-refinement/README.md`](../formal/riscv-refinement/README.md)
  for proof layout and reproduction;
- `RiscvRefinement.Publication.Opcodes` for the neutral Lean publication
  inventory; and
- `scripts/riscv_refinement.py` plus `.github/workflows/riscv-refinement.yml`
  for repository verification and receipts.

Historical team-named scripts, indexes, or theorem-building namespaces are
compatibility inputs only. They cannot classify publication entries, increase
the proof count, or define current ownership.

## Current top-level claim

```text
whole_frontend_verified = false
proof_system_soundness = false
```

The issue-136 checkpoint preserves a kernel-clean generated-Sail full-step
composition and substantial accepted-production-AIR proof prefixes. The
expanded generated bridge remains outside the current receipt-bound runner so
that its old two-normalizer receipt stays truthful. The full continuation
sources are preserved under
[`formal/riscv-refinement/checkpoints/issue-136`](../formal/riscv-refinement/checkpoints/issue-136/README.md),
outside every proof count and default import. There is no promoted 46/46
publication receipt: load/store, division, and the public generated-Sail
opcode composition still have explicit blockers recorded below.

No current artifact proves that every accepted STARK proof represents a valid
RISC-V execution. In particular, local opcode refinement is not a substitute
for the remaining word/field invariant, cross-row trace composition, or the
soundness of the PCS/FRI proof system.

## Verification ladder

| Gate | Checked statement | Status | What remains |
| --- | --- | --- | --- |
| Source binding | The formal evaluator consumes the exact generated constraint programs for all 46 admitted RV32IM opcodes, with pinned selector, event order, fixed-table schemas, and source digests. | Landed | Keep regeneration and source-drift checks fail-closed. |
| FV-1 — generated Sail | Each admitted opcode has a generated-Sail retirement normalizer, and the retained full-step trace erases to the exact pinned generated `try_step` semantics. | Full-step erasure kernel-clean in the non-gating checkpoint; carried receipt still proves 2 normalizers | Resolve the generated barrier-placeholder universe in the public FENCE contract, extend the public composition to all selectors, promote Pilot and Composition atomically, capture exact axioms, and reproduce from the live pinned runner. |
| FV-2 — local AIR refinement | Acceptance of each exact production AIR program implies the matching generated-Sail opcode retirement under explicit row, state, profile, and admission bindings. | Partial, fail-closed | Finish load/store after `fixedConsequences`, finish division after `baseConstraintRootZeroAt`, compile every canonical family module, run non-vacuity/axiom audits, and mint the exact receipt. |
| FV-3 — `Word32` / M31 boundary | Every conversion between a 32-bit architectural value and one M31 element is injective or carries a proved bound; machine arithmetic never silently becomes field arithmetic. | Partial; blocking | Complete issue [#157](https://github.com/teddyjfpender/stwo-zig/issues/157), including the mechanical conversion gate and per-site negative controls. |
| FV-4 — trace composition | Local opcode theorems compose across arbitrary admitted traces, including fetch/decode, register and memory buses, clocks, traps, interrupts, and cross-row state. | Open; blocking | Prove a named length-parametric trace-refinement theorem and connect local admission to global frontend invariants. |
| FV-5 — reproduction and review | Independent reviewers reproduce the exact artifacts and approve the claim/axiom/trusted-base boundary. | Open; blocking | Clean-room reproduction, independent sign-offs, and final claim promotion. |

`whole_frontend_verified` may become `true` only after FV-1 through FV-5 all
have named, kernel-checked, reproduced evidence. `proof_system_soundness` is a
separate project and remains false even then unless the proof-system theorem is
also delivered.

## What FV-1 and FV-2 buy us

When their publication receipt lands, FV-1 and FV-2 will provide a strong local
semantic guarantee:

1. The architectural target is the pinned generated Sail RV32IM model, not a
   handwritten lookalike.
2. Every one of the 46 manifest opcodes is covered exactly once; a missing,
   duplicate, relabelled, or stale selector fails the inventory gate.
3. The theorem begins with acceptance of the exact generated production AIR
   evaluator, not an assumed family predicate or an expected result supplied
   by the caller.
4. Selector activation, result limbs, carries, ordered lookup tuples, and all
   live non-fixed relations are load-bearing in the proof result.
5. Generated decoder and execute-monad effects are retained. The proof cannot
   replace an effectful generated call with a pure result equality.
6. The axiom receipt records the exact Lean kernel and generated-model axioms
   used by every normalizer, cross-project theorem, full-step theorem, and
   universal contract.

This substantially reduces the risk of an opcode row satisfying the shipped
constraints while retiring a different instruction result in the reference
architecture. It does **not** by itself eliminate bugs in global invariants,
trace wiring, field representations, generated callbacks, or the proof
system.

## Trusted base and explicit assumptions

The publication claim relies on:

- the Lean kernel and the exact axioms listed in the generated receipt;
- the pinned generated Sail source and its Lean backend;
- the source-to-constraint-program generator and its digest/regeneration
  checks;
- the explicit zkVM execution profile used by the theorems;
- componentwise bindings for architectural registers, PC, memory effects, and
  decoder state; and
- callback branches proved unreachable under that profile, or explicitly
  constrained where reachable.

For load/store publication, the profile disables HTIF termination writes,
uses the admitted non-reservation path, and relies on the production address
bound now present on `main`. The broader non-injective `composeU32` discipline
is still FV-3, not something the local memory theorem may silently assume.

## Remaining roadmap

1. Resume from the
   [`issue-136 checkpoint`](../formal/riscv-refinement/checkpoints/issue-136/README.md):
   close the public FENCE barrier typing, validate the load/store clock and
   next-PC layer, and isolate the division direct-equation stack overflow.
2. Land FV-1/FV-2 with exact 46/46 receipts and a neutral opcode-family proof
   surface. Metadata names and locally checked prefixes do not count.
3. Finish the FV-3 conversion inventory and enforce it mechanically. Retain
   the concrete M31 alias witnesses as mutation-pinned regressions.
4. Prove FV-4 from local accepted rows to arbitrary complete frontend traces,
   including all cross-row register, memory, clock, and control-flow
   invariants.
5. Run FV-5 clean-room reproduction and independent review, then promote the
   receipt only if every blocking gate is present.
6. Track proof-system soundness separately; do not fold it into a frontend
   refinement claim.

## Claim language

Until the promotion rule passes, accurate language is:

> The repository has production-bound, kernel-checked local refinement
> evidence and an exact generated-Sail full-step erasure theorem. Aggregate
> 46-opcode publication and whole-frontend trace soundness are not yet
> formally verified.

The phrases “the RISC-V frontend is formally verified”, “sound for all
executions”, or equivalent unqualified claims are not permitted while
`whole_frontend_verified` is false.
