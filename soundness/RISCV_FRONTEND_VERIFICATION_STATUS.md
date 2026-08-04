# RISC-V frontend verification status and roadmap

**Status date:** 2026-08-04

**Claim owner:** the repository-wide RISC-V refinement gate

**Normative detailed contract:**
[`UNIVERSAL_AIR_SAIL_REFINEMENT.md`](UNIVERSAL_AIR_SAIL_REFINEMENT.md)

This file is the short claim ledger for the RISC-V frontend. It separates
what the checked artifacts establish from what remains an engineering plan.
If an issue, pull request, or older document makes a stronger claim, this
ledger takes precedence. A machine-readable receipt is authoritative only for
the source revision and artifact identities it actually binds. The regenerated
generated-Sail bridge receipt binds the row-local FV-1/FV-2 source and makes no
FV-3/FV-4/FV-5 claim; the clean-tree top-level release receipt remains a TODO.

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

The current checked Lean source closure contains the full row-local FV-1/FV-2
surface: 46 generated-Sail retirement normalizers, 46
accepted-production-AIR publication implications, one generated full-step
framing theorem, and one typed universal publication contract. The bridge's
exact public inventory is therefore 94 theorems, and its policy records
`constructive_row_local_execution = true`. Load/store, division, decode, and
the remaining opcode families are part of that checked source surface rather
than non-gating checkpoint prefixes.

The generated-Sail bridge receipt was regenerated from the live pinned Sail
toolchain for this 46/46 source. It binds the exact 47-source closure,
94-theorem inventory, source digests, axiom inventory, and
`constructive_row_local_execution = true` policy. Future identity drift must
fail closed and requires fresh regeneration. Minting/replaying the top-level
clean-tree release receipt is deliberately left as a publication TODO.

No current artifact proves that every accepted STARK proof represents a valid
RISC-V execution. In particular, local opcode refinement is not a substitute
for the remaining word/field invariant, cross-row trace composition, or the
soundness of the PCS/FRI proof system.

## Verification ladder

| Gate | Checked statement | Status | What remains |
| --- | --- | --- | --- |
| Source binding | The formal evaluator consumes the exact generated constraint programs for all 46 admitted RV32IM opcodes, with pinned selector, event order, fixed-table schemas, and source digests. | Landed | Keep regeneration and source-drift checks fail-closed. |
| FV-1 — generated Sail | Each admitted opcode has a generated-Sail retirement normalizer, and the retained full-step trace erases to the exact pinned generated `try_step` semantics. | **46/46 receipt-bound**; full-step framing present | Independently reproduce the exact source/digest and 94-theorem inventories; keep regeneration fail-closed. |
| FV-2 — local AIR refinement | Acceptance of each exact production AIR program implies the matching generated-Sail opcode retirement under explicit row, state, profile, and admission bindings. | **46/46 receipt-bound row-local publication implications**; `constructive_row_local_execution = true` | Maintain the exact axiom/source audit. Do not widen this local statement into an arbitrary-trace claim. |
| FV-3 — `Word32` / M31 boundary | Every conversion between a 32-bit architectural value and one M31 element is injective or carries a proved bound; machine arithmetic never silently becomes field arithmetic. | Open; blocking; partial mitigations only | Complete issue [#157](https://github.com/teddyjfpender/stwo-zig/issues/157), including the mechanical conversion gate and per-site negative controls. |
| FV-4 — trace composition | Local opcode theorems compose across arbitrary admitted traces, including fetch/decode, register and memory buses, clocks, traps, interrupts, and cross-row state. | Open; blocking | Prove a named length-parametric trace-refinement theorem and connect local admission to global frontend invariants. |
| FV-5 — reproduction and review | Independent reviewers reproduce the exact artifacts and approve the claim/axiom/trusted-base boundary. | Open; blocking | Clean-room reproduction, independent sign-offs, and final claim promotion. |

`whole_frontend_verified` may become `true` only after FV-1 through FV-5 all
have named, kernel-checked, reproduced evidence. `proof_system_soundness` is a
separate project and remains false even then unless the proof-system theorem is
also delivered.

## What FV-1 and FV-2 buy us

The current FV-1/FV-2 theorem source and regenerated receipts provide a strong,
portable, machine-readable local semantic guarantee:

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

1. Mint and replay the top-level clean-tree release receipt, then independently
   reproduce the exact 46 normalizers, 46 row-local publication
   implications, full-step/universal theorems, and source/axiom inventories.
2. Finish the FV-3 conversion inventory and enforce it mechanically. Retain
   the concrete M31 alias witnesses as mutation-pinned regressions.
3. Prove FV-4 from local accepted rows to arbitrary complete frontend traces,
   including all cross-row register, memory, clock, and control-flow
   invariants.
4. Run FV-5 clean-room reproduction and independent review, then promote the
   receipt only if every blocking gate is present.
5. Track proof-system soundness separately; do not fold it into a frontend
   refinement claim.

Local source validation and live publication use:

```sh
python3 scripts/riscv_formal_tools.py prepare \
  --workspace /tmp/stwo-riscv-formal
python3 scripts/riscv_refinement.py prepare-sail \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
python3 -m unittest scripts.tests.test_riscv_refinement_sail_policy -v
python3 -m unittest scripts.tests.test_riscv_refinement_publication -v
(cd formal/riscv-refinement && lake build)
python3 scripts/riscv_refinement.py generate \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
# Commit the regenerated inputs before minting the clean-tree receipt.
python3 scripts/riscv_refinement.py receipt \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
python3 scripts/riscv_refinement.py verify-receipt \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
```

## Claim language

Until FV-3/FV-4/FV-5 completion, accurate language is:

> The current Lean source has 46/46 production-bound, kernel-checked row-local
> AIR-to-generated-Sail publication implications, 46/46 retirement
> normalizers, and an exact generated full-step framing theorem. The
> generated-Sail bridge receipt binds that row-local result; top-level release
> receipt replay remains a TODO. Whole-trace frontend refinement and
> proof-system soundness are not established.

The phrases “the RISC-V frontend is formally verified”, “sound for all
executions”, or equivalent unqualified claims are not permitted while
`whole_frontend_verified` is false.
