# Upstream Pin Ledger

This file is the single source-pin ledger for the repository's independent correctness
authorities. A revision applies only to the compatibility lane that names it. Native Stwo
acceptance does not establish Cairo acceptance, and neither establishes RISC-V ISA conformance.
`python3 scripts/check_upstream_pins.py` rejects drift in manifests, lockfiles, source constants,
formal-profile metadata, generated registries, persistent sessions, prover boundaries, and hosted
CI checkout metadata.

## Native Stwo Lane

This lane governs the backend-neutral Native Stwo API, protocol, proof, and verifier surface.
The field names below are retained for compatibility with the Native parity and upstream-surface
checkers.

- Upstream repository: `https://github.com/starkware-libs/stwo`
- Pinned commit: `a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`
- Pin date: `2026-02-07`

## RISC-V Formal ISA Lane

This lane governs RV32IM decode and architectural retirement semantics. Sail is the normative
executable ISA model, Spike is the independent implementation cross-check, and riscv-arch-test is
the architectural corpus. The exact Sail compiler is part of the pin because generated simulator
behavior is not attributed to an unversioned toolchain.

- Sail RISC-V repository: `https://github.com/riscv/sail-riscv`
- Pinned Sail RISC-V commit: `8c7f2da58de0ba5e4457e4de07e0046f0439f35f`
- Pinned Sail compiler version: `0.20.2`
- Sail RISC-V pin date: `2026-07-26`
- Spike repository: `https://github.com/riscv-software-src/riscv-isa-sim`
- Pinned Spike commit: `520a5f185083ac3c97b751501dfac02a6c1f5970`
- RISC-V Architectural Tests repository: `https://github.com/riscv-non-isa/riscv-arch-test`
- Pinned RISC-V Architectural Tests commit: `426e1598ebc3688eaf9aba7b4a1b8a81dae9807f`

The normative environment and refinement boundary are
`conformance/2026-07-26-riscv-sail-contract.md` and
`conformance/riscv/rv32im-sail-profile.json`. A semantic disagreement is resolved in favor of the
pinned Sail model under those exact configuration overrides.

## RISC-V Legacy Protocol Layout Lane

Stark-V is retained only as the source of legacy opcode IDs, witness column ordering, relation
ordering, and proof-transcript compatibility. It is not an ISA semantic oracle and cannot override
Sail decode or retirement behavior.

- Legacy Stark-V repository: `https://github.com/ClementWalter/stark-v`
- Pinned legacy Stark-V commit: `d478f783055aa0d73a93768a433a3c6c31c91d1c`
- Legacy Stark-V pin date: `2026-06-12`

## Cairo Lane

This lane governs Cairo AIR, witness generation, statement, proof, and canonical `verify_cairo`
acceptance. Stwo-Cairo commit `dcd58345` has two deliberately distinct Stwo authorities: the
verifier-compatible revision declared by the source tree, and the clean companion revision needed
to compile its complete prover and witness surface. Evidence must name the applicable sub-lane;
the revisions are not interchangeable.

- Stwo-Cairo repository: `https://github.com/teddyjfpender/stwo-cairo`
- Pinned Stwo-Cairo commit: `dcd5834565b7a26a27a614e353c9c60109ebc1d9`
- Stwo repository: `https://github.com/teddyjfpender/stwo`
- Pinned Cairo verifier Stwo commit: `9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2`
- Pinned Cairo prover Stwo commit: `3fe684648ff31e55b71525ad689fab7dfbd88880`

The Cairo lane is accepted only by the canonical Rust `verify_cairo` implementation built from
the Stwo-Cairo and verifier-Stwo pair. Zig scalar, SIMD, Metal, trace-oracle, or Zig-verifier
agreement cannot override its rejection. Base-trace and witness receipts are authoritative only
when generated from the Stwo-Cairo and prover-Stwo pair, without path dependencies or dirty source.

The pinned Stwo-Cairo manifest itself contains a `LOCAL-ONLY` absolute-path patch and does not
compile its full prover against its declared verifier Stwo revision. Repository-owned Rust prover
tools must therefore isolate the crate in their own workspace and replace every affected Stwo
package with the exact prover revision above. The pin checker validates that complete replacement
graph and its lockfile; inheriting the upstream absolute path is forbidden.

## Native Stwo Parity Slice

The current Native Stwo increment targets:

- `core/fields/*`
- `core/fri`
- `core/pcs/quotients`
- `core/pcs/verifier`
- `core/pcs/utils`
- `core/proof`
- `core/verifier`
- `core/vcs/verifier`
- `core/test_utils`
- `core/vcs/hash`
- `core/vcs/merkle_hasher`
- `core/vcs/utils`
- `core/vcs/test_utils`
- `core/vcs_lifted/merkle_hasher`
- `core/vcs_lifted/verifier`
- `core/vcs_lifted/test_utils`
- `prover/vcs/prover`
- `prover/vcs/ops`
- `prover/vcs_lifted/prover`
- `prover/vcs_lifted/ops`
- `prover/line`
- `prover/air` (accumulation + component-prover slices)
- `prover/prove` (prepared-samples + sampled-points + component-driven prove_ex slices)
- `prover/fri` (full fri prover commit/decommit flow + layer decommit slices)
- `prover/pcs` (quotient-ops + commitment tree/decommit + prove-values + prove-values-from-samples slices)
- `prover/channel` (logging channel slice)
- `prover/lookups` (utils + mle + sumcheck + gkr verifier + gkr prover prove-batch slice)
- `prover/poly` (module + twiddles + circle evaluation/poly/secure_poly/ops slices)
- `prover/secure_column`
- `tracing/mod`

## Upgrade Policy

1. Name the compatibility lane being upgraded; never reuse evidence from another lane.
2. Bump every exact revision that composes that lane's Rust oracle in this ledger. For Cairo,
   state whether the verifier sub-lane, prover sub-lane, or both change.
3. Update manifests, lockfiles, constants, proof envelopes, receipts, and generated artifacts that
   carry those revisions.
4. Re-run vector generation for all committed fixtures in the affected lane.
5. For RISC-V ISA changes, validate the exact Sail configuration, run retirement-level Sail and
   Spike differentials, and run every applicable architectural test through execute → prove →
   independent verify.
6. Require the affected Zig parity, bidirectional interoperability, and exact external-authority
   tests to pass before merging.
7. Document any intentional divergence in `conformance/divergence-log.md`.
