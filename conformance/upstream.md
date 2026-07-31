# Upstream Pin Ledger

This file is the single source-pin ledger for the repository's independent correctness
authorities. A revision applies only to the compatibility lane that names it. Native Stwo
acceptance does not establish Cairo acceptance, and neither establishes RISC-V ISA conformance.
No one of those lanes establishes SM83 ISA conformance.
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
pinned Sail model under those exact configuration overrides. Sail is the only RV32IM semantic
authority in this repository; the legacy lane below cannot override it, and neither lane arbitrates
AIR soundness, which is proved by the constraint- and lookup-level tests in the frontend.

## RISC-V Legacy Protocol Layout Lane

Stark-V is retained as a non-normative historical layout and performance reference. Its pin makes
old receipts and benchmark results reproducible; it has no current release-admission, semantic,
AIR-soundness, transcript, relation, or proof-acceptance authority. Source-level legacy opcode IDs
and column ordering may still be documented or compared for migration archaeology, but current
Zig protocol specifications and tests own those invariants.

The pinned revision admits the under-constraints enumerated in the
`Opcode AIR constraint and lookup layout` row of `conformance/divergence-log.md`, which is the
authoritative disclosure: a source register access may emit a value it did not consume (which also
leaves any witness derived from that value, including the `LB`/`LH` and `SRL`/`SRA` sign witnesses,
a free prover choice); `SB`/`SH` leave every unmarked destination byte free; the `AUIPC` immediate
admits a second byte decomposition offset by `p + 2`; and `composeU32(rs1.next)` is unbounded in
`JALR`; DIV permits non-byte divisors and an ambiguous quotient sign; the shift carry lookup admits
negative carries; and every operand access in one instruction reuses the same clock while a zero
clock gap is admissible. That last pair permits an aliased read to hide an arbitrary value in a
same-tuple/same-clock memory-relation self-loop. Zig therefore derives three ordered access
subclocks inside a four-wide instruction bucket and range-checks `current - previous - 1`.
It also rejects statement geometries whose combined memory or Merkle relation-source
coefficients could reach the M31 modulus, including malicious cross-source tuple collisions.
An oracle that accepts an unsound AIR cannot arbitrate AIR soundness, so agreement with it is no
longer evidence of correctness on those surfaces and disagreement with it is no longer evidence
of a defect.

The pre-Sail CP-11 producer, bundle, challenge, owner-dispatch inputs, and fast
producer-linked smoke profile are retired. Their top-level CLIs fail closed,
and `contract.receipt_errors` rejects even a structurally valid archived
receipt as current evidence. The old parser and divergence-shape code remain
read-only so historical bundles can be inspected; no shape can be added to
authorize release. `scripts/riscv_stark_v_benchmark.py` and the Stark-V side of
the autoresearch performance lane remain optional performance comparisons
only. Pinned Sail/Spike evidence and the current Zig constraint/proof suites
own correctness admission.

Pins:

- Legacy Stark-V repository: `https://github.com/ClementWalter/stark-v`
- Pinned legacy Stark-V commit: `d478f783055aa0d73a93768a433a3c6c31c91d1c`
- Legacy Stark-V pin date: `2026-06-12`
- Legacy Stark-V AIR-oracle demotion date: `2026-07-26`

## SM83 ISA Lane

This development lane governs SM83 opcode metadata and instruction-level
retirement semantics. gb-opcodes and Pan Docs define instruction metadata,
SingleStepTests supplies the admitted per-opcode transition corpus, and
SameBoy is the independent reference emulator. Blargg and Mooneye are pinned
now but remain whole-machine integration gates; they do not validate an
individual family before the complete machine model exists.

- SM83 opcode repository: `https://github.com/gbdev/gb-opcodes`
- Pinned SM83 opcode commit: `376f61c86fdac2048f7ce5fe838ae756b306017e`
- Pinned SM83 opcode JSON SHA-256: `e7e3cd657d8e87b44570474eb3a6ed735501c9a00520f3d6937881203c823bc5`
- Pan Docs repository: `https://github.com/gbdev/pandocs`
- Pinned Pan Docs commit: `fe246067b695b5404a4a6a47efb4fd6d921ececb`
- SM83 SingleStepTests repository: `https://github.com/SingleStepTests/sm83`
- Pinned SM83 SingleStepTests commit: `f9c30210245dd691661db39f5ace022c465ecc2f`
- Pinned SM83 SingleStepTests v1 SHA-256: `f4116a3776c2c5e25bfffa75d41b0b4af78fb75b4e8cfd9785efd76a9abeca0a`
- SameBoy repository: `https://github.com/LIJI32/SameBoy`
- Pinned SameBoy commit: `213a12ce93d66b105a113debd9396306066a7cfc`
- Blargg test ROM repository: `https://github.com/retrio/gb-test-roms`
- Pinned Blargg test ROM commit: `c240dd7d700e5c0b00a7bbba52b53e4ee67b5f15`
- Mooneye test suite repository: `https://github.com/Gekkio/mooneye-test-suite`
- Pinned Mooneye test suite commit: `31510e12eea6286d36eea060a6adde755e1067aa`
- Pinned Mooneye WLA-DX commit: `89a90a56be5c2b8cf19a9afa3e1b32384ddb1a97`
- Pinned Mooneye release: `mts-20260714-0944-31510e1`
- Pinned Mooneye release SHA-256: `6d4fdda2f1d8d2f5f51b0ff3f6f3cc2fbae047aa395a39c82bda3a0e7cbd2641`
- SM83 pin date: `2026-07-30`

The official Mooneye release ROMs are the byte authority: 112 of 115 ROMs
assembled on macOS differed from the Linux release even with both source and
WLA-DX revisions pinned.

The first application reproducibility check used pret/pokered commit
`405b6246372d7e5a2cb029cbb65219b13286b8c9`. Its byte-identical outputs matched
the known Pokémon Red SHA-1 `ea9bcae617fdf159b045185467ae58b2e4a48b9a`
and Pokémon Blue SHA-1 `d7037c83e1ae5b39bde3c30787637ba1d4c48ce2`.
Those ROMs are fixtures and future public inputs, not semantic authorities.

## Cairo Lane

This lane governs Cairo AIR, witness generation, statement, proof, and canonical `verify_cairo`
acceptance. The production port targets the current official StarkWare source pair:

- Official Stwo-Cairo repository: `https://github.com/starkware-libs/stwo-cairo`
- Pinned official Stwo-Cairo commit: `82f21252a68ec006d73e299f5bf1ce6d4db0ee78`
- Official Cairo Stwo repository: `https://github.com/starkware-libs/stwo`
- Pinned official Cairo Stwo commit: `7b211edde786775016ef3eecb837a6240d8fe792`
- Cairo language repository: `https://github.com/starkware-libs/cairo`
- Pinned Cairo language commit: `eea264fa54fac04a1a5745ad533a0c0ab3106ab3`
- Cairo language version: `2.20.0`
- Cairo VM version: `3.2.0`

These revisions govern the production AIR registry, isolated base/interaction
trace oracle, and final Rust `verify_cairo` adapter. The completion
requirements are recorded in
`conformance/2026-07-26-stwo-cairo-production-port-goal.md`.

The official-source witness checkpoint is
`vectors/cairo/official/witness_programs_v1.bin`, authenticated by its adjacent
provenance and compiler-receipt records. Its 27 programs are deterministically
compiled from the official source pair above by
`tools/cairo-witness-compiler` and contain no proof-selected semantics. The
repository-owned compiler authenticates and isolates the upstream checkout,
fails closed on unsupported writers, and reproduces the historical migration
artifact byte-for-byte. The artifact remains `release_eligible: false` until
the complete official writer and input-edge surfaces are covered and complete
SIMD and Metal proofs pass the official verifier. The pin gate validates its
compiler identities, binary grammar, semantic hashes, component order, and
exact column-parity evidence; it cannot promote the artifact.

### Legacy SN2 evidence

Historical SN2 tooling was built from Stwo-Cairo commit `dcd58345`, which has
two deliberately distinct Stwo authorities: the verifier-compatible revision
declared by the source tree, and the clean companion revision needed to compile
its complete prover and witness surface. This evidence remains bound to the
following fork revisions and is not eligible to release the official Cairo
products:

- Stwo-Cairo repository: `https://github.com/teddyjfpender/stwo-cairo`
- Pinned Stwo-Cairo commit: `dcd5834565b7a26a27a614e353c9c60109ebc1d9`
- Stwo repository: `https://github.com/teddyjfpender/stwo`
- Pinned Cairo verifier Stwo commit: `9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2`
- Pinned Cairo prover Stwo commit: `3fe684648ff31e55b71525ad689fab7dfbd88880`

The official Cairo lane is accepted only by the canonical Rust `verify_cairo`
implementation built from the official Stwo-Cairo and Stwo pair. Zig scalar,
SIMD, Metal, trace-oracle, legacy-fork, or Zig-verifier agreement cannot
override its rejection. The official trace oracle supplies component
checkpoints, not proof acceptance. Legacy base-trace and witness receipts are
authoritative only for their explicitly labelled legacy comparison and only
when generated from the fork Stwo-Cairo and prover-Stwo pair, without path
dependencies or dirty source.

The corresponding historical generated claim registry is retained at
`archive/cairo/legacy_claim_registry.zig`. Production code must not import it;
the active registry is the official generated registry under
`src/frontends/cairo/air/`.

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
   state whether the official production pair, a legacy SN2 evidence pair, or both change.
3. Update manifests, lockfiles, constants, proof envelopes, receipts, and generated artifacts that
   carry those revisions.
4. Re-run vector generation for all committed fixtures in the affected lane.
5. For RISC-V ISA changes, validate the exact Sail configuration, run retirement-level Sail and
   Spike differentials, and run every applicable architectural test through execute → prove →
   independent verify.
6. For SM83 ISA changes, run the pinned per-opcode corpus and retain Blargg/Mooneye as
   whole-machine gates once their required machine layers exist.
7. Require the affected Zig parity, bidirectional interoperability, and exact external-authority
   tests to pass before merging.
8. Document any intentional divergence in `conformance/divergence-log.md`.
