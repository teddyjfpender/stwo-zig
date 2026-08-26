# 2026-08-12 — Zisk comparison and borrowing plan for recursion, continuations, and precompiles

## Question

What does Polygon Hermez's Zisk zkVM ([github.com/0xPolygonHermez/zisk](https://github.com/0xPolygonHermez/zisk),
[docs](https://0xpolygonhermez.github.io/zisk-docs/intro/introduction/background)) do that this
frontend should borrow or validate against — specifically for the recursion work in flight
(R-012/M9), the eventual continuation design, and the precompile roadmap — and what is the
typed-AIR delivery missing that the comparison surfaces?

## Context and exact sources

Produced by AI-assisted analysis (Claude, 15 research agents over two passes) on 2026-08-12,
against this repo's working tree on `feat/typed-air-precompiles` (uncommitted typed-AIR work
included; local citations reflect the working tree, not HEAD) and Zisk's public `main` branch.
All local analysis was read-only. A human familiar with both systems should review before
anything here is treated as decision-grade; security-parameter and performance claims about
Zisk in particular need first-party verification. Unconfirmed items are marked inline.

### Working-tree reconciliation

The local completion counts below are a research-snapshot observation, not a live status
authority. Later on 2026-08-12 the branch reached all 34 logical rows through authenticated
typed AIR and the generic adapter plus two authenticated shared providers: exact 36/36 AIR
closure, with 3/36 real proof-byte gates. The normative live counts remain in
[`../PROGRESS.md`](../PROGRESS.md) and the exact roster in
[`2026-08-12-r012-universal-recursion-component-map.md`](2026-08-12-r012-universal-recursion-component-map.md).
The A2/A3 shape has since entered implementation as an allocation-free native pair-node
shadow: fixed ordered children, session/challenge/full-authority rederivation, VK injection
and root pinning, exact expected-child comparison, relation closure, and a power-of-two
session count bounded at 1,024 leaves. Protocol audit and expanded all-mode tests are green.
The shadow still cannot establish the provenance of caller-supplied verifier outputs and
neither verifies nor produces a recursive proof, so R-009 remains open. This update does not
accept A1--A5, B1--B4, or C1--C5 as protocol decisions; it records implementation substrate
and preserves the note's first-party verification requirements.

Zisk sources are cited inline and collected in the References section. The decisive external
sources are Zisk's in-repo whitepaper (`documents/papers/whitepaper.pdf`, 41 pp. — §5.2–5.3
trace splitting and continuations, §6.2 LtHash, §6.4 recursion relations), `pil/zisk.pil` and
`state-machines/main/pil/main.pil`, pil2-proofman's challenge accumulation and recursion
drivers, and the ziskos syscall/fcall sources.

## Observations — how the two systems actually compare

Both systems decompose execution into per-instruction-family AIRs (Zisk: "chips"/state
machines in [`state-machines/`](https://github.com/0xPolygonHermez/zisk/tree/main/state-machines);
here: witness families/components) joined by LogUp buses with a global sum-to-zero closure.
Most vocabulary differences at that layer are naming ("bus" ≈ relation domain; Zisk's
fixed/cached/witness column tiers ≈ preprocessed/main trees). The genuine forks:

1. **Field/ISA pairing.** Circle STARK over M31 with RV32IM here, versus classical FRI STARKs
   over Goldilocks (cubic extension) with RV64IMA there
   ([background](https://0xpolygonhermez.github.io/zisk-docs/intro/introduction/background)).
   Each is internally coherent; neither side can trivially adopt the other's width.
2. **Proof topology.** One STARK with shared transcript and a single closure check here;
   ~30 independently sized AIR instances (`Main(N: 2**21)`, `Keccakf(N: 2**17)`, …, per
   [`pil/zisk.pil`](https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/pil/zisk.pil))
   glued by recursive aggregation there, with the bus sum closed at the aggregation root.
3. **Shipped scale-out.** Zisk has per-chip continuations, a complete recursion ladder ending
   in an optional PLONK/fflonk wrap, MPI + coordinator/worker cluster proving, and CUDA — all
   shipping. Here: no continuation (deliberately out of protocol per
   `src/frontends/riscv/recursion/protocol.zig`), recursion then at 23–24/36 typed-logical
   rows with ~0/36 concrete adapters (subsequently 36/36 AIR closure) and no 2→1 proof,
   aggregation a native non-recursive
   reference (`src/frontends/riscv/aggregation/`, `NATIVE_REFERENCE_ONLY = true`), no RISC-V
   CUDA lane.
4. **Where this repo is ahead.** Semantic assurance (pinned Sail oracle replayed per-retirement
   over RVFI-DII, Spike + riscv-arch-test cross-checks; Zisk documents only RISCOF), the
   typed-IR soundness story (types-as-invariants, hint-bound division, digest-pinned
   `.stwairc` artifacts, one `Builder(S)` for production QM31 and formal extraction — S-01),
   fail-closed ELF-note admission profiles (no Zisk analog found), and evidentiary discipline
   (script-enforced single security profile; machine-readable M5–M9 promotion gates).

Reference points worth keeping (each verified against the cited source):

- **Acceleration accounting.** Zisk's headline sha2 example (1,000-leaf Merkle tree,
  [optimizing-your-program](https://0xpolygonhermez.github.io/zisk-docs/developer/writing-programs/optimizing-your-program)):
  steps 13,284,475 → 610,031 (~95% fewer) with the patched `sha2` crate; *cost* (proof-area
  units, not time) 1.76B → 389M (~78%). Per-op cost constants live in
  `core/src/zisk_ops_costs.rs` (binary op 60, Poseidon2 1,050, SHA-256f 8,712,
  Keccak-f 75,550, ArithEq 1,424 = 89×16, DMA memcpy 46).
- **Minimal trace.** `common/src/emu_minimal_trace.rs`: checkpoint = `EmuTraceStart`
  (registers, pc, sp, step) plus only the *values of memory reads* per chunk;
  `CHUNK_SIZE = 1 << 18` (`emulator-asm/src/constants.hpp`). Replay expands full witnesses in
  parallel (`executor/src/execution/asm/mt_chunk.rs`).
- **Instance planning.** `executor/src/plan.rs` + `common/src/planner_helpers.rs`: per-chunk
  operation counters greedily packed into fixed-size instances with skip-offsets
  (`CollectSkipper`); padding confined to at most one partial instance per chip
  (whitepaper §5.2).
- **Continuation bus.** `state-machines/main/pil/main.pil`: payload is only
  `(segment_id, is_last, pc, last_c)` via paired `direct_update_assumes/proves`; registers
  cross segments through the memory argument (register file mapped into the address space,
  per-segment final reload); genesis/terminus anchored by one-shot
  `direct_global_update_proves/assumes` messages at `BOOT_ADDR`/`END_PC`, with `is_last`
  hardwired 0 on the assumed tuple so a final segment cannot seed a new chain.
- **LtHash / global challenge.** Whitepaper §6.2 +
  `pil2-proofman/proofman/src/challenge_accumulation.rs`: each instance's stage-1 commitment
  root is hashed (Poseidon2) and expanded to an n = 372 Goldilocks vector; vectors are
  *summed* (homomorphic multiset hash; collision resistance from SIS; cardinality bound
  B = 2^20); α = DeriveAlpha(accumulator). Aggregation nodes sum children's contributions c
  and leaf counts κ; the final verifier checks α = DeriveAlpha(c), global bus sum s = 0, and
  κ < 2B (§6.4.4). This is what avoids serializing Fiat–Shamir across segment provers.
- **Recursion ladder.** `pil2-proofman/proofman/src/recursion.rs` + circom templates in
  `setup/stark-recurser/stark2circom/`: leaf STARK → optional compressor (per-AIR
  `hasCompressor` in
  [`state-machines/starkstructs.json`](https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/state-machines/starkstructs.json))
  → `recursive1` (per-AIR leaf verifier, with the `recursive2` verification key *injected as
  a public input* — the self-reference resolution, whitepaper §6.4) → `recursive2`
  (aggregation; code arity is **3**, though the docs describe a binary tree) → `vadcop_final`
  → `recursivef` (GL→BN128 bridge) → Plonk/fflonk SNARK wrap. No Groth16; no trusted setup.
- **FRI parameters are computed, not pinned.** `pil2-proofman/setup/pil2-stark/src/types/security.rs`
  targets 128 bits over Goldilocks³: `n_queries = ceil((128 − grindingBits)/bitsPerQuery)`.
  Concrete points: rate 1/2 → 219 queries @ 22 grinding bits; compressor (rate 1/4) →
  110 @ 20; `recursivef` (rate 2⁻⁶) → **37 queries** @ 19. Compare this repo's frozen
  recursion V1 (`recursion/protocol.zig`): blowup 2¹, 193 queries, fold 4, PoW 16,
  target 120 bits.
- **fcall (unconstrained hints).** `ziskos/entrypoint/src/fcall.rs` +
  `zisklib/fcalls/mod.rs`: CSR-based hint channel (IDs 1–23: field inverses/sqrts, bigint
  division, MSB positions, GLV decomposition). Hints are verified by constrained code —
  bigint division re-checked with a constrained multiply-and-compare
  (`zisklib/lib/bigint/div_long.rs`); secp256k1 field inverse verified with **one**
  `arith256_mod` precompile call (`zisklib/lib/secp256k1/field.rs`).
- **arith_eq equation machine.** `precompiles/arith_eq/` README + `arith_eq_generator.rs`:
  each op is ≤3 degree-2 equations as flat sum-of-product strings (secp256k1 add slope:
  `s*x2-s*x1-y2+y1-p*q0+p*offset`; witness quotients q_i prove the identity mod p; offset
  keeps terms positive); operands in 16-bit chunks (22-bit top quotient chunk); carries
  range-checked in ±2^22; selector columns multiplex all ops through one AIR at 16 rows/op;
  the generator emits the Rust executor and the PIL from the same definition.

Local seams this maps onto (working-tree reads):

- `src/frontends/riscv/air/public_data.zig` — `PublicData` already carries an entry/exit
  machine state (initial/final regs, pc, clock, `initial_rw_root`/`final_rw_root`), but
  `validate()` hard-codes an unsegmented run (mandatory `completion`) and there is **no
  statement version tag** on `RiscVStatement`/`PublicData`.
- `src/frontends/riscv/runner/state_chain.zig` — `MAX_CLOCK_DIFF = 2^20 − 1`,
  `CLOCK_PREV_BOUND = 2^26`, a *per-proof* decomposition argument riding on the 2^24-row
  geometry cap; `src/frontends/riscv/access_clock.zig` fixes the 4-wide access-clock stride.
- `src/frontends/riscv/air/public_logup.zig` — `registersStateSum` emits public boundary
  terms (initial `(pc, 1)`, final `(pc, clock+1)`); four independently-cancelling LogUp
  domains.
- `src/frontends/riscv/recursion/air/proof_kind.zig` — already enumerates
  `segment_leaf`/`binary_node`/`empty_leaf`; `statement_input.zig` carries
  SEGMENT/LEFT/RIGHT/PARENT scopes; `fixed_wire.zig` adapts dynamic proofs into a fixed
  verifier wire (structurally the compressor's role).
- `src/frontends/riscv/runner/trace.zig` — witness generation is already structurally
  two-pass (`columnsForFamily` is a separate pass over `TraceRow`s); `TraceRow` carries
  recomputable fields; the sequential core is `state_chain.StateChainTracker`.
- `src/frontends/riscv/host/` — ECALL is `UnsupportedForProof`
  (`host/prove_block.zig`), so HINT_LEN/HINT_READ and the KECCAK256/ECRECOVER/SHA256
  oracles are host-mode only; typed hint recipes (ADR-0006, ADR-0033) feed prover-side
  witness generation, not the guest.

## Interpretation — the borrowing plan

### A. Recursion and aggregation (act while the protocol is still soft)

- **A1. Revisit the recursion FRI profile: trade blowup for queries.** In-circuit
  verification cost scales with query count (each query is a Merkle-path check the next
  layer must verify), and recursion traces are small enough that blowup is cheap — Zisk's
  recursion layers run 37–110 queries at rates 2⁻⁶–1/4 versus V1's 193 at rate 1/2. With
  concrete adapters at ~0/36, evaluating a higher-blowup V1.1 profile now is likely the
  single largest lever on R-012 circuit size; digest pinning makes this a deliberate
  profile-version decision. The adapters have since reached 36/36 closure, so this is now a
  measured V1.1 comparison before the complete outer proof—not a reason to rewrite the AIR.
- **A2. Adopt the verification-key self-reference trick for the 2→1 node (R-009).** Inject
  the aggregator's vk into leaf-verifier publics and pin it at the root against a constant,
  resolving the aggregator-verifies-itself circularity without circular setup. The native
  shadow now carries and rebinds that injected VK, exposes the explicit root-pin seam, and
  returns a distinct root-authorized result type. The production child-verifier seam,
  reviewed in-circuit constant, and recursive proof are still open.
- **A3. Keep ADR-0030's session binding; import Zisk's in-circuit derivation checks.**
  Session binding is the right V1 call (no new cryptographic assumption — an M31 LtHash
  would need fresh SIS parameterization and review). Import two obligations: verify
  challenge-context folding at every tree level (node checks children's contexts match and
  folds; root re-derives the challenge from accumulated commitment material rather than
  trusting an equality claim), and add a κ-style leaf-count guard against multiset padding
  (`recursion/protocol.zig` `validateAndFoldPair` is the seam). File the order-free
  accumulator as a research ticket — it is what would free distributed leaf proving from
  ADR-0030's eight-barrier session ordering. The native shadow now re-derives its session
  challenge and complete authority context, checks signed-relation closure, and applies a
  checked `kappa <= 1024` first-layer guard with exact power-of-two session cardinality. It
  compares every encoded child field against separately supplied expected verifier output,
  and its event bound matches the native protocol. Those expected outputs must still be
  sourced from the real child verifier, and all obligations still need to be constrained and
  proved by the outer verifier.
- **A4. Per-leaf proof parameters.** `fixed_wire` already plays the compressor's structural
  role; keep a per-leaf-profile slot in the aggregation manifest so heterogeneous leaves can
  carry tuned parameters instead of one uniform profile (Zisk tunes blowup/PoW per AIR in
  `starkstructs.json`).
- **A5. Benchmark aggregation arity 2 vs 3** once any 2→1 proof exists; Zisk deployed 3.
  The M9 gates (eight-leaf speed lower-CI ≥ 1.25; 32/2 root proof-size ratio ≤ 1.05) are
  the instrument.

### B. Continuation architecture (decisions to lock before the statement wire freezes)

- **B1. Add a statement version discriminator now.** One version word mixed into the
  transcript (v1 = unsegmented, `completion` mandatory) makes the continuation statement a
  compatible V2 instead of a transcript-breaking change. Cheapest, highest-option-value item
  in this note; should land while the recursion statement wire is still ~0/36 concrete.
- **B2. Copy the continuation-bus shape, not its content.** Keep explicit register carry
  (`PublicData` is already entry/exit-shaped); import the chain algebra: generalize the
  `registersStateSum` boundary terms into segment-boundary emit/consume tuples
  `(segment_id, pc, clk_base, …)` with one-shot genesis/terminus anchors and an `is_last`
  that cannot seed a new chain; make `completion` a property of the chain, not of every
  proof. ADR-0035's closed-grammar extension is the authoring template; ADR-0031's
  machine-derived-operation discipline keeps the boundary emit unforgeable.
- **B3. Design the clock rebase and the global execution ceiling together.** The
  `CLOCK_PREV_BOUND = 2^26` decomposition argument is per-proof and segment rebasing
  invalidates it. Carrying `clk_base` as a public and decomposing `(clk − clk_base)`
  per segment fixes it, but the global clock must still fit M31 — with the 4-wide
  access-clock stride that caps whole executions near 2^29 steps. Zisk documents its
  ceiling (2^36 steps, [limits](https://0xpolygonhermez.github.io/zisk-docs/intro/how-zisk-works/limits));
  ours belongs in the continuation ADR from day one.
- **B4. Build the minimal-trace layer now — one design, two payoffs.** Zisk's checkpoint
  (start registers + pc + step + memory-read values only) is provably sufficient for
  deterministic replay. Here, the hard part is splitting the sequential
  `StateChainTracker` via a per-segment carry — and that carry object is the same structure
  the continuation statement needs. Serves M7's parallel witness fill beyond the 32-worker
  pool immediately; defines segment-boundary semantics for M9 later. Acceptance test: at
  most one partial shard per family (Zisk's padding property).

### C. Acceleration and the precompile roadmap

- **C1. Two-metric cost accounting for C-013.** The stalled Poseidon2 crossover evidence
  (~604.9 ms precompile vs 480.0 ms software at 8 calls) is wall-clock only. A per-family
  proof-area cost table (rows × columns + interaction batches), analogous to
  `zisk_ops_costs.rs`, would show whether the deficit is the caller component's fixed
  overhead (417 constraints, 77 LogUp batches) failing to amortize at 8 calls, or intrinsic
  to the AIR shape. The same table later feeds counter-driven instance planning (B4).
- **C2. Open a guest-visible provable hint channel — currently absent, and the cheapest
  acceleration rung.** Proposal fitting the admission discipline: a versioned CUSTOM-0
  hint-read instruction under an execution profile — retirement fully constrained, the
  written value a deliberately unconstrained witness column, the guest verifying it in
  software (division by multiply-and-compare; inverse by one modular-mul once an arithmetic
  precompile exists). Accelerates *proved* workloads with zero new precompile AIRs and
  composes with every future precompile, exactly as Zisk's fcall tier composes with
  `arith256_mod`.
- **C3. Equation-machine precompile (the ECDSA path) — with an M31 caveat.** Typed-AIR's
  S-01 single-source property is a strictly stronger version of arith_eq's
  executor-and-AIR-from-one-definition guarantee, so a comptime equation-machine generator
  inherits digest pinning for free. The caveat: Zisk's 16-bit chunks with ±2^22 carries
  assume Goldilocks headroom and do not fit M31 — an M31 equation machine needs smaller
  chunks (8-bit products fit) or QM31 accumulation, and that chunking decision is the real
  design problem to solve first. The carry/range-table architecture transfers as-is.
- **C4. Consider a DMA/bulk-memory family as precompile #2, before curves.** memcpy-class
  precompiles need no new cryptography, exercise exactly ADR-0025's 17-term-per-row memory
  budget, and give the C-013 methodology a second data point where the win should be
  unambiguous (Zisk: memcpy cost 46 units vs per-word software retirements).
- **C5. Patched-crate DX layer later.** Plain `[patch.crates-io]` forks pinned per zkVM
  version, each swapping a hot inner function for a syscall; worth a line in
  PRECOMPILES.md as the eventual zero-source-change layer, not actionable until ≥2
  precompiles exist.

### Gaps the comparison surfaces in the typed-AIR delivery

No statement versioning (B1); no guest-visible hint tier (C2); no cached per-program
commitment tier (Zisk commits the transpiled ROM once per program and reuses it — guest
program commitments here are per-proof today, and the artifact/digest system is the natural
home for amortizing them); no per-family cost-model artifact (C1); single uniform proof
parameters where Zisk tunes per AIR and per recursion layer (A1, A4).

Equally: several gaps are smaller than they first appear. `PublicData` is already an
entry/exit pair, `segment_leaf` is already enumerated, witness generation is already
structurally two-pass, and `fixed_wire` already plays the compressor's role. The distance to
a Zisk-shaped continuation-plus-recursion architecture is mostly *protocol decisions*
(versioning, clock rebase, challenge-context verification), not missing machinery.

## What this does not establish

- No Zisk claim here has been verified beyond the cited public sources; the ~1.5 GHz AOT
  emulation figure and the EthProofs 24×RTX-5090 result are third-party, Zisk's audit status
  is unconfirmed, and the exact fcall striding and selector-column details marked
  UNCONFIRMED in the underlying research were not re-derived.
- The ~128-bit (Zisk, computed) vs ~96-bit (here, read from source) security comparison is
  not apples-to-apples until someone reproduces Zisk's `security.rs` computation against our
  profile assumptions.
- Nothing here is a decision. A1/B1–B3 touch protocol soundness and belong to whoever owns
  the recursion/continuation ADRs; C2/C3 need their own ADRs per PRECOMPILES.md's ladder.
- AI-generated analysis; a human familiar with both systems should review before circulating
  or acting on it.

## Decisions/tasks affected

- **R-012 / M9** (A1, A2, A4, A5) — FRI profile choice before the full outer proof; A2's
  VK-injection/root-pin native shadow and authority checks are green, while the production
  child-verifier seam, in-circuit constant, and proved 2→1 node remain open.
- **ADR-0030** (proposed) and **ADR-0036** (proposed) (A3) — the native pair shadow now
  represents challenge/full-authority derivation, exact expected-child comparison, and
  relation/session-count closure; provenance, in-circuit proof, and the order-free
  accumulator remain open.
- **Future continuation ADR** (B1–B4) — statement version word, boundary emit/consume
  grammar (template: ADR-0035; discipline: ADR-0031), clock rebase + global ceiling,
  minimal-trace/`StateChainTracker` split (also serves **M7**, R-002/R-003).
- **C-013** (C1) — add proof-area accounting alongside wall-clock.
- **PRECOMPILES.md ladder / future precompile ADRs** (C2–C5) — hint-read instruction,
  equation machine with M31 chunking study, DMA family, patched-crate note; budget checks
  against **ADR-0025**.

## References

Zisk repo (all `main` branch, `github.com/0xPolygonHermez`):

- Whitepaper: `zisk/documents/papers/whitepaper.pdf` (§3 bus/LogUp; §5.2–5.3 splitting +
  continuations; §6.2 LtHash; §6.4 recursion relations R_AIR/R_LEAF/R_AGG/R_FINAL)
- PIL: [`zisk/pil/zisk.pil`](https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/pil/zisk.pil),
  `zisk/state-machines/main/pil/main.pil` (continuation bus),
  [`zisk/state-machines/starkstructs.json`](https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/state-machines/starkstructs.json),
  `zisk/precompiles/keccakf/pil/keccakf.pil`
- Execution/planning: `zisk/common/src/emu_minimal_trace.rs`,
  `zisk/emulator-asm/src/constants.hpp`, `zisk/executor/src/plan.rs`,
  `zisk/common/src/planner_helpers.rs`, `zisk/executor/src/execution/asm/mt_chunk.rs`
- Guest ABI: `zisk/ziskos/entrypoint/src/syscalls/mod.rs` (CSR syscalls),
  `zisk/ziskos/entrypoint/src/fcall.rs` + `zisklib/fcalls/mod.rs` (hints),
  `zisk/ziskos/entrypoint/src/zisklib/lib/bigint/div_long.rs` and
  `…/lib/secp256k1/field.rs` (hint-verification patterns),
  `zisk/definitions/src/syscall.rs` (CSR IDs)
- Precompiles: `zisk/precompiles/arith_eq/` (README, `src/arith_eq_generator.rs`,
  `pil/arith_eq_lt_table.pil`), `zisk/core/src/zisk_ops_costs.rs` (cost constants)
- pil2-proofman ([github.com/0xPolygonHermez/pil2-proofman](https://github.com/0xPolygonHermez/pil2-proofman)):
  `proofman/src/challenge_accumulation.rs` (LtHash), `proofman/src/recursion.rs` +
  `setup/stark-recurser/stark2circom/circuit_templates/tera/` (recursion ladder),
  `setup/pil2-stark/src/types/stark_struct.rs` and `…/types/security.rs` (FRI defaults and
  query computation), `snark_wrapper.rs` (Plonk/fflonk wrap)

Zisk docs ([0xpolygonhermez.github.io/zisk-docs](https://0xpolygonhermez.github.io/zisk-docs/)):

- [Background](https://0xpolygonhermez.github.io/zisk-docs/intro/introduction/background) ·
  [Arithmetization](https://0xpolygonhermez.github.io/zisk-docs/intro/how-zisk-works/arithmetization) ·
  [Segments](https://0xpolygonhermez.github.io/zisk-docs/intro/how-zisk-works/segments) ·
  [Limits](https://0xpolygonhermez.github.io/zisk-docs/intro/how-zisk-works/limits) ·
  [Optimizing your program](https://0xpolygonhermez.github.io/zisk-docs/developer/writing-programs/optimizing-your-program)
  (patched crates; sha2 step/cost figures) ·
  [Profiling](https://0xpolygonhermez.github.io/zisk-docs/developer/writing-programs/profiling-your-program) ·
  [zisk-lib reference](https://0xpolygonhermez.github.io/zisk-docs/references/zisk-lib/)
- Book (in-repo): `zisk/book/getting_started/writing_programs.md` (MPI),
  `zisk/book/getting_started/distributed_execution.md` (coordinator/worker, phase-1
  challenge exchange)

Local files read (working tree, `feat/typed-air-precompiles`):

- Recursion: `src/frontends/riscv/recursion/protocol.zig`, `recursion/engine.zig`,
  `recursion/air/universal_roster.zig`, `recursion/air/inventory.zig`,
  `recursion/air/proof_kind.zig`, `recursion/air/statement_input.zig`,
  `recursion/fixed_wire.zig`, `recursion/fixed_profile.zig`,
  `recursion/air/composition_circuit.zig`
- Statement/publics: `src/frontends/riscv/air/statement.zig` (`mixShardManifest`),
  `air/public_data.zig`, `air/public_logup.zig`, `air/relations.zig`,
  `owned_statement.zig`, `proof_transcript.zig`
- Clocks/memory: `src/frontends/riscv/runner/state_chain.zig`, `access_clock.zig`,
  `air/clock_update_component.zig`
- Witness pipeline: `src/frontends/riscv/runner/trace.zig`,
  `prover/statement_geometry.zig`, `prover/main_trace_plan_execution.zig`,
  `prover/orchestration.zig`, `src/prover/work_pool.zig`
- Precompiles/hints: `src/frontends/riscv/air/guest_precompile/` (manifest, statement,
  interaction, proof_admission), `isa/custom0.zig`, `isa/execution_profile.zig`,
  `host/mod.zig`, `host/runtime.zig`, `host/prove_block.zig`
- Design docs: `design/typed-air/PROGRESS.md`, `TASKS.md`, `PRECOMPILES.md`,
  `PERFORMANCE.md`, `decisions/0006`, `0025`, `0030`, `0031`, `0033`, `0035`,
  `0036` (untracked), `aggregation/` (R-007 reference)
