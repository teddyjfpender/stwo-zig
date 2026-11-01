# Recursion for the `ethereum_services_v3` services

Status 2026-11-01, branch `codex/rv64-guest-prover-recursion-v3` (merged with
`codex/rv64-guest-prover-v3-integration`). This records what recursion needs
for the three v3 services (SHA-256 family 3, arith256_mod family 4, bulk
memory inside the CPU proof), what now exists, what was measured, and what is
still missing.

## 1. Correction to the starting assumption

The request was to make v3 bundles "wrap and fold to a single root like v2
bundles". **No Word16 services bundle, v2 or v3, can be wrapped today.** The
RV64 recursion that exists (`rv64_recursion/{leaf_statement,leaf_wrap,
fold_root,transcript_walk,closure}.zig`, `zig build rv64-recursion`) wraps the
legacy *authenticated* RV64 batch proofs (`rv64_authenticated_execution`,
`ReceiverKey`/`Public`). `rv64-word16-recursion-readiness.md` states this
explicitly: the Word16 services protocol has no leaf statement, no transcript
walker, no closure and no fold statement. What the Word16 lane has is:

- the generic in-circuit native verifier `frontends/circuit/native_verifier`
  (Blake2s channel, prefixed lifted Merkle, fold step 1/4, composition split
  1/2), which the Word16 suite uses unchanged (`pcs_suite.zig`: production is
  the legacy `rv64_air.protocol.config()`);
- lane-generic point authorities (`evaluateQuotientsAtPointFor`/
  `evaluatePointFor`) for the Word16 CPU/ROM/JALR, LS v2, register boundary,
  scalar providers, DIV/MUL degree-3, Keccak pair2n and secp truths, each with
  a circuit-lane parity test (`test-riscv64-*-circuit`, `-lanes`);
- OM31 MAIN-only parity for the Keccak/secp Word16 bridges
  (`om31_service_main_test.zig`): MAIN residuals only, no interaction, claims
  or challenges as wires.

So v3 recursion is not "add three families to an existing services leaf":
the services leaf itself is the largest missing piece. This document splits
the work so that the per-family parts are done once and the shared parts are
named precisely.

## 2. What a delegation family needs, component by component

A family has up to two physical parts: a **truth** (its own PCS, own proof)
and a **bridge** (columns inside the issuing CPU proof). Bulk memory has only
bridge-like components (`desc`, `copy`, `set`) inside the CPU proof.

| # | Component | SHA-256 | arith256_mod | bulk memory |
|---|---|---|---|---|
| 1 | Truth point authority over circuit wires (degree-3 residuals at OODS, scaled by the vanishing inverse, Horner-accumulated) | **done** `sha256/component.zig evaluatePointFor` | **done** `arith256/component.zig evaluatePointFor` | n/a |
| 2 | Bridge point authority with claims, challenges and span as wires | **done** `word16_bridge` kind `.sha256` (`ClaimsFor/ChallengesFor`, typed span) | **done** same bridge, kind `.arith256_mod` | **done** `bulk_memory/component.zig evaluatePointFor`, `RowsFor` |
| 3 | Native/circuit parity + mutated-wire tests | **done** | **done** | **done** (desc, copy, set) |
| 4 | Receiver shape authority (tree logs, mask offsets, split from the receiver's own geometry, never from the proof) | **done** `truthShape(.sha256, log)` | **done** `truthShape(.arith256_mod, log)` | part of the CPU shape (missing, row 9) |
| 5 | Truth transcript replay in-circuit (`beginTruth`, roots, `shared(manifest)` RAM14/IO11/Wire35 draws, `drawTruth`, claims, interaction) | **done** `services_truth_leaf.Statement` | **done** (+ local BYTE draw) | n/a |
| 6 | Truth leaf: native capture -> fixed-width witness -> native verifier -> statement digest | **done** `Leaf.build`, tool `rv64-v3-truth-leaf` | **done** | n/a |
| 7 | Root-side check of a truth leaf (statement words equal the receiver's roster span, `Expected`, manifest digest, manifest spec and MAIN root) | **done** `checkStatement` | **done** | n/a |
| 8 | Wire35 claim closure across leaves | truth terms: **done** (leaf claim words). Bridge terms: **missing** (need CPU leaves) | same | RAM14/OWNER terms: **missing** (CPU leaves) |
| 9 | CPU-with-bridges leaf: lifted CPU roster in exact component order, `beginCpu` replay incl. the v3 SHA (`0x57534833`), arith (`0x57534134`) and bulk blocks, `drawCpu`, the 20/25-claim `CpuClaims` vector, local closure | **missing** | **missing** | **missing** |
| 10 | Services root: recompute the manifest seal from all leaves' specs and roots, close RAM14 / KeccakIO11 / Wire35 sums, INIT/TERM anchors, epoch/adjacency, terminal output | **missing** | | |
| 11 | Keccak and secp truth leaves (v2 families) | n/a | n/a | n/a (**missing**, needed for any complete block) |
| 12 | Fold: production multiverifier over padded leaves (`fold_root.zig` pattern) | reusable once 9-10 exist | | |

### 2.1 Transcript order (truth proof), as implemented and parity-tested

1. `PcsConfig.mixInto` (one felt), then `mixU32s([0x57534345, 1, 1, ordinal, family, first_id, calls, 3])`;
2. program identity, image identity (8 words each), `total_steps`,
   `max_total_steps`, initial pc, 32 initial registers, final pc, 32 final
   registers (one `mixU64` each);
3. family geometry: SHA `[0x53484132, log, 3, 7409, 8, 7751, 35, 3]`, arith
   `[0x41524d34, log, FIXED, MAIN, INTER, CONSTRAINTS, 35, 4, BYTE_QUERIES]`;
4. fixed root (constrained equal to the receiver key root), MAIN root;
5. a fresh channel: `[0x5753434d, 1]`, manifest digest, `[0x52414d31, 14]` +
   15 draws, `[0x4b494f31, 11]` + 12 draws, `[0x53574952, 35]`,
   `[0x53575031]`, Wire35 offset + 35 coefficients;
6. the proof channel: `[0x57534332, 1, 1, ordinal, family]`, manifest digest,
   and for arith `[0x41524231, 8]` + the BYTE point;
7. `mixFelts([claim, 0, 0])` (slots 1-2 are circuit constants, which is the
   receiver's `NonzeroAbsentServiceClaim` rule), interaction root, then the
   generic native verifier (composition, OODS, DEEP, FRI, PoW, queries).

The test asserts the circuit channel's final digest equals the native
verifier's after the query draw, on real fixture proofs of both families.

### 2.2 Leaf statement (175 words, output digest = Blake2s of the words)

`ordinal, first_id, calls, program_identity[8], image_identity[8],
total_steps[2], max_total_steps[2], initial_pc[2], initial_registers[64],
final_pc[2], final_registers[64], manifest_digest[8], claim[4], main_root[8]`.
The claim limbs are the canonical `m31_to_u32` limbs the channel absorbs, so
the revealed claim is exactly the transcript-bound claim. Family and log are
circuit constants (one leaf circuit per (family, log)); the root must admit
the leaf circuit hash from that set.

### 2.3 What closes where

- In-circuit: proof validity, transcript, fixed root, every family constraint
  at OODS, zero absent claim slots.
- Root (native today, `checkStatement` + sum): roster span and `Expected`
  equal the receiver's; manifest spec of the entry equals the receiver's own
  `beginTruth` digest; MAIN root equals the manifest entry; claim canonical;
  sum of all Wire35 claims (truth leaves + CPU bridges + secp truths) is zero.
- Not yet anywhere recursive: the bridge and CPU side of every relation,
  RAM14, OWNER, KIO, INIT/TERM, adjacency, terminal output.

## 3. What was implemented

- `sha256/component.zig`, `arith256/component.zig`: one `evaluatePointFor`
  per truth, used by the native vtable path too (single authority).
- `secp256k1/word16_bridge/{types,equations,component}.zig`:
  `ChallengesFor(C)`, `ClaimsFor(C)`, `emitFor` takes a typed call span, and
  `evaluatePointFor` (native vtable path routed through it). Covers ADD,
  DOUBLE, SHA-256 and arith256_mod bridge kinds.
- `bulk_memory/{types,equations,component}.zig`: same for desc/copy/set,
  with `RowsFor(C)` (rows + `rows != 0` wire for an external lane).
- `rv64_recursion/services_truth_leaf.zig`: shape authority, statement,
  native capture, `build`, `statementWords`, `checkStatement`.
- `word16_recursion/v3_truth_leaf_main.zig` (`zig build rv64-v3-truth-leaf`):
  runs the full native receiver on a bundle, then builds (and with `prove`,
  pads and proves) one leaf per v3 truth, reporting JSON.
- Fixed a pre-existing build break: `word16_recursion/main.zig` (shape
  diagnostic) and `joint_write_invariants_test.zig` no longer compiled after
  the SHA-256 merge.
- Tests: `zig build test-riscv64-v3-services-recursion`.

## 4. Measurements

See section 6 (filled from the run log).

## 5. Next steps, in order

1. CPU-with-bridges leaf (row 9). Prerequisites from the readiness audit:
   lifted ALU/BINARY/SHIFT and CPU register-boundary components, LS v2
   top-level dispatcher, Keccak Word16 bridge `ClaimsFor/ChallengesFor`
   (the secp/SHA/arith bridge and bulk memory are now done), a `beginCpu`
   walker shared by native and circuit, and the CPU claim vector as wires.
2. Keccak (pair2n, 3 components) and secp (product + linear) truth leaves:
   the point authorities exist; they need the `services_truth_leaf` family
   arms (geometry words, local draws, roster order).
3. Services root receiver: manifest seal recomputation from leaf words,
   RAM14/KIO/Wire35 closure, INIT/TERM, adjacency and terminal output, then
   folding with the production multiverifier as in `fold_root.zig`.
4. Leaf-hash admission: one circuit per (family, log); pin the admitted set.
