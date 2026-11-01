# Handover: recursion for the v3 services (paused 2026-11-01)

Branch `codex/rv64-guest-prover-recursion-v3` (worktree
`/private/tmp/stwo-rv64-guest-prover-recursion-v3`), based on
`codex/rv64-guest-prover-sha256` and merged with
`origin/codex/rv64-guest-prover-v3-integration` (b25175ff6). The plan, with a
component-by-component table of what exists and what is missing, is in
`design/riscv-proving-stack/rv64-v3-services-recursion.md`.

## Key finding (read this first)

No Word16 services bundle, v2 or v3, can be wrapped or folded today. The RV64
recursion that exists (`rv64_recursion/leaf_wrap.zig`, `fold_root.zig`,
`zig build rv64-recursion`) wraps the legacy authenticated RV64 batch proofs.
The Word16 lane has the generic in-circuit native verifier and per-component
lane parity, but no services leaf statement, no CPU-with-bridges leaf and no
services root. So "wrap like v2" is not possible yet: the shared services
leaf and root are the main missing pieces, not the per-family parts.

## Done and verified (with evidence)

Evidence is the ReleaseSafe run of `zig build test-riscv64-v3-services-recursion`
just before the last fixes (log:
`/private/tmp/claude-501/-Users-theodorepender-code-cryptography-stwo-zig-rv64-frontend/41eff230-75ab-4f11-a53b-7db4dcd5a611/scratchpad/prover-recursion-v3/test3.log`,
and the direct binary run): 10 of 12 passed. The 2 failures were test-side
mistakes that are fixed in the tree but **not re-run** (see "In progress").

Passing tests in that run:
- SHA-256 truth: the circuit point authority equals the native residuals and
  the composition. Every bound wire (Wire35 offset and coefficient, claim,
  calls, first ID, a MAIN, a previous-ACTIVE and an interaction sample)
  invalidates the circuit when mutated.
- Word16 bridge kind `.sha256`: the same parity with claims, challenges and
  span as wires (13 mutations). The native vtable path gives the same
  composition.
- SHA-256 truth shape: the receiver derivation equals the real component
  `maskPoints` and `columnLogSizes` for each admitted log.
- arith256_mod truth: the same parity and mutation test.
- bulk memory desc, copy and set: the same parity and mutation test, with
  rows and nonempty as wires.
- v3 truth leaves, test "locally valid false outputs": on the all-services v3
  fixture, both the SHA-256 leaf (ordinal 0) and the arith256_mod leaf
  (ordinal 1) build valid circuits for the `wrong_sha_output` and
  `wrong_arith_output` mutations. `checkStatement` accepts them, the
  cross-leaf Wire35 sum does not close, and the native receiver returns
  `UnclosedCombinedSecpWire`. This shows the full truth leaf works for both
  families on real fixture proofs.
- In the honest leaf test, the SHA-256 leaf built a valid circuit:

  | Leaf | vars | blake_g | qm31_ops | m31_to_u32 | triple_xor | eq |
  |---|---:|---:|---:|---:|---:|---:|
  | SHA-256, log 5 fixture | 15,253,544 | 3,081,280 | 1,492,889 | 552,512 | 308,128 | 6,047 |

  This is about 37% of the 2^23 production target, so it pads to the same
  shape as a legacy RV64 leaf.

## In progress: exact state, nothing below re-run after the last edits

Changed files:
- `src/frontends/riscv/rv64/air/delegations/sha256/component.zig`,
  `arith256/component.zig`: a lane-generic `evaluatePointFor` (lazy mask view).
  The native `evaluateConstraintQuotientsAtPoint` routes through it.
- `secp256k1/word16_bridge/{types,equations,component}.zig`:
  `ChallengesFor(C)`, `ClaimsFor(C)`, and `emitFor` now takes a typed call
  span instead of `(calls, first_id)`. Adds `evaluatePointFor`.
- `bulk_memory/{types,equations,component}.zig`: `ChallengesFor`,
  `ClaimsFor`, `RowsFor` and `evaluatePointFor`.
- `src/integrations/riscv_cpu/rv64_recursion/services_truth_leaf.zig`:
  `truthShape`/`sha256Shape`, `Statement` (`beginTruth`, shared and
  `drawTruth` replay, claims, composition), `verifyNative` (capture), `build`,
  `statementWords`/`statementDigest` (175 words) and `checkStatement` (root
  side).
- `src/integrations/riscv_cpu/tests/rv64_v3_services_recursion_test.zig`, the
  root `rv64_v3_services_recursion_test_root.zig`, and the step
  `test-riscv64-v3-services-recursion` (`riscv_recursion.zig` and
  `catalog.zig`).
- Tool `rv64-v3-truth-leaf` (`word16_recursion/v3_truth_leaf_main.zig` and
  root `rv64_v3_truth_leaf_main.zig`): native receiver on a bundle, then one
  leaf per v3 truth, with `prove` to pad and run a CPU circuit proof. **Never
  compiled successfully**: the first build hit the `config_v2` break below,
  and the build with the fix was stopped.
- Fixes to existing breaks:
  - `word16_recursion/main.zig`: the shape diagnostic no longer compiled after
    the SHA-256 merge. Fixed and verified: it built and ran on the prefix4
    bundle.
  - `joint_write_invariants_test.zig`: a kind-type mismatch.
  - `secp/bridge_test.zig`, `arith256/bridge_test.zig`: updated to the typed
    span. Unverified.
  - `src/core/pcs/mod_family.zig`: exposes `config_v2` on the family struct
    (the import was renamed `config_v2_module`). This repairs
    `engine_family.zig`, which referenced `pcs_core.config_v2` and broke every
    circuit-prover build (`rv64-recursion`, the new tool). **Unverified**: the
    build was stopped by the pause.

Test-side fixes made after the last run, not re-run:
- Statement words: the CLAIM word is free at the root, so flipping it is
  caught by Wire35 closure, not by `checkStatement`. The test now checks that.
- The absent-claim mutation moved from in-circuit (absent slots are circuit
  constants) to `verifyNative`, which expects `NonzeroAbsentServiceClaim`.
- The interaction OODS mutation now uses sample 0, because column 6 of
  arith256 has one sample.

## Known issues and risks

- `test-riscv64-word16-memory`: the tripwire `expectEqual(4, Sources.len)` in
  `joint_write_invariants_test.zig` now reads 7. The comment says "adding
  another RAM-writing service requires reopening the induction". The v3
  integration added SHA-256, arith256 and bulk memory without reopening it;
  the test did not compile on that branch, which hid this. It is deliberately
  left failing: it is a soundness review item for the v3 owners, not
  something to bump.
- Running the v3 fixture in Debug crashes (stack overflow, bus error) in a
  prover worker (`division/word16_product` domain eval). Run the suite with
  `-Doptimize=ReleaseSafe`.
- The truth leaf binds family and log as circuit constants, so there is one
  leaf circuit per (family, log). The root must admit leaf circuit hashes
  from a pinned set (not done).
- The Wire35 closure in tests and in the tool uses native CPU bridge claims,
  because CPU leaves do not exist. It is not recursive acceptance.
- Whole-protocol security bits are not established, as for all services.

## Next steps

1. Re-run without other edits:
   `zig build -j3 -Doptimize=ReleaseSafe test-riscv64-v3-services-recursion test-riscv64-sha256-truth test-riscv64-arith256-truth test-riscv64-word16-arith256-bridge test-riscv64-word16-arith256-services test-riscv64-word16-bulk-memory test-riscv64-word16-bulk-services test-riscv64-word16-secp-bridge test-riscv64-word16-keccak-bridge test-riscv64-word16-v3-services test-riscv64-word16-combined-services rv64-v3-truth-leaf rv64-word16-recursion-shape rv64-recursion`
   under `lockf -k /private/tmp/stwo-rv64-perf-build.lock`. Then fix fallout
   and commit.
2. Measure on the complete-block v3 bundle,
   `.../scratchpad/prover-v3/eth/full`: truth-4 is SHA-256 (2,901 calls,
   log 12) and truth-5 is arith256_mod (319 calls, log 9). Under the heavy
   lock, run with the trusted config used to produce it:
   `rv64-v3-truth-leaf CONFIG .../prover-v3/eth/full full prove`
   (ReleaseFast). Record gates, pad and prove ms, and proof bytes in the
   design doc, section 4.
3. Per service:
   - SHA-256: the truth leaf is done. The bridge point authority is done. It
     still needs the CPU-with-bridges leaf for its bridge terms.
   - arith256_mod: the same status as SHA-256.
   - bulk memory: the point authority is done. Everything else is part of the
     CPU leaf (no truth proof).
4. Shared work for wrapping and folding a complete v3 block:
   - (a) A CPU-with-bridges leaf. This needs the lifted ALU, BINARY, SHIFT
     and CPU register-boundary components, the LS v2 dispatcher, the Keccak
     Word16 bridge `ClaimsFor`/`ChallengesFor`, a `beginCpu` walker
     including the v3 SHA (`0x57534833`), arith (`0x57534134`) and bulk
     blocks, `drawCpu`, and the CPU claim vector as wires.
   - (b) Keccak (pair2n) and secp (product/linear) truth leaves: add family
     arms to `services_truth_leaf`.
   - (c) A services root: recompute the manifest seal from the leaf words,
     close RAM14, KIO11 and Wire35, check INIT/TERM, adjacency and the
     terminal output, then fold with the production multiverifier as in
     `fold_root.zig`.
