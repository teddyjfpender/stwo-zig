# Handoff: RV64 guest-efficiency program (2026-11-01 23:30)

Snapshot of every track: what is done and verified, what is in flight on which
branch, and the concrete TODOs to deliver each track and to keep driving both
scores down. All branches are pushed to `origin`. Read with
[PATH-TO-BIG-JUMP.md](PATH-TO-BIG-JUMP.md) (checklist),
[CONTEXT.md](CONTEXT.md) (prover cost model, ABIs) and [README.md](README.md)
(harness contract).

## Where the scores are (scored set, 12 blocks; exact outputs on all 15)

| Variant | instr/gas | committed bits/gas | Status |
|---|---:|---:|---|
| Baseline Rust guest | 13.881 | 158,723 | promotable |
| evmone client, v2 admitted | 6.807 | 86,044 | promotable |
| **evmone client, v3 admitted (SHA-256, arith256_mod, aligned memcpy/memset)** | **4.778** | **67,192** | promotable; **complete block 24,628,607 proved**, 8.865 G cells vs 20.336 G baseline, fresh verify |
| evmone client + all candidate services | 3.394 | 55,556 | execution-only |
| Targets: L3 ziskethone parity / L4 | 2.02 / 1.50 | ~23,000 / ~17,000 | |

PR #308 branch `codex/rv64-guest-efficiency` now ALSO contains the six
in-flight tracks below, merged as **UNVERIFIED** checkpoints at the user's
request (merge commits titled "Merge UNVERIFIED checkpoint: ..."). Conflicting
hunks were resolved in favour of the verified side. The interpreter pass 2
patch is parked in `client_evmone/patches/wip/` (not applied). The verified
numbers in the table were measured before those merges; the post-merge
re-check is recorded below under "Post-merge status".

## How to resume any track

1. `git fetch origin && git worktree add /path codex/rv64-guest-<track>`.
2. Merge `origin/codex/rv64-guest-efficiency` (and, for prover tracks,
   `origin/codex/rv64-guest-prover-v3-integration`) to pick up the latest
   numbering, formats and client fixes.
3. Score with `autoresearch/guest_efficiency/bench.py` (README.md). The
   evmone client builds with `client_evmone/build.py --profile admitted|v3|candidate`
   and runs with its input adapter (client README "Score").
4. Every commit: measured delta plus a "Quality note:" paragraph. Push after
   each verified step. Never merge unverified checkpoints into the PR branch.

Conventions to keep: v3 families 3 = SHA-256, 4 = arith256_mod, bulk memory is
a separate roster block, new families take 5+; tape order steps, memory,
Keccak, secp, SHA-256, then the optional arith256_mod section flagged by the
top bit of the SHA count word; one `admitted_services` cost table in
`calibration.json`; v2 and SHA-only v3 bundles must stay byte-identical.

## In-flight tracks (pushed WIP; agents may still be adding commits)

### Keccak sponge service in the prover
Branch `codex/rv64-guest-prover-keccak-sponge` (head `936505bbf`). Has: admitted
executor (tag `0x30130`, v3), two-component Word16 sponge bridge,
`delegations/keccak_sponge/` (layout, equations, source, interaction, tests),
services roster wiring, `services/sponge_fixture.zig`, `sponge_test.zig`,
design doc `rv64-keccak-sponge-service.md`. Candidate measured: client Keccak
glue 0.43 -> 0.08 instr/gas.
- [ ] TODO finish and run truth/bridge tests: known answers vs Keccak-256 for many lengths and alignments; adversarial (skipped block, wrong XOR, reordered blocks, forged final state, length mismatch).
- [ ] TODO services fixture proof with a fresh receiver; v2 and SHA-only v3 bundles byte-identical.
- [ ] TODO route the evmone client's Keccak (>64-byte inputs) to the admitted sponge; harness on all 15 blocks; measured cells per call and per block into `admitted_services`.
- [ ] TODO Ethereum driver: sponge in the v3 work-packet route; prefix and complete-block proof.
- [ ] TODO (next lever) throughput-table Keccak AIR from `rv64-keccak-and-memory-cost-reduction.md` (-43% cells per permutation).

### BN254 and BLS12-381 services in the prover
Branch `codex/rv64-guest-prover-curves` (head `f4e0d7a62`). Has:
`delegations/curves/` (spec, native, layout, equations, trace, component,
910-line tests), executor `ethereum_services/curves.zig`,
`word16_global_execution/curves/roster.zig`. Candidate measured: BN254
0.30 -> 0.06, BLS/KZG 0.46 -> 0.09 instr/gas.
- [ ] TODO finish BN254 G1 add/double and Fp2 mul truth AIRs with exactness and carry bounds; known-answer (independent big-int) and adversarial tests.
- [ ] TODO BLS12-381 Fp2 mul and the 384-bit Montgomery product (`arith384_mont`) used by blst; BLS G1 add/double if time.
- [ ] TODO bridge kinds and services-lane families (5+), receiver, fresh-receiver fixture; byte identity of v2 and v3 bundles.
- [ ] TODO route evmone's BN254/BLS precompiles (ecAdd/ecMul/ecPairing, EIP-2537, KZG) to the admitted tags; harness; measured costs.
- [ ] NOTE this branch shows deletions of the v3 integration note and receipts relative to the integration head: re-merge `origin/codex/rv64-guest-prover-v3-integration` before finishing so those files are not lost.

### Unaligned memcpy and memcmp
Branch `codex/rv64-guest-prover-bulk-unaligned` (head `23677a9e3`). Has:
executor admits unaligned-source memcpy and memcmp (`0x30003`), bulk-memory
AIR changes (layout, equations, source, types, tests), guest mem crate and
evmone runtime routing, boundary capture changes. Aligned-only saves just
-2.15% on the Rust guest vs -12% for the candidate; only 3.34M of 9.08M copies
qualified.
- [ ] TODO measure fallback reasons (mismatched alignment, overlap, short) and record them.
- [ ] TODO unaligned body row (two aligned source words, byte shift 1..7) keeping canonical limbs and the joint REG/RAM write induction; adversarial tests (wrong shift, wrong byte, skipped word).
- [ ] TODO memcmp rows with a sound first-difference argument; adversarial tests (wrong result, early-stop forgery).
- [ ] TODO fixture proof with fresh receiver; byte identity; harness on Rust guest and evmone v3 client; measured costs.

### Recursion for v3 services
Branch `codex/rv64-guest-prover-recursion-v3` (head `2836da9c9`). Has: plan
`design/riscv-proving-stack/rv64-v3-services-recursion.md`,
`rv64_recursion/services_truth_leaf.zig`, `word16_recursion/v3_truth_leaf_main.zig`,
lane-generic SHA-256 truth and Word16 bridge point authorities, arith256 and
bulk-memory component refactors for circuit lanes, `rv64_v3_services_recursion_test.zig`.
- [ ] TODO finish SHA-256: in-circuit truth and bridge evaluation, shape authority, native vs in-circuit parity tests, adversarial (tampered OODS, wrong shape, missing bridge).
- [ ] TODO arith256_mod and bulk-memory components in circuit lanes (bulk lives inside the CPU proof: CPU leaf shape changes).
- [ ] TODO wrap and fold the complete v3 block bundle of 24,628,607 to one root; leaf gate counts and wrap time.
- [ ] TODO check the hard-wired Starkware circuit pin is untouched (`circuit-starkware-pin`).

### Interpreter second pass
Branch `codex/rv64-guest-client-interpreter2` (head `9fb12eca4`). Has a large
new patch `0023-evmone-rv64-translated-segments.patch` (pre-translated
segments / threaded dispatch). Interpreter is 1.66 instr/gas after pass 1;
each opcode pays ~10 fixed instructions, dispatch 1.12/gas.
- [ ] TODO renumber the patch: `0023` is already taken by the v3 modexp patch; on the PR branch it is parked unapplied at `client_evmone/patches/wip/0023-evmone-rv64-translated-segments.patch`. Re-merge `origin/codex/rv64-guest-efficiency` first (this branch predates the v3 merge).
- [ ] TODO finish and measure threaded dispatch; per-basic-block gas and stack checks cached per JUMPDEST; top-of-stack in registers in fused jumps.
- [ ] TODO extend the fused-dispatch differential fuzzer to every gas/stack accounting change; EEST re-run on the affected groups.
- [ ] TODO harness on admitted, v3 and candidate profiles; target interpreter ~1.0 instr/gas.

### evmone bugs found by EEST
Branch `codex/rv64-guest-client-eest-fixes` (head `365f1b165`). Has: portable
blst host test `tests/blst_portable.c`, a change to patch `0002-blst-rv64-64bit-limbs.patch`,
`stwo_client.cpp` changes, `build.py` changes, and
`eest/upstream-reth-issues.md`.
- [ ] TODO BLS G2 crash on RV64 (40 blocks): confirm the root cause in the portable-C blst path with 64-bit limbs; fix; host test.
- [ ] TODO table sizing independent of the block gas limit (fails at >= 2^52 synthetic limits on host and at 500M gas in the 212 MiB guest heap) without regressing the basket.
- [ ] TODO bound per-frame memory on the max-depth EIP-7702 call chain.
- [ ] TODO report BLS MSM blocks over the 10^10-instruction budget.
- [ ] TODO re-run affected EEST groups (host and RV64) and the full host tier; new receipt version; basket unchanged.
- [ ] Human decision: file the two reth consensus bugs upstream (write-up in `eest/upstream-reth-issues.md`).

## Next levers to drive both scores down (not yet started)

Ordered by expected effect per unit of work. Numbers are estimates unless noted.

1. **Admit the remaining candidate services** (sponge, curves, unaligned copy,
   memcmp; tracks above): v3 client 4.78 -> ~3.4 instr/gas (the candidate
   profile measures 3.39).
2. **Interpreter**: dispatch and fixed per-opcode overhead (1.66 -> ~1.0).
3. **CPU cells per instruction** (the binding limit for committed bits): at
   ~3 instr/gas the CPU alone is ~29,700 bits/gas at ~153 cells/instruction.
   Load/store ~200 cells, other ~124 (`rv64-keccak-and-memory-cost-reduction.md`).
   Levers: aligned 8-byte LS row (needs the load/store width histogram first),
   range-check trims under canonical induction, CPU row width. Target ~91
   cells/instruction for < 30,000 bits/gas.
4. **Throughput-table Keccak AIR** (-43% per permutation, ~3,200 bits/gas per
   week of work) plus the padding ladder.
5. **Zbb BINARY extension** (`proposals/isa-extension.md`): measured -5.5%
   instr/gas, -3.7% bits/gas; build only andn/orn/xnor/rev8/sext/zext.h first.
6. **Client**: remaining trie/state (0.39 + 0.43 instr/gas), state tables,
   SSZ-root SHA-256 now a service; zero-parse input measured at <= 4-6%.
7. **Capture**: parallel capture plus in-process handoff (~22 s -> ~3 s before
   proving; `rv64-minimal-trace-design.md`).
8. **Segment size 2^23** after the lane sweep (`rv64-segment-size-analysis.md`):
   ~40% fewer proof bytes and recursion work.

## Cross-cutting TODOs before production

- [ ] Put the v3 execution profile into the program identity / statement (today a receiver policy).
- [ ] Whole-protocol 128-bit security accounting including the new lookup masses (`rv64-whole-protocol-security-policy.md`).
- [ ] Clean-machine timing of the complete-block v3 proof vs the 135.6 s baseline (61.6 s was measured on a shared machine).
- [ ] Recursion for all v3 services (track above).
- [ ] Licence notices recorded for vendored/fetched code (ziskethone Apache-2.0/MIT, evmone, intx, blst Apache-2.0); the user confirmed these licences.
- [ ] Debug-build stack overflow in the division evaluator on 1 MiB worker threads (suites run in ReleaseSafe).
- [ ] Rust guest: two reth consensus bugs (EEST) remain while it is kept as a fallback.

## Branch index

| Branch | Content | State |
|---|---|---|
| `codex/rv64-guest-efficiency` | PR #308: harness, program, evmone client, v3 integration, EEST | verified |
| `codex/rv64-guest-prover-v3-integration` | SHA-256 + arith256_mod + bulk memory in v3, complete-block proof | verified, merged |
| `codex/rv64-guest-prover-{sha256,arith256,bulk-memory}` | individual service tracks | verified, merged via integration |
| `codex/rv64-guest-prover-eest` | EEST runner, receipt, two evmone fixes | verified, merged |
| `codex/rv64-guest-client-{evmone,trie-state,interpreter}` | client port and passes | verified, merged |
| `codex/rv64-guest-candidate-{services,curves,isa}` | execution-only candidates | verified, merged |
| `codex/rv64-guest-rust-lean` | Rust guest lean track (9.93) | verified, not merged (overlaps track C) |
| `codex/rv64-guest-prover-keccak-sponge` | sponge service | WIP, merged UNVERIFIED |
| `codex/rv64-guest-prover-curves` | BN254/BLS12-381 services | WIP, merged UNVERIFIED |
| `codex/rv64-guest-prover-bulk-unaligned` | unaligned memcpy, memcmp | WIP, merged UNVERIFIED |
| `codex/rv64-guest-prover-recursion-v3` | recursion for v3 services | WIP, merged UNVERIFIED |
| `codex/rv64-guest-client-interpreter2` | interpreter pass 2 | WIP, merged UNVERIFIED (patch parked in wip/) |
| `codex/rv64-guest-client-eest-fixes` | EEST liveness bugs | WIP, merged UNVERIFIED |
| `codex/rv64-keccak-memory-cost` | Keccak/memory cost design | verified doc |

## Post-merge status (after merging the six UNVERIFIED checkpoints)

- Harness unit tests (`test_bench.py`): pass.
- **The merged head does not build yet.** Resolving conflicts in favour of the
  verified side kept the verified versions of shared executor plumbing hunks
  that the curves and Keccak-sponge checkpoints had changed. Remaining errors
  from `bench.py build-exec`:
  - `compact_tape.zig`: no `curve` event in the session `Event` union.
  - `ethereum_services/curves.zig`: `execution_profile.CURVE_TAGS` missing; a
    parameter shadows `value`.
  - `ethereum_services/session.zig`: no `sponge` field on `Session`.
  Already repaired: the `curves` import in `ethereum_services/session.zig`, the
  `KECCAK_SPONGE_TAG` constant in `execution_profile.zig`, and the duplicate
  blst fix (patch `0022-blst-rv64-quot-rem-single-limb.patch` removed: the same
  quot_rem_64 fix now lives in `0002-blst-rv64-64bit-limbs.patch` from the
  EEST-fixes track, and both could not apply).
- Post-merge repair log (dropped `-X ours` hunks found by re-running each
  merge with `git merge-tree`; conflicts only in sponge and curves merges plus
  client build.py (EEST) and bulk_memory component/equations (recursion-v3)):
  - Gate 1 (executor): restored in `ethereum_services/session.zig` the sponge
    `sponge()` executor (dropped in the sponge merge) and the curve event,
    `CurveServiceDomain` error, per-op `curve_calls`, curve dispatch; in
    `execution_profile.zig` `CURVE_TAGS`/`isCurveTag` and `admitsV3` now admits
    SHA-256, arith256_mod, payload-free (bulk + sponge) and curve tags; tape
    `appendCurve`; boundary-capture `.curve` arm; execution report
    `curve_calls`; `air.curves` exports; `prepared.zig` combined-v3 tag set
    includes both 0x30130 and the curve tags. Fixed the curves branch's own
    `opOfTag(value)` shadow. Tape-wire test updated: the curves track made the
    v3 extension's reserved word the curve record count, so a nonzero word with
    no records is now rejected as truncated (still rejected). Tags are
    distinct: sponge 0x30130, curves 0x30100..0x30121.
    `bench.py build-exec` OK; `zig build test` in src/frontends/riscv/rv64:
    100/100 pass.
  - Gate 2 (evmone client): restored the EEST track's blst portable-C vs
    assembly host check in `client_evmone/build.py --tests` (dropped by the
    EEST merge; host-test only, not on the guest build path). `build.py` builds
    default/admitted (`client-evmone-admitted.elf` sha256 a83dea52...bc59),
    `--host` (0b609c82...d874) and `--profile v3` (909477e5...82f4).
- TODO (in progress on this branch): re-run the 15-block basket, and the Word16 services suites. The last
  verified head of this branch before the unverified merges is `1c821fc9d`.
