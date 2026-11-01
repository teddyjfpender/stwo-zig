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
- [x] measure fallback reasons (mismatched alignment, overlap, short) and record them (handover section 1: 57% of copies mismatched alignment, overlap 0.004%).
- [x] unaligned body row (two aligned source words, byte shift 1..7) keeping canonical limbs and the joint REG/RAM write induction; adversarial tests (wrong shift, wrong byte, skipped word, zero length). `codex/rv64-ge-bulk`; `test-riscv64-word16-bulk-memory` passes; argument B8/B11 in rv64-bulk-memory-service.md.
- [x] memcmp rows with a sound first-difference argument; adversarial tests (wrong result, early-stop forgery, forged equal, length mismatch, zero length); B9/B10 in rv64-bulk-memory-service.md. Fix: memcmp len = 0 was forgeable (now a cdesc length inverse).
- [x] fixture proof with fresh receiver (`services/bulk_ext_fixture.zig`, `test-riscv64-word16-bulk-services`); byte identity, basket and costs: see handover/prover-bulk-unaligned.md section 7.

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

## Paused tracks: handovers (2026-11-02)

All six in-flight tracks were paused at the user's request. Each wrote its own
handover (done and verified with evidence, in progress, next steps, risks,
resume commands), committed, pushed its branch, and was merged into this branch
as an UNVERIFIED final checkpoint ("Merge UNVERIFIED final checkpoint + handover").

| Track | Handover | Branch head | One-line state |
|---|---|---|---|
| Keccak sponge | [handover/prover-keccak-sponge.md](handover/prover-keccak-sponge.md) | `fb253bde8` | AIR + services lane verified with real STARKs and a fresh receiver (23 lengths x 8 alignments, 8 adversarial); regression suites, byte identity, driver hooks and evmone option not run; costs estimated (~1,074 cells/call + 1,661/block) |
| BN254 / BLS12-381 | [handover/prover-curves.md](handover/prover-curves.md) | `e15fb991a` | one truth AIR for 7 ops, verified vs independent big-int; measured truth cells (BN254 add 2,036, dbl 1,884, Fp2 1,126; BLS Fp2 2,088, add 3,460, dbl 3,502; arith384_mont 1,256) + 378 per 32-byte coordinate; one quotient-tamper test unresolved; lane/receiver/driver wiring not compiled on the track branch; packets now inline 32-byte aligned |
| Unaligned memcpy / memcmp | [handover/prover-bulk-unaligned.md](handover/prover-bulk-unaligned.md) | `6806dec8c` (resumed: `codex/rv64-ge-bulk`) | RESUMED 2026-11-02: AIR + services lane verified with real STARKs and a fresh receiver; two zero-length forgeries fixed; v2/v3 byte identity; evmone v3 with umem default 4.525 instr/gas, 64,978 bits/gas (charged), all guards pass; RAM-writer induction re-established (joint-induction note section 11). Previous state: measured: 57% of copies (4.52M calls) have mismatched alignment; executor and Rust guest routing pass (-4.9% instr/gas, exact); AIR rows written, tests not confirmed green; not wired into the lane. Routing is gated off on this branch (`776015b65`) so guests stay provable |
| Recursion for v3 | [handover/prover-recursion-v3.md](handover/prover-recursion-v3.md) | `701ee5f0b` | correction: no Word16 services bundle (v2 or v3) can be wrapped/folded yet; needs a CPU-with-bridges leaf and a services root closing RAM14/KIO11/Wire35. Circuit evaluators built for SHA-256, arith256_mod, bridge, bulk; SHA leaf ~37% of the 2^23 budget on a fixture; 10/12 tests last run |
| Interpreter pass 2 | [handover/client-interpreter2.md](handover/client-interpreter2.md) | `68a0867d3` | negative result: translated segments cut dispatch 1.117 -> 0.836/gas but translation cost more (all-blocks 6.566 -> 6.834); not kept (~4.5 executions per unique opcode); patch parked in `client_evmone/patches/wip/` (not applied); 3-way differential fuzzer added |
| evmone EEST bugs | [handover/client-eest-fixes.md](handover/client-eest-fixes.md) | `365f1b165` | BLS G2 crash fixed (blst 0002, 40 -> 0 failures); table sizing fixed (host 200/200, guest 307/309); 7702 depth fixed by the same change; BLS MSM step budget not started; full host re-run and new receipt pending |

### Flags that need an owner

- **Soundness: joint REG/RAM write induction.** RESOLVED on `codex/rv64-ge-bulk`:
  argument re-established for every roster RAM writer in
  `design/riscv-proving-stack/rv64-ls-joint-write-induction.md` section 11
  (generic W1-W5 + per-writer table; sponge/curves owners may append). The
  guard now pins roster fields, bridge kinds, bulk kinds and sponge kinds by
  name (`joint_write_invariants_test.zig`, "services RAM writer inventory").
- **Candidate-profile output mismatch.** The interpreter track saw the
  candidate-profile baseline fail exact output with no interpreter change;
  uninvestigated. Re-check the candidate basket at the current head.
- **Unverified code is merged.** Default builds exercise only the verified or
  gated paths; each handover states what is unverified.

## Post-merge status (after merging the six UNVERIFIED checkpoints)

- **Status: repaired, all four gates pass** on the head that also contains
  the six tracks' final checkpoints and handovers (merged at `77e137c3c`).
  Details and the gated-out pieces follow; the history below records how the
  head got there.
- Harness unit tests (`test_bench.py`): pass.
- (Historical) the first merged head did not build. Resolving conflicts in favour of the
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
  - Gate 3 (basket, all 15 blocks, client input adapter, executor built
    from this tree): admitted client 6.807 scored instr/gas, 86,044 bits/gas;
    v3 client (`--profile ethereum_services_v3`) 4.778, 67,192 bits/gas; all
    guards G1-G6 pass, exact outputs. Per-block instruction counts differ from
    the pre-merge runs by -31..+198 per block (identical deltas in both
    clients, at most 0.0006%). Cause, confirmed by rebuilding the admitted
    client with the pre-merge `glue/stwo_client.cpp` (then identical on all 15
    blocks): the EEST track's `row_reserve`, which sizes the account/storage
    tables from gas_used instead of gas_limit (fixes bad_alloc on EEST blocks
    with 2^63-1 gas limits); kept.
    Gated out: the bulk-unaligned merge made the default v3 client route
    unaligned-source memcpy and memcmp (0x0003_0003) to the bulk service
    (v3 4.525), but the Word16 collector rejects memcmp and the unaligned AIR
    row is not built. That routing now needs `--v3-set sha,arith,mem,umem`
    (`-DADMITTED_UMEM`, ELF `-v3-sha-arith-mem-umem`); default v3 is
    aligned-only again. The executor still admits 0x0003_0003 and unaligned
    sources (execution-only; no verified client issues them).
    - [x] (bulk-unaligned track): unaligned memcpy and memcmp proved in the
      bulk AIR and services collector; `umem` is the default v3 set on
      `codex/rv64-ge-bulk` (aligned-only: `--v3-set sha,arith,mem`).
    `test_bench.py`: 40 tests OK.
  - Services lane (curves merge dropped hunks): curve request/claims fields
    in `services/wire.zig` (request `curve_calls` omitted from JSON when zero,
    so v2/v3 bytes are unchanged), curve replay in `collector.zig`,
    FAMILIES-wide call vector in `pipeline.zig`, call-count bound in
    `protocol.zig`, each union-merged with the sponge code. Gated WIP gaps,
    each with a TODO for its track:
    - [x] (bulk-unaligned): `ucopy`/`cdesc`/`cmp` wired through the services
      lane with their own claims (`bulk_ext`), counts and tests; the collector
      replays memcmp and unaligned copies.
    - [ ] TODO (curves): `ethereum/keys.zig` rejects curve truth families with
      `UnsupportedServicesTruthFamily` (Ethereum work-packet route not wired);
      `services/owned_truth_test.zig` marks `.curve` unreachable (its fixture
      has no curve truths).
- Re-run after merging the tracks' final checkpoints (`77e137c3c`): those
  merges used `-X ours` again; `git merge-tree` shows conflicts only in the
  interpreter's 0023 patch location (it stays only in `patches/wip/` and
  `notes/attempts/`, not in `patches/`) and in `build_support/products/catalog.zig`,
  where the `test-riscv64-word16-curves-services` entry was dropped; restored.
  No other track-added line is missing. Results on this head:
  - Gate 1: `bench.py build-exec` OK; `zig build test` in src/frontends/riscv/rv64 passes.
  - Gate 2: admitted, `--host` and `--profile v3` clients build (client guest
    sources unchanged by the final merges).
  - Gate 3: per-block instruction counts identical to the gate-3 runs above:
    admitted 6.807 / 86,044, v3 4.778 / 67,192, all guards pass, exact
    outputs on all 15 blocks; `test_bench.py` 40 OK.
  - Gate 4 (ReleaseSafe, all pass): word16-combined-services,
    word16-v3-services, sha256-truth, arith256-truth, word16-arith256-bridge,
    word16-arith256-services, word16-bulk-memory, word16-bulk-services,
    execution. v2 byte identity: `rv64-word16-combined-services-fixture
    produce` equals the golden v2 bundle in all seven files (`bundle.json`
    `be49c88c...`), and this head's receiver verifies the golden bundle.
  - Not run (unverified-track suites, outside the gates): curves-truth,
    keccak-sponge, word16-sponge-services, word16-curves-services,
    v3-services-recursion.
- The last verified head before the unverified merges is `1c821fc9d`.
