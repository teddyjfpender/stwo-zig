# Path to the big jump (status 2026-11-02 08:00; session-2 summary first)

Where the program stands, what limits each metric, and the order of work that
gets both metrics down far enough to start the GPU port. Numbers are on the
12-block scored set unless stated; "est." marks estimates.

## Status 2026-11-02 (session 2): tracks delivered

Provable evmone v3 client (`ethereum_services_v3`), 12-block scored set, exact
outputs on all 15 blocks, all guards G1-G6, promotable. Each row adds to the
one above.

| Step | instr/gas | committed bits/gas (proxy) | Branch / commit |
|---|---:|---:|---|
| Start of session (merged head, aligned memory only) | 4.778 | 67,192 | `4e4b38a62` |
| Client pass 2 (memory functions, code hash in copy, blst constant limbs, word copies) | 4.538 | 64,578 | `codex/rv64-ge-interp` |
| Unaligned memcpy + memcmp proven (ucopy/cdesc/cmp), `umem` default | 4.447 | 63,851 | `codex/rv64-ge-bulk` |
| Keccak-256 sponge proven, `keccak` default | 4.060 | 60,527 | `codex/rv64-ge-sponge` |
| Throughput-table Keccak-f truth (-43% cells/permutation) | 4.060 | 54,544 | `codex/rv64-ge-keccak-tput` |
| JUMPDEST analysis service (jdesc/jscan/jtab) | 3.778 | 51,817 | `codex/rv64-ge-jumpdest` |
| BN254 / BLS12-381 curve services (`bn,bls` default) | **3.283** | **46,463** | `codex/rv64-ge-curves` (PR head `2f80736fe`) |
| CPU fused-tail + byte-pair queries (CPU INTER 40 -> 32), v3 default | 3.283 | est. -2,160 | `codex/rv64-ge-cells-fused-tail` |
| LS-D64 aligned-doubleword load/store row (102 -> 67 cells/access), v3 default | 3.283 | est. -2,890 | `codex/rv64-ge-ls64` |
| Zbb BINARY subset (rev8 via .insn), opt-in profile `ethereum_services_v3_zbb` | 3.864 vs 4.060 (-4.8%) | -2.7% | `codex/rv64-ge-zbb` (driver cannot prove blocks yet) |

LogUp/GKR CPU: packed fused GKR prover 2.3-3.4x per thread (QM31 and OM31),
15x at 8 threads on the services shape, byte-identical transcripts;
`generateParallelColumns` 1.1-1.3x (`codex/rv64-ge-logup`,
`design/riscv-proving-stack/rv64-logup-cpu-performance.md`). Not yet on a
production path: the OM GKR route of PR #309 has its own packed kernels;
reconcile and benchmark both.

PR #309 merged into this program on `codex/rv64-ge-base-merge`; the OM GKR /
wide route is v2-only and rejects every v3 family, bulk/sponge/JUMPDEST kind
and the throughput Keccak truth with `GkrV3ServiceUnsupported`.

Proxy caveat: the last four committed-bits steps use costs derived from proven
fixture geometry and the block 24,628,607 roster, not a complete-block
`cost.json` of the final client. Run a complete-block proof of the final client
before quoting committed cells externally.

## Route from here to ~2 instr/gas and ~20,000 bits/gas

Where the cost sits now (all 15 blocks, v3 client): interpreter ~1.96 instr/gas
(dispatch ~1.12), Keccak glue ~0.11, BLS/BN254 now on services,
misaligned copies ~0.2; committed cells ~64% CPU at ~158 cells/instruction
before the two CPU cuts (~139 after), Keccak ~12%, secp ~6%.

| # | Track | Effect (est.) | Size | Notes |
|---|---|---|---|---|
| 1 | Zbb CPU lane in the Ethereum driver (Zbb-aware native batch / packet authority), then compatible with fused tail | -4.8% instr/gas | days | chip, ROM, services lane proven |
| 2 | 256-bit EVM stack arithmetic/compare services or an AOT translation of hot contract code | -0.8 to -1.2 instr/gas | weeks | the main route from ~3.3 to ~2; threaded dispatch measured worse |
| 3 | Fused LS+CPU row for aligned LD/SD (M2) | ~-24 cells/instr | ~30 h | high soundness risk (PC/tick continuity) |
| 4 | Compact CPU decode (CPU MAIN 47 -> 37) | ~-10 cells/instr | ~26 h | re-derive pairing against the fused/pair layout |
| 5 | GKR for the global RAM/register/owner relations (extend the OM GKR route to v3 first) | up to ~-40 cells/instr | weeks | today's v2 GKR route saves only -6.9% cells and is slower; the ceiling is the 44% interaction share |
| 6 | Keccak: second 2x (fewer permutation rows or a cheaper sponge bridge) | ~-3,500 bits/gas | weeks | Keccak is ~12% of bits after the throughput truth |

At ~2 instr/gas and ~91 cells/instruction the CPU is ~11,800 bits/gas; with
Keccak and secp halved again the total lands near 20,000.

The sections below are the 2026-11-01 state, kept for history.

## Where we are (measured, exact outputs on all 15 blocks)

| Variant | instructions/gas | committed bits/gas | Promotable |
|---|---:|---:|---|
| Baseline Rust guest | 13.88 | 158,723 | yes |
| Rust guest, track C on this branch | 13.18 | 151,710 | yes |
| Rust guest, lean track (`codex/rv64-guest-rust-lean`) | 9.93 | 118,986 | yes |
| evmone client (`client_evmone/`), admitted services | 8.32 | 101,192 | yes |
| evmone client + candidate memory, SHA-256, arith256_mod + input adapter | 5.65 | 78,849 | no (services not yet in the prover) |
| **evmone client, merged trie/state + interpreter tracks + EEST fixes, admitted** | **6.81** | **86,044** | yes |
| **evmone client, admitted v3 services (SHA-256, arith256_mod, aligned memory)** | **4.78** | **67,192** | yes (complete block proved, 8.87 G cells) |
| **same client + all candidate services (mem, SHA-256, arith, BN254, BLS12-381, Keccak sponge)** | **3.39** | **55,556** | no (services being added to the prover) |
| Reference: ZisK reth guest / ZisK production commit | 6.38 / - | - / ~95,000 | |
| Target: ziskethone parity (L3) | 2.02 | ~23,000 | |

## What limits each metric

**Instructions per gas** (evmone client, candidate services on, instructions per gas by bucket):
EVM interpreter 1.86, trie and receipts 0.83, state tables 0.57, BLS12-381/KZG
0.46, Keccak sponge glue 0.43, BN254 0.30, JUMPDEST analysis 0.30, secp 0.22.
Input parsing is at most 0.5 in total; Keccak calls are already at their floor
(each witness node and code hashed once).

**Committed bits per gas** is bound by the CPU, not by Keccak:
`design/riscv-proving-stack/rv64-keccak-and-memory-cost-reduction.md` (branch
`codex/rv64-keccak-memory-cost`) measures a Keccak call at 78,323 cells all-in,
the same bits per call as ZisK, while a load/store costs ~200 cells and any
other instruction ~124 (153 average). At 3 instructions/gas the CPU alone is
~29,700 bits/gas, so the ~23,000 target needs both fewer instructions (~2/gas)
and a cheaper CPU row (~91 cells per instruction).

## Order of work

| # | Work | Where | Expected effect (est.) |
|---|---|---|---|
| 1 | **SHA-256 compression service in the prover** (truth AIR + bridge + services lane) | prover | evmone client 8.3 -> ~7.2; removes 1.35 instr/gas of SSZ-root hashing on any client |
| 2 | **Bulk-memory services in the prover** (aligned memcpy/memset first, memcmp after) | prover | -0.7 to -0.8 instr/gas on the client; -14% on the Rust guest |
| 3 | arith256_mod service (MULMOD/ADDMOD/modexp) | prover | -0.5 instr/gas on the client (measured as candidate: -9% instructions) |
| 4 | BN254 and BLS12-381 operations (add, double/mul, field ops) as candidates, then services | guest + prover | -0.6 to -0.7 instr/gas on blocks using those precompiles |
| 5 | Interpreter: evmone tuned for RV64IM (dispatch, jump-table address, U256 fast paths, JUMPDEST bitmaps cached per code hash) | guest | interpreter 1.9 -> ~1.0 |
| 6 | Throughput-table Keccak AIR (-43% cells per call) and padding ladder | prover | -8,000 to -9,000 bits/gas |
| 6b | Instruction-set extension, candidate first (Zbb/Zba subset) | guest + prover | measured: -5.5% instr/gas, -3.7% bits/gas; ~6.5% of the gap to 2.02 |
| 7 | **CPU cells per instruction** (row width, LS row for aligned 8-byte accesses, range trims) | prover | the only route to <30,000 bits/gas at ~3 instr/gas |

Items 1-4 together: client from 8.3 to roughly 3.5-4.5 instructions/gas
(est.). With item 5: roughly 2.5-3. Items 6-7 decide whether committed bits
reach the ~25,000-30,000 range.

## The Zbb gap and how to measure it

**Measured result (`notes/zbb-gap-report.md`):** Zba+Zbb close only about 6.5%
of the gap to ziskethone's 2.02. The rest splits roughly evenly between
services ZisK has and we lack (BLS12-381, BN254, Keccak absorb, ~44%) and client
code (interpreter, trie, state tables, ~45%). The route to ~2 is therefore the
curve and sponge services plus client work, with the ISA extension a small
final step. The method below is kept for re-measurement.


Everything on the service and client list lands the client around 3-3.5
instructions/gas (est.). ziskethone reaches 2.02 on ZisK, whose guests are
compiled with Zbb bit-manipulation and use single-step DMA and a wide precompile
set. Our executor and CPU AIR are plain RV64IM, so every rotate (3
instructions), byte swap (~15), count-leading-zeros (a loop), `andn`, min/max or
shift-and-add costs several instructions. The EVM interpreter, Keccak glue,
U256 arithmetic and trie nibble handling are full of these idioms.

To find out how much of the gap Zbb explains before building any AIR:

1. **Candidate ISA profile.** The execution tool decodes and executes the Zbb/Zba
   subset only under a candidate profile (admitted decode and the prover are
   untouched), counting each as one retired instruction.
2. **Rebuild with the extension enabled** (`-march=rv64im_zba_zbb` for C++,
   `-C target-feature=+zba,+zbb` for Rust) and run the basket. Per-extension
   builds (Zba only, Zbb only, both) isolate each effect.
3. **Price it.** Each new instruction needs CPU-AIR support; estimate cells per
   row for a new instruction family (similar to the ALU/BINARY/SHIFT chips) so
   committed bits per gas are scored, not just instruction counts.
4. **Attribute the remainder.** Compare buckets after Zbb with ziskethone's per
   bucket costs (its `docs/perf-notes.md`) and with ZisK's DMA/precompile call
   counts on the same blocks (`guest-steps-comparison-v1.json` records them), so
   the rest of the gap to 2.02 is split into ISA, services and client code.
5. **Static check.** Count instruction idioms in the current ELF that map to Zbb
   (rotate pairs, byte-swap sequences, `and`+`not`) to confirm the measured
   saving is where it should be.

## Gates for every step

- Exact outputs on all 15 blocks (`bench.py run --set all`), holdout guard, scope check.
- New services: soundness argument, adversarial tests, services-lane fixture
  proof with a fresh receiver, then a Word16 prefix proof of block 24,628,607
  with a guest that uses the service.
- New client: Ethereum execution spec tests (EEST) and differential runs against
  the reth guest; licences recorded (ziskethone Apache-2.0/MIT, evmone
  Apache-2.0, intx Apache-2.0, blst Apache-2.0) with their notices.

## Checklist

For resumable per-track TODOs, branch heads and the next levers, see [HANDOFF.md](HANDOFF.md).

Ticked items are done and evidenced; each line names its branch or commit.
Unticked items are in progress or not started. Keep this list current: tick an
item only with its evidence.

### Foundations
- [x] Guarded harness: basket (12 scored + 3 holdout), guards G1-G6, frozen calibration, targets, scope, ledger, unit tests (PR #308, `8f75a38fa`, `3e2455379`)
- [x] Execution contract admits 4 or 16 MiB input windows; pinned round-five guest unchanged (`8f75a38fa`)
- [x] Architecture-first program: CONTEXT.md, PROGRAM.md, candidate-service ABI (`3e2455379`)
- [x] Client input adapters for private input layouts (`89572e384`)
- [x] Comparisons vs ZisK: committed work, guest steps on 15 identical blocks, capture throughput, segment size (PR #307)

### Move A: client
- [x] evmone-class client (ziskethone + evmone v0.24) on the RV64IM ABI, exact output on all 15 blocks: 8.32 instr/gas admitted (`client_evmone/`, merged `e832241ec`)
- [x] Soundness fix: payload state root, receipts root and gas used checked against re-execution (`d79ebdd47`)
- [x] Verified signature-recovery hints via input adapter, Keccak memo (`004878ebc`, `1549143bb`)
- [x] Zero-parse input evaluated: at most 4-6% available, not pursued (notes/evmone-port.md)
- [x] Ethereum execution spec tests (tests@v21.0.2, Prague/Osaka/BPO1/BPO2: 34,561 tests, 37,295 valid + 3,543 invalid blocks) on both clients, host and full RV64 guest tiers (`eest/`, receipt `eest-guests-v1.json`). evmone RV64: 36,942 valid pass, all 3,543 invalid rejected; two evmone bugs fixed (EIP-7702 delegation code, trie delete-before-insert), costing +0.1% on the basket. Rust guest: two reth consensus bugs (accepts 4 SYSTEM_CONTRACT_EMPTY invalid blocks; rejects 8 valid withdrawals-before-request blocks)
- [ ] Fix the open evmone liveness bugs from EEST: BLS G2 crash on RV64 (portable-C blst path, 40 blocks), table sizing from the gas limit (>=500M gas), max-depth 7702 call-chain memory (branch `codex/rv64-guest-client-eest-fixes`, in progress)
- [ ] Report the two reth consensus bugs upstream (write-up in `eest/upstream-reth-issues.md`; filing is a human decision)
- [x] Port the Rust-lean techniques to the client's trie and state code (branch `codex/rv64-guest-client-trie-state`, 11 commits): admitted 8.317 -> 7.140 instr/gas; trie/MPT/receipts 0.825 -> 0.388, state tables 0.569 -> 0.430 instr/gas
- [x] Interpreter tuned for RV64IM, first pass (branch `codex/rv64-guest-client-interpreter`, 11 commits): admitted 8.317 -> 7.978 instr/gas; interpreter 1.921 -> 1.659, JUMPDEST 0.299 -> 0.265 (MUL 211 -> 67, MLOAD ~153 -> ~89, SLOAD ~336 -> ~185 instructions)
- [ ] Interpreter second pass to reach ~1.0 (branch `codex/rv64-guest-client-interpreter2`, in progress): per-basic-block gas and stack checks cached per JUMPDEST, top-of-stack in registers in fused jumps, `rev8` via the ISA extension (each opcode still pays ~10 fixed instructions; dispatch alone is 1.12 instr/gas)
- [x] Combined client verified (trie/state + interpreter + curves merged): admitted 6.801 scored / 6.566 all instr/gas, 85,987 bits/gas, all guards, promotable; all candidate services 3.390 scored, 55,508 bits/gas

### Move B: services
- [x] Six candidate services in the execution tool with tests and cost estimates; measured per family on the Rust guest (`bca94c643`, merged `228a6a38a`)
- [x] Candidate services measured on the evmone client: 5.65 instr/gas, 78,849 bits/gas (`519337489`)
- [x] SHA-256 compression service in the prover: admitted profile `ethereum_services_v3`, truth AIR (one compression per row, degree 3, own PCS), secp/Word16 bridge `.sha256` kind, services lane family 3, receiver (v3-only), Ethereum driver (branch `codex/rv64-guest-prover-sha256`, 6 commits). Cost 8,551 cells per compression nominal, 12,151 padded on the real block (software was ~616k). v2 bundles byte-identical. Rust guest -12.4% instr/gas, -10.6% bits/gas, promotable
- [x] **First provable v3 result:** 4-shard prefix of block 24,628,607 with the SHA-256 guest proved (29.5 s, 22.8 GB) and accepted by a fresh `verify-prefix` (2,771 compressions)
- [x] SHA-256, bulk memory and arith256_mod integrated into one `ethereum_services_v3` profile (branch `codex/rv64-guest-prover-v3-integration`, `b25175ff6`): 20 suites + new v3 suite pass; v2 and SHA-only v3 bundles byte-identical and cross-verifying; all-three fixture proved, fresh receiver, adversarial rejections hold
- [ ] Recursion-circuit support for v3 services (SHA-256, bulk memory, arith256_mod) (branch `codex/rv64-guest-prover-recursion-v3`, in progress)
- [x] Aligned memcpy/memset services in the prover: desc/copy/set components (degree <= 3), RAM bridge, services lane, fresh receiver; 17 bulk tests incl. 16 adversarial, v2 bundles byte-identical (branch `codex/rv64-guest-prover-bulk-memory`, `1d2f62e8c`). Measured cost 112 cells per call + 77 per copied word (~10x below the estimate)
- [ ] Unaligned memcpy body row (byte shift across two source words) (branch `codex/rv64-guest-prover-bulk-unaligned`, in progress): admitted aligned-only service saves just -2.15% instr/gas on the Rust guest vs -12% for the candidate, because most copies have mismatched alignment
- [ ] memcmp service (same branch, in progress)
- [ ] Ethereum driver v3 work-packet route (native prepare, packet admission, authority) so a guest using v3 services can be prefix-proved
- [x] Guests routed to the admitted services; harness on `ethereum_services_v3` with measured costs in calibration.json (SHA-256 12,615 cells/call; arith256_mod 4,460; memcpy 154 + 15.15/byte; memset 154 + 8.46/byte, measured on block 24,628,607)
- [x] arith256_mod service in the prover: truth AIR (degree 3, own PCS, exact identity over byte limbs, r < m by borrow chain, m = 0 flag), Word16 bridge kind 4, services lane family 4, fresh receiver; >1,000 known answers, adversarial rows, v2 bundles byte-identical (branch `codex/rv64-guest-prover-arith256`). Cost 2,779 cells per call unpadded (~18 instructions' worth; estimate was 6,500). Rust guest MULMOD/ADDMOD on the admitted tag: -0.71% scored, exact on 15 blocks, promotable
- [x] evmone client routed to all admitted v3 services (`build.py --profile v3`: SHA-256, arith256_mod incl. odd-modulus modexp, aligned memcpy/memset): 6.807 -> **4.778** scored instr/gas, 86,044 -> **67,192** bits/gas; all 15 blocks exact, promotable
- [ ] Plain 512-bit arith256 (a*b+c) service, if MUL/EXP measure as worth it on the client
- [x] BN254, BLS12-381 and Keccak-sponge operations as candidates, measured on the client (`fa8a2c7aa`, `683c40b2b`): client 5.653 -> 4.662 instr/gas (-17.5%), 78,849 -> 68,671 bits/gas (-12.9%); BLS/KZG 0.46 -> 0.09, Keccak glue 0.43 -> 0.08, BN254 0.30 -> 0.06 instr/gas
- [ ] BN254 and BLS12-381 services in the prover (branch `codex/rv64-guest-prover-curves`, in progress)
- [ ] Keccak sponge service in the prover (branch `codex/rv64-guest-prover-keccak-sponge`, in progress)
- [ ] Recursion-circuit support for each new service

### Move D: instruction-set extension (candidate first)
- [x] Candidate ISA profile in the execution tool (`b68291571`; 32 instructions, 13 tests incl. LLVM encodings and admitted-decoder rejection): Zbb subset (`andn`, `orn`, `xnor`, `clz`/`ctz`/`cpop` and `w` forms, `max`/`min`/`maxu`/`minu`, `sext.b`/`sext.h`, `zext.h`, `rol`/`ror`/`rori` and `w` forms, `orc.b`, `rev8`) plus Zba (`sh1add`/`sh2add`/`sh3add` and `.uw` forms, `add.uw`, `slli.uw`), execution-only, admitted decode untouched
- [x] Client and Rust guest rebuilt with `-march=rv64im_zba_zbb` / `+zba,+zbb`; per-extension measurement on the basket with an estimated cost per new instruction (`b9a1dd66e`): client 5.653 -> 5.343 instr/gas (-5.5%), 78,849 -> 75,960 bits/gas (-3.7%); Rust guest 9.825 -> 9.282
- [x] Gap report (`notes/zbb-gap-report.md`, `b9a1dd66e`): on ziskethone's three blocks the ISA closes only ~6.5% of the gap to 2.02; services ZisK has and we lack (BLS12-381, BN254, Keccak absorb) ~44%, client code (interpreter, trie, state tables) ~45%, small-copy DMA ~4%
- [x] Proposal (`proposals/isa-extension.md`): BINARY extension for andn/orn/xnor/rev8/sext/zext.h first (cheapest, most of the Zbb saving); measure Zbkb vs Zbb before AIR work; defer bit-count; Zba marginal; do not build rotates
- [ ] BINARY-extension Zbb subset in the CPU AIR (only after services and client work, given its ~4-5% value)

### Move C: hygiene
- [x] Rust guest lean track: 9.93 instr/gas admitted, 12 measured commits (branch `codex/rv64-guest-rust-lean`, not merged; overlaps track C)
- [x] Track C on the PR branch: -5.05% (`6dba79ad1`)

### Prover cost (committed bits)
- [x] Keccak and memory cost model: Keccak at bits parity with ZisK; CPU cells per instruction is the binding limit (branch `codex/rv64-keccak-memory-cost`, `7c9362a3d`)
- [ ] Throughput-table Keccak AIR (-43% cells per call) and padding ladder
- [ ] Load/store width histogram to validate the aligned 8-byte LS row assumption
- [ ] CPU cells per instruction: row width, aligned 8-byte LS row, range trims (target ~91 cells per instruction)

### Promotion gates
- [x] Word16 prefix proof of block 24,628,607 with a guest using a new service (SHA-256), fresh `verify-prefix` accepted (branch `codex/rv64-guest-prover-sha256`)
- [x] Same for the evmone client with all admitted v3 services: 4-shard prefix 32.2 s, fresh verify-prefix accepted
- [x] **Complete block 24,628,607 with the evmone v3 guest**: 9 CPU + 6 truth proofs, prove 61.6 s (shared machine, indicative), 37.5 GB max RSS, fresh `verify` accepted (4.6 s); **8.865 G committed cells incl. fixed vs 20.336 G for the Rust guest baseline (2.29x fewer)**
- [ ] Clean-machine timing of the complete-block v3 proof vs the 135.6 s baseline
- [ ] Complete-block proof and fresh `verify` with the new guest; exact committed cells replace the proxy
