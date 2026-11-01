# Path to the big jump (status 2026-11-01, checklist updated 20:15)

Where the program stands, what limits each metric, and the order of work that
gets both metrics down far enough to start the GPU port. Numbers are on the
12-block scored set unless stated; "est." marks estimates.

## Where we are (measured, exact outputs on all 15 blocks)

| Variant | instructions/gas | committed bits/gas | Promotable |
|---|---:|---:|---|
| Baseline Rust guest | 13.88 | 158,723 | yes |
| Rust guest, track C on this branch | 13.18 | 151,710 | yes |
| Rust guest, lean track (`codex/rv64-guest-rust-lean`) | 9.93 | 118,986 | yes |
| evmone client (`client_evmone/`), admitted services | 8.32 | 101,192 | yes |
| evmone client + candidate memory, SHA-256, arith256_mod + input adapter | **5.65** | **78,849** | no (services not yet in the prover) |
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
| 7 | **CPU cells per instruction** (row width, LS row for aligned 8-byte accesses, range trims) | prover | the only route to <30,000 bits/gas at ~3 instr/gas |

Items 1-4 together: client from 8.3 to roughly 3.5-4.5 instructions/gas
(est.). With item 5: roughly 2.5-3. Items 6-7 decide whether committed bits
reach the ~25,000-30,000 range.

## Gates for every step

- Exact outputs on all 15 blocks (`bench.py run --set all`), holdout guard, scope check.
- New services: soundness argument, adversarial tests, services-lane fixture
  proof with a fresh receiver, then a Word16 prefix proof of block 24,628,607
  with a guest that uses the service.
- New client: Ethereum execution spec tests (EEST) and differential runs against
  the reth guest; licences recorded (ziskethone Apache-2.0/MIT, evmone
  Apache-2.0, intx Apache-2.0, blst Apache-2.0) with their notices.

## Checklist

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
- [ ] Ethereum execution spec tests on both clients, host and guest tiers (branch `codex/rv64-guest-prover-eest`, in progress)
- [ ] Port the Rust-lean techniques that apply (batch ECDSA vs supplied keys, witness node table, aligned MPT re-encode, register-resident dispatch) to the client
- [ ] Interpreter tuned for RV64IM: dispatch, jump-table address, U256 fast paths, cached JUMPDEST bitmaps (target interpreter 1.9 -> ~1.0 instr/gas)

### Move B: services
- [x] Six candidate services in the execution tool with tests and cost estimates; measured per family on the Rust guest (`bca94c643`, merged `228a6a38a`)
- [x] Candidate services measured on the evmone client: 5.65 instr/gas, 78,849 bits/gas (`519337489`)
- [ ] **SHA-256 compression service in the prover**: admitted profile `ethereum_services_v3`, truth AIR, bridge, services lane, receiver, fixture proof (branch `codex/rv64-guest-prover-sha256`; truth AIR committed `6645e7e76`)
- [ ] **Bulk-memory services in the prover** (aligned memcpy/memset, then memcmp) (branch `codex/rv64-guest-prover-bulk-memory`; bridge AIR committed `49576d8ce`)
- [ ] Guests routed to the admitted services; harness on `ethereum_services_v3` with measured costs in calibration.json
- [ ] arith256_mod service in the prover (MULMOD/ADDMOD/modexp)
- [ ] BN254 and BLS12-381 operations as candidates, then services
- [ ] Recursion-circuit support for each new service

### Move C: hygiene
- [x] Rust guest lean track: 9.93 instr/gas admitted, 12 measured commits (branch `codex/rv64-guest-rust-lean`, not merged; overlaps track C)
- [x] Track C on the PR branch: -5.05% (`6dba79ad1`)

### Prover cost (committed bits)
- [x] Keccak and memory cost model: Keccak at bits parity with ZisK; CPU cells per instruction is the binding limit (branch `codex/rv64-keccak-memory-cost`, `7c9362a3d`)
- [ ] Throughput-table Keccak AIR (-43% cells per call) and padding ladder
- [ ] Load/store width histogram to validate the aligned 8-byte LS row assumption
- [ ] CPU cells per instruction: row width, aligned 8-byte LS row, range trims (target ~91 cells per instruction)

### Promotion gates
- [ ] Word16 prefix proof of block 24,628,607 with a guest using the new services, fresh `verify-prefix`
- [ ] Complete-block proof and fresh `verify` with the new guest; exact committed cells replace the proxy
