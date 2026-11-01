# Path to the big jump (status 2026-11-01)

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
