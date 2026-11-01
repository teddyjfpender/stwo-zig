# Interpreter tuning on RV64IM (evmone client, 2026-11-01)

Branch `codex/rv64-guest-client-interpreter`, admitted profile
(`ethereum_services_v2`), input adapter on, `--set all`, all guards pass and
exact output on all 15 blocks for every kept step. Client:
`autoresearch/benchmarks/guest_runtime/ethereum/client_evmone/` (patches
0005-0017). Ledger: `ledger/attempts.jsonl` (track A, this branch).

## Result

| | scored instr/gas | scored bits/gas | holdout instr/gas | all instr/gas |
|---|---:|---:|---:|---:|
| Start (`b7ab408e3`) | 8.317 | 101,192 | 6.941 | 8.045 |
| End (`0389489f8`) | **7.978** | **97,792** | 6.648 | 7.715 |
| Change | -4.1% | -3.4% | -4.2% | -4.1% |

Buckets on all 15 blocks (instructions per gas):

| Bucket | start | end |
|---|---:|---:|
| EVM interpreter (dispatch, handlers, intx; also the evmc host thunks, ~0.11) | 1.921 | 1.659 |
| JUMPDEST analysis | 0.299 | 0.265 |

The ~1.0 target for the interpreter was not reached; see "What is left".

## Kept changes (scored instr/gas after each)

| Commit | Patch | Change | scored |
|---|---|---|---:|
| `8de712318` | 0005, 0006 | aligned big-endian word transfers: mask swap, frameless MLOAD/MSTORE fast paths, funnel CALLDATALOAD | 8.218 |
| `7ef0a2f89` | 0007 | gas tested on the decremented value (addi + bltz) | 8.173 |
| `4df328f18` | 0008 | sentinel JUMPDEST scan over the padded copy | 8.151 |
| `c3947149f` | 0009, 0010 | column-wise uint256 multiply; native DIV/MOD for 64-bit operands | 8.095 |
| `a96ac204d` | 0011 | constant gas returned on a failed requirement (removes a `mv` per opcode) | 8.073 |
| `093daa84d` | 0012 | MLOAD/MSTORE fast paths inlined into the dispatch | 8.065 |
| `92caea937` | 0013 | host storage/log calls take `&msg->recipient` (no 20-byte temporaries) | 8.032 |
| `6ffb71409` | 0014 | JUMPDEST scan unrolled by four (committed as a forced WIP checkpoint) | 8.020 |
| `64f87c95f` | 0015 | aligned-word context loads (CALLER, CALLVALUE, ...) with the mask swap | 8.001 |
| `dac061eca` | 0016 | fused-jump stack bounds as pointer compares | 7.986 |
| `0389489f8` | 0017 | LT/GT/SLT/SGT + PUSH2 + JUMPI fused (stwo build only) | 7.978 |

## Cost per opcode (instructions, all 15 blocks, inline + out-of-line handler)

| Opcode | count | start | end |
|---|---:|---:|---:|
| PUSH1 | 2.19M | 18 | 16 |
| PUSH2 (incl. fused jumps) | 1.57M / 1.38M | 33.2 | 28.8 |
| POP | 1.30M | 12 | 10 |
| SWAP1 | 1.15M | 27 | 25 |
| DUP2 | 1.01M | 21 | 19 |
| ADD | 0.96M | 38 | 36 |
| MSTORE (47% grow memory) | 0.56M | ~112 | ~102 |
| ISZERO (incl. fused) | 0.50M | 36.8 | 34.1 |
| JUMP (fused, incl. JUMPDEST) | 0.47M | 33 | 31 |
| MLOAD | 0.44M | ~153 | ~89 |
| CALLDATALOAD | 0.14M | ~155 | ~116 |
| PUSH32 | 0.12M | 108 | 106 |
| MUL | 0.10M | 211 | 67 |
| SLOAD | 0.09M | ~336 | ~185 |
| CALLER / CALLVALUE | 29k / 21k | 129 / 126 | 63 / 75 |

Average in `dispatch_cgoto`: 27.8 -> 28.1 instructions per dispatched opcode
(more work moved inline: MLOAD/MSTORE, fused compares); dispatched opcodes
17.90M -> 17.71M. Per-opcode overhead now: 6 for dispatch (addi, lbu, slli,
add, ld, jr), 2 for gas, 1-2 stack checks, 1 stack-pointer update.

Method: opcode counts from the PC profile at each `cgoto_table` target
(read from the ELF), per-opcode cost by assigning `dispatch_cgoto` PCs to the
nearest preceding handler label (approximate where LLVM shares tails).

## Measured, not kept

| Attempt | scored | Why |
|---|---:|---|
| intx aligned swap, outlined | 8.286 | result through an sret temporary + frame; superseded |
| sentinel scan v1 | 8.208 | LLVM kept a copy of the opcode address (4 instr/opcode) |
| inline memory growth in MLOAD/MSTORE fast path | 8.141 | callee-saved spills on every call |
| inline memory growth in check_memory | 8.115 | slow path grew more than grow_memory + memset saved |
| `-Os` everywhere | 14.181 | ModArith/addmul outlined (+66%); G4 fails |
| PUSHn via funnel-shifted aligned code words | 8.020 | PUSH32 -6, PUSH20 +2, PUSH8 +5: net zero |
| word-store zeroing in Memory::grow | 8.035 | grow outlined; memset was not the cost |

Not tried, by estimate: per-basic-block gas and stack checks (evmone
advanced style) saves ~3-4 instructions per opcode (~0.12/gas) but needs
per-block costs, and a full analysis scan already costs 0.265/gas against
17.7M executed opcodes on 24M scanned ones; a lazy, per-JUMPDEST cache is the
only form that could pay. The advanced interpreter has the same problem
(heavier analysis per contract per block). Lazy JUMPDEST validation (backward
32-byte check per target) is about break-even by the Rust-lean measurement.

## Checks beyond the basket

- Scratch host tests: column multiply vs intx's generic loop on 3M random and
  edge-case operand pairs; sentinel scan vs upstream's scan on 200k random
  codes (truncated trailing PUSH, lengths 0-299, padding restored); funnel
  big-endian load at all 8 alignments. All identical.
- ziskethone's fused-dispatch differential fuzzer
  (`cpp-guest/test/fused_dispatch_difffuzz.cpp`), extended to emit
  LT/GT/SLT/SGT before PUSH2 JUMPI, linked against the host build with patches
  0001-0017: 1,000,000 programs, 0 mismatches against the switch dispatch; a
  swapped-operand LT mutant gives mismatches within 100,000 programs. Host
  builds do not compile the `__riscv`-only paths (gas barrier, halt gas, byte
  swaps).
- No EEST run.

## What is left in the interpreter (1.66/gas)

`dispatch_cgoto` 1.12, JUMPDEST analysis 0.27, host thunks (state code) ~0.11,
MSTORE growth path 0.05, division 0.06, SLOAD/CALLDATALOAD 0.07. The handlers
are near their RV64IM floor: a DUP is 8 memory operations plus ~11 overhead, a
SWAP 16 plus ~9, a 256-bit ADD 15 ALU plus 12 memory. Getting to ~1.0 needs a
structural change, in order of expected value:

1. Zbb in the candidate ISA (`rev8` makes every 256-bit transfer 4 x ld + rev8;
   `andn`/`orc.b`/`clz` help the JUMPDEST scan and SIGNEXTEND/BYTE).
2. Per-basic-block gas and stack checks computed lazily at first entry to a
   JUMPDEST block and cached per code hash (-3 to -4 instructions per opcode).
3. Top-of-stack in registers for the fused jump paths (no store/reload of
   the condition word).
