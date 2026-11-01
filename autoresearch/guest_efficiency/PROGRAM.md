# RV64 Ethereum guest efficiency program

**Goal:** cut the work our RV64 Ethereum guest asks the prover to do per unit of
gas, until we match and then beat ZisK on the same blocks. The prover can only
prove what the guest executes; today the guest, not the arithmetization, is the
largest gap.

## Where we start (measured)

Same 15 mainnet blocks, same witnesses, outputs verified on both sides
(`vectors/reports/rv64-ethereum-20261101/guest-steps-comparison-v1.json`):

| Guest | instructions or steps per gas |
|---|---:|
| Ours: reth stateless-validator + revm, RV64IM, `ethereum-services-v2-lean` | 13.46 |
| ZisK reth guest (ZisK ops, with bit-manipulation and DMA) | 6.21 |
| ziskethone, C++ + evmone (3 blocks) | 2.02 |

Per instruction we commit about half of ZisK's bits, but per gas we commit
1.75x more (`committed-work-comparison-v1.json`). On the scored basket the
harness baseline is **13.88 instructions/gas** and **158,724 committed bits/gas**.

Where our instructions go on block 24,628,607 (PC-histogram attribution):

| Bucket | Share |
|---|---:|
| EVM interpreter (revm) | 34.6% |
| memcpy/memset/memcmp + allocation | 20.8% |
| Merkle-Patricia trie + RLP | 15.9% |
| Software SHA-256 for the SSZ payload-request root | 10.8% |
| Software setup around secp256k1 service calls | 10.7% |
| Software setup around Keccak service calls | 3.4% |

Keccak and secp **service call counts already match ZisK's precompile counts**,
so the gap is ordinary instructions.

## Metrics and targets

The harness (`bench.py`) is exact and deterministic. Primary metric:
**instructions per gas** on the scored set (total instructions / total gas).
Co-metric: **committed bits per gas**, a frozen linear proxy calibrated on the
schema-7 complete-block proof (`calibration.json`). Levels (`targets.json`):

| Level | instructions/gas | committed bits/gas | Meaning |
|---|---:|---:|---|
| baseline | 13.88 | 158,724 | today |
| L1 Part 1 hygiene | 8.61 | 98,409 | remove ~38% of instructions |
| L2b ZisK committed parity | 8.32 | 95,174 | commit no more bits/gas than ZisK's production block |
| L2 ZisK reth parity | 6.38 | 72,965 | match ZisK's reth guest |
| L3 ziskethone parity | 2.02 | 23,094 | match the evmone client |
| L4 supersede | 1.50 | 17,152 | beat ziskethone by >25% |

Because our per-instruction cost is half of ZisK's, **reaching L1 already
reaches committed-bits parity with ZisK**, and L3 would commit about 4x fewer
bits per gas than ZisK does today.

## Part 1: guest hygiene (stays on the current client)

All of these keep the public output (43 bytes) and the service ABI unchanged.

1. **SSZ payload-request root (10.8%).** The guest hashes the full
   `NewPayloadRequest` with software SHA-256. Options in order of preference:
   - Optimise the software SHA-256 for RV64IM: 32-bit rotates via 64-bit shifts,
     full unrolling, word-aligned message schedule, no per-byte copies.
   - Avoid re-hashing: hash each SSZ subtree exactly once, reuse transaction
     roots, and stream directly from the input buffer.
   - A SHA-256 service is the large win but changes the prover (new truth AIR).
     That is a proposal, not a loop edit (see "Out of scope for the loop").
2. **Bulk memory (20.8%).** `mem/` already has aligned-only fast paths.
   Extend to unaligned word copies with shift-merge, 8-way unrolled loops,
   `memcmp` by 64-bit words, and cut copies at the source: avoid `Vec` growth
   reallocation (`with_capacity`), avoid cloning `Bytes`/`U256`, and borrow
   from the input buffer instead of copying (zero-copy SSZ decoding).
   Allocator: the exact-layout allocator is already lean; measure `alloc` vs
   `memcpy` separately with `bench.py attribute`.
3. **secp setup (10.7%).** Recovery runs GLV on service add/double packets.
   Remaining software: scalar decomposition, field inversion, wNAF recoding,
   affine conversions, and signature parsing. Use batch inversion across all
   transactions in a block, precomputed tables for the generator, Jacobian
   coordinates throughout, and a single final normalization per signature.
4. **Keccak glue (3.4%).** Absorb directly from aligned input words; avoid
   intermediate buffers for MPT node hashing.

## Part 2: reach ZisK's reth-guest efficiency (L2) on the current client

Remaining gap after Part 1 is mostly EVM interpreter and MPT/RLP.

- **revm dispatch:** the vendored `revm-interpreter` already has patches.
  Look at gas accounting, stack bounds checks, `U256` arithmetic (use 64-bit
  limb fast paths for small values), memory expansion, and opcode table
  dispatch. Compare per-opcode instruction cost against ZisK's reth guest using
  the same blocks.
- **MPT/RLP:** decode witness nodes once into a compact arena, avoid re-encoding
  for hashing where the witness already contains the encoding, and cache node
  hashes. The vendored `zeth-mpt` is the place.
- **Compiler settings:** `opt-level=3` vs `s`, LTO, codegen-units=1, and
  `target-cpu` features available in RV64IM only. No B or Zbb: our executor is
  RV64IM.
- **State access:** pre-index the witness into a hash map keyed by address and
  slot to avoid repeated trie walks.

## Part 3: an evmone-class client (L3 and L4)

**Yes, we can use evmone and iterate on it, and this should start now in
parallel with Part 1.** The 4x gap between ZisK's own reth and evmone guests
says the client design, not the zkVM, dominates. The ready-made reference is
ziskethone, a C++ stateless verifier using evmone v0.24 with its own state DB
and MPT and a zero-parse binary input. It commits the same public value our
guest does: the EIP-8025 `new_payload_request_root`. It is dual
Apache-2.0/MIT; evmone is Apache-2.0. **Both licences must be confirmed by
legal before any code is copied into this repository.**

What "just use evmone" actually involves:

1. **It is the whole client, not just the interpreter.** The EVM interpreter is
   35% of our instructions; the rest is state access, MPT, RLP, signature
   recovery and statement hashing. ziskethone's gain comes from all of these.
2. **Toolchain:** C++20 freestanding for `rv64im`/`lp64`
   (`riscv-none-elf-gcc` 14 or 16, or clang), static link, our `linker-wide.ld`,
   our entrypoint and halt/output ABI.
3. **Precompile mapping:** ZisK CSR precompiles (keccakf, secp256k1 add/dbl,
   arith256, bn254, DMA memcpy) become our ECALL services where they exist
   (Keccak-f, secp add/double) and software elsewhere. ZisK's single-step DMA
   and Zbb are not available on RV64IM; expect more than 2.02 instructions/gas
   at first.
4. **Input:** keep our public output identical. The private input may change
   format (ZEG0 is zero-parse), but the harness basket must then gain a
   converter from the ZisK reth fixtures and the host validator must cover the
   new format. Until then the C++ client consumes our canonical SSZ.
5. **Correctness is soundness.** The prover proves whatever the guest computes;
   a consensus bug yields valid proofs of a wrong state transition. Gate with:
   the 15-block basket (exact output), the EEST corpus that ziskethone runs,
   and differential testing against the reth guest on every block.

Suggested sequence: build ziskethone's guest unmodified for RV64IM with
software Keccak/secp and measure instructions/gas on the basket (expect a
large gain immediately), then wire our Keccak and secp services, then optimize.

## Out of scope for the loop (proposal-only)

These change the prover's AIR, transcript or statement and need a design gate,
soundness review and prover work. Write them under `proposals/`:

- A SHA-256 service (truth AIR plus bridge) for the SSZ root.
- A bulk-copy (DMA-style) service.
- A full ECDSA-recovery service.
- Larger input windows than 16 MiB, or changes to the 43-byte public output.

## Gates before a guest is adopted for proving

1. `bench.py run --set all`: all guards pass (exact output on every block,
   determinism, per-block regression <= 2%, holdout generalises).
2. `bench.py check-scope --base <base>`: only editable paths changed.
3. Word16 prefix proof of block 24,628,607 with the new ELF plus a fresh
   `verify-prefix` receiver (heavy; run under the heavy-run lock).
4. Complete-block proof and fresh `verify` for the promotion receipt, with
   exact committed cells from `cost.json` replacing the proxy.
