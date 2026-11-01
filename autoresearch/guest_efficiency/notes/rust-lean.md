# Move C on the Rust (reth/revm) guest: lessons

Branch `codex/rv64-guest-rust-lean`, admitted profile only (Keccak-f, secp add/double).
Block 24,628,607 instruction counts unless noted; scored = basket metric.

## Tooling

- `bench.py attribute` only gives self counts. A call-tree profile was essential:
  a scratch copy of the execution tool (`src/frontends/riscv/rv64`, outside the
  repo) with a shadow call stack (push on `jal/jalr rd=ra`, pop on `ret` to the
  matching return address) that writes `node parent target self calls` lines.
  Inclusive costs, callers of memcpy and per-call-site averages come from it.
  (The harness and these patches live in the session scratchpad, not in the repo.)
- `llvm-objdump` with RISC-V support: rustup `llvm-tools` of nightly-2026-03-04.
- Per-PC counts (`--keep-profiles`) + disassembly show the actual loops.

## Kept (cumulative 104.26M -> 75.17M, scored 13.880 -> 10.266)

| change | block delta |
|---|---|
| SHA-256: RV64IM compress (doubled-word rotates, volatile BE loads), constant schedule for the 64-byte padding block | 104.26 -> 101.02 |
| MPT: open-addressing witness table (`PrehashedNodes`), inline digest-child probes, decode resolved nodes into their box | 101.02 -> 93.18 |
| SparseState fields ManuallyDrop (no end-of-block teardown) | 93.18 -> 91.84 |
| revm: big-endian limb transfers for MLOAD/MSTORE/CALLDATALOAD/PUSHn | 91.84 -> 90.07 |
| zeth-mpt: funnel copy of child digests into boxes (no memmove) | 90.07 -> 88.10 |
| zeth-mpt memoize: branch re-encoding in an aligned word buffer, RlpNode as aligned digest | 88.10 -> 84.71 |
| jumpdest analysis: sentinel-terminated scan (5 instr/opcode) | 84.71 -> 83.13 |
| ECDSA: batch *verification* against the supplied public keys (no sqrt; one s-inversion and one Z-inversion per block) | 83.13 -> 76.34 |
| revm: inline dispatch of 38 hot opcodes behind a mainnet-table guard | 76.34 -> 75.17 |

## Lessons

- LLVM fuses byte loads into a little-endian word and then emits its generic
  byte swap (~45 instructions per u64) whenever code does `from_be_bytes` on
  unaligned bytes. Volatile byte loads, or aligned loads plus a mask swap with
  opaque masks, avoid it. Earlier notes calling MLOAD "bookkeeping" were wrong.
- The stateless input carries the sender public keys: verifying is far cheaper
  than recovering (no square root), and verification batches. Exactness
  argument is in `vendor/stateless/src/stwo_verify.rs`; differential harness
  in `notes/rust-lean-harness/`.
- Nearly every MPT branch child is a digest that is not in the witness: the
  probe for it must be cheap (no hash, no memcmp call, no recursive call).
- Lazy jumpdest analysis does not pay: jump targets cover ~95% of each
  contract's code; the per-JUMP check costs more than the scan saved.
- Caching the last hashed address in SparseState saved 481 Keccak-f calls but
  cost more instructions than it saved (20-byte compare + copy per call).
- A `match` dispatch only wins if it lowers to a dense jump table (cover
  0x00..0xff) and the bodies inline (`#[inline(always)]` on MLOAD/MSTORE/...).

## Next candidates (measured shares at 75.17M)

- EVM loop with stack pointer, ip and gas in locals for the hot opcodes
  (~17 dispatch instructions per op today; ~430k ops).
- MPT digest children without a Box per child (tagged pointers into the
  witness bytes): decode is ~6.6M incl. allocation.
- Keccak glue: first block absorbed by assignment, no 200-byte memset.
- secp: wNAF with a precomputed G table to cut service adds.
