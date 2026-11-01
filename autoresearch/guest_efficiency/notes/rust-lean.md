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

## Kept (cumulative 104.26M -> 72.11M, scored 13.880 -> 9.925)

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
| Keccak glue: first block assigned, volatile zero lanes (no memset) | 75.17 -> 74.43 |
| revm: register-resident loop (ip/gas/stack len in locals) for stack/jump/ALU ops | 74.43 -> 73.19 |
| zeth-mpt: unresolved children as tagged references into witness bytes | 73.19 -> 72.11 |

Final `--set all` (ELF sha256 52378ad0...): scored 9.925 instr/gas (118,986 bits/gas),
holdout 8.360 (100,380), all 9.616 (115,313); all guards pass, promotable.
Final attribution: notes/rust-lean-final-attribution-24628607.json.

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

## Transfer to the C++ (evmone-class) client

- Witness node table: hash each witness node once into an open-addressing
  table keyed by digest prefix with the 32-bit tag beside the index; probe
  every branch child inline; keep unresolved children as pointers into the
  witness bytes (no per-child allocation or copy).
- MPT re-encode: build modified branch encodings in an aligned u64 word
  buffer, digests moved as four aligned words, hash straight from it.
- Register-resident EVM loop: ip, gas and stack length in locals for the hot
  stack/jump/ALU opcodes, sync only around complex opcodes; dense 0x00..0xff
  dispatch table. evmone's own loop already resembles this; check its
  RV64IM codegen for jump-table rematerialization.
- Keccak init: assign the first absorbed block, zero only capacity lanes,
  volatile stores so the compiler does not reintroduce memset.
- Also client-independent: ECDSA batch verification against supplied keys
  (no sqrt, one inversion per block per kind), SHA-256 compress with
  doubled-word rotates and a constant padding-block schedule, sentinel
  jumpdest scan, big-endian limb loads without LLVM's generic byte swap.

## Next candidates (measured shares at 75.17M; superseded by the wrap-up)

- EVM loop with stack pointer, ip and gas in locals for the hot opcodes
  (~17 dispatch instructions per op today; ~430k ops).
- MPT digest children without a Box per child (tagged pointers into the
  witness bytes): decode is ~6.6M incl. allocation.
- Keccak glue: first block absorbed by assignment, no 200-byte memset.
- secp: wNAF with a precomputed G table to cut service adds.

- Open at wrap-up: resolve_digests hit compare calls memcmp on an unaligned
  digest (~0.8M, 204 instr/call): compare as funnel-read words instead.
