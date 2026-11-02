# Move A: ziskethone/evmone client on the RV64IM guest (2026-11-01)

Branch `codex/rv64-guest-client-evmone`. Client: `autoresearch/benchmarks/guest_runtime/ethereum/client_evmone/`
(README there: licences, build, ABI mapping, design, gaps).

## Results (15-block basket, all guards pass, exact output on every block)

| Variant | scored instr/gas | scored bits/gas | all instr/gas | all bits/gas | promotable |
|---|---:|---:|---:|---:|---|
| Rust baseline | 13.881 | 158,723 | 13.462 | 153,942 | baseline |
| evmone, admitted, plain SSZ (`d79ebdd47`) | 8.467 | 103,597 | 8.198 | 100,356 | yes |
| evmone, admitted, adapter + Keccak memo (`1549143bb`) | 8.317 | 101,192 | 8.045 | 97,925 | yes |
| evmone, candidate mem+sha | 6.388 | 86,286 | 6.169 | 83,439 | no |
| evmone, candidate mem+sha+arith256_mod (`d79ebdd47`) | 5.808 | 81,276 | 5.651 | 78,972 | no |
| ... + arith256 for MUL | 5.778 | 81,117 | 5.623 | 78,821 | no |
| evmone, candidate, adapter + memo (`1549143bb`) | 5.653 | 78,849 | 5.494 | 76,522 | no |

Candidate bits use the sibling track's nominal costs (scratch harness copy).
Admitted: level L1 (8.61) reached. Candidate: level L2 (6.38) passed.

## Where the instructions go now (all blocks)

| Bucket | admitted /gas | candidate /gas |
|---|---:|---:|
| EVM interpreter (evmone dispatch, stack, intx) | 1.92 | 1.86 |
| SSZ request-root SHA-256 | 1.35 | 0.06 |
| memory functions + heap | 1.01 | 0.26 |
| witness trie / MPT / receipts | 0.83 | 0.83 |
| BN254 precompiles (ModArith) | 0.76 | 0.30 |
| state tables + host (ziskethone) | 0.57 | 0.57 |
| BLS12-381 / KZG (blst) | 0.46 | 0.46 |
| Keccak sponge glue | 0.43 | 0.43 |
| JUMPDEST analysis | 0.30 | 0.30 |
| secp256k1 glue | 0.22 | 0.22 |
| other / SSZ input | 0.20 | 0.20 |

## What moved the number (in order)

1. evmone's software ECDSA recover was 62% of a block: secp recovery on the
   admitted add/double services, then SSZ public keys as sender hints with one
   batched GLV verification (secp ~1.3 -> 0.2 /gas).
2. SHA-256: unrolled rounds, precomputed schedule of the 64-byte padding block
   (every SSZ node hash), duplicated-word rotations (-17% per compression).
3. Witness trie: decode each node once, tagged clean children, in-place
   mutation (encode/decode/copy -40%).
4. RV64IM data movement: aligned-word memcpy with masked head/tail, bytewise
   intx big-endian loads/stores (an RV64IM bswap64 is ~32 instructions),
   word-wise fixed-size key compares, 64-bit blst limbs.
5. Input adapter with verified recovery hints (-2.2% admitted, -3.2% candidate).
6. Keccak memo for <= 64-byte inputs (bits -0.6/-0.8%, instructions +0.3%).

## Measured, not pursued

- **Full zero-parse layout (ZEG0-style pre-walked trie).** All parse/decode work
  together is <= 0.5 instr/gas (witness RLP decode 0.28, trie walk 0.10,
  transaction RLP 0.10, SSZ/ZEG0 synthesis 0.02), and the guest would still have
  to verify it, so the upper bound is ~4-6%.
- **Fewer Keccak-f calls.** On block 24628595, 54% of permutations hash witness
  nodes and 27% hash contract code: every node and code is used and hashed
  exactly once, and only dirty paths are re-hashed. Repeated <= 64-byte inputs
  are ~6% of permutations (now memoized).
- **-O3** is identical to -O2 under zig.
- **evmone ModArith** is ~328 instructions per 256-bit Montgomery product,
  close to what RV64IM carry chains allow (no carry flag).

## Lessons

- The tamper test found a soundness bug: execution-result fields of the SSZ
  payload (state/receipts root, bloom, gas) were never compared because the
  pipeline builds the header from computed values. Any client that derives its
  own header must check every payload field explicitly.
- Host profiles hide RV64 costs: arm64 inlines align-1 copies that RV64
  (strict alignment) turns into memcpy calls. Use the guest PC profile, counts
  at call instructions give exact call-site frequencies.
- `bench.py attribute` keeps the top 60 functions; diff full PC attributions.
- What remains is structural: evmone's interpreter on 64-bit limbs, the SSZ
  statement hash and precompile arithmetic. Bigger moves need services: SHA-256
  and bulk memory (already candidates), arith256_mod (pays on this client), and
  by measured share Keccak absorb (0.43), JUMPDEST bitmap (0.30), BLS12-381 (0.46).

## Trie, receipts and state track (branch `codex/rv64-guest-client-trie-state`)

Rust-lean techniques ported to the client's witness trie, receipts and
ziskethone's state tables. Admitted profile with the input adapter, all 15
blocks exact, all guards pass (ledger lines `A_client_trie_state`):

| Step | scored instr/gas | scored bits/gas | all instr/gas |
|---|---:|---:|---:|
| start (`b7ab408e3`) | 8.317 | 101,192 | 8.045 |
| witness node table, in-place digests, tagged witness items, run-copy re-encode (`294c1b153`) | 7.874 | 96,752 | 7.615 |
| lazy branch children, packed leaf paths, no ZEG0 zero-fill (`fbd90327e`) | 7.746 | 95,472 | 7.493 |
| word-wise seeded hash and fixed-size compares (`b4f3f14f3`) | 7.592 | 93,925 | 7.341 |
| single-buffer signing pre-image (`40b1ee025`) | 7.518 | 93,183 | 7.269 |
| evmc word equality, Keccak lanes without memset (`09fa419bb`) | 7.448 | 92,479 | 7.199 |
| bit-iterated re-encode, word leaf compares, SWAR calldata count (`22f1b9871`) | 7.387 | 91,866 | 7.140 |
| evmc host trampolines without argument copies (`5147287d4`) | 7.261 | 90,607 | 7.015 |
| open-addressing account/storage row index (`0046938cb`) | 7.201 | 89,997 | 6.955 |
| word bloom OR, word storage-key construction (`e39f2bbd8`) | 7.160 | 89,590 | 6.916 |
| lazy branch scan, SWAR key unpack (`cdafa2151`) | **7.140** | **89,387** | 6.896 |

Candidate profile (mem+sha+arith, nominal costs) at `cdafa2151`: scored 4.706
instr/gas, 68,856 bits/gas (from 5.653 / 78,849).

Buckets (all blocks, admitted, instr/gas), start -> end: witness trie / MPT /
receipts 0.825 -> 0.388; state tables + host 0.569 -> 0.430; memory functions
+ heap 1.010 -> 0.697; other 0.179 -> 0.037; "EVM interpreter" 1.921 -> 1.796
(that bucket's regex includes the evmc::internal host trampolines, which are
host glue). The rest is unchanged.

Lessons:

- Every alignment-1 evmc array access is a byte loop on RV64IM: struct copies
  (the host trampolines copied 52 bytes per SLOAD), `load64le` compares,
  memcpy-to-word hashing. Funnel loads of the aligned words that hold the
  bytes cost ~8 instructions per word instead of ~25.
- Branch re-encoding should reuse the witness encoding: copying the runs of
  unchanged child items cut the encoder's memcpy calls from 1.11M to 0.29M.
- A loop over 16 branch positions to find one or two modified ones costs more
  than the copies; iterate set bits (de Bruijn index, no ctz on RV64IM).
- The signing-hash pre-image built from ~10 temporary vectors per
  transaction was the largest "other" item (vector insert 0.083/gas).
- Not pursued / small: lazy branch scanning gained only 0.008/gas (the
  rolled scan loop costs more per child than the unrolled one it replaced);
  presizing the flat index from the gas-limit hint would zero megabytes per
  block for a rehash cost of ~0.005/gas.
- Batch ECDSA verification against the supplied keys was already in place
  (glue/secp256k1_stwo.cpp); nothing to port.

Attribution to ZisK's ziskethone (Apache-2.0/MIT) and evmone (Apache-2.0).
