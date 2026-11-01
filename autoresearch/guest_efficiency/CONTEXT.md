# Context: what the prover charges the guest for

Read this before changing anything. Every decision in this program is a trade
between instructions the guest executes and the cost of what the prover has to
commit to prove them.

## The machine the guest runs on

- **ISA:** RV64IM, LP64, single thread, no A, C, F, D, B or Zbb extensions.
  Anything outside RV64IM costs ordinary instructions (a 64-bit rotate is about
  three instructions; a byte-population count is a loop).
- **Services:** the only accelerators are ECALL services. Today the prover
  admits exactly two families (`execution_profile = ethereum_services_v2`):
  - Keccak-f[1600] in place: `a0` = pointer to 25 little-endian u64 lanes,
    `a7 = 0x0001_0001`.
  - secp256k1 projective add/double on word packets: `a0` = 32-byte-aligned
    packet of little-endian u64 limbs, `a7 = 0x0002_0011` (add) or
    `0x0002_0012` (double). See `ethereum/rv64/service_abi/src/lib.rs`.
  All registers are preserved; only the packet changes.
- **I/O:** input window at `__input_start` (u32 length + canonical SSZ
  `StatelessInput`), 43-byte output (request root 32, success 1, chain id 8 LE,
  schema id 2 LE), `__halt_flag`. Window 4 or 16 MiB.

## What the prover commits (calibrated on the schema-7 complete block)

| Item | Cells | Bits at the LDE (x62) |
|---|---:|---:|
| One retired RV64IM instruction (CPU proof incl. LS/ALU/memory share) | 154.8 | 9,598 |
| One Keccak-f call (truth proof, padded) | 72,159 | 4.47 M |
| One secp add or double (truth proof, padded) | 18,935 | 1.17 M |

So a Keccak-f call costs about as much as **466 instructions**, and a secp
operation about **122 instructions**. A service only pays when it replaces more
instructions than that. ZisK's single-step DMA and bit-manipulation ops are
cheap because they are designed in from the start; ours must earn their AIR.

## What it costs to add a service to the prover

A new service is a protocol change, not a guest change:

1. A truth AIR proving the operation (like `air/delegations/keccak` or
   `secp256k1`), degree <= 3 on the 2n domain or its own PCS.
2. A bridge that joins the guest's packet reads and writes into the global RAM
   argument, plus IO/Wire lookups between CPU and truth proofs.
3. A soundness argument and adversarial tests, then complete-block
   qualification with a fresh receiver.
4. Support in the recursion circuits.

Each is weeks of prover work. That is why the loop measures a candidate's value
**before** anyone builds it.

## Candidate services: measure before you build

Profile `ethereum_services_v3_candidate` is execution-only. The execution tool
implements these services; the prover does not. Results using it are reported
but never promotable. Their committed-bits cost comes from estimated entries in
`calibration.json` `candidate_services`, each with its derivation.

ABI (same convention as the admitted services: `a0` = packet pointer, 8-byte
aligned; `a7` = tag; all registers preserved; packet updated in place):

| Tag | Name | Packet (little-endian u64 fields) | Semantics |
|---|---|---|---|
| `0x0003_0001` | `memcpy` | `dst, src, len` | copy `len` bytes, memmove-safe |
| `0x0003_0002` | `memset` | `dst, byte, len` | fill `len` bytes with `byte & 0xff` |
| `0x0003_0003` | `memcmp` | `a, b, len, result` | `result` = -1, 0 or 1 by first differing byte (as signed i64) |
| `0x0003_0010` | `sha256_compress` | `state[8]` as u32 pairs packed in 4 u64, then 64 message bytes | one SHA-256 compression; state words are the standard big-endian-defined u32 values stored little-endian |
| `0x0003_0020` | `arith256` | `a[4], b[4], c[4], lo[4], hi[4]` | `hi:lo = a*b + c` (512-bit) |
| `0x0003_0021` | `arith256_mod` | `a[4], b[4], c[4], m[4], r[4]` | `r = (a*b + c) mod m`; `m = 0` gives `r = 0` |

The execution tool reports `candidate_service_calls: {name: {calls, bytes}}`.
Adding a new candidate means: an ABI row here, an executor implementation, a
cost entry with derivation, and a proposal under `proposals/`.

## Correctness is soundness

The proof attests to whatever the guest computes. A faster EVM that disagrees
with consensus on some block produces a valid proof of a false state
transition. Every change keeps exact outputs on the basket; a client
replacement additionally needs the Ethereum execution spec tests (EEST) and
differential runs against the reth guest.

## Reference points

- ZisK reth guest: 6.21 steps/gas; ziskethone (C++, evmone v0.24, own state DB
  and MPT, zero-parse input): 2.02 steps/gas. Both use ZisK DMA ops and Zbb.
- Our guest today: 13.46 instructions/gas. Buckets on block 24,628,607: EVM 34.8%,
  memory and allocation 20.5%, MPT/RLP 17.3%, SSZ SHA-256 10.8%, secp glue
  10.8%, Keccak glue 3.4% (`notes/baseline-attribution-24628607.json`).
