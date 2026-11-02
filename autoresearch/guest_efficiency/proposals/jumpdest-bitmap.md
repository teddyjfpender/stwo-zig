# Proposal: JUMPDEST analysis service (`jumpdest_bitmap`, 0x0003_0040)

Status: **admitted in `ethereum_services_v3` on branch `codex/rv64-ge-jumpdest`**
(AIR, executor, collector, services lane, fixture with a fresh receiver;
design and soundness argument:
`design/riscv-proving-stack/rv64-jumpdest-service.md`). The candidate
measurement below motivated it; the admitted result is in "Admitted result".

## Motivation (measured)

evmone analyzes every executed contract once per block (analysis cache): a
byte walk that marks each `0x5b` outside PUSH1..PUSH32 data. On the v3 client
(`build.py --profile v3`, 4.538 scored instr/gas) the sentinel scan
(`analyze_into`, patches 0008/0014) is 0.265 instr/gas over all 15 blocks.
ZisK ships the same operation as a precompile (`jump_dest_bitmap`, CSR 0x81C;
ziskethone patch 05).

All runs: `bench.py run --set all`, input adapter on, executor and client built
from this branch, all guards G1-G6 pass, exact outputs on all 15 blocks.
Reference = v3 client run on `ethereum_services_v3` (promotable). Candidate =
the same v3 client plus `--candidate-jumpdest` run on
`ethereum_services_v3_candidate`. The candidate run prices the v3 services it
issues (memcpy, memset, sha256_compress, arith256_mod) with the measured
`admitted_services` entries (checked: the plain v3 ELF on the candidate
profile reproduces the v3 scores exactly, 4.538 / 64,578) and
`jumpdest_bitmap` with `candidate-jumpdest-costs.json`.

| Set | instr/gas v3 -> +jumpdest | committed bits/gas v3 -> +jumpdest |
|---|---|---|
| scored | 4.538 -> **4.257** (-6.2%) | 64,578 -> **61,851** (-4.2%) |
| holdout | 3.841 -> 3.637 (-5.3%) | 54,442 -> 52,464 (-3.6%) |
| all | 4.401 -> 4.134 (-0.266/gas) | 62,577 -> 59,998 (-4.1%) |

Usage on the 15 blocks: 4,365 calls, 42.53 MB of code (0.0955 bytes/gas,
9,743 bytes per call: the analysis cache means each contract is analyzed once
per block, and the big ones dominate). The software scan cost 2.79
instructions per code byte (~430 cells per byte at 154.8 cells/instruction);
the service is estimated at ~12 cells per byte.

At zero service cost the bits would be 61,754 (scored); the estimate adds 97
bits/gas. Even the pessimistic end of the range (25 cells/byte, 60,000 per
call) adds ~200, so the bits saving holds (-4.0%).

## Admitted result (merged head b83ca8577, 2026-11-02)

`bench.py run --set all`, profile `ethereum_services_v3` (promotable), all
guards G1-G6 pass, exact outputs on all 15 blocks. Reference = the v3 client
without the service (`--v3-set sha,arith,mem,umem,keccak`), which reproduces the
coordinator's baseline exactly; the new default `--profile v3` adds `jumpdest`.
JUMPDEST priced with `calibration.json admitted_services.jumpdest_bitmap`
(layout-exact from the verified fixture, table amortized; not yet a
complete-block cost.json).

| Set | instr/gas | committed bits/gas |
|---|---|---|
| scored | 4.060 -> **3.778** (-6.9%) | 54,544 -> **51,817** (-5.0%) |
| holdout | 3.440 -> 3.236 (-5.9%) | 46,051 -> 44,072 (-4.3%) |
| all | 3.937 -> 3.671 | 52,867 -> 50,289 |

4,365 calls, 42.53 MB of code on the 15 blocks.

## ABI

`a0` = 8-aligned packet of three LE u64 `code, len, bitmap`; `a7 = 0x0003_0040`;
all registers preserved; packet unchanged; one retired instruction.

- `code` 64-byte aligned, `bitmap` 8-byte aligned, `len` a nonzero multiple of
  8, `len <= 2^20`.
- Reads the `len/8` code words; writes exactly `ceil(len/64)` words at
  `bitmap`: bit `i % 64` of word `i / 64` is 1 iff `code[i] == 0x5b` and byte
  `i` is not immediate data of a PUSH1..PUSH32 at an earlier opcode position
  (data running past `len` is cut off). This is evmone's `BitsetSpan` layout.
- Code words, bitmap words and the packet are pairwise disjoint; every check
  precedes any write (a trapping call changes nothing). Reported `bytes` = `len`.

Why word granularity and 64-byte alignment: the proof then has no byte masks,
and the eight code words that feed one bitmap word share one address carry
(row base address limb 0 is a multiple of 64). The guest passes the code size
rounded up to 8 over evmone's zero-padded copy: zero bytes are never JUMPDESTs
and can only affect bits at or past the true size, which `check_jumpdest`
never reads (it returns false for `position >= code_size` first). The copy is
64-aligned inside its analysis-cache slot (ziskethone slot + 56 bytes, patch
0029); a misaligned copy falls back to the sentinel scan (none did on the
basket: all 4,365 analyses used the service).

Executor: `src/frontends/riscv/rv64/ethereum_services/candidate_jumpdest.zig`
(reference walk, random-code agreement test with an independent walk, trap
tests). Client: patches 0028 (evmone `baseline_analysis.cpp`) and 0029
(ziskethone slot size), `glue/services.hpp` `stwo::jumpdest_bitmap`, host
emulation in `glue/host_services.cpp`; `build.py --profile v3
--candidate-jumpdest` (ELF suffix `-cjd`, define `CANDIDATE_JUMPDEST`).
Without the define both patches are inert (v3 per-block instruction counts
identical on all 15 blocks).

## Cost model (estimate; replaced by measurement once built)

Rows per code byte decide the cost. Three layouts were compared (raw
MAIN+INTER cells, before power-of-two padding):

| Layout | cells per 64 code bytes | per byte |
|---|---:|---:|
| one row per byte, "remaining push bytes" counter | ~64 x 30 | ~30 |
| one row per code word, bitmap word accumulated in-row and written every 8th row | ~8 x 131 | ~16 |
| **one row per 64 code bytes (8 code reads, 1 bitmap write)** | **520** | **8.1** |

Chosen: the wide row. Per byte `k` of the row: the byte `b_k`, the pending
push-data counter `c_k` (bytes of PUSH data still to skip before byte `k`,
0..32) and the JUMPDEST bit `j_k`, tied by ONE lookup
`(c_k, b_k, c_{k+1}, j_k)` into a fixed transition table of 33 x 256 = 8,448
entries:

- `c > 0`: `c' = c - 1`, `j = 0` (data byte);
- `c = 0`, `0x60 <= b <= 0x7f`: `c' = b - 0x5f`, `j = 0` (PUSH opcode);
- `c = 0`, otherwise: `c' = 0`, `j = [b = 0x5b]`.

The lookup also range-checks every byte, so the code word limbs are
`b_{2i} + 256 b_{2i+1}` (affine, no extra columns). The counter chains across
rows (`c_0` = previous row's `c_64`, 0 on a call's first row). The written
bitmap limb `l` is `sum_{i<16} j_{16l+i} 2^i`, independently anchored (Boolean
table outputs), which is the RAM-writer case of the write induction.

Row (`jscan`): MAIN 288 = header 7 (active, start, last, epoch, tick lo/hi,
remaining words) + code address 4 + 3 carries + bitmap address 4 + 3 carries +
8 word-valid bits (last row) + 8 x (6 clock + 1 W bit) for the code reads + 64
bytes + 65 counters + 64 JUMPDEST bits + bitmap write before-value 4 + clock 6.
INTER 232: 109 fractions (64 table, 18 RAM14, 27 U16) in 55 paired QM31 inverse
slots, plus 3 relation prefixes. 520 / 64 = 8.13 raw, x 1/ln 2 = 11.7 per byte.

Per call: a descriptor row (`jdesc`, like bulk `desc`: 3 packet reads, ECALL
tuple, len and alignment decompositions, one token) ~112 raw, 162 padded; plus
the transition table (`jtab`, 2^14 rows x 17 cells = 278,528 per CPU proof that
calls the service), amortized over the basket's ~438 CPU proofs and 4,365
calls: ~27,950 per call. Entry: 28,400 per call + 11.8 per byte
(`candidate-jumpdest-costs.json`, with the range).

## Soundness sketch (for the prover build)

The bitmap must be exactly the canonical one for the RAM contents of the code
words at the call's clock:

1. Call authenticity, packet reads, token to the body run, RAM order and
   freshness: as bulk memory B1-B5 (`design/riscv-proving-stack/rv64-bulk-memory-service.md`).
2. Every code byte is classified: each valid byte position contributes one
   table lookup with weight = its word-valid bit; the table is fixed (in the
   fixed root) and the lookup relation closes per CPU proof, so every tuple
   `(c_k, b_k, c_{k+1}, j_k)` is a table row (multiplicities are prover
   chosen, mass < p).
3. PUSH data is skipped exactly: the counter is a chain through every byte of
   the call (start 0, carried across rows, each step a table transition), so by
   induction on the byte index `c_k` equals the number of pending data bytes of
   evmone's walk and `j_k = [b_k = 0x5b and c_k = 0]`, which is the canonical
   bit. A forged JUMPDEST inside push data needs `c_k > 0` with `j_k = 1`: no
   table row. A missing JUMPDEST needs `c_k = 0, b_k = 0x5b, j_k = 0`: no row.
4. Length: `remaining` counts code words down by 8 per row; the last row has
   `sum(valid) = remaining in [1, 8]` and every non-last row 8 valid words
   followed by a continuation, so the run reads exactly `len/8` words and
   writes `ceil(len/64)` bitmap words (as bulk B3). Invalid words have weight 0
   on their reads and lookups and `j = 0` (constraint), so the last bitmap word
   has zeros past `len`.
5. Truncated PUSH at the end: the counter after the last byte is unconstrained
   (no continuation), exactly evmone's cut-off.

Adversarial tests to build: forged JUMPDEST in push data, missing JUMPDEST,
wrong length (extra row, short run), truncated PUSH32 at the end, stale code
read, wrong bitmap word, bitmap written to a read-only word, misaligned code.

## Prover work

A bulk-style kind set (`jdesc`, `jscan`, `jtab`) inside the CPU proof, after the
bulk block (no truth proof, no tape payload: the ECALL step carries pointer and
tag), the services-lane wiring with claims omitted when absent (v2 and v3
bundles byte-identical), the executor's admitted path, then the v3 client
routed by `--v3-set ...,jumpdest` and measured cells into
`calibration.json` `admitted_services`.
