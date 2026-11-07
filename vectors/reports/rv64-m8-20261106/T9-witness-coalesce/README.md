# T9: witness generation — coalesced Keccak MAIN, privatised histograms, base G parameter fix (round 2)

Branch `codex/rv64-m8-opt-T9-witness-coalesce`.
Owned files (claim in `/workspace/m3/M8-INTERFACES.md`):
- `src/backends/cuda/native/rv64/keccak_witness.cu`
- `src/backends/cuda/native/rv64/bridge_witness.cu`
- `src/backends/cuda/native/circuit/base_witness.cu`

Entry points, structs and ABI are unchanged. The flag-off kernels are unchanged:
- `keccak_witness` and `bridge::witness` keep their original text.
- `circuit_base::generate<K>` gains an unused, defaulted `nullptr` argument. Its SASS has the same 680 B stack frame.

Selection is `STWO_RV64_M8_WITNESS_COALESCE=1`. It is off by default and read once per process, in each file's host entry. So the default path and the GPU-native job path both pick it up by env alone.

## What changed

### `keccak_witness` (the biggest item)

The census2 diagnosis was right: each 4-byte store goes to a bit-reversed physical row. A store instruction touches 25 sectors, and the 8 rows of one 32 B sector come from logical rows n/4 apart. So DRAM sees a read-modify-write for every 4 bytes [M: 18–20 GB/s effective].

The brief's plan (physical-row tiles of one pair in shared memory) does not work as stated. 32 consecutive physical rows are logical rows about n/32 apart, so they belong to 32 different pairs spread over the whole trace. One CTA never owns a physical tile. The work is therefore split into two coalesced passes:

1. **`keccak_witness_staged<Count>`** (4 warps, 47.7 KB static shared memory)
   - Each warp runs its pair's permutation as `keccak_witness` does. The lookup events are verbatim, in a shared `keccak_events` helper.
   - It stages the 25 distinct states and 24 parities in shared memory.
   - The CTA then writes its 4 pairs' rows in **circle order**: even logical rows ascend from row/2, odd rows descend from n-1-row/2. So every warp store is 32 consecutive words.
   - All 1,923 columns of an active row are written, zeros included.
2. **`keccak_bitrev`**: an in-place circle → bit-reversed physical permutation of each column.
   - Both 32×32 tiles of a (m, brev(m)) pair are read into shared memory before either is written.
   - Loads and stores are coalesced, and the shared tiles are padded against bank conflicts.
   - Circle rows that were never written are read as zero, so the 1,923 × 2^log MAIN `memset` is dropped.
   - `keccak_bitrev_small` handles log < 10.
3. **Policy 1 (`triple_v2`, pair29) lookup counts.**
   - chi has 2^13 bins and xor5 has 2^10. Global atomics on them contend (about 46k events per pair).
   - `keccak_witness_counts` privatises both in 36 KB of shared memory (2 CTAs/SM) and runs as a persistent grid. It flushes each nonzero bin once, to `keccak_physical(bin)`.
   - The overflow status is unchanged: an increment saw ≥ 0x7ffffffe ⇔ the final total is ≥ 0x7fffffff ⇔ some flush ends there.
   - Policy 0's tables (2^21 and 2^16 bins) do not fit in shared memory, so it keeps the original global atomics, inside the staged kernel.

### `bridge::witness`

- `witness_private` keeps `range8` (256 bins) in a per-CTA shared histogram and flushes it once per nonzero bin.
- `range16` keeps the warp-aggregated global atomics.
- Invalid rows behave exactly as before. The padding mass is skipped when row 0 is invalid, as the original early `return` does.

### `circuit_base::generate<4>` (Blake G)

- `xor_count` relation 2 indexes `columns.counts[column]` with a runtime column. ptxas therefore copies the whole 680 B `Columns` kernel parameter to a per-thread stack frame [M: ptxas `-v` reports 680 B of stack for `generate<4>` and 0 B for every other kind].
- `generate_shared` stages the 16 relation-2 pointers in shared memory instead. Its stack frame is 0 B.
- It makes the same rows and the same atomics.
- Diagnosis [M, 2^22 rows]:
  - with the relation-2 atomics removed (an experiment copy), the time drops from 8.79 ms to 1.54 ms;
  - standalone, the same 8M relation-2 atomics into the 64 MB table take 1.24 ms;
  - streaming stores (`__stcs`) and streaming loads gave no change (8.35 ms).

## Parity [M]

Each bench binary includes the product `.cu` and toggles the flag in-process.

| bench | inputs | compared | result |
|---|---|---|---|
| `keccak_bench.cu selftest` | 100 shapes: both policies; log 5–17; calls 1, 2, 3, 7, 8, 9, max−1, max; all-zero and all-ones states; MAIN poisoned with 0xab before the coalesced run (tests the dropped memset) | MAIN, chi, xor5, status | bit-exact |
| `bridge_bench.cu selftest` | valid synthetic predecessors (uniform and zero-heavy "skew"); kinds 0 and 1; 1/4/6 coordinates; 0/1/max calls; log 5–16; plus 2 corrupted inputs | MAIN, range16, range8, status | bit-exact (status 1/1 on the corrupted cases) |
| `base_bench.cu selftest` | all 5 components; log 4–18; random, local and skewed address/value patterns | every out column, all 22 count tables, error | bit-exact, error 0 |

In `base_bench.cu`, comp 2 rows satisfy w3 = w0^w1^w2. Comp 4 rows satisfy the Blake G relations (w9 = rotr8(w6^xr16), w7 = rotr7(xr12^w8)), so every lookup is counted.

## Microbenchmarks (CUDA events; reference and T9 interleaved in one process on the same inputs; RTX 5090, GPU 0) [M]

| kernel / shape | reference median (min–max) | T9 median (min–max) | × |
|---|---|---|---|
| keccak policy 0, log 17, 9,708 calls (2^17 MAIN, 1.01 GB), 7 reps | 56.05 ms (56.03–56.09) | 3.30 ms (3.30–3.31): staged 1.94 + bitrev 1.33 | 17.0 |
| keccak policy 1, log 17, 9,038 calls, 7 reps | 53.27 ms (53.19–53.30) | 3.64 ms (3.62–3.69): counts 1.18 + staged 1.02 + bitrev 1.32 | 14.6 |
| keccak policy 1, log 15, 2,258 calls, 7 reps | 11.64 ms (11.51–11.72) | 0.83 ms (0.83–0.89) | 14.0 |
| keccak policy 0, log 15, 2,426 calls, 7 reps | 12.67 ms (12.64–12.69) | 0.72 ms (0.71–0.73) | 17.6 |
| bridge kind 1, 2^16 rows, 4 coordinates, 7 reps | 0.743 ms (0.743–0.745) | 0.088 ms (0.085–0.092) | 8.4 |
| bridge kind 1, 2^16, skew | 0.333 ms | 0.083 ms | 4.0 |
| bridge kind 0, 2^16 rows, 7 reps | 0.212 ms | 0.051 ms | 4.2 |
| bridge kind 0, 2^18 rows | 0.850 ms | 0.213 ms | 4.0 |
| base comp 4, 2^22 rows, random addresses, 7 reps | 8.29 ms (8.28–8.30) | 3.48 ms (3.48–3.48) | 2.4 |
| base comp 4, 2^22, local addresses | 6.57 ms | 3.02 ms | 2.2 |
| base comp 4, 2^22, skewed values | 11.36 ms | 7.99 ms | 1.4 |
| base comp 4, 2^16 rows | 0.080 ms | 0.035 ms | 2.3 |

Notes:
- **bitrev runs at bandwidth.** It moves 2 GB in 1.33 ms, about 1.5 TB/s.
- **Policy 0's staged pass is 1.0 ms without its counts.** The remaining ~0.9 ms is its global atomics.
- **The production bridge cost is not reproduced.** census2 measured about 25 ms per 2^16 launch. These synthetic shapes run in under 1 ms even in the reference, so that number is most likely inflated by concurrent kernels (owner/callback overlap) or comes from data not modelled here. The request-level 3+3 is the arbiter.
- **The keccak shapes are production shapes** [D]. census2's launches are 2 × 112.7 ms at grid 2,428 and 2 × 53.6 ms at grid 1,171. That is about 11.5 µs per pair, matching the reference here (56.05 ms / 4,854 pairs). Keccak's input is any 1,600-bit state, so random inputs are representative.

## Frontier

- **ZisK** (`precompiles/keccakf/cu/keccakf_witness.cu`) hits the same wall and uses the same two-pass answer.
  - Its kernel is slot-parallel, with a lane pair per slot.
  - It writes row-major, and its comment measures column-major at 0.86 → 3.73 ms (498 → 115 GB/s: "8 useful bytes per 128-byte line").
  - It transposes at commit, where one thread per row makes both sides coalesce.
- **This kernel** has to emit stwo's column-major, bit-reversed circle MAIN. So pass 1 emits column-major in circle order, where consecutive logical rows are contiguous, and pass 2 is the tiled bit reversal.
- **sppark** `ntt/kernels.cu` `bit_rev_permutation_z` is the same idea: shared-memory exchange tiles, for bit-reversal at bandwidth. Its simple `bit_rev_permutation` is the per-element version.
- **pil2-proofman** (`starkpil/witness_hints_slot.cu`) generates witnesses row-parallel, with no bit-reversed target.

## Request-level (pending)

See `pipe1.sh`. Image `img1` is composed by `compose_image.py`: the m7-combined-residency recipe plus the 3 T9 objects. The frozen m7-integrate objects for the 3 files have SASS identical to the integrate sources [M].

The pipeline is:
1. gate with the flag off (26235156);
2. gates with the flag on (26235156 and 24628607);
3. a canonical 3+3 on 24628607 with `ab-preset.json`: both arms the default fullstack, only the flag differs.
