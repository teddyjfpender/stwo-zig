# Proposal: bulk memory services (memcpy / memset / memcmp)

Status: **candidate, measured; recommended for prover work (memcpy first)**. The
results are execution-only evidence from profile `ethereum_services_v3_candidate`
and cannot be promoted.

## Motivation (measured, 15-block basket, 2026-11-01)

All runs use the same reference: this branch built without candidate features,
run on the candidate profile. Committed bits use the nominal estimates in
[candidate-service-costs.md](candidate-service-costs.md). Every call goes to the
service; the threshold choice is explained below.

| Service (alone) | Set | instr/gas | Δ instr/gas | committed bits/gas | Δ bits/gas | Guards |
|---|---|---:|---:|---:|---:|---|
| memcpy (+memmove) | scored | 12.207 | -1.672 (-12.0%) | 148,752 | -6.27% | all pass |
| | holdout | 10.323 | -1.434 (-12.2%) | 125,953 | -6.36% | |
| | all | 11.835 | -1.625 (-12.1%) | 144,251 | -6.29% | |
| memset | scored | 13.746 | -0.133 (-1.0%) | 158,092 | -0.39% | all pass |
| | holdout | 11.640 | -0.117 (-1.0%) | 133,958 | -0.41% | |
| | all | 13.330 | -0.130 (-1.0%) | 153,328 | -0.39% | |
| memcmp (+bcmp) | scored | 13.700 | -0.180 (-1.3%) | 157,550 | -0.73% | all pass |
| | holdout | 11.619 | -0.137 (-1.2%) | 133,634 | -0.65% | |
| | all | 13.289 | -0.171 (-1.3%) | 152,828 | -0.72% | |
| all three | scored | 11.894 | -1.986 (-14.3%) | 146,973 | -7.39% | all pass |
| | holdout | 10.069 | -1.688 (-14.4%) | 124,537 | -7.41% | |
| | all | 11.534 | -1.927 (-14.3%) | 142,544 | -7.40% | |

The reference build scores 13.880 / 11.757 / 13.461 instr/gas and
158,710 / 134,504 / 153,931 bits/gas (scored / holdout / all). The three effects
add up almost exactly: -6.27 - 0.39 - 0.73 = -7.39%.

Across all 15 blocks there were 9.08M memcpy calls (798 MB), 1.26M memset calls
(159 MB) and 1.73M memcmp calls (17.5 MB examined).

On block 24,628,607 the `mem_alloc` attribution bucket fell from 21.43M to 4.52M
instructions (`notes/candidate-services-attribution-24628607.json`). What
remains is mostly the allocator and the wrapper calls. The block averaged 88
bytes per memcpy and saved about 74 instructions per call.

**Threshold.** One threshold for all three services, scored set:

| Minimum bytes | instr/gas | bits/gas |
|---:|---:|---:|
| 0 | 11.894 | 146,973 |
| 1 | 11.920 | 147,216 |
| 8 | 11.965 | 147,534 |
| 16 | 11.979 | 147,651 |
| 32 | 12.116 | 148,629 |
| 64 | 12.941 | 154,346 |
| 128 | 13.393 | 156,787 |
| 256 | 13.572 | 157,576 |
| 1024 | 13.716 | 158,432 |

Lower is better on both metrics. This holds even at the high end of the cost
range, where threshold 0 still gives -5.02% bits/gas. The length test itself
costs +0.52% bits when compiled in but never taken. Small copies are expensive
in software because of the call, prologue and tail code, while the service
charges 1 instruction plus a packet.

memset alone is close to neutral: -0.39% bits nominal, -0.19% at high cost. It
pays because there is no length test.

## ABI

As in CONTEXT.md, with the clarifications in `notes/candidate-services-abi.md`:

- `memcpy` packet `dst, src, len`, memmove-safe;
- `memset` packet `dst, byte, len`;
- `memcmp` packet `a, b, len, result`, where `result` ∈ {-1, 0, 1};
- no alignment requirement on the bulk pointers;
- `len = 0` touches nothing.

## AIR sketch

The design is a DMA family modeled on ZisK's Dma + Dma64Aligned + DmaUnaligned +
DmaPrePost, but on our word16 RAM argument.

1. **Descriptor row (one per call).**
   - It consumes the CPU's ECALL IO/Wire tuple (pc, clock, a0, tag) and reads the
     packet words through the RAM bridge.
   - It splits `len` into a head (0-7 bytes up to destination alignment), a body
     word count and a tail.
   - It emits a DMA continuation token.
2. **Body rows (one per destination word).**
   - Each row consumes a token and emits the next.
   - It emits one RAM write for the destination word (before and after limbs) and,
     for memcpy and memcmp, RAM reads of the source words.
   - When the source offset is not zero, the destination word is assembled from 8
     source bytes spread across two source words. The byte columns are
     range-checked and recombined into word16 limbs.
   - memcmp rows carry an `equal_so_far` flag. The first differing word gives the
     byte index (one-hot), an inverse witness for `a_i - b_i ≠ 0` and an unsigned
     `<` lookup that fixes the sign.
3. **Head/tail rows.** Partial-word writes with byte masks; the bytes outside
   `[dst, dst+len)` keep their before value.
4. **Overlap (memcpy).** The descriptor fixes the direction bit
   `dst ≤ src || dst ≥ src+len`. Body rows run in ascending or descending address
   order so that every source read happens before any write that could alias
   it. The RAM argument's clock ordering enforces this because each row has its
   own tick.

**Soundness obligations:**

- the body rows' word count equals the descriptor's split of `len`, with no
  wrap of addresses (range-check `dst+len`, `src+len` < 2^64 and the mapping
  bound);
- every source read precedes any aliasing write (direction bit);
- edge bytes outside the range are preserved;
- the memcmp result is the sign at the first difference, and zero only if every
  body word is equal (the `equal_so_far` chain);
- permissions: destination ranges must lie in writable segments. The existing
  write-permission model must cover service writes the same way it covers
  stores.
- Adversarial tests: misaligned packets, `len = 0` with wild pointers, overlap
  in both directions, ranges that straddle pages and segments, and memcmp sign
  with bytes ≥ 0x80.

## Estimated prover work

| Service | cells/call | cells/byte | Range (call; byte) |
|---|---:|---:|---|
| memcpy | 1,500 | 40 | 1,000-2,500; 28-55 |
| memset | 1,300 | 20 | 900-2,000; 13-28 |
| memcmp | 2,000 | 45 per examined byte | 1,300-3,000; 30-60 |

Derivations are in [candidate-service-costs.md](candidate-service-costs.md).

For effort, this is one AIR family with three selectors. It reuses the word16
bridge and closed_ram, so it is roughly comparable to the Keccak word16 bridge
plus a small descriptor table. Recursion support is needed for the new
components.

## Expected benefit

- **Current reth/revm client:** -14.3% instr/gas and -7.4% committed bits/gas,
  measured.
- **evmone-class client:** the absolute saving per gas should be similar or
  larger. ZisK's ziskethone relies on single-step DMA for its 2.02 steps/gas, and
  a C++ client's `memcpy` of 32-byte EVM words and calldata is just as hot.
  - At about 3.5 instr/gas, the same about 1.9 instr/gas of bulk-memory work
    would be 30-50% of the total, or about -20% committed bits/gas.
  - This must be measured once the client runs. The executor at
    `<scratch>/candidate-exec` supports it unchanged.
- **Interaction with SHA-256:** the services are independent. With all
  services together the scored score is 9.986 instr/gas and 128,534 bits/gas
  (-28.1% / -19.0%).
