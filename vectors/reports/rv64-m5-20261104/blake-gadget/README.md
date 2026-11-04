# Stream blake-gadget, M5: `fused_blake2s_v1` (receipts)

Labels: **[M]** measured, with a receipt in this directory. **[D]** arithmetic on measured numbers (`scripts/blake_gadget/fused_census.py`). **[E]** estimate.

| file | what |
|---|---|
| `gpu-selftest-16M.log` | `tests/cuda/rv64/fused_blake2s_selftest.cu` on an RTX 5090: 16,777,216 random compressions, the device checker, negative probes, fill timing |
| `zig-spec-tests-1M-and-gpu-dump.log` | spec tests with 1,048,576 random CPU rows; the GPU dump (4,096 rows, 13.6 M cells) equals the CPU fill |
| `zig-spec-and-corpus-tests.log` | 22/22 spec + negative corpus BG01–BG08 hooks |

## Gadget results [M]

- **Completeness.** The gadget matches std `Blake2s256` and the RFC 7693 vectors (chained, 0–4,096 bytes). 1,048,576 random compressions on the CPU and 16,777,216 on the GPU all pass with **0 violations**. The XOR multiplicities balance exactly (rows × 704 / 320 / 320).
- **GPU fill equals CPU fill** cell for cell: 4,096 rows × 3,328 columns.
- **Soundness smoke.**
  - All 13,312 single-cell perturbations are rejected on the CPU.
  - 27 of 27 corruptions are caught by the device checker.
  - Corpus BG01–BG08 is green.
- **Fill kernel** (72 registers, no stack, column-major coalesced stores), median of 7 runs:

  | rows | with XOR-multiplicity atomics | fill only (write-bound) |
  |---:|---:|---:|
  | 2^16 | 1.24 ms (18.9 ns/compression) | 0.55 ms (8.35 ns, 1.59 TB/s) |
  | 2^18 | 4.78 ms | 2.34 ms |
