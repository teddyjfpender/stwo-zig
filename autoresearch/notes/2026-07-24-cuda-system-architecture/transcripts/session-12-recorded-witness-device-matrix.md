# Session 12: SN2 recorded-witness device matrix

## Scope

Generalize the single `add_ap_opcode` strict-AOT smoke into one data-driven
device differential for every standalone SN2 recorded-witness placement.
Product admission and device parity are separate claims:

- **Product admission** means the canonical SN2 bundle resolves to an
  authenticated product-registry entry with the exact semantic hash, program
  identity, kernel name, cache key, and module-global capability.
- **Device parity** means the authenticated cubin executes on the RTX 4090 and
  exactly matches the independent Zig SIMD interpreter for every output,
  lookup word, and sub word, with zero fallback telemetry.

The deterministic fixture uses four zero-input rows. Zero is inside the
recorded programs' selector/table domains; unconstrained hash-derived inputs
were rejected after they selected an out-of-domain Blake sigma round.
Auxiliary words are transposed explicitly from the SIMD interpreter's
row-major layout to CUDA's word-major ABI.

## Matrix

| # | placement | product admission | device parity |
| -: | --- | --- | --- |
| 1 | `add_ap_opcode` | admitted | exact |
| 2 | `add_opcode` | admitted | exact |
| 3 | `add_opcode_small` | admitted | exact |
| 4 | `assert_eq_opcode` | admitted | exact |
| 5 | `assert_eq_opcode_double_deref` | admitted | exact |
| 6 | `assert_eq_opcode_imm` | admitted | exact |
| 7 | `bitwise_builtin` | admitted | exact |
| 8 | `blake_compress_opcode` | admitted | exact |
| 9 | `call_opcode_abs` | admitted | exact |
| 10 | `call_opcode_rel_imm` | admitted | exact |
| 11 | `jnz_opcode_non_taken` | admitted | exact |
| 12 | `jnz_opcode_taken` | admitted | exact |
| 13 | `jump_opcode_double_deref` | admitted | exact |
| 14 | `jump_opcode_rel` | admitted | exact |
| 15 | `jump_opcode_rel_imm` | admitted | exact |
| 16 | `mul_opcode` | admitted | exact |
| 17 | `mul_opcode_small` | admitted | exact |
| 18 | `pedersen_builtin` | admitted | exact |
| 19 | `poseidon_builtin` | admitted | exact |
| 20 | `range_check_builtin` | admitted | exact |
| 21 | `ret_opcode` | admitted | exact |
| 22 | `blake_round` | admitted | exact |
| 23 | `pedersen_aggregator_window_bits_18` | admitted, Pedersen globals | exact |
| 24 | `poseidon_aggregator` | admitted | exact |
| 25 | `triple_xor_32` | admitted | exact |
| 26 | `verify_instruction` | admitted | exact |
| 27 | `blake_g` | admitted | exact |
| 28 | `partial_ec_mul_window_bits_18` | admitted, Pedersen globals | exact |
| 29 | `poseidon_3_partial_rounds_chain` | admitted | exact |
| 30 | `poseidon_full_round_chain` | admitted | exact |
| 31 | `cube_252` | admitted | exact |
| 32 | `range_check_252_width_27` | admitted | exact |
| - | `partial_ec_mul_generic` | native composite writer | deliberately excluded |

`partial_ec_mul_generic` remains in the product package but is not a
standalone recorded-witness launch placement. The request compiler owns its
native composite lowering, so treating it as a recorded kernel here would be
false coverage.

## Pedersen authority and residency

The Zig oracle pins SHA-256
`022d8d8b99dba145c4abbe9fca8cfd8306d41fad1ef8e84396b7ec3236841d28`
for `pedersen_table_init.cu`. The checked fixture carries the 28 canonical
sparse rows addressed by the two zero-input Pedersen programs and hashes the
source identity, row indices, and all 56 words per row. On device, 56 full
`2^23`-row columns are allocated through `stwo_exec_context_alloc_u32`; unused
rows are poisoned and addressed rows are populated from the checked fixture.
This makes an unexpected table access fail differential parity.

## Defects exposed by the cumulative matrix

The first unconstrained diagnostic fixture failed at:

```text
blake_round output mismatch word=144 expected=1 actual=0
```

This was not an admissible device mismatch: the hash-derived input selected a
Blake sigma round outside `0..9`, while the recorded program relies on that
input invariant. The fixture was corrected to use admitted zero inputs.

The admitted matrix then passed 22 placements exactly and stopped before the
first Pedersen launch:

```text
publish authenticated Pedersen recorded-witness globals:
status=201 (invalid device context)
current_status=0 pointer_status=0 same_context=0
```

The focused module-global smoke had used raw `cuMemAlloc` and therefore missed
this defect. Production allocations come from the execution context's custom
`cudaMallocFromPoolAsync` pool. The loader now validates exact bases and
interior ranges against the execution context's allocation ledger. A
300-allocation growth-and-release probe runs before the matrix, both Pedersen
global placements pass, and pool current bytes return to zero.

The next cumulative run reached placement 30 and found:

```text
poseidon_full_round_chain output mismatch word=372
expected=67515900 actual=12124
```

`word=372` is column 93, row zero: the second packed word produced by
`FeltMul(1, round_key[0])`. A standalone device call returned all 28 limbs
exactly, while the 238-register generated full-round kernel returned exact
limbs 0 through 2 and corrupted limbs 3 onward. Inputs were byte-exact and
Compute Sanitizer reported no memory errors.

The imported fp256 implementation carries PTX condition state across separate
inline assembly statements and explicitly relies on the compiler not
interleaving them. Inlining that chain into the large generated kernel violated
the assumption. The smallest fix makes only
`stwo_wit_deduce_felt_mul` a real `__noinline__` device-call boundary.
`scripts/cuda_recorded_witness_product.py` derives every affected Native
recorded source from the immutable imported authority, refreshes its
source SHA-256, and rejects drift. The imported source and host authority
closures remain unchanged.

## Final RTX 4090 evidence

The release archive is
`/root/build-sn2-recorded-final/libstwo_cuda_kernels.a`, SHA-256
`2a9219e993283c60ef974396e1ee9eeba954d67f5e6bd538cfbf7b6a4f6f7d72`.
The complete run passed 32 exact differentials, loaded 32 authenticated AOT
modules, recorded zero AOT misses, zero launch failures, and returned the
execution pool's used-current bytes to zero. Wall time was 0.43 seconds and
maximum RSS was 133,736 KiB.

Seven Nsight Systems runs measured the affected full-round kernel at a
133.992 us median after isolation versus 141.385 us for the frozen broken
inline binary. The correctness boundary introduced no measured regression;
the observed median was 7.393 us, or 5.23%, lower. This is a focused
four-row correctness measurement, not a throughput claim.

The clean release build compiled all 319 declared product AOT entries,
including unrelated Cairo-eval and large Blake bodies. Repeat matrix
validation should reuse its content-addressed output or select the recorded
product set; rebuilding an empty full-product directory is not part of the
fast parity loop.

## Reproduction

Local fixture oracle:

```sh
python3 scripts/cuda_recorded_witness_product.py
python3 scripts/zig_protocol_test.py src/stwo_deep.zig -ODebug \
  --test-filter 'recorded witness CUDA matrix'
```

RTX 4090 device differential:

```sh
/tmp/native_recorded_witness_matrix_final \
  tests/cuda/fixtures/recorded_witness_matrix_fixture.bin
```
