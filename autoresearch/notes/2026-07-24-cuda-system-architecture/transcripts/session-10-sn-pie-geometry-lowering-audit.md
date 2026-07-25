# CUDA System Extraction: Session 10

## Record

- Date: 2026-07-25
- Integration branch: `feature/cuda-system-architecture`
- Subject: canonical SN PIE geometry and SN2 CUDA lowering inventory
- Status: authenticated AOT inventory, first device differential, and
  architecture checkpoint

This checkpoint records the actual size of the four canonical SN PIEs and the
remaining CUDA lowering work. It does not claim an end-to-end SN PIE proof,
proof parity, or SN PIE CUDA performance.

## Canonical SN PIE Geometry

The Cairo AIR is heterogeneous. It is not one rectangular `rows x columns`
trace: each component has its own power-of-two domain and its own main and
interaction widths. Consequently, raw Cairo VM steps, padded component rows,
and committed coefficient cells are different quantities.

The canonical source record has 57 named source components. Proof planning
splits `memory_id_to_big` into its big and small instances, producing 58 AIR
component instances. Their schemas contain 5,886 logical columns in total:
161 preprocessed, 3,449 main, 2,268 interaction, and eight quotient columns.
These counts are sums across heterogeneous component schemas, not the width of
one rectangle. Across the four PIEs, component domains range from `2^4` rows
through `2^24` rows.

| PIE | VM steps | Raw PC/AP/FP cells | Tallest domain | Main cells | Interaction cells | Composition cells | Dynamic cells | Total logical cells | LDE cells |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SN PIE 1 | 14,645,112 | 43,935,336 | `2^24` | 3,423,495,184 | 2,578,726,976 | 134,217,728 | 6,136,439,888 | 6,679,540,416 | 13,359,080,832 |
| SN PIE 2 | 7,706,864 | 23,120,592 | `2^23` | 1,750,725,904 | 1,356,284,992 | 67,108,864 | 3,174,119,760 | 3,717,220,288 | 7,434,440,576 |
| SN PIE 3 | 14,075,019 | 42,225,057 | `2^23` | 2,672,230,416 | 2,153,713,728 | 67,108,864 | 4,893,053,008 | 5,436,153,536 | 10,872,307,072 |
| SN PIE 4 | 14,058,247 | 42,174,741 | `2^24` | 2,732,385,808 | 1,934,035,008 | 134,217,728 | 4,800,638,544 | 5,343,739,072 | 10,687,478,144 |

`Dynamic cells` are the exact heterogeneous sum of each component's local
main and interaction domains plus the eight-column composition domain. The
543,100,528 fixed cells are reusable preprocessed tables; adding them to the
dynamic count gives `Total logical cells`. Fixed cells describe cold complete
statement geometry, but are excluded from dynamic per-block work when the
authenticated fixed-table identity is already resident. `LDE cells` applies
the current blowup factor of two to the total logical coefficient cells.

None of these totals is a claim about peak device memory: transforms, Merkle
storage, quotient workspaces, FRI layers, and allocator lifetimes must be
measured separately.

For reference, summing padded component rows without applying column widths
gives 64,136,208, 38,590,736, 56,205,328, and 60,630,544 rows respectively.
Those values describe schedule geometry, not committed-cell throughput.

## SN2 Lowering Inventory

The complete SN2 request contains 58 components and **395 missing lowerings**:

| Lowering class | Count |
| --- | ---: |
| Base writers | 58 |
| Interaction writers | 58 |
| Constraint parts | 279 |
| **Total** | **395** |

The earlier value 174 was not the true inventory. The exact expression is
`58 + 58 + 279 = 395`.

### Base writers

The 58 base writers divide into:

| Base family | Components |
| --- | ---: |
| Recorded AOT | 32 |
| Fixed table | 21 |
| Memory trace | 3 |
| Native backend | 2 |

All 33 active witness bytecode programs match the copied generated CUDA
sources by component label and semantic hash, including
`partial_ec_mul_generic`. The Native product archive now binds every source
to its SHA-256, exact label, semantic hash, Blake3 program identity, ABI, and
kernel name. Of the 32 recorded-writer components, 30 are currently
execution-admitted. The two Pedersen-global programs remain fail-closed, and
the generic EC program remains behind its native-composite boundary.

### Recorded-witness ABI audit

An instruction-by-instruction audit of
`vectors/cairo/sn_pie_2_witness_programs.bin` against all 33 authenticated
generated `.cu` sources established the following common contract:

- every source exports exactly the eight `RecordedWitnessV1` arguments, in
  order: input-column pointers, execution-table pointers, execution-table
  strides, output-column pointers, multiplicity-table pointers, lookup words,
  subcomponent words, and row count;
- every input, output, lookup-word, and sub-word index remains within the
  corresponding bytecode count, and every declared output/auxiliary slot is
  written;
- all 33 programs declare zero multiplicity tables and emit no multiplicity
  writes; and
- the only execution-table identifiers are zero and one. They map to the
  canonical 37-pointer table: address-to-id at slot zero, 28 big-value limb
  columns at slots 1 through 28, and eight small-value limb columns at slots
  29 through 36, with the three address/big/small strides.

The generated signature and word-major auxiliary layout are defined by the
Rust source authority at
`src/backends/cuda/vendor/host_authority/crates/backend-cuda/src/backend/jit_witness/codegen.rs:153-160`.
The execution-table mapping is documented and constructed at
`src/backends/cuda/vendor/host_authority/crates/backend-cuda/src/backend/exec_tables.rs:351-367`.
The Zig binding supplies the same eight arguments at
`src/integrations/cairo_cuda/recorded_witness.zig:60-80` and validates the
declared buffer geometry at
`src/integrations/cairo_cuda/recorded_witness.zig:108-161`.

The program-family result is:

| Family | Programs | ABI result |
| --- | ---: | --- |
| Arithmetic, control, and instruction verification | 17 | Eight arguments sufficient; standard execution tables only |
| Bitwise and range-check | 4 | Eight arguments sufficient; no hidden state |
| Blake | 3 | Eight arguments sufficient; selectors 0 and 1 are self-contained |
| Poseidon and field arithmetic | 5 | Eight arguments sufficient; selectors 4 through 11 are self-contained |
| Pedersen and EC | 4 | Two module-global exceptions and one native-composite boundary, described below |

#### Pedersen module-global blocker

The eight launch arguments are **not the complete execution contract** for
two sources:

- `pedersen_aggregator_window_bits_18`, at
  `src/backends/cuda/aot/native/witness_pedersen_aggregator_window_bits_18_5e8b70227fdbf2f0.cu:41`
  and `:2017-2054`; and
- `partial_ec_mul_window_bits_18`, at
  `src/backends/cuda/aot/native/witness_partial_ec_mul_window_bits_18_cfd5cd0b51ed26c6.cu:41`
  and `:2017-2054`.

Both define `STWO_WIT_NEEDS_PEDERSEN` and compile module-local
`g_stwo_wit_pedersen_cols[56]` and `g_stwo_wit_pedersen_n_rows` symbols.
The remaining fp256 sources contain the guarded support text but do not define
`STWO_WIT_NEEDS_PEDERSEN`, so those globals do not survive preprocessing.
No other hidden module initialization was found in the 33-source set.

The Rust ISA classifies exactly the corresponding selectors as
`PedersenTableColumnsAndRowsV1` at
`src/backends/cuda/vendor/host_authority/crates/backend-cuda/src/backend/jit_witness/isa.rs:197-212`.
Its AOT identity authority detects and binds this requirement at
`src/backends/cuda/vendor/host_authority/crates/backend-cuda-kernels/src/aot_identity.rs:123-148`.
The reference loader discovers, validates, populates, reads back, and fences
the symbols at
`src/backends/cuda/vendor/upstream/runtime_jit.cu:647-745`.

The Zig AOT pack entry currently records no module-global class
(`scripts/cuda_build_lib/aot_pack.py:90-99`), and the Zig loader currently
authenticates the image and resolves only the function
(`src/backends/cuda/native/aot_loader.cpp:294-329`). Therefore these two
kernels must remain fail-closed. The semantic rejection in
`src/integrations/cairo_cuda/recorded_witness.zig:94-104` and the request
compiler rejection in
`src/integrations/cairo_cuda/request_compiler.zig:289-304` are required
containment, not optional conservatism. Admission requires an identity-bound
module-global class, authenticated Pedersen table ownership and geometry,
symbol publication, readback, and completion fencing.

#### Native EC composite boundary

`partial_ec_mul_generic` has a valid standalone eight-argument generated
source and uses only self-contained field selectors 4 through 7. It is still
not the production `ec_op_builtin` lowering. The upstream CUDA architecture
prepares EC-op state and executes a multi-kernel graph with dedicated
workspace and partial-input ownership in
`src/backends/cuda/vendor/host_authority/crates/backend-cuda/src/backend/prepared_ec_op.rs:1-6`
and `:122-167`.

The proof plan correctly marks this component as `native_backend` at
`src/frontends/cairo/proof_plan.zig:226-234`, and the request compiler admits
only `recorded_aot` writers at
`src/integrations/cairo_cuda/request_compiler.zig:289-300`. The strict
recorded-witness binding also rejects this exact label before registry
resolution, so a lower-level caller cannot accidentally treat the packaged
`partial_ec_mul_generic` kernel as the complete native composite.

#### Auxiliary layout boundary

The Zig bytecode interpreter writes lookup and subcomponent words row-major
at `src/frontends/cairo/witness/program.zig:290-295` and `:352-356`. Generated
CUDA writes the same logical values word-major as
`word * row_count + row`; the CUDA feed consumer uses that layout at
`src/backends/cuda/vendor/upstream/witness_feed_counts.cu:75` and `:103-105`.
The differential fixture makes the equivalence explicit by transposing at
`src/frontends/cairo/witness/recorded_cuda_fixture_test.zig:115-126` and
`:191-231`.

This is a deliberate backend boundary, not byte-layout parity. CUDA buffer
types and names must continue to state `word_major`, and release admission
must retain a full device-output differential against the transposed Zig SIMD
oracle. A flat untyped `lookup_words` or `sub_words` slice is otherwise easy
to bind with the wrong layout while still satisfying its byte extent.

### Interactions

The 58 interaction entries do not require 58 unrelated hand-written kernels.
They are instances of one generic relation adapter over 58 component-local
traces. The implementation should lower the authenticated relation
descriptors into a shared resident CUDA relation engine while preserving
component order, local height, tuple arity, multiplicity source, challenge
binding, and cumulative LogUp state.

### Constraints

The 279 constraint parts contain:

- 271 unique semantic hashes;
- 1,325 constraints;
- 2,002,168 encoded program bytes;
- a largest encoded program of 25,672 bytes;
- maximum register declarations of 267 base-field and 41 extension-field
  registers;
- `PreprocessedCol` in every part, with 867 recorded uses; and
- zero semantic matches in the copied constraint AOT inventory.

`PreprocessedCol` support is therefore a universal blocker, not a rare
component exception. The copied Rust CUDA constraint kernels cannot close
this inventory.

## Constraint Compiler Plan

The critical path is to extract the existing Metal evaluation scheduler into
a backend-neutral evaluator IR and preserve its authenticated program
semantics. CUDA then receives a native AOT emitter for that IR:

1. Decode and validate the existing constraint bytecode once.
2. Lower constants, local columns, next-row columns, `PreprocessedCol`,
   extension operations, accumulators, and output powers into a typed
   backend-neutral schedule.
3. Bind component-local tree spans and heterogeneous domain geometry
   explicitly.
4. Emit one deterministic CUDA kernel per constraint part initially: 279
   kernels, 271 unique bodies where identity permits reuse.
5. Differential every emitted part against the Zig SIMD evaluator before
   allowing it into a proof request.
6. Fuse parts only after exact parity and hardware profiling identify a
   profitable boundary. Kernel-count reduction is not allowed to obscure
   transcript or component boundaries.

This keeps the semantic authority in Zig rather than translating Metal source
text or trusting copied CUDA binaries.

## Validation And Oracle Policy

The SN2 request compiler currently produces the complete 58-component proof
program and CUDA plan, preserves component instances, accounts for all 395
lowerings, and remains deliberately fail-closed.

The RTX 4090 product archive contains 48 authenticated AOT cubins: the prior
15 Native kernels plus 33 recorded-witness sources. All 20 existing hardware
smokes pass against this archive. The first Cairo component differential,
`add_ap_opcode`, launches the exact eight-argument AOT ABI and compares all 68
main words, 220 lookup words, and 44 subcomponent words against the independent
Zig SIMD interpreter. The auxiliary oracle is explicitly transposed from
row-major to CUDA word-major. Its AOT receipt, launch telemetry, zero-fallback
evidence, allocation balance, and every output word pass.

No end-to-end SN PIE proof has been produced by the Zig CUDA backend yet.
There is therefore no valid SN PIE CUDA latency, MHz, committed-cells/s, or
speedup result to report.

Routine development uses:

1. Zig CUDA versus Zig SIMD stage and proof-byte differentials;
2. an RTX 4090 for fast compile, device, zero-fallback, and memory gates; and
3. a cached pinned Rust CPU verifier for final independent proof acceptance.

The Rust CUDA implementation is architecture and historical-performance
reference material only. It is not part of the iterative build, parity, or
promotion loop, and no repeated Rust CUDA builds are required.
