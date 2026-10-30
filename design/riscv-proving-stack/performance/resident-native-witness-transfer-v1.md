# Canonical typed witnesses on CUDA

The required operation is an exact, allocation-free map from architectural
retirement records into the existing typed AIR's final column-major witness.
The finite RV32IM roster contains 17 families and 46 admitted opcodes. Each row
is independent after stable family classification; global register, RAM, ROM
and lookup relations remain obligations of the complete proof.

The selected transfer is ahead-of-time compilation of the existing pure Zig
validation and row-writing functions through Zig 0.15.2's C backend and then
nvcc. It preserves the canonical recipe instead of introducing handwritten CUDA
instruction semantics. The CUDA decoration changes function execution space,
not arithmetic expressions. Integer helper bodies are extracted mechanically
from the pinned compiler's `zig.h`. The exporter rejects referenced static
runtime data and unknown declaration forms. Its manifest pins both compiler
helper input and generated code. This is a compilation technique, not a new
constraint system or a reduction in the verifier's checks.

The device input is an explicit 24-word architectural retirement record;
register indices, opcodes and boolean encodings are checked before narrowing.
Each family kernel validates through its production typed authority and writes
the same physical main columns directly. Padding is zeroed on device. Optional
device row-index lists must be bounded and strictly ordered. A sticky status
records malformed input; a resident controller must reject that transaction.
The launcher allocates nothing, copies nothing and never falls back to a CPU
writer. It receives an explicit CUDA stream.

For R rows and C physical columns, work is O(R*C), with the existing family's
bounded arithmetic cost per row, and output size O(R*C). Host-to-device input
is 96 bytes per raw retirement plus any device-generated selection metadata;
expanded witness columns stay on device. This removes the CPU witness map and
its upload from a future resident original-proof path. It does not remove ISA
execution, global relation generation or recursive witness construction.

The differential gate executes the committed ELF corpus, covers every family
and opcode selector, and compares every output field word against the native
ReleaseSafe Zig writer. It checks nonempty padding, explicit source indices,
output canaries, malformed encodings, invalid rows and out-of-range sources.
Device-event primitive timings are diagnostic; the final falsifier is an
independently verified complete resident proof timed from raw request ingress.
No end-to-end gain or complete GPU prover qualification follows from this
primitive alone. The V7 local-zero hints, projection/access rows and all global
providers must still be produced and closed by the actual resident controller.

Implementation: `src/integrations/riscv_cuda/native_witness_exports_v1.zig` and
`scripts/riscv_native_witness_cuda.py`. Generated C/CUDA and binaries belong in
external build directories. Numerical fixtures and runners belong under the
integration's `tests` directory.
