# Compact Cairo input transport, version 1

This is a lossless encoding of the official adapter's `ProverInput`, not a
witness or proof format. Rust execution writes it and Zig's canonical input
admission dispatches by its magic. JSON remains supported. The independent
all-opcodes fixture is `vectors/cairo/official/all_opcodes.prover_input.cpi`;
its bytes are compared against Rust output and its semantic summary against
official JSON.

All integers are unsigned little-endian. Counts are `u64`. A state is three
`u32` values in `pc, ap, fp` order. Reserved fields must be zero.

| Field | Encoding |
| --- | --- |
| Magic | 8 bytes: `STWZCPI\0` |
| Version, flags | `u32(1), u32(0)` |
| Initial, final state | two states |
| Distinct PC count | `u64` |
| Public segment mask | `u16`, only low 11 bits admitted |
| Reserved | `u16(0), u32(0)` |
| Opcode group count, reserved | `u32(20), u32(0)` |
| Opcode groups | for each frozen group: count followed by states |
| Small-value maximum | `u128` |
| Small-value capacity log, reserved | `u32, u32(0)` |
| Address-ID, large-value, small-value counts | three `u64` counts |
| Address-ID table | `u32` encoded IDs |
| Large-value table | eight `u32` limbs per value |
| Small-value table | `u128` values |
| Public memory | count followed by `u32` addresses |
| Nine builtin segments | each: presence `u8`, seven zero bytes, begin and stop `u64` |

The frozen opcode order is defined in `opcodes.zig` and mirrored explicitly in
the Rust writer: generic, add-ap, add, small-add, assert-eq,
double-deref-assert-eq, immediate-assert-eq, absolute-call, relative-call,
non-taken-jnz, taken-jnz, immediate-relative-jump, relative-jump,
double-deref-jump, absolute-jump, small-mul, mul, ret, Blake-compress,
QM31-add-mul. Segments follow add-mod, bitwise, output, mul-mod, Pedersen,
Poseidon, range-check-96, range-check, EC-op.

An absent segment has zero begin/stop pointers. Trailing data is rejected.
Lengths are checked against caller limits and remaining encoded bytes before
allocation. Memory tags, canonical field values, capacity, state address
bounds, PC cardinality, builtin alignment, public memory and segment context
use the same admission checks as JSON. Decoding owns the resulting arrays;
failure frees every allocation.
