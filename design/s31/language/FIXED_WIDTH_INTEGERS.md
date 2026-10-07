# Fixed-width integers for S31 math and standard libraries

Status: **core ten-type family implemented in S31 source**, 2026-10-07.
The implemented slice has `u8`, `u16`, `u32`, `u64`, `u128` and signed peers;
range-checked bit patterns; checked/wrapping addition and subtraction;
signed/unsigned comparisons; and same-width reinterpretation and limb views.
Multiplication, division, bitwise operations, shifts, and cross-width numeric
casts remain design work. An M31 value is a field element, not a fixed-width
integer. A `[u16; N]` array does not by itself specify signedness, overflow,
or an integer operation.

## Source contract

Each width is a scalar nominal type. Its representation is little-endian base-$2^{16}$ limbs. For `u8` and `i8`, the one underlying `u16` limb must additionally be below $2^8$. For other listed widths, every limb is a range-checked `u16`.

| Width | Unsigned | Signed | Limbs | Stored bit pattern |
| ---: | --- | --- | ---: | --- |
| 8 | `u8` | `i8` | 1 | `0..255`, with an explicit 8-bit range check |
| 16 | `u16` | `i16` | 1 | `0..65535` |
| 32 | `u32` | `i32` | 2 | `0..2^32-1` |
| 64 | `u64` | `i64` | 4 | `0..2^64-1` |
| 128 | `u128` | `i128` | 8 | `0..2^128-1` |

For a signed `iW`, interpret its constrained bit pattern $b$ as $b$ when $b<2^{W-1}$ and $b-2^W$ otherwise. The source type and verifier key distinguish signed from unsigned values even though their AIR limbs and low-level public ABI word arrays have the same shape. The generated package also records source types in its typed interface. A directly supplied nominal input remains a claim about a value; the proof must constrain its range and all operations that use it.

No implicit conversion is allowed between these types, `UInt256`, `Bytes32`, and M31. In particular, a field subtraction must never silently stand in for signed integer subtraction, and `u32` values at or above the M31 modulus cannot be silently converted to a field value. Implemented explicit operations cover bit-pattern reinterpretation between equal-width `uW` and `iW`, plus conversion to and from exactly sized little-endian `[u16; N]` limbs. Zero/sign extension, checked narrowing, truncation, and reduction modulo M31 remain to be implemented.

## Arithmetic semantics

Integer arithmetic must specify overflow in source. The API should use explicit `std::int::add_checked`, `add_wrapping`, `sub_checked`, and `sub_wrapping` calls on equal types; `mul_checked` and `mul_wrapping` follow after a bounded product relation exists. Checked operations make overflow or underflow unsatisfiable. Wrapping operations return the low $W$ bits. No build-mode-dependent behavior is allowed. Comparisons use the type's signed or unsigned ordering and return a constrained `bit`.

For unsigned addition, let $B=2^{16}$, except $B=2^8$ for an 8-bit scalar. Each limb satisfies

$$a_j+b_j+c_j=r_j+B c_{j+1},\qquad c_0=0,$$

with range-checked limbs and Boolean carries. Checked addition also requires $c_L=0$. For `u8`, $250+10=4+256\cdot1$: `add_wrapping` returns 4, while `add_checked` rejects that witness. A mere field equation without the byte range and carry constraints would be unsound.

Signed wrapping addition uses the same bit-vector equation. Signed checked addition must also prove the sign bits and reject when equal-sign operands produce the opposite-sign result. For `i8`, $120+10$ has bit pattern 130, interpreted as $-126$ after wrapping, and is rejected by checked addition. Checked subtraction and multiplication must similarly use the mathematical signed bounds $-2^{W-1}\le x\le2^{W-1}-1$. An integer hint never counts as a constraint.

Division and remainder come after the core arithmetic. The intended unsigned rule is $a=q b+r$, $b>0$, and $0\le r<b$ as an integer equality. Signed division rounds toward zero, the remainder has the dividend's sign, division by zero rejects, and checked `MIN / -1` rejects. Shifts and bitwise operations will have explicit shift-count and width semantics; they need bit or byte constraints rather than host-only computation.

## Lowering and cost

Add a width-bearing normalized relation operation or equivalent compiler-owned shape metadata. The verifier must bind width, signedness, operation, overflow mode, limb geometry, and any extra byte-range table into its key and transcript. The circuit compiler must reject a profile if a required range table or lookup producer is absent. An `i8` or `u8` input cannot be accepted as an unrestricted `u16` limb. A checked `u32` sum cannot be implemented by simply padding into `UInt256` and forgetting to constrain overflow at bit 32.

Use the existing generic circuit as the correctness baseline, then measure a limb or byte AIR chip against it. A width-$W$ add should scale with $W/16$ limbs rather than paying for sixteen `UInt256` limbs when $W=8$ or 32. Cost reports must expose raw and padded rows, range-table cells, lookup interactions, proof bytes, native verification, and proving time with proof-of-work separated. Promote a chip only after the same source, witnesses, public ABI, and verifier policy show a measured total-cost win.

## Release sequence and acceptance

1. Implement `u8`, `u16`, and `u32` with checked/wrapping add and subtract, equality, ordering, explicit casts, and source-to-AIR explanations. Prove the 8-bit high-range constraint and width-specific carry behavior.
2. Generalize the same constraints to `u64` and `u128`; add `i8` through `i128` with constrained sign extraction, signed comparisons, and checked overflow. Keep all ten types in one parameterized semantic implementation rather than ten unrelated gadgets.
3. Add checked/wrapping multiplication with a bounded full-width product relation, then division/remainder and bitwise/shift operations with their stated edge cases. Benchmark wide kernels and select chips only where they beat the generic circuit.
4. Add independent Python big-integer oracles and positive/negative native proofs at zero, one, maximum, signed minimum, signed maximum, carries across every limb boundary, overflow, division by zero, and cast failures. Pin source-to-relation shape and AIR cost baselines for each width family. Reject changed public claims, proof bytes, keys, width tags, and signedness tags.

The focused `std@1` library MVP gate covers a representative M31 and
`UInt256` subset. The ten scalar integer types have source, relation,
circuit, and oracle tests for this operation slice; wider release still
needs the edge-case, native negative-proof, and cost gate in item 4 for
every width and signedness. The [worked source-to-AIR chapter](../../../src/frontends/s31/docs/fixed-width-integers.md)
states the shipped subset. General Bitcoin counters, timestamps, difficulty
arithmetic, fixed-point algorithms, and broader math kernels can then use
integer semantics without confusing them with M31 arithmetic.
