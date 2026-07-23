//! Native Metal shader compiler for V1 bytecode programs.
//!
//! Translates an [`OwnedMetalEvaluationProgramV1`] into a Metal shader source
//! string where every V1 instruction is unrolled into a direct Metal
//! statement.  This eliminates the interpretation loop overhead and
//! switch/case dispatch present in the generic interpreter kernel.
//!
//! The generated kernel uses the same buffer bindings as the interpreter
//! kernel (`eval_program_v1_reference_u32x4`), except the instruction
//! buffers (`base_insts`, `ext_insts`, `constraint_roots`) and their count
//! uniforms are no longer needed — instructions are baked into the shader
//! source.

// Ported intact from the prototype; the non-fused entry points are unused by this
// trimmed lane but kept so the module stays diffable against the source project.
#![allow(dead_code)]

use super::program::{
    MetalEvaluationProgramBaseOpcodeV1, MetalEvaluationProgramExtOpcodeV1,
    OwnedMetalEvaluationProgramV1,
};

/// Compile a V1 evaluation program into a Metal shader source string.
///
/// The returned source is a complete, self-contained Metal shader file that
/// includes the necessary field arithmetic functions inline (so it does not
/// depend on external header files at compile time) and defines a single
/// `kernel void` entry point whose name encodes the program's semantic hash.
///
/// # Panics
///
/// Panics if any instruction contains an unknown opcode.  This should never
/// happen with programs produced by [`lower_framework_eval_to_v1`].
pub fn compile_v1_to_metal_source(program: &OwnedMetalEvaluationProgramV1) -> String {
    let header = program.header();

    let kernel_name = format!("eval_compiled_{:016x}", header.semantic_hash);

    let mut src = String::with_capacity(8192);

    // ── Preamble: inline field arithmetic ──────────────────────────────────
    emit_preamble(&mut src);

    // ── Kernel signature ───────────────────────────────────────────────────
    //
    // Buffer layout matches the interpreter kernel.  We keep `trace_values`,
    // `interaction_offsets`, `preprocessed_values`, `base_params`,
    // `ext_params`, `random_coeff_powers`, and `dst` at their original
    // binding indices.  The instruction/count buffers (6-8, 11-13) are not
    // bound because the instructions are baked in.
    src.push_str(&format!(
        "kernel void {kernel_name}(\n\
         \x20   device const uint *trace_values [[buffer(0)]],\n\
         \x20   device const uint *interaction_offsets [[buffer(1)]],\n\
         \x20   device const uint *preprocessed_values [[buffer(2)]],\n\
         \x20   device const uint *base_params [[buffer(3)]],\n\
         \x20   device const uint *ext_params [[buffer(4)]],\n\
         \x20   device const uint *random_coeff_powers [[buffer(5)]],\n\
         \x20   device uint *dst [[buffer(9)]],\n\
         \x20   constant uint &row_count [[buffer(10)]],\n\
         \x20   uint row_index [[thread_position_in_grid]]\n\
         ) {{\n"
    ));

    src.push_str("    if (row_index >= row_count) {\n");
    src.push_str("        return;\n");
    src.push_str("    }\n\n");

    // ── Shared instruction body + constraint accumulation ───────────────
    emit_instruction_body(program, &mut src);

    // ── Store result ───────────────────────────────────────────────────────
    src.push_str("    stwo_metal_store_qm31(dst, row_index, acc);\n");
    src.push_str("}\n");

    src
}

/// Returns the kernel function name for a given semantic hash.
pub fn compiled_kernel_name(semantic_hash: u64) -> String {
    format!("eval_compiled_{semantic_hash:016x}")
}

/// Returns the fused kernel name for a given semantic hash.
///
/// The fused variant applies denominator inverse multiplication and writes
/// directly to 4 coordinate buffers, eliminating the GPU->CPU->GPU
/// round-trip in the composition pipeline.
pub fn compiled_fused_kernel_name(semantic_hash: u64) -> String {
    format!("eval_compiled_fused_{semantic_hash:016x}")
}

/// Compile a V1 evaluation program into a Metal shader source string
/// containing **only** the fused composition kernel.
///
/// The returned source contains a single `eval_compiled_fused_<hash>` kernel
/// that:
/// - Evaluates the constraint accumulation.
/// - Multiplies the result by a per-row denominator inverse scalar (`denom_inv[row_index >>
///   log_n_rows]`).
/// - Writes the 4 QM31 coordinates directly to separate output buffers (`coord_0..coord_3`),
///   matching `SecureColumnByCoords` layout.
///
/// Unlike the previous implementation which prepended the entire standard
/// kernel source (doubling JIT compilation time), this generates only the
/// fused kernel with its own preamble.
pub fn compile_v1_to_metal_source_with_fused(program: &OwnedMetalEvaluationProgramV1) -> String {
    let header = program.header();
    let fused_name = compiled_fused_kernel_name(header.semantic_hash);

    let mut src = String::with_capacity(8192);

    // ── Preamble: inline field arithmetic ──────────────────────────────────
    emit_preamble(&mut src);

    // ── Fused kernel signature ──────────────────────────────────────────
    //
    // Buffer layout:
    //   buffer(0): trace_values
    //   buffer(1): interaction_offsets
    //   buffer(2): preprocessed_values
    //   buffer(3): base_params
    //   buffer(4): ext_params
    //   buffer(5): random_coeff_powers
    //   buffer(6): denom_inv — small array of M31 denominator inverses
    //   buffer(7): coord_0 — output coordinate buffer 0
    //   buffer(8): coord_1 — output coordinate buffer 1
    //   buffer(10): row_count
    //   buffer(11): coord_2 — output coordinate buffer 2
    //   buffer(12): coord_3 — output coordinate buffer 3
    //   buffer(13): log_n_rows — shift amount for denom_inv indexing
    src.push_str(&format!(
        "kernel void {fused_name}(\n\
         \x20   device const uint *trace_values [[buffer(0)]],\n\
         \x20   device const uint *interaction_offsets [[buffer(1)]],\n\
         \x20   device const uint *preprocessed_values [[buffer(2)]],\n\
         \x20   device const uint *base_params [[buffer(3)]],\n\
         \x20   device const uint *ext_params [[buffer(4)]],\n\
         \x20   device const uint *random_coeff_powers [[buffer(5)]],\n\
         \x20   device const uint *denom_inv [[buffer(6)]],\n\
         \x20   device uint *coord_0 [[buffer(7)]],\n\
         \x20   device uint *coord_1 [[buffer(8)]],\n\
         \x20   constant uint &row_count [[buffer(10)]],\n\
         \x20   device uint *coord_2 [[buffer(11)]],\n\
         \x20   device uint *coord_3 [[buffer(12)]],\n\
         \x20   constant uint &log_n_rows [[buffer(13)]],\n\
         \x20   uint row_index [[thread_position_in_grid]]\n\
         ) {{\n"
    ));

    src.push_str("    if (row_index >= row_count) {\n");
    src.push_str("        return;\n");
    src.push_str("    }\n\n");

    // ── Shared instruction body + constraint accumulation ───────────────
    emit_instruction_body(program, &mut src);

    // ── Fused denom_inv multiply + coordinate store ─────────────────────
    src.push_str("    // ── Fused denom_inv multiply + coordinate unpack ──\n");
    src.push_str("    uint denom_idx = row_index >> log_n_rows;\n");
    src.push_str(
        "    StwoMetalQm31 result = stwo_metal_qm31_mul_base(acc, denom_inv[denom_idx]);\n",
    );
    src.push_str("    coord_0[row_index] = result.a;\n");
    src.push_str("    coord_1[row_index] = result.b;\n");
    src.push_str("    coord_2[row_index] = result.c;\n");
    src.push_str("    coord_3[row_index] = result.d;\n");
    src.push_str("}\n");

    src
}

// ---------------------------------------------------------------------------
// Shared instruction body emission
// ---------------------------------------------------------------------------

/// Emit the base instructions, ext instructions, and constraint accumulation
/// into the given source string.  This is the shared body used by both the
/// standard kernel and the fused composition kernel.
///
/// On return, the source contains local variables `b0..bN`, `e0..eM`, and
/// the accumulated result in `StwoMetalQm31 acc`.
fn emit_instruction_body(program: &OwnedMetalEvaluationProgramV1, src: &mut String) {
    let header = program.header();
    let base_insts = program.base_insts();
    let ext_insts = program.ext_insts();
    let constraint_roots = program.constraint_roots();

    let n_base_regs = header.max_base_regs as usize;
    let n_ext_regs = header.max_ext_regs as usize;

    // Track which base/ext registers have been written to avoid re-declaring.
    let mut base_declared = vec![false; n_base_regs];
    let mut ext_declared = vec![false; n_ext_regs];

    // ── Base instructions ──────────────────────────────────────────────────
    src.push_str("    // ── Base instructions ──\n");
    for inst in base_insts {
        let dst = inst.dst as usize;
        let decl = if !base_declared[dst] {
            base_declared[dst] = true;
            "uint "
        } else {
            ""
        };
        let dst_var = format!("b{dst}");

        let opcode = MetalEvaluationProgramBaseOpcodeV1::from_raw(inst.op)
            .unwrap_or_else(|| panic!("unknown base opcode {}", inst.op));

        match opcode {
            MetalEvaluationProgramBaseOpcodeV1::TraceCol => {
                let interaction = inst.interaction;
                let column = inst.a;
                let offset = inst.imm;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_eval_program_trace_value(\
                     trace_values, interaction_offsets, row_count, \
                     {interaction}u, {column}u, row_index, {offset});\n"
                ));
            }
            MetalEvaluationProgramBaseOpcodeV1::PreprocessedCol => {
                let column = inst.a;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_eval_program_preprocessed_value(\
                     preprocessed_values, row_count, {column}u, row_index);\n"
                ));
            }
            MetalEvaluationProgramBaseOpcodeV1::Param => {
                let slot = inst.a;
                src.push_str(&format!("    {decl}{dst_var} = base_params[{slot}u];\n"));
            }
            MetalEvaluationProgramBaseOpcodeV1::Const => {
                let value = inst.a;
                src.push_str(&format!("    {decl}{dst_var} = {value}u;\n"));
            }
            MetalEvaluationProgramBaseOpcodeV1::Add => {
                let a = inst.a;
                let b = inst.b;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_m31_add(b{a}, b{b});\n"
                ));
            }
            MetalEvaluationProgramBaseOpcodeV1::Sub => {
                let a = inst.a;
                let b = inst.b;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_m31_sub(b{a}, b{b});\n"
                ));
            }
            MetalEvaluationProgramBaseOpcodeV1::Mul => {
                let a = inst.a;
                let b = inst.b;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_m31_mul(b{a}, b{b});\n"
                ));
            }
            MetalEvaluationProgramBaseOpcodeV1::Neg => {
                let a = inst.a;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_m31_neg(b{a});\n"
                ));
            }
            MetalEvaluationProgramBaseOpcodeV1::Inv => {
                let a = inst.a;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_m31_inv(b{a});\n"
                ));
            }
        }
    }
    src.push('\n');

    // ── Ext instructions ───────────────────────────────────────────────────
    src.push_str("    // ── Ext instructions ──\n");
    for inst in ext_insts {
        let dst = inst.dst as usize;
        let decl = if !ext_declared[dst] {
            ext_declared[dst] = true;
            "StwoMetalQm31 "
        } else {
            ""
        };
        let dst_var = format!("e{dst}");

        let opcode = MetalEvaluationProgramExtOpcodeV1::from_raw(inst.op)
            .unwrap_or_else(|| panic!("unknown ext opcode {}", inst.op));

        match opcode {
            MetalEvaluationProgramExtOpcodeV1::SecureCol => {
                let a = inst.a;
                let b = inst.b;
                let c = inst.c;
                let d = inst.d;
                src.push_str(&format!(
                    "    {decl}{dst_var} = StwoMetalQm31 {{ b{a}, b{b}, b{c}, b{d} }};\n"
                ));
            }
            MetalEvaluationProgramExtOpcodeV1::Param => {
                let slot = inst.a;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_load_qm31(ext_params, {slot}u);\n"
                ));
            }
            MetalEvaluationProgramExtOpcodeV1::Const => {
                let a = inst.a;
                let b = inst.b;
                let c = inst.c;
                let d = inst.d;
                src.push_str(&format!(
                    "    {decl}{dst_var} = StwoMetalQm31 {{ {a}u, {b}u, {c}u, {d}u }};\n"
                ));
            }
            MetalEvaluationProgramExtOpcodeV1::Add => {
                let a = inst.a;
                let b = inst.b;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_qm31_add(e{a}, e{b});\n"
                ));
            }
            MetalEvaluationProgramExtOpcodeV1::Sub => {
                let a = inst.a;
                let b = inst.b;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_qm31_sub(e{a}, e{b});\n"
                ));
            }
            MetalEvaluationProgramExtOpcodeV1::Mul => {
                let a = inst.a;
                let b = inst.b;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_qm31_mul(e{a}, e{b});\n"
                ));
            }
            MetalEvaluationProgramExtOpcodeV1::Neg => {
                let a = inst.a;
                src.push_str(&format!(
                    "    {decl}{dst_var} = stwo_metal_qm31_sub(\
                     StwoMetalQm31 {{ 0u, 0u, 0u, 0u }}, e{a});\n"
                ));
            }
        }
    }
    src.push('\n');

    // ── Constraint accumulation ────────────────────────────────────────────
    src.push_str("    // ── Constraint accumulation ──\n");
    src.push_str("    StwoMetalQm31 acc = StwoMetalQm31 { 0u, 0u, 0u, 0u };\n");
    for (i, &root) in constraint_roots.iter().enumerate() {
        src.push_str(&format!(
            "    acc = stwo_metal_qm31_add(acc, \
             stwo_metal_qm31_mul(e{root}, \
             stwo_metal_load_qm31(random_coeff_powers, {i}u)));\n"
        ));
    }
    src.push('\n');
}

// ---------------------------------------------------------------------------
// Preamble: inline field arithmetic and helper functions
// ---------------------------------------------------------------------------

fn emit_preamble(src: &mut String) {
    src.push_str(
        "\
#include <metal_stdlib>
using namespace metal;

// ── M31 field constants and arithmetic ─────────────────────────────────────
constant uint STWO_METAL_M31_P = 2147483647u;

static inline uint stwo_metal_m31_add(uint lhs, uint rhs) {
    uint sum = lhs + rhs;
    return sum >= STWO_METAL_M31_P ? sum - STWO_METAL_M31_P : sum;
}

static inline uint stwo_metal_m31_sub(uint lhs, uint rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_METAL_M31_P - rhs;
}

static inline uint stwo_metal_m31_neg(uint value) {
    uint negated = STWO_METAL_M31_P - value;
    return negated == STWO_METAL_M31_P ? 0u : negated;
}

static inline uint stwo_metal_m31_mul(uint lhs, uint rhs) {
    ulong product = (ulong)lhs * (ulong)rhs;
    ulong reduced =
        (((((product >> 31u) + product + 1u) >> 31u) + product) & (ulong)STWO_METAL_M31_P);
    return (uint)reduced;
}

static inline uint stwo_metal_m31_square(uint value) {
    return stwo_metal_m31_mul(value, value);
}

static inline uint stwo_metal_m31_pow_to_power_of_two(uint squarings, uint value) {
    uint result = value;
    for (uint i = 0; i < squarings; ++i) {
        result = stwo_metal_m31_square(result);
    }
    return result;
}

static inline uint stwo_metal_m31_inv(uint value) {
    uint t0 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(2u, value), value);
    uint t1 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(1u, t0), t0);
    uint t2 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(3u, t1), t0);
    uint t3 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(1u, t2), t0);
    uint t4 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(8u, t3), t3);
    uint t5 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(8u, t4), t3);
    return stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(7u, t5), t2);
}

// ── QM31 (secure field) types and arithmetic ───────────────────────────────
struct StwoMetalQm31 {
    uint a;
    uint b;
    uint c;
    uint d;
};

static inline StwoMetalQm31 stwo_metal_qm31_add(StwoMetalQm31 lhs, StwoMetalQm31 rhs) {
    return StwoMetalQm31 {
        stwo_metal_m31_add(lhs.a, rhs.a),
        stwo_metal_m31_add(lhs.b, rhs.b),
        stwo_metal_m31_add(lhs.c, rhs.c),
        stwo_metal_m31_add(lhs.d, rhs.d),
    };
}

static inline StwoMetalQm31 stwo_metal_qm31_sub(StwoMetalQm31 lhs, StwoMetalQm31 rhs) {
    return StwoMetalQm31 {
        stwo_metal_m31_sub(lhs.a, rhs.a),
        stwo_metal_m31_sub(lhs.b, rhs.b),
        stwo_metal_m31_sub(lhs.c, rhs.c),
        stwo_metal_m31_sub(lhs.d, rhs.d),
    };
}

static inline StwoMetalQm31 stwo_metal_qm31_mul_base(StwoMetalQm31 value, uint scalar) {
    return StwoMetalQm31 {
        stwo_metal_m31_mul(value.a, scalar),
        stwo_metal_m31_mul(value.b, scalar),
        stwo_metal_m31_mul(value.c, scalar),
        stwo_metal_m31_mul(value.d, scalar),
    };
}

static inline StwoMetalQm31 stwo_metal_qm31_mul(StwoMetalQm31 lhs, StwoMetalQm31 rhs) {
    uint a0 = lhs.a;
    uint a1 = lhs.b;
    uint a2 = lhs.c;
    uint a3 = lhs.d;
    uint b0 = rhs.a;
    uint b1 = rhs.b;
    uint b2 = rhs.c;
    uint b3 = rhs.d;

    uint x0 = stwo_metal_m31_sub(stwo_metal_m31_mul(a0, b0), stwo_metal_m31_mul(a1, b1));
    uint x1 = stwo_metal_m31_add(stwo_metal_m31_mul(a0, b1), stwo_metal_m31_mul(a1, b0));
    uint y0 = stwo_metal_m31_sub(stwo_metal_m31_mul(a2, b2), stwo_metal_m31_mul(a3, b3));
    uint y1 = stwo_metal_m31_add(stwo_metal_m31_mul(a2, b3), stwo_metal_m31_mul(a3, b2));

    uint cross0 = stwo_metal_m31_sub(stwo_metal_m31_mul(a0, b2), stwo_metal_m31_mul(a1, b3));
    uint cross1 = stwo_metal_m31_add(stwo_metal_m31_mul(a0, b3), stwo_metal_m31_mul(a1, b2));
    uint cross2 = stwo_metal_m31_sub(stwo_metal_m31_mul(a2, b0), stwo_metal_m31_mul(a3, b1));
    uint cross3 = stwo_metal_m31_add(stwo_metal_m31_mul(a2, b1), stwo_metal_m31_mul(a3, b0));

    uint r_y0 = stwo_metal_m31_sub(stwo_metal_m31_mul(2u, y0), y1);
    uint r_y1 = stwo_metal_m31_add(y0, stwo_metal_m31_mul(2u, y1));

    return StwoMetalQm31 {
        stwo_metal_m31_add(x0, r_y0),
        stwo_metal_m31_add(x1, r_y1),
        stwo_metal_m31_add(cross0, cross2),
        stwo_metal_m31_add(cross1, cross3),
    };
}

static inline StwoMetalQm31 stwo_metal_load_qm31(device const uint *values, uint index) {
    uint base = index * 4u;
    return StwoMetalQm31 {
        values[base + 0u],
        values[base + 1u],
        values[base + 2u],
        values[base + 3u],
    };
}

static inline void stwo_metal_store_qm31(device uint *values, uint index, StwoMetalQm31 value) {
    uint base = index * 4u;
    values[base + 0u] = value.a;
    values[base + 1u] = value.b;
    values[base + 2u] = value.c;
    values[base + 3u] = value.d;
}

// ── Trace value helper ─────────────────────────────────────────────────────
static inline uint stwo_metal_bit_reverse(uint index, uint bits) {
    // Use Metal's hardware reverse_bits intrinsic and shift to get
    // 'bits'-wide reversal.  This replaces a variable-iteration loop with
    // a single ALU instruction + shift.
    return reverse_bits(index) >> (32u - bits);
}

static inline uint stwo_metal_offset_bit_reversed_circle_domain_index(
    uint i,
    uint domain_log_size,
    uint eval_log_size,
    int offset
) {
    uint prev = stwo_metal_bit_reverse(i, eval_log_size);
    uint half_size = 1u << (eval_log_size - 1u);
    int step = offset * int(1u << (eval_log_size - domain_log_size - 1u));
    if (prev < half_size) {
        prev = uint((int(prev) + step) % int(half_size));
        if (int(prev) < 0) prev += half_size;
    } else {
        int p = int(prev) - step;
        p = p % int(half_size);
        if (p < 0) p += int(half_size);
        prev = uint(p) + half_size;
    }
    return stwo_metal_bit_reverse(prev, eval_log_size);
}

static inline uint stwo_metal_eval_program_trace_value(
    device const uint *trace_values,
    device const uint *interaction_offsets,
    uint row_count,
    uint interaction,
    uint column,
    uint row_index,
    int offset
) {
    uint target_row;
    if (offset == 0) {
        target_row = row_index;
    } else {
        uint eval_log_size = 0u;
        uint tmp = row_count;
        while (tmp > 1u) { tmp >>= 1u; eval_log_size++; }
        uint domain_log_size = eval_log_size - 1u;
        target_row = stwo_metal_offset_bit_reversed_circle_domain_index(
            row_index, domain_log_size, eval_log_size, offset
        );
    }
    uint global_column = interaction_offsets[interaction] + column;
    return trace_values[global_column * row_count + target_row];
}

static inline uint stwo_metal_eval_program_preprocessed_value(
    device const uint *preprocessed_values,
    uint row_count,
    uint column,
    uint row_index
) {
    return preprocessed_values[column * row_count + row_index];
}

// ── Generated kernel ───────────────────────────────────────────────────────
",
    );
}

// The prototype's unit tests exercised the host-side interpreter, which this
// trimmed lane does not port; conformance is enforced end-to-end by the testkit
// (proof byte-equality on both channels, with the CPU lane as reference).
