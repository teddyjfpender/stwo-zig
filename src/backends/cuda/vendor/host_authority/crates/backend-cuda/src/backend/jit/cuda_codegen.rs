//! CUDA source emitter for V1 evaluation programs.
//!
//! Mechanical port of the Metal JIT shader compiler (`backend-metal/src/backend/jit/
//! shader.rs`, conformance-proven byte-equal): the same instruction unrolling and the
//! same field-arithmetic formulas, emitted as self-contained CUDA C for NVRTC. The
//! kernel ABI is explicit C (pointer/scalar parameters only) — generated kernels never
//! read Rust struct layouts, which is what made the precompiled NitrooZK kernel set
//! unportable across AIR/compiler revisions.

use super::program::{
    MetalEvaluationProgramBaseOpcodeV1 as BaseOp, MetalEvaluationProgramExtOpcodeV1 as ExtOp,
    OwnedMetalEvaluationProgramV1,
};

/// Version of this source emitter. Mixed into [`jit_cache_key`] so that a change to
/// the emitted CUDA (new fusion, different ABI) can never collide with PTX persisted
/// to disk by an older build for the same bytecode. MUST be bumped whenever the
/// emitted source for a fixed program changes.
///
/// History: 1 = initial scratch-writing kernel; 2 = fused accumulate (the kernel adds
/// into the accumulator coordinates in place); 3 = `rc_base` runtime kernel parameter
/// (random-coeff power indices are now `rc_base + i`, enabling size-governed kernel
/// splitting — old fused PTX and new split-aware PTX must never collide on disk);
/// 4 = shifted trace reads use the kernel's true `log_n_rows` instead of
/// assuming that every evaluation domain is exactly one bit larger; 5 = emit the
/// in-order ext prefix as soon as each SecureCol's base operands are available,
/// releasing base values instead of retaining the whole base section; 6 = demand-
/// driven versioned base-cone emission plus folding each ready canonical constraint-
/// root prefix into `acc` at its final definition, eliminating artificial base/root
/// lifetimes without changing the ext or coefficient order; 7 = default-off
/// `STWO_M31_FAST32_GLOBAL` candidate with the byte-identical 64-bit fallback.
pub const CODEGEN_VERSION: u64 = 7;

/// Cache key for compiled kernels: the program's content semantic hash mixed (FNV-1a)
/// with [`CODEGEN_VERSION`]. This is the key for both the in-process function cache
/// and the on-disk PTX cache — content + emitter version, never pointers or implicit
/// scope, per the repository's cache-keying rule.
pub fn jit_cache_key(semantic_hash: u64) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in semantic_hash
        .to_le_bytes()
        .into_iter()
        .chain(CODEGEN_VERSION.to_le_bytes())
    {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn fused_kernel_name(semantic_hash: u64) -> String {
    format!("stwo_jit_fused_{semantic_hash:016x}")
}

/// Compile a V1 program into CUDA C source defining one fused `__global__` kernel:
/// constraint evaluation, random-coefficient accumulation, `denom_inv` multiply, and
/// in-place accumulator update, one thread per row.
pub fn compile_v1_to_cuda_source(program: &OwnedMetalEvaluationProgramV1) -> Option<String> {
    let header = program.header();
    let name = fused_kernel_name(header.semantic_hash);
    let mut src = String::with_capacity(16384);
    emit_preamble(&mut src);

    src.push_str(&format!(
        "extern \"C\" __global__ void __launch_bounds__(128) {name}(\n\
         \x20   const unsigned *const *trace_cols,\n\
         \x20   const unsigned *interaction_offsets,\n\
         \x20   const unsigned *base_params,\n\
         \x20   const unsigned *ext_params,\n\
         \x20   const unsigned *random_coeff_powers,\n\
         \x20   const unsigned *denom_inv,\n\
         \x20   unsigned *coord_0,\n\
         \x20   unsigned *coord_1,\n\
         \x20   unsigned *coord_2,\n\
         \x20   unsigned *coord_3,\n\
         \x20   unsigned row_count,\n\
         \x20   unsigned log_n_rows,\n\
         \x20   unsigned rc_base\n\
         ) {{\n\
         \x20   unsigned row_index = blockIdx.x * blockDim.x + threadIdx.x;\n\
         \x20   if (row_index >= row_count) {{ return; }}\n\n"
    ));

    emit_instruction_body(program, &mut src)?;

    // Fused accumulate: coord_i[row] += result — the same per-coordinate M31 add the
    // separate AccumulationOps::accumulate pass performed, done in-register here.
    // Each thread touches only its own row, so the read-modify-write is race-free.
    src.push_str("    // Fused denom_inv multiply + in-place accumulator update.\n");
    src.push_str("    unsigned denom_idx = row_index >> log_n_rows;\n");
    src.push_str("    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);\n");
    src.push_str("    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);\n");
    src.push_str("    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);\n");
    src.push_str("    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);\n");
    src.push_str("    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);\n");
    src.push_str("}\n");
    Some(src)
}

/// Compile several already-governed constraint parts into one launch which owns
/// one evaluation-domain accumulator. Each part remains a separate device
/// function so the component split's register/resource boundary survives
/// ptxas, while the global kernel keeps the accumulator in registers and writes
/// each coordinate exactly once.
pub(crate) fn compile_composition_wave_to_cuda_source(
    programs: &[&OwnedMetalEvaluationProgramV1],
    kernel_name: &str,
) -> Option<String> {
    if programs.is_empty() || kernel_name.is_empty() {
        return None;
    }
    let mut src = String::with_capacity(
        programs
            .iter()
            .map(|program| {
                (program.base_insts().len() + program.ext_insts().len()).saturating_mul(80)
            })
            .sum::<usize>()
            .saturating_add(16_384),
    );
    emit_preamble(&mut src);
    src.push_str(
        "struct StwoCudaCompositionWavePart {\n\
         \x20   const unsigned *const *trace_cols;\n\
         \x20   const unsigned *interaction_offsets;\n\
         \x20   const unsigned *base_params;\n\
         \x20   const unsigned *ext_params;\n\
         \x20   const unsigned *denom_inv;\n\
         \x20   unsigned log_n_rows;\n\
         \x20   unsigned rc_base;\n\
         };\n\
         static_assert(sizeof(StwoCudaCompositionWavePart) == 48, \"wave part ABI\");\n\n",
    );
    for (ordinal, program) in programs.iter().enumerate() {
        emit_composition_wave_fragment(program, ordinal, &mut src)?;
    }
    src.push_str(&format!(
        "extern \"C\" __global__ void __launch_bounds__(128) {kernel_name}(\n\
         \x20   const StwoCudaCompositionWavePart *parts,\n\
         \x20   const unsigned *random_coeff_powers,\n\
         \x20   unsigned *coord_0,\n\
         \x20   unsigned *coord_1,\n\
         \x20   unsigned *coord_2,\n\
         \x20   unsigned *coord_3,\n\
         \x20   unsigned full_domain_rows,\n\
         \x20   unsigned shard_start,\n\
         \x20   unsigned shard_rows\n\
         ) {{\n\
         \x20   unsigned local_row = blockIdx.x * blockDim.x + threadIdx.x;\n\
         \x20   if (shard_rows == 0u || shard_start >= full_domain_rows ||\n\
         \x20       shard_rows > full_domain_rows - shard_start || local_row >= shard_rows) {{ return; }}\n\
         \x20   unsigned row_index = shard_start + local_row;\n\
         \x20   StwoCudaQm31 wave_acc = StwoCudaQm31{{0u, 0u, 0u, 0u}};\n",
    ));
    for ordinal in 0..programs.len() {
        src.push_str(&format!(
            "    wave_acc = stwo_qm31_add(wave_acc, stwo_composition_wave_part_{ordinal}(\n\
             \x20       parts[{ordinal}u], random_coeff_powers, full_domain_rows, row_index));\n"
        ));
    }
    src.push_str(
        "    coord_0[local_row] = wave_acc.a;\n\
         \x20   coord_1[local_row] = wave_acc.b;\n\
         \x20   coord_2[local_row] = wave_acc.c;\n\
         \x20   coord_3[local_row] = wave_acc.d;\n\
         }\n",
    );
    Some(src)
}

fn emit_composition_wave_fragment(
    program: &OwnedMetalEvaluationProgramV1,
    ordinal: usize,
    src: &mut String,
) -> Option<()> {
    src.push_str(&format!(
        "__device__ __noinline__ StwoCudaQm31 stwo_composition_wave_part_{ordinal}(\n\
         \x20   const StwoCudaCompositionWavePart &part,\n\
         \x20   const unsigned *random_coeff_powers,\n\
         \x20   unsigned full_domain_rows,\n\
         \x20   unsigned row_index\n\
         ) {{\n\
         \x20   unsigned row_count = full_domain_rows;\n\
         \x20   const unsigned *const *trace_cols = part.trace_cols;\n\
         \x20   const unsigned *interaction_offsets = part.interaction_offsets;\n\
         \x20   const unsigned *base_params = part.base_params;\n\
         \x20   const unsigned *ext_params = part.ext_params;\n\
         \x20   unsigned log_n_rows = part.log_n_rows;\n\
         \x20   unsigned rc_base = part.rc_base;\n"
    ));
    emit_instruction_body(program, src)?;
    src.push_str(
        "    unsigned denom_idx = row_index >> log_n_rows;\n\
         \x20   return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);\n\
         }\n\n",
    );
    Some(())
}

fn emit_instruction_body(program: &OwnedMetalEvaluationProgramV1, src: &mut String) -> Option<()> {
    let mut ext_declared = vec![false; program.header().max_ext_regs as usize];
    let base_schedule = BaseDefinitionSchedule::build(program)?;
    let mut base_states = vec![DefinitionEmissionState::Pending; base_schedule.nodes.len()];
    let root_final_definitions = constraint_root_final_definitions(program)?;
    let mut next_root = 0usize;
    let mut acc_declared = false;

    src.push_str("    // Canonical ext stream with demand-driven, versioned base cones.\n");
    for (ext_i, inst) in program.ext_insts().iter().enumerate() {
        if ExtOp::from_raw(inst.op)? == ExtOp::SecureCol {
            for register in [inst.a, inst.b, inst.c, inst.d] {
                emit_base_definition(
                    base_schedule.final_definition(register)?,
                    &base_schedule,
                    &mut base_states,
                    src,
                )?;
            }
        }
        emit_ext_instruction(
            inst,
            &base_schedule.final_definitions,
            &mut ext_declared,
            src,
        )?;
        emit_ready_root_prefix(
            program,
            &root_final_definitions,
            ext_i,
            &mut next_root,
            &mut acc_declared,
            src,
        );
    }
    src.push('\n');

    // Unreached base definitions are dead pure expressions. Deliberately omit
    // them: TraceCol, Param, Const, and field arithmetic have no side effects.
    if !acc_declared || next_root != program.constraint_roots().len() {
        return None;
    }
    Some(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DefinitionEmissionState {
    Pending,
    Visiting,
    Emitted,
}

#[derive(Clone, Copy, Debug)]
struct BaseDefinitionNode {
    inst: super::program::MetalEvaluationProgramBaseInstV1,
    dependencies: [Option<usize>; 2],
}

struct BaseDefinitionSchedule {
    nodes: Vec<BaseDefinitionNode>,
    final_definitions: Vec<Option<usize>>,
}

impl BaseDefinitionSchedule {
    fn build(program: &OwnedMetalEvaluationProgramV1) -> Option<Self> {
        let mut final_definitions = vec![None; program.header().max_base_regs as usize];
        let mut nodes = Vec::with_capacity(program.base_insts().len());
        for &inst in program.base_insts() {
            let dependencies = match BaseOp::from_raw(inst.op)? {
                BaseOp::TraceCol | BaseOp::Param | BaseOp::Const => [None, None],
                BaseOp::Add | BaseOp::Sub | BaseOp::Mul => [
                    *final_definitions.get(inst.a as usize)?,
                    *final_definitions.get(inst.b as usize)?,
                ],
                BaseOp::Neg | BaseOp::Inv => [*final_definitions.get(inst.a as usize)?, None],
                BaseOp::PreprocessedCol => return None,
            };
            let required_dependencies = match BaseOp::from_raw(inst.op)? {
                BaseOp::Add | BaseOp::Sub | BaseOp::Mul => 2,
                BaseOp::Neg | BaseOp::Inv => 1,
                _ => 0,
            };
            if dependencies[..required_dependencies]
                .iter()
                .any(Option::is_none)
            {
                return None;
            }
            let definition = nodes.len();
            *final_definitions.get_mut(inst.dst as usize)? = Some(definition);
            nodes.push(BaseDefinitionNode { inst, dependencies });
        }
        Some(Self {
            nodes,
            final_definitions,
        })
    }

    fn final_definition(&self, register: u32) -> Option<usize> {
        *self.final_definitions.get(register as usize)?
    }
}

fn emit_base_definition(
    definition: usize,
    schedule: &BaseDefinitionSchedule,
    states: &mut [DefinitionEmissionState],
    src: &mut String,
) -> Option<()> {
    // Production AIRs contain dependency cones deep enough to overflow a host
    // worker stack. Keep the same post-order traversal, but put its frames in a
    // bounded heap vector instead of recursive Rust calls.
    let mut stack = vec![(definition, false)];
    while let Some((definition, dependencies_visited)) = stack.pop() {
        if dependencies_visited {
            if *states.get(definition)? != DefinitionEmissionState::Visiting {
                return None;
            }
            emit_base_definition_node(definition, schedule, src)?;
            states[definition] = DefinitionEmissionState::Emitted;
            continue;
        }
        match *states.get(definition)? {
            DefinitionEmissionState::Emitted => continue,
            DefinitionEmissionState::Visiting => return None,
            DefinitionEmissionState::Pending => {}
        }
        states[definition] = DefinitionEmissionState::Visiting;
        stack.push((definition, true));
        let node = schedule.nodes.get(definition)?;
        for dependency in node.dependencies.into_iter().flatten().rev() {
            stack.push((dependency, false));
        }
    }
    Some(())
}

fn emit_base_definition_node(
    definition: usize,
    schedule: &BaseDefinitionSchedule,
    src: &mut String,
) -> Option<()> {
    let node = *schedule.nodes.get(definition)?;
    let dst = format!("b{definition}");
    match BaseOp::from_raw(node.inst.op)? {
        BaseOp::TraceCol => {
            let (interaction, column, offset) = (node.inst.interaction, node.inst.a, node.inst.imm);
            src.push_str(&format!(
                "    unsigned {dst} = stwo_trace_value(trace_cols, interaction_offsets, \
                 row_count, log_n_rows, {interaction}u, {column}u, row_index, {offset});\n"
            ));
        }
        BaseOp::Param => src.push_str(&format!(
            "    unsigned {dst} = base_params[{}u];\n",
            node.inst.a
        )),
        BaseOp::Const => src.push_str(&format!("    unsigned {dst} = {}u;\n", node.inst.a)),
        BaseOp::Add | BaseOp::Sub | BaseOp::Mul => {
            let [Some(a), Some(b)] = node.dependencies else {
                return None;
            };
            let operation = match BaseOp::from_raw(node.inst.op)? {
                BaseOp::Add => "stwo_m31_add",
                BaseOp::Sub => "stwo_m31_sub",
                BaseOp::Mul => "stwo_m31_mul",
                _ => unreachable!(),
            };
            src.push_str(&format!("    unsigned {dst} = {operation}(b{a}, b{b});\n"));
        }
        BaseOp::Neg | BaseOp::Inv => {
            let [Some(a), None] = node.dependencies else {
                return None;
            };
            let operation = match BaseOp::from_raw(node.inst.op)? {
                BaseOp::Neg => "stwo_m31_neg",
                BaseOp::Inv => "stwo_m31_inv",
                _ => unreachable!(),
            };
            src.push_str(&format!("    unsigned {dst} = {operation}(b{a});\n"));
        }
        BaseOp::PreprocessedCol => return None,
    }
    Some(())
}

fn constraint_root_final_definitions(
    program: &OwnedMetalEvaluationProgramV1,
) -> Option<Vec<usize>> {
    let mut final_definitions = vec![None; program.header().max_ext_regs as usize];
    for (ext_i, inst) in program.ext_insts().iter().enumerate() {
        *final_definitions.get_mut(inst.dst as usize)? = Some(ext_i);
    }
    program
        .constraint_roots()
        .iter()
        .map(|&root| *final_definitions.get(root as usize)?)
        .collect()
}

fn emit_ready_root_prefix(
    program: &OwnedMetalEvaluationProgramV1,
    final_definitions: &[usize],
    emitted_ext: usize,
    next_root: &mut usize,
    acc_declared: &mut bool,
    src: &mut String,
) {
    while final_definitions
        .get(*next_root)
        .is_some_and(|&definition| definition <= emitted_ext)
    {
        if !*acc_declared {
            src.push_str("    // Canonical root accumulation begins at first readiness.\n");
            src.push_str("    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};\n");
            *acc_declared = true;
        }
        let root = program.constraint_roots()[*next_root];
        src.push_str(&format!(
            "    acc = stwo_qm31_add(acc, stwo_qm31_mul(e{root}, \
             stwo_load_qm31(random_coeff_powers, rc_base + {next_root}u)));\n"
        ));
        *next_root += 1;
    }
}

fn emit_ext_instruction(
    inst: &super::program::MetalEvaluationProgramExtInstV1,
    base_final_definitions: &[Option<usize>],
    declared: &mut [bool],
    src: &mut String,
) -> Option<()> {
    let opcode = ExtOp::from_raw(inst.op)?;
    let dst = inst.dst as usize;
    let inputs = match opcode {
        ExtOp::Add | ExtOp::Sub | ExtOp::Mul => &[inst.a, inst.b][..],
        ExtOp::Neg => &[inst.a][..],
        ExtOp::SecureCol | ExtOp::Param | ExtOp::Const => &[],
    };
    if inputs
        .iter()
        .any(|&input| declared.get(input as usize).copied() != Some(true))
    {
        return None;
    }
    let was_declared = *declared.get(dst)?;
    *declared.get_mut(dst)? = true;
    let decl = if !was_declared { "StwoCudaQm31 " } else { "" };
    let dst_var = format!("e{dst}");
    match opcode {
        ExtOp::SecureCol => {
            let definition = |register: u32| *base_final_definitions.get(register as usize)?;
            let (a, b, c, d) = (
                definition(inst.a)?,
                definition(inst.b)?,
                definition(inst.c)?,
                definition(inst.d)?,
            );
            src.push_str(&format!(
                "    {decl}{dst_var} = StwoCudaQm31{{ b{a}, b{b}, b{c}, b{d} }};\n"
            ));
        }
        ExtOp::Param => {
            let slot = inst.a;
            src.push_str(&format!(
                "    {decl}{dst_var} = stwo_load_qm31(ext_params, {slot}u);\n"
            ));
        }
        ExtOp::Const => {
            let (a, b, c, d) = (inst.a, inst.b, inst.c, inst.d);
            src.push_str(&format!(
                "    {decl}{dst_var} = StwoCudaQm31{{ {a}u, {b}u, {c}u, {d}u }};\n"
            ));
        }
        ExtOp::Add => {
            let (a, b) = (inst.a, inst.b);
            src.push_str(&format!(
                "    {decl}{dst_var} = stwo_qm31_add(e{a}, e{b});\n"
            ));
        }
        ExtOp::Sub => {
            let (a, b) = (inst.a, inst.b);
            src.push_str(&format!(
                "    {decl}{dst_var} = stwo_qm31_sub(e{a}, e{b});\n"
            ));
        }
        ExtOp::Mul => {
            let (a, b) = (inst.a, inst.b);
            src.push_str(&format!(
                "    {decl}{dst_var} = stwo_qm31_mul(e{a}, e{b});\n"
            ));
        }
        ExtOp::Neg => {
            let a = inst.a;
            src.push_str(&format!(
                "    {decl}{dst_var} = stwo_qm31_sub(StwoCudaQm31{{0u,0u,0u,0u}}, e{a});\n"
            ));
        }
    }
    Some(())
}

fn emit_preamble(src: &mut String) {
    // Same formulas as the Metal preamble (byte-equal with the CPU reference via the
    // Metal conformance gate); CUDA syntax.
    src.push_str(
        "\
typedef unsigned long long u64;

#define STWO_M31_P 2147483647u

#ifndef STWO_M31_FAST32_GLOBAL
#define STWO_M31_FAST32_GLOBAL 0
#endif
#if STWO_M31_FAST32_GLOBAL != 0 && STWO_M31_FAST32_GLOBAL != 1
#error \"STWO_M31_FAST32_GLOBAL must be 0 or 1\"
#endif

__device__ __forceinline__ unsigned stwo_m31_add(unsigned lhs, unsigned rhs) {
    unsigned sum = lhs + rhs;
    return sum >= STWO_M31_P ? sum - STWO_M31_P : sum;
}

__device__ __forceinline__ unsigned stwo_m31_sub(unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}

__device__ __forceinline__ unsigned stwo_m31_neg(unsigned value) {
    unsigned negated = STWO_M31_P - value;
    return negated == STWO_M31_P ? 0u : negated;
}

__device__ __forceinline__ unsigned stwo_m31_mul(unsigned lhs, unsigned rhs) {
#if STWO_M31_FAST32_GLOBAL
    unsigned lo = lhs * rhs;
    unsigned hi = __umulhi(lhs, rhs);
    unsigned quotient = (hi << 1) | (lo >> 31);
    unsigned reduced = (lo & STWO_M31_P) + quotient;
    reduced = (reduced & STWO_M31_P) + (reduced >> 31);
    return reduced == STWO_M31_P ? 0u : reduced;
#else
    u64 product = (u64)lhs * (u64)rhs;
    u64 reduced = (((((product >> 31) + product + 1u) >> 31) + product) & (u64)STWO_M31_P);
    return (unsigned)reduced;
#endif
}

__device__ __forceinline__ unsigned stwo_m31_square(unsigned value) {
    return stwo_m31_mul(value, value);
}

__device__ __forceinline__ unsigned stwo_m31_pow2k(unsigned squarings, unsigned value) {
    unsigned result = value;
    for (unsigned i = 0; i < squarings; ++i) { result = stwo_m31_square(result); }
    return result;
}

__device__ __forceinline__ unsigned stwo_m31_inv(unsigned value) {
    unsigned t0 = stwo_m31_mul(stwo_m31_pow2k(2u, value), value);
    unsigned t1 = stwo_m31_mul(stwo_m31_pow2k(1u, t0), t0);
    unsigned t2 = stwo_m31_mul(stwo_m31_pow2k(3u, t1), t0);
    unsigned t3 = stwo_m31_mul(stwo_m31_pow2k(1u, t2), t0);
    unsigned t4 = stwo_m31_mul(stwo_m31_pow2k(8u, t3), t3);
    unsigned t5 = stwo_m31_mul(stwo_m31_pow2k(8u, t4), t3);
    return stwo_m31_mul(stwo_m31_pow2k(7u, t5), t2);
}

struct StwoCudaQm31 { unsigned a, b, c, d; };

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_add(StwoCudaQm31 l, StwoCudaQm31 r) {
    return StwoCudaQm31{stwo_m31_add(l.a, r.a), stwo_m31_add(l.b, r.b),
                        stwo_m31_add(l.c, r.c), stwo_m31_add(l.d, r.d)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_sub(StwoCudaQm31 l, StwoCudaQm31 r) {
    return StwoCudaQm31{stwo_m31_sub(l.a, r.a), stwo_m31_sub(l.b, r.b),
                        stwo_m31_sub(l.c, r.c), stwo_m31_sub(l.d, r.d)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_mul_base(StwoCudaQm31 v, unsigned s) {
    return StwoCudaQm31{stwo_m31_mul(v.a, s), stwo_m31_mul(v.b, s),
                        stwo_m31_mul(v.c, s), stwo_m31_mul(v.d, s)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_mul(StwoCudaQm31 l, StwoCudaQm31 r) {
    unsigned a0 = l.a, a1 = l.b, a2 = l.c, a3 = l.d;
    unsigned b0 = r.a, b1 = r.b, b2 = r.c, b3 = r.d;
    unsigned x0 = stwo_m31_sub(stwo_m31_mul(a0, b0), stwo_m31_mul(a1, b1));
    unsigned x1 = stwo_m31_add(stwo_m31_mul(a0, b1), stwo_m31_mul(a1, b0));
    unsigned y0 = stwo_m31_sub(stwo_m31_mul(a2, b2), stwo_m31_mul(a3, b3));
    unsigned y1 = stwo_m31_add(stwo_m31_mul(a2, b3), stwo_m31_mul(a3, b2));
    unsigned c0 = stwo_m31_sub(stwo_m31_mul(a0, b2), stwo_m31_mul(a1, b3));
    unsigned c1 = stwo_m31_add(stwo_m31_mul(a0, b3), stwo_m31_mul(a1, b2));
    unsigned c2 = stwo_m31_sub(stwo_m31_mul(a2, b0), stwo_m31_mul(a3, b1));
    unsigned c3 = stwo_m31_add(stwo_m31_mul(a2, b1), stwo_m31_mul(a3, b0));
    unsigned ry0 = stwo_m31_sub(stwo_m31_mul(2u, y0), y1);
    unsigned ry1 = stwo_m31_add(y0, stwo_m31_mul(2u, y1));
    return StwoCudaQm31{stwo_m31_add(x0, ry0), stwo_m31_add(x1, ry1),
                        stwo_m31_add(c0, c2), stwo_m31_add(c1, c3)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_load_qm31(const unsigned *values, unsigned index) {
    unsigned base = index * 4u;
    return StwoCudaQm31{values[base], values[base + 1u], values[base + 2u], values[base + 3u]};
}

__device__ __forceinline__ unsigned stwo_bit_reverse(unsigned index, unsigned bits) {
    return __brev(index) >> (32u - bits);
}

__device__ __forceinline__ unsigned stwo_offset_bit_reversed_circle_domain_index(
    unsigned i, unsigned domain_log_size, unsigned eval_log_size, int offset
) {
    unsigned prev = stwo_bit_reverse(i, eval_log_size);
    unsigned half_size = 1u << (eval_log_size - 1u);
    int step = offset * (int)(1u << (eval_log_size - domain_log_size - 1u));
    if (prev < half_size) {
        int p = ((int)prev + step) % (int)half_size;
        if (p < 0) p += (int)half_size;
        prev = (unsigned)p;
    } else {
        int p = (int)prev - step;
        p = p % (int)half_size;
        if (p < 0) p += (int)half_size;
        prev = (unsigned)p + half_size;
    }
    return stwo_bit_reverse(prev, eval_log_size);
}

__device__ __forceinline__ unsigned stwo_trace_value(
    const unsigned *const *trace_cols, const unsigned *interaction_offsets, unsigned row_count,
    unsigned log_n_rows, unsigned interaction, unsigned column, unsigned row_index, int offset
) {
    unsigned target_row;
    if (offset == 0) {
        target_row = row_index;
    } else {
        unsigned eval_log_size = 0u;
        unsigned tmp = row_count;
        while (tmp > 1u) { tmp >>= 1u; eval_log_size++; }
        target_row = stwo_offset_bit_reversed_circle_domain_index(
            row_index, log_n_rows, eval_log_size, offset);
    }
    unsigned global_column = interaction_offsets[interaction] + column;
    return trace_cols[global_column][target_row];
}

",
    );
}

#[cfg(test)]
#[path = "cuda_codegen_tests.rs"]
mod tests;
