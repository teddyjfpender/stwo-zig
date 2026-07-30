//! V1 evaluation-program types and lowering (shared with the Metal JIT lane; the
//! recording evaluator and bytecode are GPU-API-agnostic). Extracted from the stwo-metal
//! prototype's `eval_program_v1.rs` (types, semantic hash, program builder, ABI
//! validation, and the generic `FrameworkEval` -> bytecode lowering entry).
//!
//! The interpreter, registry/overlay, and planner machinery of the original file
//! were intentionally left behind: this lane always JIT-compiles the program to a
//! Metal shader (see [`super::shader`]) and falls back to the CPU constraint lane
//! on any failure.

// The V1 program ABI is ported intact from the prototype; parts of its surface
// (debug sections, budgets, accessors) are unused by this trimmed JIT lane but kept
// so the ABI stays whole and diffable against the source project.
#![allow(dead_code)]
// The builder/header constructors mirror the prototype's V1 ABI signatures one-to-one.
#![allow(clippy::too_many_arguments)]

use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::FrameworkEval;

use super::recording::RecordingEvaluator;

pub const STWO_METAL_EVAL_PROGRAM_MAGIC_V1: u32 = u32::from_le_bytes(*b"STP1");
pub const STWO_METAL_EVAL_PROGRAM_ABI_MAJOR_V1: u16 = 1;
pub const STWO_METAL_EVAL_PROGRAM_ABI_MINOR_V1: u16 = 0;

pub const STWO_METAL_EVAL_PROGRAM_FLAG_PREFINALIZED_LOGUP_V1: u32 = 1 << 0;
#[allow(dead_code)]
pub const STWO_METAL_EVAL_PROGRAM_FLAG_DEBUG_PRESENT_V1: u32 = 1 << 1;

pub const STWO_METAL_EVAL_PROGRAM_CAP_BASE_INV_V1: u64 = 1 << 0;
pub const STWO_METAL_EVAL_PROGRAM_CAP_EXT_MUL_V1: u64 = 1 << 1;
pub const STWO_METAL_EVAL_PROGRAM_CAP_PREFINALIZED_LOGUP_V1: u64 = 1 << 2;

pub const STWO_METAL_EVAL_PROGRAM_SECURE_EXT_DEGREE_V1: u32 = 4;

/// Maximum compacted live value footprint for one generated constraint kernel,
/// expressed as scalar u32 lanes (one base register = one lane, one secure-field
/// register = four lanes). The exact CUDA 11.8/sm_90 cap-192 risk gate compiled
/// 53/53 kernels and reduced the SN composition schedule to 145 launches (versus
/// 180 at 160 and 245 at 128). Two bounded rows retain small spills and some rows
/// remain occupancy-limited, so 192 is a measured ceiling, not permission to remove
/// the governor. Keep it fixed between AOT generation and runtime lowering.
pub const CONSTRAINT_SPLIT_MAX_LIVE_U32_LANES: usize = 192;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MetalEvaluationProgramBaseOpcodeV1 {
    TraceCol = 0,
    PreprocessedCol = 1,
    Param = 2,
    Const = 3,
    Add = 4,
    Sub = 5,
    Mul = 6,
    Neg = 7,
    Inv = 8,
}

impl MetalEvaluationProgramBaseOpcodeV1 {
    pub const fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::TraceCol),
            1 => Some(Self::PreprocessedCol),
            2 => Some(Self::Param),
            3 => Some(Self::Const),
            4 => Some(Self::Add),
            5 => Some(Self::Sub),
            6 => Some(Self::Mul),
            7 => Some(Self::Neg),
            8 => Some(Self::Inv),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MetalEvaluationProgramBaseInstV1 {
    pub op: u8,
    pub interaction: u8,
    pub dst: u16,
    pub a: u32,
    pub b: u32,
    pub imm: i32,
}

impl MetalEvaluationProgramBaseInstV1 {
    pub const fn trace_col(dst: u16, interaction: u8, column: u32, offset: i32) -> Self {
        Self {
            op: MetalEvaluationProgramBaseOpcodeV1::TraceCol as u8,
            interaction,
            dst,
            a: column,
            b: 0,
            imm: offset,
        }
    }

    pub const fn const_value(dst: u16, value: u32) -> Self {
        Self {
            op: MetalEvaluationProgramBaseOpcodeV1::Const as u8,
            interaction: 0,
            dst,
            a: value,
            b: 0,
            imm: 0,
        }
    }

    pub const fn binary(op: MetalEvaluationProgramBaseOpcodeV1, dst: u16, a: u32, b: u32) -> Self {
        Self {
            op: op as u8,
            interaction: 0,
            dst,
            a,
            b,
            imm: 0,
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MetalEvaluationProgramExtOpcodeV1 {
    SecureCol = 0,
    Param = 1,
    Const = 2,
    Add = 3,
    Sub = 4,
    Mul = 5,
    Neg = 6,
}

impl MetalEvaluationProgramExtOpcodeV1 {
    pub const fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::SecureCol),
            1 => Some(Self::Param),
            2 => Some(Self::Const),
            3 => Some(Self::Add),
            4 => Some(Self::Sub),
            5 => Some(Self::Mul),
            6 => Some(Self::Neg),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MetalEvaluationProgramExtInstV1 {
    pub op: u8,
    pub reserved0: u8,
    pub dst: u16,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

impl MetalEvaluationProgramExtInstV1 {
    pub const fn secure_col(dst: u16, a: u32, b: u32, c: u32, d: u32) -> Self {
        Self {
            op: MetalEvaluationProgramExtOpcodeV1::SecureCol as u8,
            reserved0: 0,
            dst,
            a,
            b,
            c,
            d,
        }
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[allow(dead_code)] // Debug sections are part of the V1 ABI even though this lane never emits them.
pub enum MetalEvaluationProgramSectionKindV1 {
    BaseConsts = 1,
    ExtConsts = 2,
    BaseInsts = 3,
    ExtInsts = 4,
    ConstraintRoots = 5,
    DebugStrings = 6,
    ParamDebugMap = 7,
    NodeDebugMap = 8,
}

impl MetalEvaluationProgramSectionKindV1 {
    pub const REQUIRED: [Self; 5] = [
        Self::BaseConsts,
        Self::ExtConsts,
        Self::BaseInsts,
        Self::ExtInsts,
        Self::ConstraintRoots,
    ];

    pub const fn from_raw(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::BaseConsts),
            2 => Some(Self::ExtConsts),
            3 => Some(Self::BaseInsts),
            4 => Some(Self::ExtInsts),
            5 => Some(Self::ConstraintRoots),
            6 => Some(Self::DebugStrings),
            7 => Some(Self::ParamDebugMap),
            8 => Some(Self::NodeDebugMap),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MetalEvaluationProgramHeaderV1 {
    pub magic: u32,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub n_sections: u32,
    pub flags: u32,
    pub semantic_hash: u64,
    pub capability_bits: u64,
    pub n_interactions: u32,
    pub n_base_params: u32,
    pub n_ext_params: u32,
    pub n_constraints: u32,
    pub max_base_regs: u32,
    pub max_ext_regs: u32,
    pub secure_ext_degree: u32,
    pub reserved: [u32; 8],
}

impl MetalEvaluationProgramHeaderV1 {
    pub const fn new(
        n_sections: u32,
        semantic_hash: u64,
        capability_bits: u64,
        n_interactions: u32,
        n_base_params: u32,
        n_ext_params: u32,
        n_constraints: u32,
        max_base_regs: u32,
        max_ext_regs: u32,
    ) -> Self {
        Self {
            magic: STWO_METAL_EVAL_PROGRAM_MAGIC_V1,
            abi_major: STWO_METAL_EVAL_PROGRAM_ABI_MAJOR_V1,
            abi_minor: STWO_METAL_EVAL_PROGRAM_ABI_MINOR_V1,
            n_sections,
            flags: STWO_METAL_EVAL_PROGRAM_FLAG_PREFINALIZED_LOGUP_V1,
            semantic_hash,
            capability_bits,
            n_interactions,
            n_base_params,
            n_ext_params,
            n_constraints,
            max_base_regs,
            max_ext_regs,
            secure_ext_degree: STWO_METAL_EVAL_PROGRAM_SECURE_EXT_DEGREE_V1,
            reserved: [0; 8],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MetalEvaluationProgramSectionDescV1 {
    pub kind: u32,
    pub elem_size: u32,
    pub offset_bytes: u64,
    pub count: u64,
}

impl MetalEvaluationProgramSectionDescV1 {
    pub const fn new(
        kind: MetalEvaluationProgramSectionKindV1,
        elem_size: u32,
        offset_bytes: u64,
        count: u64,
    ) -> Self {
        Self {
            kind: kind as u32,
            elem_size,
            offset_bytes,
            count,
        }
    }

    pub const fn section_kind(self) -> Option<MetalEvaluationProgramSectionKindV1> {
        MetalEvaluationProgramSectionKindV1::from_raw(self.kind)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MetalEvaluationProgramBudgetV1 {
    pub max_base_regs: u32,
    pub max_ext_regs: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedMetalEvaluationProgramV1 {
    header: MetalEvaluationProgramHeaderV1,
    sections: Vec<MetalEvaluationProgramSectionDescV1>,
    base_consts: Vec<u32>,
    ext_consts: Vec<[u32; 4]>,
    base_insts: Vec<MetalEvaluationProgramBaseInstV1>,
    ext_insts: Vec<MetalEvaluationProgramExtInstV1>,
    constraint_roots: Vec<u32>,
}

impl OwnedMetalEvaluationProgramV1 {
    /// Construct an owned program from pre-built parts.
    ///
    /// This is primarily intended for test code that needs to build programs
    /// without going through the full lowering pipeline.
    pub fn from_parts(
        header: MetalEvaluationProgramHeaderV1,
        sections: Vec<MetalEvaluationProgramSectionDescV1>,
        base_consts: Vec<u32>,
        ext_consts: Vec<[u32; 4]>,
        base_insts: Vec<MetalEvaluationProgramBaseInstV1>,
        ext_insts: Vec<MetalEvaluationProgramExtInstV1>,
        constraint_roots: Vec<u32>,
    ) -> Self {
        Self {
            header,
            sections,
            base_consts,
            ext_consts,
            base_insts,
            ext_insts,
            constraint_roots,
        }
    }

    pub fn header(&self) -> MetalEvaluationProgramHeaderV1 {
        self.header
    }

    pub fn sections(&self) -> &[MetalEvaluationProgramSectionDescV1] {
        &self.sections
    }

    pub fn base_consts(&self) -> &[u32] {
        &self.base_consts
    }

    pub fn ext_consts(&self) -> &[[u32; 4]] {
        &self.ext_consts
    }

    pub fn base_insts(&self) -> &[MetalEvaluationProgramBaseInstV1] {
        &self.base_insts
    }

    pub fn ext_insts(&self) -> &[MetalEvaluationProgramExtInstV1] {
        &self.ext_insts
    }

    pub fn constraint_roots(&self) -> &[u32] {
        &self.constraint_roots
    }

    /// Collision-resistant identity of the exact typed inputs consumed by the
    /// ordinary CUDA source emitter. Invocation context (parameter extents,
    /// domain size and section serialization) is deliberately supplied through
    /// the structured launch ABI and may differ for one deduplicated source.
    pub fn semantic_identity(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"stwo-cuda-constraint-program-semantic-identity-v1\0");
        let header = self.header;
        hasher.update(&header.semantic_hash.to_le_bytes());
        for value in [header.max_base_regs, header.max_ext_regs] {
            hasher.update(&value.to_le_bytes());
        }
        hash_len(&mut hasher, self.base_insts.len());
        for inst in &self.base_insts {
            hasher.update(&[inst.op, inst.interaction]);
            hasher.update(&inst.dst.to_le_bytes());
            hasher.update(&inst.a.to_le_bytes());
            hasher.update(&inst.b.to_le_bytes());
            hasher.update(&inst.imm.to_le_bytes());
        }
        hash_len(&mut hasher, self.ext_insts.len());
        for inst in &self.ext_insts {
            hasher.update(&[inst.op, inst.reserved0]);
            hasher.update(&inst.dst.to_le_bytes());
            hasher.update(&inst.a.to_le_bytes());
            hasher.update(&inst.b.to_le_bytes());
            hasher.update(&inst.c.to_le_bytes());
            hasher.update(&inst.d.to_le_bytes());
        }
        hash_len(&mut hasher, self.constraint_roots.len());
        for root in &self.constraint_roots {
            hasher.update(&root.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    pub fn payload_len_bytes(&self) -> u64 {
        self.sections
            .iter()
            .map(|section| section.offset_bytes + section.count * section.elem_size as u64)
            .max()
            .unwrap_or(0)
    }
}

fn hash_len(hasher: &mut blake3::Hasher, len: usize) {
    hasher.update(
        &u64::try_from(len)
            .expect("constraint program length fits u64")
            .to_le_bytes(),
    );
}

#[derive(Debug)]
pub enum MetalEvaluationProgramLoweringError {
    UnsupportedComponent {
        component_name: &'static str,
    },
    InvalidWideFibonacciColumnCount {
        n_columns: u32,
    },
    InvalidVirtualSnosColumnCount {
        n_columns: u32,
    },
    ParameterBudgetOverflow,
    RegisterBudgetOverflow,
    AbiLayoutMismatch {
        record: &'static str,
        expected_size: usize,
        actual_size: usize,
    },
    AbiAlignmentMismatch {
        record: &'static str,
        expected_align: usize,
        actual_align: usize,
    },
    AbiFieldOffsetMismatch {
        record: &'static str,
    },
}

#[derive(Debug)]
pub enum MetalEvaluationProgramExecutionError {
    MetalRuntime { message: String },
}

#[derive(Debug)]
pub enum MetalEvaluationProgramDispatchKindV1 {
    JitCompiled,
}

pub fn metal_evaluation_program_semantic_hash_v1(chunks: &[&[u8]]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for chunk in chunks {
        for byte in *chunk {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

fn hash_u32s(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>()
}

fn hash_u32x4s(values: &[[u32; 4]]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.iter().flat_map(|limb| limb.to_le_bytes()))
        .collect::<Vec<_>>()
}

fn hash_base_insts(values: &[MetalEvaluationProgramBaseInstV1]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|inst| {
            let mut bytes = Vec::with_capacity(16);
            bytes.push(inst.op);
            bytes.push(inst.interaction);
            bytes.extend_from_slice(&inst.dst.to_le_bytes());
            bytes.extend_from_slice(&inst.a.to_le_bytes());
            bytes.extend_from_slice(&inst.b.to_le_bytes());
            bytes.extend_from_slice(&inst.imm.to_le_bytes());
            bytes
        })
        .collect()
}

fn hash_ext_insts(values: &[MetalEvaluationProgramExtInstV1]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|inst| {
            let mut bytes = Vec::with_capacity(20);
            bytes.push(inst.op);
            bytes.push(inst.reserved0);
            bytes.extend_from_slice(&inst.dst.to_le_bytes());
            bytes.extend_from_slice(&inst.a.to_le_bytes());
            bytes.extend_from_slice(&inst.b.to_le_bytes());
            bytes.extend_from_slice(&inst.c.to_le_bytes());
            bytes.extend_from_slice(&inst.d.to_le_bytes());
            bytes
        })
        .collect()
}

fn build_owned_program_v1(
    capability_bits: u64,
    n_interactions: u32,
    n_base_params: u32,
    n_ext_params: u32,
    max_base_regs: u32,
    max_ext_regs: u32,
    base_consts: Vec<u32>,
    ext_consts: Vec<[u32; 4]>,
    base_insts: Vec<MetalEvaluationProgramBaseInstV1>,
    ext_insts: Vec<MetalEvaluationProgramExtInstV1>,
    constraint_roots: Vec<u32>,
    domain_log_size: u32,
) -> OwnedMetalEvaluationProgramV1 {
    let base_consts_bytes = hash_u32s(&base_consts);
    let ext_consts_bytes = hash_u32x4s(&ext_consts);
    let base_insts_bytes = hash_base_insts(&base_insts);
    let ext_insts_bytes = hash_ext_insts(&ext_insts);
    let constraint_roots_bytes = hash_u32s(&constraint_roots);

    let semantic_hash = metal_evaluation_program_semantic_hash_v1(&[
        &base_consts_bytes,
        &ext_consts_bytes,
        &base_insts_bytes,
        &ext_insts_bytes,
        &constraint_roots_bytes,
    ]);

    let mut offset_bytes = 0u64;
    let mut next_section =
        |kind: MetalEvaluationProgramSectionKindV1, elem_size: u32, count: u64| {
            let section =
                MetalEvaluationProgramSectionDescV1::new(kind, elem_size, offset_bytes, count);
            offset_bytes += elem_size as u64 * count;
            section
        };

    let sections = vec![
        next_section(
            MetalEvaluationProgramSectionKindV1::BaseConsts,
            4,
            base_consts.len() as u64,
        ),
        next_section(
            MetalEvaluationProgramSectionKindV1::ExtConsts,
            16,
            ext_consts.len() as u64,
        ),
        next_section(
            MetalEvaluationProgramSectionKindV1::BaseInsts,
            size_of::<MetalEvaluationProgramBaseInstV1>() as u32,
            base_insts.len() as u64,
        ),
        next_section(
            MetalEvaluationProgramSectionKindV1::ExtInsts,
            size_of::<MetalEvaluationProgramExtInstV1>() as u32,
            ext_insts.len() as u64,
        ),
        next_section(
            MetalEvaluationProgramSectionKindV1::ConstraintRoots,
            4,
            constraint_roots.len() as u64,
        ),
    ];

    let mut header = MetalEvaluationProgramHeaderV1::new(
        sections.len() as u32,
        semantic_hash,
        capability_bits,
        n_interactions,
        n_base_params,
        n_ext_params,
        constraint_roots.len() as u32,
        max_base_regs,
        max_ext_regs,
    );
    // Store the trace domain log_size in reserved[0] so the interpreter
    // can compute correct offset_bit_reversed_circle_domain_index for
    // components where eval_domain_log_size > log_size + 1.
    header.reserved[0] = domain_log_size;

    OwnedMetalEvaluationProgramV1 {
        header,
        sections,
        base_consts,
        ext_consts,
        base_insts,
        ext_insts,
        constraint_roots,
    }
}

pub fn validate_eval_program_abi_layout_v1() -> Result<(), MetalEvaluationProgramLoweringError> {
    use core::mem::{align_of, offset_of, size_of};

    // MetalEvaluationProgramHeaderV1: 96 bytes, 8-byte align
    if size_of::<MetalEvaluationProgramHeaderV1>() != 96 {
        return Err(MetalEvaluationProgramLoweringError::AbiLayoutMismatch {
            record: "MetalEvaluationProgramHeaderV1",
            expected_size: 96,
            actual_size: size_of::<MetalEvaluationProgramHeaderV1>(),
        });
    }
    if align_of::<MetalEvaluationProgramHeaderV1>() != 8 {
        return Err(MetalEvaluationProgramLoweringError::AbiAlignmentMismatch {
            record: "MetalEvaluationProgramHeaderV1",
            expected_align: 8,
            actual_align: align_of::<MetalEvaluationProgramHeaderV1>(),
        });
    }
    // Header field offsets
    if offset_of!(MetalEvaluationProgramHeaderV1, magic) != 0
        || offset_of!(MetalEvaluationProgramHeaderV1, abi_major) != 4
        || offset_of!(MetalEvaluationProgramHeaderV1, abi_minor) != 6
        || offset_of!(MetalEvaluationProgramHeaderV1, n_sections) != 8
        || offset_of!(MetalEvaluationProgramHeaderV1, flags) != 12
        || offset_of!(MetalEvaluationProgramHeaderV1, semantic_hash) != 16
        || offset_of!(MetalEvaluationProgramHeaderV1, capability_bits) != 24
        || offset_of!(MetalEvaluationProgramHeaderV1, n_interactions) != 32
        || offset_of!(MetalEvaluationProgramHeaderV1, n_base_params) != 36
        || offset_of!(MetalEvaluationProgramHeaderV1, n_ext_params) != 40
        || offset_of!(MetalEvaluationProgramHeaderV1, n_constraints) != 44
        || offset_of!(MetalEvaluationProgramHeaderV1, max_base_regs) != 48
        || offset_of!(MetalEvaluationProgramHeaderV1, max_ext_regs) != 52
        || offset_of!(MetalEvaluationProgramHeaderV1, secure_ext_degree) != 56
        || offset_of!(MetalEvaluationProgramHeaderV1, reserved) != 60
    {
        return Err(
            MetalEvaluationProgramLoweringError::AbiFieldOffsetMismatch {
                record: "MetalEvaluationProgramHeaderV1",
            },
        );
    }

    // MetalEvaluationProgramSectionDescV1: 24 bytes, 8-byte align
    if size_of::<MetalEvaluationProgramSectionDescV1>() != 24 {
        return Err(MetalEvaluationProgramLoweringError::AbiLayoutMismatch {
            record: "MetalEvaluationProgramSectionDescV1",
            expected_size: 24,
            actual_size: size_of::<MetalEvaluationProgramSectionDescV1>(),
        });
    }
    if align_of::<MetalEvaluationProgramSectionDescV1>() != 8 {
        return Err(MetalEvaluationProgramLoweringError::AbiAlignmentMismatch {
            record: "MetalEvaluationProgramSectionDescV1",
            expected_align: 8,
            actual_align: align_of::<MetalEvaluationProgramSectionDescV1>(),
        });
    }
    if offset_of!(MetalEvaluationProgramSectionDescV1, kind) != 0
        || offset_of!(MetalEvaluationProgramSectionDescV1, elem_size) != 4
        || offset_of!(MetalEvaluationProgramSectionDescV1, offset_bytes) != 8
        || offset_of!(MetalEvaluationProgramSectionDescV1, count) != 16
    {
        return Err(
            MetalEvaluationProgramLoweringError::AbiFieldOffsetMismatch {
                record: "MetalEvaluationProgramSectionDescV1",
            },
        );
    }

    // MetalEvaluationProgramBaseInstV1: 16 bytes, 4-byte align
    if size_of::<MetalEvaluationProgramBaseInstV1>() != 16 {
        return Err(MetalEvaluationProgramLoweringError::AbiLayoutMismatch {
            record: "MetalEvaluationProgramBaseInstV1",
            expected_size: 16,
            actual_size: size_of::<MetalEvaluationProgramBaseInstV1>(),
        });
    }
    if align_of::<MetalEvaluationProgramBaseInstV1>() != 4 {
        return Err(MetalEvaluationProgramLoweringError::AbiAlignmentMismatch {
            record: "MetalEvaluationProgramBaseInstV1",
            expected_align: 4,
            actual_align: align_of::<MetalEvaluationProgramBaseInstV1>(),
        });
    }
    if offset_of!(MetalEvaluationProgramBaseInstV1, op) != 0
        || offset_of!(MetalEvaluationProgramBaseInstV1, interaction) != 1
        || offset_of!(MetalEvaluationProgramBaseInstV1, dst) != 2
        || offset_of!(MetalEvaluationProgramBaseInstV1, a) != 4
        || offset_of!(MetalEvaluationProgramBaseInstV1, b) != 8
        || offset_of!(MetalEvaluationProgramBaseInstV1, imm) != 12
    {
        return Err(
            MetalEvaluationProgramLoweringError::AbiFieldOffsetMismatch {
                record: "MetalEvaluationProgramBaseInstV1",
            },
        );
    }

    // MetalEvaluationProgramExtInstV1: 20 bytes, 4-byte align
    if size_of::<MetalEvaluationProgramExtInstV1>() != 20 {
        return Err(MetalEvaluationProgramLoweringError::AbiLayoutMismatch {
            record: "MetalEvaluationProgramExtInstV1",
            expected_size: 20,
            actual_size: size_of::<MetalEvaluationProgramExtInstV1>(),
        });
    }
    if align_of::<MetalEvaluationProgramExtInstV1>() != 4 {
        return Err(MetalEvaluationProgramLoweringError::AbiAlignmentMismatch {
            record: "MetalEvaluationProgramExtInstV1",
            expected_align: 4,
            actual_align: align_of::<MetalEvaluationProgramExtInstV1>(),
        });
    }
    if offset_of!(MetalEvaluationProgramExtInstV1, op) != 0
        || offset_of!(MetalEvaluationProgramExtInstV1, reserved0) != 1
        || offset_of!(MetalEvaluationProgramExtInstV1, dst) != 2
        || offset_of!(MetalEvaluationProgramExtInstV1, a) != 4
        || offset_of!(MetalEvaluationProgramExtInstV1, b) != 8
        || offset_of!(MetalEvaluationProgramExtInstV1, c) != 12
        || offset_of!(MetalEvaluationProgramExtInstV1, d) != 16
    {
        return Err(
            MetalEvaluationProgramLoweringError::AbiFieldOffsetMismatch {
                record: "MetalEvaluationProgramExtInstV1",
            },
        );
    }

    Ok(())
}

pub fn lower_framework_eval_to_v1<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    n_base_params: u32,
    n_ext_params: u32,
) -> Result<
    (
        OwnedMetalEvaluationProgramV1,
        Vec<BaseField>,
        Vec<SecureField>,
    ),
    MetalEvaluationProgramLoweringError,
> {
    lower_framework_eval_to_v1_with_logup(
        eval,
        n_interactions,
        n_base_params,
        n_ext_params,
        SecureField::zero(),
        eval.log_size(),
    )
}

/// Lower a [`FrameworkEval`] to a V1 evaluation program, providing the
/// correct logup `claimed_sum` and `log_size` for accurate constraint
/// recording.
///
/// The `claimed_sum` is the total logup sum for the component, divided by
/// `n_rows` to produce the per-row `cumsum_shift`.  When `claimed_sum` is
/// zero (e.g. for components without logup), the shift is zero and has no
/// effect.
///
/// Returns the program together with its base- and ext-parameter values: every
/// constant the recorder produced is hoisted out of the bytecode into a runtime
/// parameter slot, so the bytecode — and therefore the semantic hash and the
/// JIT-compiled kernel — is value-independent for structurally identical
/// evaluator recordings. The returned values must be uploaded as the kernel's
/// `base_params` and `ext_params` buffers in slot order. If the caller reserves
/// existing parameter slots, the returned vectors are the suffix to append after
/// those caller-owned values.
pub fn lower_framework_eval_to_v1_with_logup<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    n_base_params: u32,
    n_ext_params: u32,
    claimed_sum: SecureField,
    log_size: u32,
) -> Result<
    (
        OwnedMetalEvaluationProgramV1,
        Vec<BaseField>,
        Vec<SecureField>,
    ),
    MetalEvaluationProgramLoweringError,
> {
    // Uncapped: always the single fused program (the historical pipeline —
    // record, hoist, compact, build — unchanged byte-for-byte).
    let (mut parts, base_param_values, ext_param_values) =
        lower_framework_eval_to_v1_split_with_live_cap(
            eval,
            n_interactions,
            n_base_params,
            n_ext_params,
            claimed_sum,
            log_size,
            usize::MAX,
            usize::MAX,
        )?;
    debug_assert_eq!(parts.len(), 1);
    let part = parts.pop().expect("uncapped lowering yields one program");
    Ok((part.program, base_param_values, ext_param_values))
}

/// One kernel of a (possibly split) lowering.
///
/// `rc_base` is the global index of this kernel's first constraint root within the
/// component's `random_coeff_powers` sequence: kernel-local constraint `j` accumulates
/// with `random_coeff_powers[rc_base + j]` — the exact power the fused kernel used for
/// the same constraint. Splitting only regroups the exact modular sum
/// `Σ_i rc[i]·constraint_i(row)` into per-kernel partial sums, each multiplied by the
/// same `denom_inv[row >> log]` and added into the same accumulator coordinates on the
/// same stream in root order; M31/QM31 addition and distributivity are exact, so the
/// accumulated coordinates are bit-identical to the fused kernel's.
pub struct JitKernelPart {
    pub program: OwnedMetalEvaluationProgramV1,
    pub rc_base: u32,
}

/// Lower a [`FrameworkEval`] like [`lower_framework_eval_to_v1_with_logup`], but when
/// the recorded program exceeds `max_kernel_instrs` (total base + ext instructions)
/// split it into K sequential kernels, each at most that size (best effort: a single
/// constraint whose dependency cone alone exceeds the cap stays whole).
///
/// The split is by whole constraint roots: each part gets the backward slice
/// (dependency cone) of its contiguous root group, instructions kept in original
/// program order. Shared subexpressions are RECOMPUTED by every part that needs them —
/// there are no intermediate spill buffers, so the split costs zero extra VRAM; the
/// price is redundant arithmetic, not memory.
///
/// When the program fits under the cap the pipeline (and hence bytecode and semantic
/// hash) is identical to the unsplit entry point.
pub fn lower_framework_eval_to_v1_split<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    n_base_params: u32,
    n_ext_params: u32,
    claimed_sum: SecureField,
    log_size: u32,
    max_kernel_instrs: usize,
) -> Result<
    (Vec<JitKernelPart>, Vec<BaseField>, Vec<SecureField>),
    MetalEvaluationProgramLoweringError,
> {
    lower_framework_eval_to_v1_split_with_live_cap(
        eval,
        n_interactions,
        n_base_params,
        n_ext_params,
        claimed_sum,
        log_size,
        max_kernel_instrs,
        CONSTRAINT_SPLIT_MAX_LIVE_U32_LANES,
    )
}

/// Explicit-policy variant used by offline resource sweeps. Production JIT and AOT
/// callers use [`lower_framework_eval_to_v1_split`], whose live-lane cap is fixed and
/// sealed into the loaded pack identity.
pub fn lower_framework_eval_to_v1_split_with_live_cap<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    n_base_params: u32,
    n_ext_params: u32,
    claimed_sum: SecureField,
    log_size: u32,
    max_kernel_instrs: usize,
    max_live_u32_lanes: usize,
) -> Result<
    (Vec<JitKernelPart>, Vec<BaseField>, Vec<SecureField>),
    MetalEvaluationProgramLoweringError,
> {
    validate_eval_program_abi_layout_v1()?;

    let mut recorder = RecordingEvaluator::new();
    // Set the correct logup parameters. The default from
    // LogupAtRow::dummy() uses interaction=100 and cumsum_shift=1, but
    // Cairo components use INTERACTION_TRACE_IDX (2) and need the real
    // cumsum_shift derived from claimed_sum / n_rows.
    recorder.logup = stwo_constraint_framework::logup::LogupAtRow::new(
        stwo_constraint_framework::INTERACTION_TRACE_IDX,
        claimed_sum,
        log_size,
    );
    let recorder = eval.evaluate(recorder);
    let mut state = recorder.finish();

    // Statement-independence: base-field statement constants, channel-drawn lookup
    // elements, the logup cumsum shift (claimed_sum / 2^log_size), and record-time
    // const folds all land in bytecode as CONSTANTS, which would change the semantic
    // hash — and therefore force an NVRTC recompile — for every new statement. Hoist
    // EVERY constant into its own runtime parameter slot. Slots are assigned by
    // instruction occurrence, in encounter order, and values are returned to the
    // dispatcher for the base_params/ext_params buffers. Do not deduplicate by value:
    // equality between two statement values (most notably a zero claimed sum
    // colliding with another zero constant) is statement-dependent and would
    // otherwise change subsequent slot numbers, the bytecode, and the kernel semantic
    // hash. After this rewrite the bytecode is a pure function of the AIR's structure,
    // so the kernel cache (in-memory and on-disk) hits across statements, inputs, and
    // processes. The kernel reads params[slot] instead of an immediate — identical
    // values, identical arithmetic, byte-identical results.
    let checked_param_count = |reserved: u32, hoisted: usize| {
        reserved
            .checked_add(
                u32::try_from(hoisted)
                    .map_err(|_| MetalEvaluationProgramLoweringError::ParameterBudgetOverflow)?,
            )
            .ok_or(MetalEvaluationProgramLoweringError::ParameterBudgetOverflow)
    };
    let base_param_offset = n_base_params;
    let mut base_param_values = Vec::new();
    for inst in state.base_insts.iter_mut() {
        if inst.op == MetalEvaluationProgramBaseOpcodeV1::Const as u8 {
            let slot = checked_param_count(base_param_offset, base_param_values.len())?;
            base_param_values.push(BaseField::from_u32_unchecked(inst.a));
            inst.op = MetalEvaluationProgramBaseOpcodeV1::Param as u8;
            inst.interaction = 0;
            inst.a = slot;
            inst.b = 0;
            inst.imm = 0;
        }
    }
    let n_base_params = checked_param_count(base_param_offset, base_param_values.len())?;

    let ext_param_offset = n_ext_params;
    let mut ext_param_values: Vec<SecureField> = Vec::new();
    for inst in state.ext_insts.iter_mut() {
        if inst.op == MetalEvaluationProgramExtOpcodeV1::Const as u8 {
            let limbs = [inst.a, inst.b, inst.c, inst.d];
            let slot = checked_param_count(ext_param_offset, ext_param_values.len())?;
            ext_param_values.push(SecureField::from_m31_array(
                limbs.map(stwo::core::fields::m31::BaseField::from_u32_unchecked),
            ));
            inst.op = MetalEvaluationProgramExtOpcodeV1::Param as u8;
            inst.a = slot;
            inst.b = 0;
            inst.c = 0;
            inst.d = 0;
        }
    }
    let n_ext_params = checked_param_count(ext_param_offset, ext_param_values.len())?;

    // Resource governor: split the still-SSA state (each register written exactly
    // once, so backward slicing is trivial) into root groups BEFORE register
    // compaction. Bound both source size and the compacted live scalar-lane footprint;
    // instruction count alone admits 255-register kernels with local-memory spills.
    // Each part is compacted and built independently.
    let total_instrs = state.base_insts.len() + state.ext_insts.len();
    if state.constraint_roots.len() <= 1
        || (total_instrs <= max_kernel_instrs
            && compacted_live_u32_lanes(&state) <= max_live_u32_lanes)
    {
        let program =
            finalize_recording_state(state, n_interactions, n_base_params, n_ext_params, log_size);
        return Ok((
            vec![JitKernelPart {
                program,
                rc_base: 0,
            }],
            base_param_values,
            ext_param_values,
        ));
    }

    let parts = split_recording_state(&state, max_kernel_instrs, max_live_u32_lanes)
        .into_iter()
        .map(|(slice, rc_base)| JitKernelPart {
            program: finalize_recording_state(
                slice,
                n_interactions,
                n_base_params,
                n_ext_params,
                log_size,
            ),
            rc_base,
        })
        .collect();
    Ok((parts, base_param_values, ext_param_values))
}

/// Conservative source-level proxy for ptxas register pressure after the existing
/// linear-scan compaction. The weighting follows the generated CUDA representation:
/// base values occupy one u32 lane and `StwoCudaQm31` values occupy four.
fn compacted_live_u32_lanes(state: &super::recording::RecordingState) -> usize {
    let mut compacted = super::recording::RecordingState::from_parts(
        state.base_insts.clone(),
        state.ext_insts.clone(),
        state.constraint_roots.clone(),
        state.max_base_regs(),
        state.max_ext_regs(),
    );
    compacted.compact_registers();
    compacted.max_base_regs() as usize
        + STWO_METAL_EVAL_PROGRAM_SECURE_EXT_DEGREE_V1 as usize * compacted.max_ext_regs() as usize
}

/// Compact registers, sanity-check operands, and build the owned program. This is the
/// tail of the historical single-kernel pipeline, shared verbatim by the split path.
fn finalize_recording_state(
    mut state: super::recording::RecordingState,
    n_interactions: u32,
    n_base_params: u32,
    n_ext_params: u32,
    log_size: u32,
) -> OwnedMetalEvaluationProgramV1 {
    // Compact registers (linear-scan reuse) so big components don't spill: the
    // recorder's monotonic SSA allocation can produce hundreds of live slots.
    state.compact_registers();

    // Sanity check: every ext instruction's registers must be valid.
    let max_er = state.max_ext_regs();
    let max_br = state.max_base_regs();
    for (idx, inst) in state.ext_insts.iter().enumerate() {
        assert!(
            (inst.dst as u32) < max_er,
            "ext_inst[{}] has dst={} but max_ext_regs={} (op={})",
            idx,
            inst.dst,
            max_er,
            inst.op,
        );
        let op = MetalEvaluationProgramExtOpcodeV1::from_raw(inst.op);
        match op {
            Some(MetalEvaluationProgramExtOpcodeV1::Add)
            | Some(MetalEvaluationProgramExtOpcodeV1::Sub)
            | Some(MetalEvaluationProgramExtOpcodeV1::Mul) => {
                assert!(
                    inst.a < max_er,
                    "ext_inst[{}] (op={:?}) has src a={} but max_ext_regs={}",
                    idx,
                    op,
                    inst.a,
                    max_er,
                );
                assert!(
                    inst.b < max_er,
                    "ext_inst[{}] (op={:?}) has src b={} but max_ext_regs={}",
                    idx,
                    op,
                    inst.b,
                    max_er,
                );
            }
            Some(MetalEvaluationProgramExtOpcodeV1::Neg) => {
                assert!(
                    inst.a < max_er,
                    "ext_inst[{}] (op=Neg) has src a={} but max_ext_regs={}",
                    idx,
                    inst.a,
                    max_er,
                );
            }
            Some(MetalEvaluationProgramExtOpcodeV1::SecureCol) => {
                assert!(
                    inst.a < max_br,
                    "ext_inst[{}] (op=SecureCol) has base src a={} but max_base_regs={}",
                    idx,
                    inst.a,
                    max_br,
                );
            }
            _ => {}
        }
    }

    build_owned_program_v1(
        STWO_METAL_EVAL_PROGRAM_CAP_BASE_INV_V1
            | STWO_METAL_EVAL_PROGRAM_CAP_EXT_MUL_V1
            | STWO_METAL_EVAL_PROGRAM_CAP_PREFINALIZED_LOGUP_V1,
        n_interactions,
        n_base_params,
        n_ext_params,
        state.max_base_regs(),
        state.max_ext_regs(),
        Vec::new(),
        Vec::new(),
        state.base_insts,
        state.ext_insts,
        state.constraint_roots,
        log_size,
    )
}

/// Split an SSA recording state (pre-compaction: every register written exactly once)
/// into contiguous constraint-root groups whose backward slices each stay at or under
/// both `max_kernel_instrs` (base + ext instructions) and
/// `max_live_u32_lanes` (compacted base + 4*ext registers), except when a single
/// root's cone alone exceeds a cap. Returns `(slice_state, rc_base)` pairs in root
/// order; `rc_base` is the group's first root's index in the original root list.
///
/// Each slice keeps its instructions in original program order, so every root's
/// dataflow — and therefore its value — is exactly the original's. Instructions
/// shared between groups are duplicated (recomputed per kernel), never spilled.
fn split_recording_state(
    state: &super::recording::RecordingState,
    max_kernel_instrs: usize,
    max_live_u32_lanes: usize,
) -> Vec<(super::recording::RecordingState, u32)> {
    use {MetalEvaluationProgramBaseOpcodeV1 as B, MetalEvaluationProgramExtOpcodeV1 as X};

    let n_base_regs = state.max_base_regs() as usize;
    let n_ext_regs = state.max_ext_regs() as usize;

    // SSA def maps: register -> defining instruction index.
    let mut base_def = vec![usize::MAX; n_base_regs];
    for (i, inst) in state.base_insts.iter().enumerate() {
        base_def[inst.dst as usize] = i;
    }
    let mut ext_def = vec![usize::MAX; n_ext_regs];
    for (i, inst) in state.ext_insts.iter().enumerate() {
        ext_def[inst.dst as usize] = i;
    }

    // Mark the dependency cone of `root` into the needed sets; newly marked registers
    // are recorded for undo. Returns the number of newly needed instructions.
    let mark_cone = |root: u32,
                     needed_base: &mut [bool],
                     needed_ext: &mut [bool],
                     added_base: &mut Vec<u32>,
                     added_ext: &mut Vec<u32>|
     -> usize {
        let before = added_base.len() + added_ext.len();
        let mut ext_stack: Vec<u32> = Vec::new();
        let mut base_stack: Vec<u32> = Vec::new();
        if !needed_ext[root as usize] {
            needed_ext[root as usize] = true;
            added_ext.push(root);
            ext_stack.push(root);
        }
        while let Some(reg) = ext_stack.pop() {
            let inst = &state.ext_insts[ext_def[reg as usize]];
            match X::from_raw(inst.op) {
                Some(X::Add) | Some(X::Sub) | Some(X::Mul) => {
                    for src in [inst.a, inst.b] {
                        if !needed_ext[src as usize] {
                            needed_ext[src as usize] = true;
                            added_ext.push(src);
                            ext_stack.push(src);
                        }
                    }
                }
                Some(X::Neg) => {
                    if !needed_ext[inst.a as usize] {
                        needed_ext[inst.a as usize] = true;
                        added_ext.push(inst.a);
                        ext_stack.push(inst.a);
                    }
                }
                Some(X::SecureCol) => {
                    for src in [inst.a, inst.b, inst.c, inst.d] {
                        if !needed_base[src as usize] {
                            needed_base[src as usize] = true;
                            added_base.push(src);
                            base_stack.push(src);
                        }
                    }
                }
                // Param/Const are leaves.
                _ => {}
            }
        }
        while let Some(reg) = base_stack.pop() {
            let inst = &state.base_insts[base_def[reg as usize]];
            let srcs: &[u32] = match B::from_raw(inst.op) {
                Some(B::Add) | Some(B::Sub) | Some(B::Mul) => &[inst.a, inst.b],
                Some(B::Neg) | Some(B::Inv) => &[inst.a],
                // TraceCol/PreprocessedCol/Param/Const are leaves.
                _ => &[],
            };
            for &src in srcs {
                if !needed_base[src as usize] {
                    needed_base[src as usize] = true;
                    added_base.push(src);
                    base_stack.push(src);
                }
            }
        }
        added_base.len() + added_ext.len() - before
    };

    let roots = &state.constraint_roots;
    let mut out: Vec<(super::recording::RecordingState, u32)> = Vec::new();
    let mut needed_base = vec![false; n_base_regs];
    let mut needed_ext = vec![false; n_ext_regs];
    let mut count = 0usize;
    let mut group_start = 0usize;

    let make_slice = |start: usize, end: usize, needed_base: &[bool], needed_ext: &[bool]| {
        let slice_base: Vec<MetalEvaluationProgramBaseInstV1> = state
            .base_insts
            .iter()
            .filter(|inst| needed_base[inst.dst as usize])
            .copied()
            .collect();
        let slice_ext: Vec<MetalEvaluationProgramExtInstV1> = state
            .ext_insts
            .iter()
            .filter(|inst| needed_ext[inst.dst as usize])
            .copied()
            .collect();
        super::recording::RecordingState::from_parts(
            slice_base,
            slice_ext,
            roots[start..end].to_vec(),
            state.max_base_regs(),
            state.max_ext_regs(),
        )
    };
    let flush = |start: usize,
                 end: usize,
                 needed_base: &[bool],
                 needed_ext: &[bool],
                 out: &mut Vec<(super::recording::RecordingState, u32)>| {
        out.push((
            make_slice(start, end, needed_base, needed_ext),
            start as u32,
        ));
    };

    let mut i = 0usize;
    while i < roots.len() {
        let mut added_base: Vec<u32> = Vec::new();
        let mut added_ext: Vec<u32> = Vec::new();
        let added = mark_cone(
            roots[i],
            &mut needed_base,
            &mut needed_ext,
            &mut added_base,
            &mut added_ext,
        );
        let exceeds_instrs = count + added > max_kernel_instrs;
        let exceeds_live_lanes = i > group_start
            && compacted_live_u32_lanes(&make_slice(group_start, i + 1, &needed_base, &needed_ext))
                > max_live_u32_lanes;
        if i > group_start && (exceeds_instrs || exceeds_live_lanes) {
            // This root does not fit: undo its marginal cone, flush the group,
            // and retry the root against a fresh group.
            for reg in &added_ext {
                needed_ext[*reg as usize] = false;
            }
            for reg in &added_base {
                needed_base[*reg as usize] = false;
            }
            flush(group_start, i, &needed_base, &needed_ext, &mut out);
            needed_base.fill(false);
            needed_ext.fill(false);
            count = 0;
            group_start = i;
            continue;
        }
        count += added;
        i += 1;
    }
    flush(
        group_start,
        roots.len(),
        &needed_base,
        &needed_ext,
        &mut out,
    );
    out
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::Fraction;
    use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

    use super::super::recording::RecordingState;
    use super::*;

    const P: u64 = (1 << 31) - 1;

    #[derive(Clone, Copy)]
    struct ExtParamCollisionEval {
        first: SecureField,
        second: SecureField,
    }

    impl FrameworkEval for ExtParamCollisionEval {
        fn log_size(&self) -> u32 {
            4
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            5
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let first_trace = eval.next_trace_mask();
            eval.add_constraint(first_trace + self.first);
            let second_trace = eval.next_trace_mask();
            eval.add_constraint(second_trace + self.second);

            let numerator = E::EF::from(eval.next_trace_mask());
            let denominator = E::EF::from(eval.next_trace_mask());
            eval.write_logup_frac(Fraction::new(numerator, denominator));
            eval.finalize_logup();
            eval
        }
    }

    #[test]
    fn ext_param_slots_are_occurrence_stable_across_value_collisions() {
        let distinct_first = SecureField::from_u32_unchecked(17, 29, 43, 71);
        let distinct_second = SecureField::from_u32_unchecked(101, 131, 173, 211);
        let distinct_claimed_sum = SecureField::from_u32_unchecked(257, 263, 269, 271);
        let zero_eval = ExtParamCollisionEval {
            first: SecureField::zero(),
            second: SecureField::zero(),
        };
        let distinct_eval = ExtParamCollisionEval {
            first: distinct_first,
            second: distinct_second,
        };

        let lower = |eval: &ExtParamCollisionEval, claimed_sum| {
            lower_framework_eval_to_v1_split(
                eval,
                3,
                0,
                0,
                claimed_sum,
                eval.log_size(),
                usize::MAX,
            )
            .unwrap()
        };
        let (zero_parts, zero_base_values, zero_values) = lower(&zero_eval, SecureField::zero());
        let (distinct_parts, distinct_base_values, distinct_values) =
            lower(&distinct_eval, distinct_claimed_sum);

        assert_eq!(zero_parts.len(), 1);
        assert_eq!(distinct_parts.len(), 1);
        assert_eq!(zero_parts[0].program, distinct_parts[0].program);
        assert_eq!(
            zero_parts[0].program.header().semantic_hash,
            distinct_parts[0].program.header().semantic_hash
        );
        assert_eq!(zero_base_values, distinct_base_values);

        let rows = BaseField::from_u32_unchecked(1 << distinct_eval.log_size());
        assert_eq!(
            zero_values,
            vec![
                SecureField::zero(),
                SecureField::zero(),
                SecureField::zero()
            ]
        );
        assert_eq!(
            distinct_values,
            vec![distinct_first, distinct_second, distinct_claimed_sum / rows]
        );
        let slots = distinct_parts[0]
            .program
            .ext_insts()
            .iter()
            .filter(|inst| inst.op == MetalEvaluationProgramExtOpcodeV1::Param as u8)
            .map(|inst| inst.a)
            .collect::<Vec<_>>();
        assert_eq!(slots, vec![0, 1, 2]);
        assert_eq!(distinct_parts[0].program.header().n_ext_params, 3);
    }

    #[test]
    fn hoisted_param_slots_follow_reserved_prefixes_without_collisions() {
        let eval = ExtParamCollisionEval {
            first: SecureField::from_u32_unchecked(17, 29, 43, 71),
            second: SecureField::from_u32_unchecked(101, 131, 173, 211),
        };
        let lower = |n_base_params, n_ext_params| {
            lower_framework_eval_to_v1_split(
                &eval,
                3,
                n_base_params,
                n_ext_params,
                SecureField::from_u32_unchecked(257, 263, 269, 271),
                eval.log_size(),
                usize::MAX,
            )
        };
        let (parts, base_values, ext_values) = lower(5, 7).unwrap();
        let program = &parts[0].program;

        assert_eq!(base_values.len(), 1);
        assert_eq!(ext_values.len(), 3);
        assert_eq!(program.header().n_base_params, 6);
        assert_eq!(program.header().n_ext_params, 10);
        assert_eq!(
            program
                .base_insts()
                .iter()
                .filter(|inst| inst.op == MetalEvaluationProgramBaseOpcodeV1::Param as u8)
                .map(|inst| inst.a)
                .collect::<Vec<_>>(),
            vec![5]
        );
        assert_eq!(
            program
                .ext_insts()
                .iter()
                .filter(|inst| inst.op == MetalEvaluationProgramExtOpcodeV1::Param as u8)
                .map(|inst| inst.a)
                .collect::<Vec<_>>(),
            vec![7, 8, 9]
        );
        assert!(matches!(
            lower(u32::MAX, 7),
            Err(MetalEvaluationProgramLoweringError::ParameterBudgetOverflow)
        ));
        assert!(matches!(
            lower(5, u32::MAX),
            Err(MetalEvaluationProgramLoweringError::ParameterBudgetOverflow)
        ));
    }

    /// Deterministic synthetic trace value for the reference interpreter.
    fn trace_value(interaction: u8, column: u32, offset: i32) -> BaseField {
        let mix = (interaction as u64 + 1) * 1_000_003
            + (column as u64 + 1) * 7919
            + (offset + 64) as u64 * 31;
        BaseField::from_u32_unchecked((mix % P) as u32)
    }

    /// Reference interpreter for V1 programs: executes the bytecode with exact
    /// M31/QM31 field arithmetic and returns the constraint-root values. Used to
    /// prove that the split kernels' concatenated semantics equal the fused
    /// program's.
    fn interpret(
        program: &OwnedMetalEvaluationProgramV1,
        base_params: &[BaseField],
        ext_params: &[SecureField],
    ) -> Vec<SecureField> {
        use {MetalEvaluationProgramBaseOpcodeV1 as B, MetalEvaluationProgramExtOpcodeV1 as X};
        let header = program.header();
        let mut base = vec![BaseField::zero(); header.max_base_regs as usize];
        let mut ext = vec![SecureField::zero(); header.max_ext_regs as usize];
        for inst in program.base_insts() {
            let value = match B::from_raw(inst.op).unwrap() {
                B::TraceCol => trace_value(inst.interaction, inst.a, inst.imm),
                B::Param => base_params[inst.a as usize],
                B::PreprocessedCol => unreachable!("not emitted by these tests"),
                B::Const => BaseField::from_u32_unchecked(inst.a),
                B::Add => base[inst.a as usize] + base[inst.b as usize],
                B::Sub => base[inst.a as usize] - base[inst.b as usize],
                B::Mul => base[inst.a as usize] * base[inst.b as usize],
                B::Neg => -base[inst.a as usize],
                B::Inv => base[inst.a as usize].inverse(),
            };
            base[inst.dst as usize] = value;
        }
        for inst in program.ext_insts() {
            let value = match X::from_raw(inst.op).unwrap() {
                X::SecureCol => SecureField::from_m31_array([
                    base[inst.a as usize],
                    base[inst.b as usize],
                    base[inst.c as usize],
                    base[inst.d as usize],
                ]),
                X::Param => ext_params[inst.a as usize],
                X::Const => SecureField::from_m31_array(
                    [inst.a, inst.b, inst.c, inst.d].map(BaseField::from_u32_unchecked),
                ),
                X::Add => ext[inst.a as usize] + ext[inst.b as usize],
                X::Sub => ext[inst.a as usize] - ext[inst.b as usize],
                X::Mul => ext[inst.a as usize] * ext[inst.b as usize],
                X::Neg => -ext[inst.a as usize],
            };
            ext[inst.dst as usize] = value;
        }
        program
            .constraint_roots()
            .iter()
            .map(|&root| ext[root as usize])
            .collect()
    }

    #[derive(Clone, Copy)]
    struct BaseParamCollisionEval {
        first: BaseField,
        second: BaseField,
    }

    impl FrameworkEval for BaseParamCollisionEval {
        fn log_size(&self) -> u32 {
            4
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            5
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let first_trace = eval.next_trace_mask();
            eval.add_constraint(first_trace * E::F::from(self.first));
            let second_trace = eval.next_trace_mask();
            eval.add_constraint(second_trace * E::F::from(self.second));
            eval
        }
    }

    #[test]
    fn base_param_slots_make_program_hash_and_cache_key_value_independent() {
        let zero_eval = BaseParamCollisionEval {
            first: BaseField::zero(),
            second: BaseField::zero(),
        };
        let distinct_eval = BaseParamCollisionEval {
            first: BaseField::from_u32_unchecked(17),
            second: BaseField::from_u32_unchecked(29),
        };
        let lower = |eval: &BaseParamCollisionEval| {
            lower_framework_eval_to_v1_split(
                eval,
                1,
                0,
                0,
                SecureField::zero(),
                eval.log_size(),
                usize::MAX,
            )
            .unwrap()
        };
        let (zero_parts, zero_base_values, zero_ext_values) = lower(&zero_eval);
        let (distinct_parts, distinct_base_values, distinct_ext_values) = lower(&distinct_eval);

        assert_eq!(zero_parts.len(), 1);
        assert_eq!(distinct_parts.len(), 1);
        let zero_program = &zero_parts[0].program;
        let distinct_program = &distinct_parts[0].program;
        assert_eq!(zero_program, distinct_program);
        assert_eq!(zero_ext_values, distinct_ext_values);
        assert_eq!(zero_base_values, vec![BaseField::zero(); 3]);
        assert_eq!(
            distinct_base_values,
            vec![distinct_eval.first, BaseField::zero(), distinct_eval.second]
        );
        assert_eq!(distinct_program.header().n_base_params, 3);
        let slots = distinct_program
            .base_insts()
            .iter()
            .filter(|inst| inst.op == MetalEvaluationProgramBaseOpcodeV1::Param as u8)
            .map(|inst| inst.a)
            .collect::<Vec<_>>();
        assert_eq!(slots, vec![0, 1, 2]);

        let zero_hash = zero_program.header().semantic_hash;
        let distinct_hash = distinct_program.header().semantic_hash;
        assert_eq!(zero_hash, distinct_hash);
        assert_eq!(
            super::super::cuda_codegen::jit_cache_key(zero_hash),
            super::super::cuda_codegen::jit_cache_key(distinct_hash)
        );
        assert_eq!(
            interpret(zero_program, &zero_base_values, &zero_ext_values),
            vec![SecureField::zero(), SecureField::zero()]
        );
        assert_eq!(
            interpret(
                distinct_program,
                &distinct_base_values,
                &distinct_ext_values
            ),
            vec![
                SecureField::from(trace_value(1, 0, 0) * distinct_eval.first),
                SecureField::from(trace_value(1, 1, 0) * distinct_eval.second),
            ]
        );
    }

    /// Builder for synthetic SSA states (each register written exactly once), the
    /// same invariant the recorder guarantees before compaction.
    struct SsaBuilder {
        base: Vec<MetalEvaluationProgramBaseInstV1>,
        ext: Vec<MetalEvaluationProgramExtInstV1>,
        roots: Vec<u32>,
        next_base: u16,
        next_ext: u16,
    }

    impl SsaBuilder {
        fn new() -> Self {
            Self {
                base: Vec::new(),
                ext: Vec::new(),
                roots: Vec::new(),
                next_base: 0,
                next_ext: 0,
            }
        }

        fn trace(&mut self, interaction: u8, column: u32, offset: i32) -> u16 {
            let dst = self.next_base;
            self.next_base += 1;
            self.base.push(MetalEvaluationProgramBaseInstV1::trace_col(
                dst,
                interaction,
                column,
                offset,
            ));
            dst
        }

        fn bop(&mut self, op: MetalEvaluationProgramBaseOpcodeV1, a: u16, b: u16) -> u16 {
            let dst = self.next_base;
            self.next_base += 1;
            self.base.push(MetalEvaluationProgramBaseInstV1::binary(
                op, dst, a as u32, b as u32,
            ));
            dst
        }

        fn secure_col(&mut self, regs: [u16; 4]) -> u16 {
            let dst = self.next_ext;
            self.next_ext += 1;
            self.ext.push(MetalEvaluationProgramExtInstV1::secure_col(
                dst,
                regs[0] as u32,
                regs[1] as u32,
                regs[2] as u32,
                regs[3] as u32,
            ));
            dst
        }

        fn eparam(&mut self, slot: u32) -> u16 {
            let dst = self.next_ext;
            self.next_ext += 1;
            self.ext.push(MetalEvaluationProgramExtInstV1 {
                op: MetalEvaluationProgramExtOpcodeV1::Param as u8,
                reserved0: 0,
                dst,
                a: slot,
                b: 0,
                c: 0,
                d: 0,
            });
            dst
        }

        fn eop(&mut self, op: MetalEvaluationProgramExtOpcodeV1, a: u16, b: u16) -> u16 {
            let dst = self.next_ext;
            self.next_ext += 1;
            self.ext.push(MetalEvaluationProgramExtInstV1 {
                op: op as u8,
                reserved0: 0,
                dst,
                a: a as u32,
                b: b as u32,
                c: 0,
                d: 0,
            });
            dst
        }

        fn root(&mut self, reg: u16) {
            self.roots.push(reg as u32);
        }

        fn build(self) -> RecordingState {
            RecordingState::from_parts(
                self.base,
                self.ext,
                self.roots,
                self.next_base as u32,
                self.next_ext as u32,
            )
        }
    }

    /// A synthetic wide component: `n_roots` constraints, each a `chain`-long op
    /// chain over trace columns, mixed with a subexpression SHARED by every root
    /// (exercising cone duplication across split kernels) and a shared ext param
    /// (hoisted-constant leaf).
    fn synthetic_state(n_roots: usize, chain: usize) -> RecordingState {
        use {MetalEvaluationProgramBaseOpcodeV1 as B, MetalEvaluationProgramExtOpcodeV1 as X};
        let mut b = SsaBuilder::new();
        let t0 = b.trace(0, 0, 0);
        let t1 = b.trace(0, 1, 0);
        let shared = b.bop(B::Mul, t0, t1);
        let param = b.eparam(0);
        for r in 0..n_roots {
            let mut cur = b.trace(1, r as u32, 0);
            for k in 0..chain {
                let t = b.trace(
                    0,
                    ((r + k) % 5) as u32,
                    if k.is_multiple_of(2) { 0 } else { -1 },
                );
                cur = b.bop(if k.is_multiple_of(3) { B::Add } else { B::Mul }, cur, t);
            }
            let mixed = b.bop(B::Sub, cur, shared);
            let lifted = b.secure_col([mixed, cur, shared, t0]);
            let constrained = b.eop(X::Mul, lifted, param);
            b.root(constrained);
        }
        b.build()
    }

    fn finalize(state: RecordingState) -> OwnedMetalEvaluationProgramV1 {
        finalize_recording_state(state, 2, 0, 1, 6)
    }

    #[test]
    fn constraint_program_identity_covers_exact_codegen_inputs_only() {
        let program = finalize(synthetic_state(2, 2));
        let identity = program.semantic_identity();
        assert_ne!(identity, [0; 32]);

        let mut changed = program.clone();
        changed.header.semantic_hash ^= 1;
        assert_ne!(identity, changed.semantic_identity());
        let mut changed = program.clone();
        changed.header.max_base_regs += 1;
        assert_ne!(identity, changed.semantic_identity());
        let mut changed = program.clone();
        changed.base_insts[0].imm += 1;
        assert_ne!(identity, changed.semantic_identity());
        let mut changed = program.clone();
        changed.ext_insts[0].a += 1;
        assert_ne!(identity, changed.semantic_identity());
        let mut changed = program.clone();
        changed.constraint_roots[0] += 1;
        assert_ne!(identity, changed.semantic_identity());

        let mut invocation_context = program.clone();
        invocation_context.header.n_interactions += 1;
        invocation_context.header.n_base_params += 1;
        invocation_context.header.n_ext_params += 1;
        invocation_context.header.reserved[0] += 1;
        invocation_context.sections[0].count += 1;
        invocation_context.base_consts.push(1);
        invocation_context.ext_consts.push([1, 2, 3, 4]);
        assert_eq!(identity, invocation_context.semantic_identity());
    }

    fn test_ext_params() -> Vec<SecureField> {
        vec![SecureField::from_m31_array(
            [7, 11, 13, 17].map(BaseField::from_u32_unchecked),
        )]
    }

    /// Deterministic "random" coefficient powers for accumulation checks.
    fn rc_powers(n: usize) -> Vec<SecureField> {
        let alpha = SecureField::from_m31_array([3, 1, 4, 1].map(BaseField::from_u32_unchecked));
        let mut powers = Vec::with_capacity(n);
        let mut cur = SecureField::from(BaseField::from_u32_unchecked(1));
        for _ in 0..n {
            powers.push(cur);
            cur *= alpha;
        }
        powers
    }

    #[test]
    fn split_concatenated_semantics_equal_fused() {
        let ext_params = test_ext_params();
        let fused = finalize(synthetic_state(16, 8));
        let fused_roots = interpret(&fused, &[], &ext_params);
        assert_eq!(fused_roots.len(), 16);

        const CAP: usize = 60;
        let full_state = synthetic_state(16, 8);
        assert!(full_state.base_insts.len() + full_state.ext_insts.len() > CAP);
        let parts = split_recording_state(&full_state, CAP, usize::MAX);
        assert!(parts.len() > 1, "expected an actual split");

        let rc = rc_powers(fused_roots.len());
        let mut concatenated: Vec<SecureField> = Vec::new();
        let mut split_acc = SecureField::zero();
        for (slice, rc_base) in parts {
            // rc_base bookkeeping: each part's first root continues where the
            // previous part stopped.
            assert_eq!(rc_base as usize, concatenated.len());
            let program = finalize(slice);
            let instrs = program.base_insts().len() + program.ext_insts().len();
            assert!(
                instrs <= CAP,
                "split kernel has {instrs} instrs, cap is {CAP}"
            );
            let roots = interpret(&program, &[], &ext_params);
            for (j, value) in roots.iter().enumerate() {
                split_acc += *value * rc[rc_base as usize + j];
            }
            concatenated.extend(roots);
        }
        // Root-by-root equality: every constraint value is bit-identical.
        assert_eq!(concatenated, fused_roots);
        // Accumulator equality: the per-kernel partial sums (each kernel's
        // in-place accumulate) combine to exactly the fused kernel's sum.
        let fused_acc = fused_roots
            .iter()
            .zip(&rc)
            .fold(SecureField::zero(), |acc, (value, coeff)| {
                acc + *value * *coeff
            });
        assert_eq!(split_acc, fused_acc);
    }

    #[test]
    fn live_lane_cap_splits_and_preserves_root_order() {
        let ext_params = test_ext_params();
        let full_state = synthetic_state(16, 4);
        let fused_roots = interpret(&finalize(synthetic_state(16, 4)), &[], &ext_params);

        const LIVE_LANES: usize = 40;
        let parts = split_recording_state(&full_state, usize::MAX, LIVE_LANES);
        assert!(parts.len() > 1, "expected register pressure to split");

        let mut concatenated = Vec::new();
        for (slice, rc_base) in parts {
            assert_eq!(rc_base as usize, concatenated.len());
            assert!(
                compacted_live_u32_lanes(&slice) <= LIVE_LANES || slice.constraint_roots.len() == 1,
                "multi-root part exceeded the live-lane cap"
            );
            concatenated.extend(interpret(&finalize(slice), &[], &ext_params));
        }
        assert_eq!(concatenated, fused_roots);
    }

    #[test]
    fn single_group_split_is_identical_to_fused_program() {
        // With a cap that fits everything, the slice of all roots must reproduce the
        // fused program exactly (the synthetic state has no dead instructions).
        let fused = finalize(synthetic_state(12, 6));
        let state = synthetic_state(12, 6);
        let mut parts = split_recording_state(&state, usize::MAX, usize::MAX);
        assert_eq!(parts.len(), 1);
        let (slice, rc_base) = parts.pop().unwrap();
        assert_eq!(rc_base, 0);
        let program = finalize(slice);
        assert_eq!(program, fused);
        assert_eq!(program.header().semantic_hash, fused.header().semantic_hash);
    }

    #[test]
    fn oversized_single_cone_stays_whole_and_correct() {
        use {MetalEvaluationProgramBaseOpcodeV1 as B, MetalEvaluationProgramExtOpcodeV1 as X};
        // Root 0 alone exceeds the cap; the splitter must keep it whole (one
        // oversized kernel) and still split the remaining small roots off.
        let build = || {
            let mut b = SsaBuilder::new();
            let param = b.eparam(0);
            let mut cur = b.trace(0, 0, 0);
            for k in 0..100 {
                let t = b.trace(0, (k % 7) as u32, 0);
                cur = b.bop(B::Mul, cur, t);
            }
            let zero = b.trace(0, 8, 0);
            let big = b.secure_col([cur, zero, zero, zero]);
            let big = b.eop(X::Mul, big, param);
            b.root(big);
            for r in 0..4 {
                let t = b.trace(1, r, 0);
                let z = b.trace(0, 9 + r, 0);
                let small = b.secure_col([t, z, z, z]);
                b.root(small);
            }
            b.build()
        };
        const CAP: usize = 32;
        let ext_params = test_ext_params();
        let fused = finalize(build());
        let fused_roots = interpret(&fused, &[], &ext_params);

        let parts = split_recording_state(&build(), CAP, usize::MAX);
        assert!(parts.len() >= 2);
        // First part is the irreducible oversized cone.
        assert!(
            parts[0].0.base_insts.len() + parts[0].0.ext_insts.len() > CAP,
            "oversized cone should exceed the cap"
        );
        let mut concatenated: Vec<SecureField> = Vec::new();
        for (slice, rc_base) in parts {
            assert_eq!(rc_base as usize, concatenated.len());
            concatenated.extend(interpret(&finalize(slice), &[], &ext_params));
        }
        assert_eq!(concatenated, fused_roots);
    }
}
