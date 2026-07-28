//! V1 evaluation-program types and lowering, extracted from the stwo-metal
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
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::FrameworkEval;

use super::recording::RecordingEvaluator;

mod build;

use build::build_owned_program_v1;

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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExtParameterPair {
    pub primary: SecureField,
    pub probe: SecureField,
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

    pub fn payload_len_bytes(&self) -> u64 {
        self.sections
            .iter()
            .map(|section| section.offset_bytes + section.count * section.elem_size as u64)
            .max()
            .unwrap_or(0)
    }

    pub fn parameterize_extension_constants(
        &self,
        probe: &Self,
    ) -> Result<(Self, Vec<ExtParameterPair>), MetalEvaluationProgramLoweringError> {
        if self.header.n_interactions != probe.header.n_interactions
            || self.header.n_constraints != probe.header.n_constraints
            || self.header.max_base_regs != probe.header.max_base_regs
            || self.header.max_ext_regs != probe.header.max_ext_regs
            || self.base_consts != probe.base_consts
            || self.ext_consts != probe.ext_consts
            || self.base_insts != probe.base_insts
            || self.constraint_roots != probe.constraint_roots
            || self.ext_insts.len() != probe.ext_insts.len()
        {
            return Err(MetalEvaluationProgramLoweringError::ProbeTopologyMismatch);
        }

        let mut ext_insts = self.ext_insts.clone();
        let mut parameters = Vec::new();
        for (instruction, probe_instruction) in ext_insts.iter_mut().zip(&probe.ext_insts) {
            if instruction == probe_instruction {
                continue;
            }
            if instruction.op != MetalEvaluationProgramExtOpcodeV1::Const as u8
                || probe_instruction.op != MetalEvaluationProgramExtOpcodeV1::Const as u8
                || instruction.reserved0 != probe_instruction.reserved0
                || instruction.dst != probe_instruction.dst
            {
                return Err(MetalEvaluationProgramLoweringError::ProbeTopologyMismatch);
            }
            let parameter = ExtParameterPair {
                primary: secure_field(instruction),
                probe: secure_field(probe_instruction),
            };
            let slot = if let Some(slot) = parameters
                .iter()
                .position(|candidate| *candidate == parameter)
            {
                u32::try_from(slot)
                    .map_err(|_| MetalEvaluationProgramLoweringError::RegisterBudgetOverflow)?
            } else {
                let slot = u32::try_from(parameters.len())
                    .map_err(|_| MetalEvaluationProgramLoweringError::RegisterBudgetOverflow)?;
                parameters.push(parameter);
                slot
            };
            instruction.op = MetalEvaluationProgramExtOpcodeV1::Param as u8;
            instruction.a = slot;
            instruction.b = 0;
            instruction.c = 0;
            instruction.d = 0;
        }

        let program = build_owned_program_v1(
            self.header.capability_bits,
            self.header.n_interactions,
            self.header.n_base_params,
            parameters.len() as u32,
            self.header.max_base_regs,
            self.header.max_ext_regs,
            self.base_consts.clone(),
            self.ext_consts.clone(),
            self.base_insts.clone(),
            ext_insts,
            self.constraint_roots.clone(),
            self.header.reserved[0],
        );
        Ok((program, parameters))
    }

    pub fn bind_extension_parameters(
        &self,
        parameters: &[SecureField],
    ) -> Result<Self, MetalEvaluationProgramLoweringError> {
        if parameters.len() != self.header.n_ext_params as usize {
            return Err(MetalEvaluationProgramLoweringError::ParameterCountMismatch);
        }
        let mut ext_insts = self.ext_insts.clone();
        for instruction in &mut ext_insts {
            if instruction.op != MetalEvaluationProgramExtOpcodeV1::Param as u8 {
                continue;
            }
            let value = parameters
                .get(instruction.a as usize)
                .ok_or(MetalEvaluationProgramLoweringError::ParameterCountMismatch)?;
            let coordinates = value.to_m31_array();
            instruction.op = MetalEvaluationProgramExtOpcodeV1::Const as u8;
            instruction.a = coordinates[0].0;
            instruction.b = coordinates[1].0;
            instruction.c = coordinates[2].0;
            instruction.d = coordinates[3].0;
        }
        Ok(build_owned_program_v1(
            self.header.capability_bits,
            self.header.n_interactions,
            self.header.n_base_params,
            0,
            self.header.max_base_regs,
            self.header.max_ext_regs,
            self.base_consts.clone(),
            self.ext_consts.clone(),
            self.base_insts.clone(),
            ext_insts,
            self.constraint_roots.clone(),
            self.header.reserved[0],
        ))
    }
}

fn secure_field(instruction: &MetalEvaluationProgramExtInstV1) -> SecureField {
    SecureField::from_u32_unchecked(instruction.a, instruction.b, instruction.c, instruction.d)
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
    ProbeTopologyMismatch,
    ParameterCountMismatch,
}

#[derive(Debug)]
pub enum MetalEvaluationProgramExecutionError {
    MetalRuntime { message: String },
}

#[derive(Debug)]
pub enum MetalEvaluationProgramDispatchKindV1 {
    JitCompiled,
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
) -> Result<OwnedMetalEvaluationProgramV1, MetalEvaluationProgramLoweringError> {
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
pub fn lower_framework_eval_to_v1_with_logup<F: FrameworkEval>(
    eval: &F,
    n_interactions: u32,
    n_base_params: u32,
    n_ext_params: u32,
    claimed_sum: SecureField,
    log_size: u32,
) -> Result<OwnedMetalEvaluationProgramV1, MetalEvaluationProgramLoweringError> {
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
    let state = recorder.finish();

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

    Ok(build_owned_program_v1(
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
    ))
}
