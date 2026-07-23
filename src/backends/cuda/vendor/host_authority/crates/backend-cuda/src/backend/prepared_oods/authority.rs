//! Address-free authority for one collapsed mixed-pass OODS transaction.
//!
//! The Rust prepared graph is one semantic producer. Its 71 generated-SN2
//! host calls and 99 ordered child launches remain an exact internal manifest;
//! they are not fabricated as independent SSA producers.

use super::super::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};
use super::*;

#[path = "authority/compiler.rs"]
mod compiler;
#[path = "authority/identity.rs"]
mod identity;
#[cfg(test)]
#[path = "authority/tests.rs"]
mod tests;

use compiler::compile_contract;
use identity::*;

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-oods-execution-static-build-v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsExecutionColumn {
    pub source_log_size: u32,
    pub evaluation_log_size: u32,
    pub source_kind: OodsSourceKind,
    pub offset_points: Vec<CirclePoint<BaseField>>,
}

impl OodsExecutionColumn {
    pub fn topology(&self) -> OodsColumnTopology<'_> {
        match self.source_kind {
            OodsSourceKind::Coefficients => OodsColumnTopology::coefficient_offset_points(
                self.source_log_size,
                self.evaluation_log_size,
                &self.offset_points,
            ),
            OodsSourceKind::Evaluations => OodsColumnTopology::evaluation_offset_points(
                self.evaluation_log_size,
                &self.offset_points,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OodsExecutionValueRole {
    SourcePointers,
    Source { column: u32 },
    PointParameter,
    OffsetPoints,
    FoldCounts,
    OutputIndices,
    CollapsedDescriptorOffsets,
    FoldingFactors,
    ScratchA,
    ScratchB,
    SamplePoints,
    SampledValues,
    EvaluationPoints,
    BarycentricNumerators,
    BarycentricWeights,
    BarycentricPartials,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OodsExecutionValueOwnership {
    ExternalSource = 1,
    TranscriptChallenge = 2,
    PreparedMetadata = 3,
    PreparedRelocation = 4,
    ExecutionOutput = 5,
    ExecutionScratch = 6,
    ReservedUnused = 7,
}

impl OodsExecutionValueOwnership {
    pub const fn is_causal_external_input(self) -> bool {
        matches!(self, Self::ExternalSource | Self::TranscriptChallenge)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsExecutionValueLayout {
    pub role: OodsExecutionValueRole,
    pub words: usize,
    pub alignment_words: usize,
    pub ownership: OodsExecutionValueOwnership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OodsExecutionAbiArgumentKind {
    DeviceConstPointerTableU32 = 1,
    DeviceConstPointerU32 = 2,
    DeviceMutPointerU32 = 3,
    CudaStream = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OodsExecutionAbiAccess {
    ReadSourcePointerTable = 1,
    ReadPointParameter = 2,
    ReadOffsetPoints = 3,
    ReadFoldCounts = 4,
    ReadOutputIndices = 5,
    ReadCollapsedDescriptorOffsets = 6,
    ReadWriteFoldingFactors = 7,
    ReadWriteScratchA = 8,
    ReadWriteScratchB = 9,
    WriteSamplePoints = 10,
    WriteSampledValues = 11,
    ReadWriteEvaluationPoints = 12,
    ReservedBarycentricNumerators = 13,
    ReadWriteBarycentricWeights = 14,
    ReadWriteBarycentricPartials = 15,
    OrderedExecutionStream = 16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsExecutionAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: OodsExecutionAbiArgumentKind,
    pub access: OodsExecutionAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OodsExecutionAbi {
    CollapsedMixedV1 = 1,
}

impl OodsExecutionAbi {
    pub const fn wrapper_symbol(self) -> &'static str {
        "PreparedOodsGraph::launch"
    }

    pub const fn arguments(self) -> &'static [OodsExecutionAbiArgument] {
        &COLLAPSED_MIXED_ARGUMENTS
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OodsExecutionInvocationValue {
    Role(OodsExecutionValueRole),
    OrderedStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsExecutionInvocationArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub value: OodsExecutionInvocationValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsExecutionInvocation {
    pub abi: OodsExecutionAbi,
    pub arguments: Vec<OodsExecutionInvocationArgument>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OodsExecutionAccessKind {
    Read = 1,
    Write = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsExecutionAccess {
    pub role: OodsExecutionValueRole,
    pub kind: OodsExecutionAccessKind,
    pub start_word: usize,
    pub words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OodsExecutionScratch {
    A = 1,
    B = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OodsExecutionHostCallKind {
    DeriveCoefficient {
        group: u32,
    },
    EvaluateFirst {
        group: u32,
    },
    EvaluateReduce {
        group: u32,
        pass: u32,
        input_size: u32,
        input_stride: u32,
        factor_index: u32,
        output_stride: u32,
        input: OodsExecutionScratch,
        output: OodsExecutionScratch,
    },
    StoreCoefficient {
        group: u32,
        reduced_stride: u32,
        reduced: OodsExecutionScratch,
    },
    DeriveEvaluation {
        group: u32,
    },
    CollapsedWeights {
        cohort: u32,
        batch: u32,
        first_group: u32,
        group_count: u32,
    },
    EvaluateMany {
        group: u32,
        cohort: u32,
        batch: u32,
        local_group: u32,
        weight_offset_words: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsExecutionKernelLaunch {
    pub symbol: &'static str,
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub cluster: Option<[u32; 3]>,
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsExecutionHostCall {
    pub ordinal: u32,
    pub wrapper_symbol: &'static str,
    pub kind: OodsExecutionHostCallKind,
    pub children: Vec<OodsExecutionKernelLaunch>,
    pub identity: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsExecutionAuthority {
    config: OodsWorkspaceConfig,
    columns: Vec<OodsExecutionColumn>,
    program: OodsPassCollapseProgram,
    fixed_offset_words: Vec<u32>,
    fixed_fold_words: Vec<u32>,
    fixed_output_index_words: Vec<u32>,
    fixed_descriptor_offset_words: Vec<u32>,
    values: Vec<OodsExecutionValueLayout>,
    invocation: OodsExecutionInvocation,
    accesses: Vec<OodsExecutionAccess>,
    host_calls: Vec<OodsExecutionHostCall>,
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    fixed_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl OodsExecutionAuthority {
    pub fn compile(
        config: OodsWorkspaceConfig,
        columns: &[OodsColumnTopology<'_>],
        program: &OodsPassCollapseProgram,
    ) -> Result<Self, OodsExecutionAuthorityError> {
        let compiled = compile_contract(config, columns, program)?;
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = wrapper_source_identity();
        let source_identity = source_identity(static_source_identity, wrapper_source_identity);
        if [
            static_source_identity,
            wrapper_source_identity,
            source_identity,
        ]
        .contains(&ZERO_IDENTITY)
        {
            return Err(OodsExecutionAuthorityError::MissingStaticSourceIdentity);
        }
        validate_static_symbols()?;
        let fixed_identity = fixed_identity(&compiled)?;
        let abi_identity = abi_identity(&compiled.invocation);
        let effect_identity = effect_identity(&compiled.accesses)?;
        let launch_identity = launch_identity(&compiled.host_calls)?;
        let identity = contract_identity([
            source_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        ]);
        Ok(Self {
            config,
            columns: compiled.columns,
            program: program.clone(),
            fixed_offset_words: compiled.fixed_offset_words,
            fixed_fold_words: compiled.fixed_fold_words,
            fixed_output_index_words: compiled.fixed_output_index_words,
            fixed_descriptor_offset_words: compiled.fixed_descriptor_offset_words,
            values: compiled.values,
            invocation: compiled.invocation,
            accesses: compiled.accesses,
            host_calls: compiled.host_calls,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), OodsExecutionAuthorityError> {
        let topologies = self
            .columns
            .iter()
            .map(OodsExecutionColumn::topology)
            .collect::<Vec<_>>();
        let program = OodsPassCollapseProgram::compile(self.config, &topologies)?;
        let expected = Self::compile(self.config, &topologies, &program)?;
        (*self == expected)
            .then_some(())
            .ok_or(OodsExecutionAuthorityError::ContractMismatch)
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<OodsExecutionLinkedAuthority>, OodsExecutionAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked_authority(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn config(&self) -> OodsWorkspaceConfig {
        self.config
    }
    pub fn columns(&self) -> &[OodsExecutionColumn] {
        &self.columns
    }
    pub const fn program(&self) -> &OodsPassCollapseProgram {
        &self.program
    }
    pub fn fixed_offset_words(&self) -> &[u32] {
        &self.fixed_offset_words
    }
    pub fn fixed_fold_words(&self) -> &[u32] {
        &self.fixed_fold_words
    }
    pub fn fixed_output_index_words(&self) -> &[u32] {
        &self.fixed_output_index_words
    }
    pub fn fixed_descriptor_offset_words(&self) -> &[u32] {
        &self.fixed_descriptor_offset_words
    }
    pub fn values(&self) -> &[OodsExecutionValueLayout] {
        &self.values
    }
    pub const fn invocation(&self) -> &OodsExecutionInvocation {
        &self.invocation
    }
    pub fn accesses(&self) -> &[OodsExecutionAccess] {
        &self.accesses
    }
    pub fn host_calls(&self) -> &[OodsExecutionHostCall] {
        &self.host_calls
    }
    pub fn child_launch_count(&self) -> usize {
        self.host_calls.iter().map(|call| call.children.len()).sum()
    }
    pub const fn static_source_identity(&self) -> [u8; 32] {
        self.static_source_identity
    }
    pub const fn wrapper_source_identity(&self) -> [u8; 32] {
        self.wrapper_source_identity
    }
    pub const fn source_identity(&self) -> [u8; 32] {
        self.source_identity
    }
    pub const fn fixed_identity(&self) -> [u8; 32] {
        self.fixed_identity
    }
    pub const fn abi_identity(&self) -> [u8; 32] {
        self.abi_identity
    }
    pub const fn effect_identity(&self) -> [u8; 32] {
        self.effect_identity
    }
    pub const fn launch_identity(&self) -> [u8; 32] {
        self.launch_identity
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsExecutionLinkedAuthority {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl OodsExecutionLinkedAuthority {
    pub fn validate_for_target(
        &self,
        authority: &OodsExecutionAuthority,
        target_sm: u32,
    ) -> Result<(), OodsExecutionAuthorityError> {
        if self.target_sm != target_sm {
            return Err(OodsExecutionAuthorityError::StaticBuildMismatch);
        }
        let expected = authority
            .bind_static_build(target_sm)?
            .ok_or(OodsExecutionAuthorityError::StaticBuildUnavailable)?;
        (*self == expected)
            .then_some(())
            .ok_or(OodsExecutionAuthorityError::StaticBuildMismatch)
    }

    pub const fn contract_identity(&self) -> [u8; 32] {
        self.contract_identity
    }
    pub const fn module_build_identity(&self) -> [u8; 32] {
        self.module_build_identity
    }
    pub const fn static_build_source_identity(&self) -> [u8; 32] {
        self.static_build_source_identity
    }
    pub const fn static_build_identity(&self) -> [u8; 32] {
        self.static_build_identity
    }
    pub const fn target_sm(&self) -> u32 {
        self.target_sm
    }
    pub const fn sm_identity(&self) -> [u8; 32] {
        self.sm_identity
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OodsExecutionAuthorityError {
    Oods(PreparedOodsError),
    PassCollapse(OodsPassCollapseError),
    ProgramMismatch,
    InvalidDescriptorCoverage,
    MissingStaticSourceIdentity,
    MissingStaticSymbol(&'static str),
    ContractMismatch,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for OodsExecutionAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid collapsed OODS execution authority: {self:?}"
        )
    }
}

impl std::error::Error for OodsExecutionAuthorityError {}

impl From<PreparedOodsError> for OodsExecutionAuthorityError {
    fn from(error: PreparedOodsError) -> Self {
        Self::Oods(error)
    }
}

impl From<OodsPassCollapseError> for OodsExecutionAuthorityError {
    fn from(error: OodsPassCollapseError) -> Self {
        Self::PassCollapse(error)
    }
}

impl From<StaticBuildBindError> for OodsExecutionAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const COLLAPSED_MIXED_ARGUMENTS: [OodsExecutionAbiArgument; 16] = [
    abi(
        0,
        "source_pointers",
        OodsExecutionAbiArgumentKind::DeviceConstPointerTableU32,
        OodsExecutionAbiAccess::ReadSourcePointerTable,
    ),
    abi(
        1,
        "point_parameter",
        OodsExecutionAbiArgumentKind::DeviceConstPointerU32,
        OodsExecutionAbiAccess::ReadPointParameter,
    ),
    abi(
        2,
        "offset_points",
        OodsExecutionAbiArgumentKind::DeviceConstPointerU32,
        OodsExecutionAbiAccess::ReadOffsetPoints,
    ),
    abi(
        3,
        "fold_counts",
        OodsExecutionAbiArgumentKind::DeviceConstPointerU32,
        OodsExecutionAbiAccess::ReadFoldCounts,
    ),
    abi(
        4,
        "output_indices",
        OodsExecutionAbiArgumentKind::DeviceConstPointerU32,
        OodsExecutionAbiAccess::ReadOutputIndices,
    ),
    abi(
        5,
        "descriptor_offsets",
        OodsExecutionAbiArgumentKind::DeviceConstPointerU32,
        OodsExecutionAbiAccess::ReadCollapsedDescriptorOffsets,
    ),
    abi(
        6,
        "folding_factors",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::ReadWriteFoldingFactors,
    ),
    abi(
        7,
        "scratch_a",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::ReadWriteScratchA,
    ),
    abi(
        8,
        "scratch_b",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::ReadWriteScratchB,
    ),
    abi(
        9,
        "sample_points",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::WriteSamplePoints,
    ),
    abi(
        10,
        "sampled_values",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::WriteSampledValues,
    ),
    abi(
        11,
        "evaluation_points",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::ReadWriteEvaluationPoints,
    ),
    abi(
        12,
        "barycentric_numerators",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::ReservedBarycentricNumerators,
    ),
    abi(
        13,
        "barycentric_weights",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::ReadWriteBarycentricWeights,
    ),
    abi(
        14,
        "barycentric_partials",
        OodsExecutionAbiArgumentKind::DeviceMutPointerU32,
        OodsExecutionAbiAccess::ReadWriteBarycentricPartials,
    ),
    abi(
        15,
        "stream",
        OodsExecutionAbiArgumentKind::CudaStream,
        OodsExecutionAbiAccess::OrderedExecutionStream,
    ),
];

const fn abi(
    ordinal: u8,
    name: &'static str,
    kind: OodsExecutionAbiArgumentKind,
    access: OodsExecutionAbiAccess,
) -> OodsExecutionAbiArgument {
    OodsExecutionAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}
