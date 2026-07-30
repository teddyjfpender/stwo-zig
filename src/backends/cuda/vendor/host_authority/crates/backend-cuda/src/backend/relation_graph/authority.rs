//! Address-free authority for the selected fused + segmented Relation family.
//!
//! This contract deliberately covers only the generated-SN execution lane:
//! every active instance is generic-fused, the body is one proof-wide wrapper,
//! and the segmented tail is one wrapper containing five ordered kernels.
//! Blake-G, per-instance fallback, three-stage, and scan-tail execution remain
//! separate authorities and therefore fail closed here.

use super::super::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};
use super::*;

pub(super) mod challenge;
mod compiler;
mod effects;
mod identity;

use compiler::compile_contract;
use identity::*;

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-relation-execution-static-build-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationExecutionStage {
    FusedBody = 1,
    SegmentedTail = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationPointerTableKind {
    Sources = 1,
    Descriptors = 2,
    Outputs = 3,
    DenominatorsUnused = 4,
    ClaimedSums = 5,
}

pub const RELATION_POINTER_TABLE_ORDER: [RelationPointerTableKind; 5] = [
    RelationPointerTableKind::Sources,
    RelationPointerTableKind::Descriptors,
    RelationPointerTableKind::Outputs,
    RelationPointerTableKind::DenominatorsUnused,
    RelationPointerTableKind::ClaimedSums,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationValueRole {
    Descriptors,
    AlphaPowers,
    ChallengeZ,
    DispatchPointers(RelationPointerTableKind),
    Geometry,
    InstanceSourcePointers {
        batch: u32,
        instance: u32,
    },
    InstanceSource {
        batch: u32,
        instance: u32,
        source: u32,
    },
    InstanceOutputPointers {
        batch: u32,
        instance: u32,
    },
    OutputCoordinate {
        batch: u32,
        instance: u32,
        coordinate: u32,
    },
    DenominatorSentinelUnused {
        batch: u32,
        instance: u32,
    },
    ClaimedSum {
        batch: u32,
        instance: u32,
    },
    InverseScratchUnused,
    ReductionPartials,
    ScanBlockSums,
    ScanEvalScratchUnused,
    ScanTempScratchUnused,
    ScanDescriptorsUnused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationValueLayout {
    pub role: RelationValueRole,
    pub words: usize,
    pub alignment_words: usize,
    pub ownership: RelationValueOwnership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationValueOwnership {
    ExternalSource = 1,
    TranscriptChallenge = 2,
    PreparedMetadata = 3,
    ExecutionOutput = 4,
    ExecutionScratch = 5,
    ReservedUnused = 6,
}

impl RelationValueOwnership {
    /// Only these roles may be resolved from pre-existing semantic values.
    /// Prepared metadata, outputs, scratch, and reserved storage are created
    /// within the Relation transaction and cannot become causal input roots.
    pub const fn is_causal_external_input(self) -> bool {
        matches!(self, Self::ExternalSource | Self::TranscriptChallenge)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationAbiArgumentKind {
    DeviceConstPointerTableU32 = 1,
    DeviceMutPointerTableU32 = 2,
    DeviceConstPointerU32 = 3,
    DeviceMutPointerU32 = 4,
    U32 = 5,
    HostConstPointerU32 = 6,
    CudaStream = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationAbiAccess {
    ReadSourcePointerTable = 1,
    ReadDescriptorPointerTable = 2,
    ReadOutputPointerTable = 3,
    ReadGeometry = 4,
    InstanceCount = 5,
    TotalRowBlockCount = 6,
    ReadAlphaPowers = 7,
    AlphaPowerCount = 8,
    ReadChallengeZ = 9,
    CopyHostEligibilityMaskByValue = 10,
    OrderedExecutionStream = 11,
    ReadClaimedSumPointerTable = 12,
    ReadWriteReductionPartials = 13,
    ReductionCapacitySecureFields = 14,
    ReadWriteScanBlockSums = 15,
    ScanCapacityWords = 16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: RelationAbiArgumentKind,
    pub access: RelationAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationAbi {
    FusedBodyV1 = 1,
    SegmentedTailV1 = 2,
}

impl RelationAbi {
    pub const fn stage(self) -> RelationExecutionStage {
        match self {
            Self::FusedBodyV1 => RelationExecutionStage::FusedBody,
            Self::SegmentedTailV1 => RelationExecutionStage::SegmentedTail,
        }
    }

    pub const fn wrapper_symbol(self) -> &'static str {
        match self {
            Self::FusedBodyV1 => "stwo_relation_fused_on",
            Self::SegmentedTailV1 => "stwo_relation_tail_global_on",
        }
    }

    pub const fn arguments(self) -> &'static [RelationAbiArgument] {
        match self {
            Self::FusedBodyV1 => &FUSED_ARGUMENTS,
            Self::SegmentedTailV1 => &TAIL_ARGUMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationInvocationValue {
    Role(RelationValueRole),
    U32(u32),
    /// Host wrapper input copied into the captured kernel parameter by value.
    /// It has no device allocation, `RelationValueRole`, or read effect.
    HostMask([u32; RELATION_FUSED_MASK_WORDS]),
    OrderedStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationInvocationArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub value: RelationInvocationValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationInvocation {
    pub abi: RelationAbi,
    pub arguments: Vec<RelationInvocationArgument>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationAccessKind {
    Read = 1,
    Write = 2,
    ReadWrite = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationAccess {
    pub role: RelationValueRole,
    pub kind: RelationAccessKind,
    pub start_word: usize,
    pub words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationKernelArgumentValue {
    Role(RelationValueRole),
    U32(u32),
    /// Inline by-value kernel parameter produced from the wrapper's host mask.
    Mask([u32; RELATION_FUSED_MASK_WORDS]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationKernelArgument {
    pub name: &'static str,
    pub value: RelationKernelArgumentValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationKernelLaunch {
    pub symbol: &'static str,
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub cluster: Option<[u32; 3]>,
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub arguments: Vec<RelationKernelArgument>,
    pub accesses: Vec<RelationAccess>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationPartitionAuthority {
    Monolithic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationWrapperExecution {
    pub stage: RelationExecutionStage,
    pub abi: RelationAbi,
    pub invocation: RelationInvocation,
    pub partition: RelationPartitionAuthority,
    /// Exact concatenation of every child access in launch order.
    pub accesses: Vec<RelationAccess>,
    pub children: Vec<RelationKernelLaunch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationExecutionInstance {
    pub batch_index: u32,
    pub instance_index: u32,
    pub source_layout: RelationSourceLayout,
    pub n_real_rows: u32,
    pub padded_rows: u32,
    pub source_offset_rows: u32,
    pub columns: u32,
    pub source_pointer_count: u32,
    pub output_coordinate_count: u32,
    pub descriptor_word_offset: u32,
    pub geometry: [u32; 11],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationExecutionAuthority {
    program: RelationKernelProgram,
    requirements: RelationGraphRequirements,
    descriptor_words: Vec<u32>,
    geometry_words: Vec<u32>,
    eligibility_mask: [u32; RELATION_FUSED_MASK_WORDS],
    instances: Vec<RelationExecutionInstance>,
    values: Vec<RelationValueLayout>,
    wrappers: [RelationWrapperExecution; 2],
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    program_identity: [u8; 32],
    requirements_identity: [u8; 32],
    fixed_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl RelationExecutionAuthority {
    pub fn compile(
        program: &RelationKernelProgram,
        requirements: &RelationGraphRequirements,
        mode: RelationLaunchMode,
        tail: RelationTailMode,
    ) -> Result<Self, RelationExecutionAuthorityError> {
        let compiled = compile_contract(program, requirements, mode, tail)?;
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
            return Err(RelationExecutionAuthorityError::MissingStaticSourceIdentity);
        }
        validate_static_symbols()?;
        let program_identity = program_identity(program)?;
        let requirements_identity = requirements_identity(requirements)?;
        let fixed_identity = fixed_identity(
            &compiled.descriptor_words,
            &compiled.geometry_words,
            &compiled.eligibility_mask,
            &compiled.instances,
            &compiled.values,
        )?;
        let abi_identity = abi_identity(&compiled.wrappers);
        let effect_identity = effect_identity(&compiled.wrappers)?;
        let launch_identity = launch_identity(&compiled.wrappers)?;
        let identity = contract_identity([
            source_identity,
            program_identity,
            requirements_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        ]);
        Ok(Self {
            program: program.clone(),
            requirements: requirements.clone(),
            descriptor_words: compiled.descriptor_words,
            geometry_words: compiled.geometry_words,
            eligibility_mask: compiled.eligibility_mask,
            instances: compiled.instances,
            values: compiled.values,
            wrappers: compiled.wrappers,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            program_identity,
            requirements_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), RelationExecutionAuthorityError> {
        let expected = Self::compile(
            &self.program,
            &self.requirements,
            RelationLaunchMode::Fused,
            RelationTailMode::Segmented,
        )?;
        (*self == expected)
            .then_some(())
            .ok_or(RelationExecutionAuthorityError::ContractMismatch)
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<RelationLinkedExecutionAuthority>, RelationExecutionAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked_authority(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn program(&self) -> &RelationKernelProgram {
        &self.program
    }
    pub const fn requirements(&self) -> &RelationGraphRequirements {
        &self.requirements
    }
    pub fn descriptor_words(&self) -> &[u32] {
        &self.descriptor_words
    }
    pub fn geometry_words(&self) -> &[u32] {
        &self.geometry_words
    }
    pub const fn eligibility_mask(&self) -> [u32; RELATION_FUSED_MASK_WORDS] {
        self.eligibility_mask
    }
    pub fn instances(&self) -> &[RelationExecutionInstance] {
        &self.instances
    }
    pub fn values(&self) -> &[RelationValueLayout] {
        &self.values
    }
    pub const fn wrappers(&self) -> &[RelationWrapperExecution; 2] {
        &self.wrappers
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
    pub const fn program_identity(&self) -> [u8; 32] {
        self.program_identity
    }
    pub const fn requirements_identity(&self) -> [u8; 32] {
        self.requirements_identity
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
pub struct RelationLinkedExecutionAuthority {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl RelationLinkedExecutionAuthority {
    pub fn validate(
        &self,
        authority: &RelationExecutionAuthority,
    ) -> Result<(), RelationExecutionAuthorityError> {
        self.validate_for_target(authority, self.target_sm)
    }

    /// Validate this linked receipt against both the semantic authority and
    /// the exact consumer architecture selected by the caller.
    pub fn validate_for_target(
        &self,
        authority: &RelationExecutionAuthority,
        target_sm: u32,
    ) -> Result<(), RelationExecutionAuthorityError> {
        if self.target_sm != target_sm {
            return Err(RelationExecutionAuthorityError::StaticBuildMismatch);
        }
        let expected = authority
            .bind_static_build(target_sm)?
            .ok_or(RelationExecutionAuthorityError::StaticBuildUnavailable)?;
        (*self == expected)
            .then_some(())
            .ok_or(RelationExecutionAuthorityError::StaticBuildMismatch)
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
pub enum RelationExecutionAuthorityError {
    InvalidProgram(RelationGraphError),
    UnsupportedLaunchMode(RelationLaunchMode),
    UnsupportedTailMode(RelationTailMode),
    EmptyExecution,
    UnresolvedBoundedRows { batch: usize, instance: usize },
    BlakeGRequiresSeparateAuthority { batch: usize },
    FusedFallbackRequiresSeparateAuthority { batch: usize },
    NonCanonicalRequirements,
    MissingStaticSourceIdentity,
    MissingStaticSymbol(&'static str),
    ContractMismatch,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for RelationExecutionAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid fused Relation execution authority: {self:?}"
        )
    }
}

impl std::error::Error for RelationExecutionAuthorityError {}

impl From<RelationGraphError> for RelationExecutionAuthorityError {
    fn from(error: RelationGraphError) -> Self {
        Self::InvalidProgram(error)
    }
}

impl From<StaticBuildBindError> for RelationExecutionAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const FUSED_ARGUMENTS: [RelationAbiArgument; 11] = [
    abi_argument(
        0,
        "source_tables",
        RelationAbiArgumentKind::DeviceConstPointerTableU32,
        RelationAbiAccess::ReadSourcePointerTable,
    ),
    abi_argument(
        1,
        "descriptors",
        RelationAbiArgumentKind::DeviceConstPointerTableU32,
        RelationAbiAccess::ReadDescriptorPointerTable,
    ),
    abi_argument(
        2,
        "output_tables",
        RelationAbiArgumentKind::DeviceMutPointerTableU32,
        RelationAbiAccess::ReadOutputPointerTable,
    ),
    abi_argument(
        3,
        "geometry",
        RelationAbiArgumentKind::DeviceConstPointerU32,
        RelationAbiAccess::ReadGeometry,
    ),
    abi_argument(
        4,
        "n_instances",
        RelationAbiArgumentKind::U32,
        RelationAbiAccess::InstanceCount,
    ),
    abi_argument(
        5,
        "total_row_blocks",
        RelationAbiArgumentKind::U32,
        RelationAbiAccess::TotalRowBlockCount,
    ),
    abi_argument(
        6,
        "alpha_powers",
        RelationAbiArgumentKind::DeviceConstPointerU32,
        RelationAbiAccess::ReadAlphaPowers,
    ),
    abi_argument(
        7,
        "n_alpha_powers",
        RelationAbiArgumentKind::U32,
        RelationAbiAccess::AlphaPowerCount,
    ),
    abi_argument(
        8,
        "z",
        RelationAbiArgumentKind::DeviceConstPointerU32,
        RelationAbiAccess::ReadChallengeZ,
    ),
    abi_argument(
        9,
        "eligible_mask_words",
        RelationAbiArgumentKind::HostConstPointerU32,
        RelationAbiAccess::CopyHostEligibilityMaskByValue,
    ),
    abi_argument(
        10,
        "stream",
        RelationAbiArgumentKind::CudaStream,
        RelationAbiAccess::OrderedExecutionStream,
    ),
];

const TAIL_ARGUMENTS: [RelationAbiArgument; 10] = [
    abi_argument(
        0,
        "output_tables",
        RelationAbiArgumentKind::DeviceMutPointerTableU32,
        RelationAbiAccess::ReadOutputPointerTable,
    ),
    abi_argument(
        1,
        "claimed_sums",
        RelationAbiArgumentKind::DeviceMutPointerTableU32,
        RelationAbiAccess::ReadClaimedSumPointerTable,
    ),
    abi_argument(
        2,
        "geometry",
        RelationAbiArgumentKind::DeviceConstPointerU32,
        RelationAbiAccess::ReadGeometry,
    ),
    abi_argument(
        3,
        "n_instances",
        RelationAbiArgumentKind::U32,
        RelationAbiAccess::InstanceCount,
    ),
    abi_argument(
        4,
        "total_row_blocks",
        RelationAbiArgumentKind::U32,
        RelationAbiAccess::TotalRowBlockCount,
    ),
    abi_argument(
        5,
        "reduction_partials",
        RelationAbiArgumentKind::DeviceMutPointerU32,
        RelationAbiAccess::ReadWriteReductionPartials,
    ),
    abi_argument(
        6,
        "reduction_capacity",
        RelationAbiArgumentKind::U32,
        RelationAbiAccess::ReductionCapacitySecureFields,
    ),
    abi_argument(
        7,
        "scan_block_sums",
        RelationAbiArgumentKind::DeviceMutPointerU32,
        RelationAbiAccess::ReadWriteScanBlockSums,
    ),
    abi_argument(
        8,
        "scan_capacity",
        RelationAbiArgumentKind::U32,
        RelationAbiAccess::ScanCapacityWords,
    ),
    abi_argument(
        9,
        "stream",
        RelationAbiArgumentKind::CudaStream,
        RelationAbiAccess::OrderedExecutionStream,
    ),
];

const fn abi_argument(
    ordinal: u8,
    name: &'static str,
    kind: RelationAbiArgumentKind,
    access: RelationAbiAccess,
) -> RelationAbiArgument {
    RelationAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

#[cfg(test)]
#[path = "authority/tests.rs"]
mod tests;
