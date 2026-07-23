//! Address-free authority for prepared execution-table ingest and limb splits.

use super::super::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};
use super::{
    execution_tables_workspace_requirements, ExecutionTablesWorkspaceRequirements,
    PreparedExecutionTablesError, EXECUTION_TABLE_BIG_LIMBS, EXECUTION_TABLE_SMALL_LIMBS,
};

mod identity;
use identity::*;

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BLOCK_THREADS: u32 = 256;
const LIMB_BITS: u32 = 9;
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_execution_tables.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("authority.rs");
const IDENTITY_SOURCE: &[u8] = include_bytes!("authority/identity.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/memory_witness.cu");

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-wrapper-source-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-source-v1\0";
const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-requirements-v1\0";
const INGRESS_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-host-ingress-v1\0";
const FIXED_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-fixed-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-contract-v1\0";
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-static-build-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-execution-tables-linked-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesStage {
    Big = 1,
    Small = 2,
}

pub const EXECUTION_TABLES_STAGE_ORDER: [ExecutionTablesStage; 2] =
    [ExecutionTablesStage::Big, ExecutionTablesStage::Small];

impl ExecutionTablesStage {
    const fn input_words(self) -> u32 {
        match self {
            Self::Big => 8,
            Self::Small => 4,
        }
    }

    const fn output_limbs(self) -> u32 {
        match self {
            Self::Big => EXECUTION_TABLE_BIG_LIMBS as u32,
            Self::Small => EXECUTION_TABLE_SMALL_LIMBS as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesHostIngressRole {
    RawAddressToId = 1,
    F252Values = 2,
    SmallValues = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesHostIngressEncoding {
    RawU32 = 1,
    F252LittleEndianU32x8 = 2,
    SmallU128LittleEndianU32x4 = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionTablesHostIngressField {
    pub role: ExecutionTablesHostIngressRole,
    pub encoding: ExecutionTablesHostIngressEncoding,
    pub rows: u32,
    pub words_per_row: u32,
    pub copied_words: usize,
    pub arena_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTablesHostIngressGeometry {
    pub fields: [ExecutionTablesHostIngressField; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesAbiArgumentKind {
    OptionalDeviceConstPointerU32 = 5,
    U32 = 2,
    HostConstPointerTableDeviceMutU32 = 3,
    CudaStream = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesAbiAccess {
    ReadValuesWhenNonEmpty = 6,
    RealRowCount = 2,
    ColumnRowCount = 3,
    ReadHostPointersWriteDeviceColumns = 4,
    OrderedExecutionStream = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionTablesAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: ExecutionTablesAbiArgumentKind,
    pub access: ExecutionTablesAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesAbi {
    BigLe8To28V1 = 1,
    SmallLe4To8V1 = 2,
}

impl ExecutionTablesAbi {
    pub const fn stage(self) -> ExecutionTablesStage {
        match self {
            Self::BigLe8To28V1 => ExecutionTablesStage::Big,
            Self::SmallLe4To8V1 => ExecutionTablesStage::Small,
        }
    }

    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::BigLe8To28V1 => "memory_limb_split_big_columns_on",
            Self::SmallLe4To8V1 => "memory_limb_split_small_columns_on",
        }
    }

    pub const fn arguments(self) -> &'static [ExecutionTablesAbiArgument] {
        &ARGUMENTS
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesEffectAbi {
    ReadLeWordsWriteLowNineBitLimbsZeroPadV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesRowDomain {
    RealPrefixThenZeroPaddingV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionTablesColumnEffect {
    pub column_ordinal: u32,
    pub write_start_word: u32,
    pub written_words: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTablesStageEffect {
    pub stage: ExecutionTablesStage,
    pub source_start_word: usize,
    pub source_read_words: usize,
    pub input_words_per_row: u32,
    pub real_rows: u32,
    pub column_rows: u32,
    pub emitted_low_bits: u32,
    pub ignored_high_bits: u32,
    pub zero_padding_start_row: u32,
    pub zero_padding_rows: u32,
    pub output_writes: Vec<ExecutionTablesColumnEffect>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionTablesKernelLaunch {
    pub stage: ExecutionTablesStage,
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub cluster: Option<[u32; 3]>,
}

impl ExecutionTablesKernelLaunch {
    pub const fn symbol(self) -> &'static str {
        match self.stage {
            ExecutionTablesStage::Big => "memory_limb_split_into_kernel<8, 28>",
            ExecutionTablesStage::Small => "memory_limb_split_into_kernel<4, 8>",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExecutionTablesFixedField {
    BigStage = 1,
    BigInputWords = 2,
    BigOutputLimbs = 3,
    SmallStage = 4,
    SmallInputWords = 5,
    SmallOutputLimbs = 6,
    LimbBits = 7,
    BlockThreads = 8,
}

pub const EXECUTION_TABLES_FIXED_ORDER: [ExecutionTablesFixedField; 8] = [
    ExecutionTablesFixedField::BigStage,
    ExecutionTablesFixedField::BigInputWords,
    ExecutionTablesFixedField::BigOutputLimbs,
    ExecutionTablesFixedField::SmallStage,
    ExecutionTablesFixedField::SmallInputWords,
    ExecutionTablesFixedField::SmallOutputLimbs,
    ExecutionTablesFixedField::LimbBits,
    ExecutionTablesFixedField::BlockThreads,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTablesStageContract {
    abi: ExecutionTablesAbi,
    effect: ExecutionTablesEffectAbi,
    row_domain: ExecutionTablesRowDomain,
    effect_geometry: ExecutionTablesStageEffect,
    launch: ExecutionTablesKernelLaunch,
}

impl ExecutionTablesStageContract {
    pub const fn stage(&self) -> ExecutionTablesStage {
        self.abi.stage()
    }
    pub const fn abi(&self) -> ExecutionTablesAbi {
        self.abi
    }
    pub const fn effect(&self) -> ExecutionTablesEffectAbi {
        self.effect
    }
    pub const fn row_domain(&self) -> ExecutionTablesRowDomain {
        self.row_domain
    }
    pub const fn effect_geometry(&self) -> &ExecutionTablesStageEffect {
        &self.effect_geometry
    }
    pub const fn launch(&self) -> ExecutionTablesKernelLaunch {
        self.launch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTablesContract {
    requirements: ExecutionTablesWorkspaceRequirements,
    host_ingress: ExecutionTablesHostIngressGeometry,
    fixed_words: [u32; 8],
    stages: [ExecutionTablesStageContract; 2],
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    requirements_identity: [u8; 32],
    host_ingress_identity: [u8; 32],
    fixed_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl ExecutionTablesContract {
    pub fn compile(
        requirements: &ExecutionTablesWorkspaceRequirements,
    ) -> Result<Self, ExecutionTablesAuthorityError> {
        require_canonical(requirements)?;
        let host_ingress = host_ingress(requirements)?;
        let fixed_words = [
            ExecutionTablesStage::Big as u32,
            ExecutionTablesStage::Big.input_words(),
            ExecutionTablesStage::Big.output_limbs(),
            ExecutionTablesStage::Small as u32,
            ExecutionTablesStage::Small.input_words(),
            ExecutionTablesStage::Small.output_limbs(),
            LIMB_BITS,
            BLOCK_THREADS,
        ];
        let stages = [
            stage_contract(ExecutionTablesStage::Big, requirements)?,
            stage_contract(ExecutionTablesStage::Small, requirements)?,
        ];
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE);
        let source_identity = source_identity(
            static_source_identity,
            wrapper_source_identity,
            &[BINDER_SOURCE, AUTHORITY_SOURCE, IDENTITY_SOURCE],
        );
        if [
            static_source_identity,
            wrapper_source_identity,
            source_identity,
        ]
        .contains(&ZERO_IDENTITY)
        {
            return Err(ExecutionTablesAuthorityError::MissingStaticSourceIdentity);
        }
        let requirements_identity = requirements_identity(requirements)?;
        let host_ingress_identity = host_ingress_identity(&host_ingress)?;
        let fixed_identity = fixed_identity(&fixed_words);
        let abi_identity = abi_identity(&stages);
        let effect_identity = effect_identity(&stages)?;
        let launch_identity = launch_identity(&stages);
        let identity = contract_identity([
            source_identity,
            requirements_identity,
            host_ingress_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        ]);
        Ok(Self {
            requirements: requirements.clone(),
            host_ingress,
            fixed_words,
            stages,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            requirements_identity,
            host_ingress_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), ExecutionTablesAuthorityError> {
        if Self::compile(&self.requirements)? == *self {
            Ok(())
        } else {
            Err(ExecutionTablesAuthorityError::InvalidCanonicalRequirements)
        }
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<ExecutionTablesLinkedContract>, ExecutionTablesAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked_contract(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn requirements(&self) -> &ExecutionTablesWorkspaceRequirements {
        &self.requirements
    }
    pub const fn host_ingress(&self) -> &ExecutionTablesHostIngressGeometry {
        &self.host_ingress
    }
    pub const fn fixed_words(&self) -> &[u32; 8] {
        &self.fixed_words
    }
    pub const fn stages(&self) -> &[ExecutionTablesStageContract; 2] {
        &self.stages
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
    pub const fn requirements_identity(&self) -> [u8; 32] {
        self.requirements_identity
    }
    pub const fn host_ingress_identity(&self) -> [u8; 32] {
        self.host_ingress_identity
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
pub struct ExecutionTablesLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl ExecutionTablesLinkedContract {
    pub fn validate(
        &self,
        contract: &ExecutionTablesContract,
    ) -> Result<(), ExecutionTablesAuthorityError> {
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(ExecutionTablesAuthorityError::StaticBuildUnavailable)?;
        if *self == expected {
            Ok(())
        } else {
            Err(ExecutionTablesAuthorityError::StaticBuildMismatch)
        }
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
pub enum ExecutionTablesAuthorityError {
    MissingStaticSourceIdentity,
    InvalidCanonicalRequirements,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for ExecutionTablesAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid execution-tables authority: {self:?}")
    }
}

impl std::error::Error for ExecutionTablesAuthorityError {}

impl From<StaticBuildBindError> for ExecutionTablesAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const ARGUMENTS: [ExecutionTablesAbiArgument; 5] = [
    argument(
        0,
        "values",
        ExecutionTablesAbiArgumentKind::OptionalDeviceConstPointerU32,
        ExecutionTablesAbiAccess::ReadValuesWhenNonEmpty,
    ),
    argument(
        1,
        "n_values",
        ExecutionTablesAbiArgumentKind::U32,
        ExecutionTablesAbiAccess::RealRowCount,
    ),
    argument(
        2,
        "column_length",
        ExecutionTablesAbiArgumentKind::U32,
        ExecutionTablesAbiAccess::ColumnRowCount,
    ),
    argument(
        3,
        "limb_cols_host",
        ExecutionTablesAbiArgumentKind::HostConstPointerTableDeviceMutU32,
        ExecutionTablesAbiAccess::ReadHostPointersWriteDeviceColumns,
    ),
    argument(
        4,
        "stream",
        ExecutionTablesAbiArgumentKind::CudaStream,
        ExecutionTablesAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: ExecutionTablesAbiArgumentKind,
    access: ExecutionTablesAbiAccess,
) -> ExecutionTablesAbiArgument {
    ExecutionTablesAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

#[cfg(test)]
mod tests;
