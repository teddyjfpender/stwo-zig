//! Address-free authority for canonical device-born witness-input compaction.
//!
//! CUB chooses its own internal kernels and launch geometry. This contract seals
//! each ordered CUB API operation and all caller-controlled kernel launches.

mod abi;
mod identity;

use abi::ARGUMENTS;
use identity::*;

use super::static_build::{bind_static_build, StaticBuildBindError, StaticBuildBinding};
use super::{
    checked_witness_input_compact_temp_bytes, witness_input_compact_requirements,
    PreparedWitnessInputGatherError, WitnessInputCompactRequirements,
    WITNESS_INPUT_GATHER_DESCRIPTOR_ORDER, WITNESS_INPUT_GATHER_DESCRIPTOR_WORDS,
};
use crate::backend::exec_context::{cuda_device_snapshot, CudaDeviceSnapshot};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BLOCK_THREADS: u32 = 256;
const NO_SLOT: u32 = u32::MAX;
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_witness_input.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("compact_authority.rs");
const ABI_SOURCE: &[u8] = include_bytes!("compact_authority/abi.rs");
const IDENTITY_SOURCE: &[u8] = include_bytes!("compact_authority/identity.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/witness_edge_gather.cu");

pub(super) const WRAPPER_SOURCE_DOMAIN: &[u8] =
    b"stwo-cuda-witness-input-compact-wrapper-source-v1\0";
pub(super) const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-source-v1\0";
pub(super) const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-requirements-v1\0";
pub(super) const DESCRIPTOR_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-descriptors-v1\0";
pub(super) const FIXED_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-fixed-v1\0";
pub(super) const ABI_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-abi-v1\0";
pub(super) const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-effect-v1\0";
pub(super) const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-launch-v1\0";
pub(super) const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-contract-v1\0";
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-static-build-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-linked-v1\0";
const RUNTIME_SCRATCH_DOMAIN: &[u8] = b"stwo-cuda-witness-input-compact-runtime-scratch-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputCompactAbiArgumentKind {
    U32 = 1,
    Usize = 2,
    DeviceConstPointerU32 = 3,
    DeviceConstPointerTableU32 = 4,
    DeviceMutPointerU32 = 5,
    DeviceMutPointerTableU32 = 6,
    DeviceMutPointerBytes = 7,
    CudaStream = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputCompactAbiAccess {
    ReadPackedProducerColumns = 1,
    ReadCanonicalEdgeDescriptors = 2,
    EdgeCount = 3,
    TupleWords = 4,
    KeyWords = 5,
    TotalRows = 6,
    SortRows = 7,
    ConsumerRows = 8,
    ConsumerInputCount = 9,
    WriteConsumerColumns = 10,
    EnablerSlot = 11,
    IotaSlot = 12,
    MultiplicitySlot = 13,
    TupleScratch = 14,
    SortKeysA = 15,
    SortKeysB = 16,
    SortIndicesA = 17,
    SortIndicesB = 18,
    RunHeads = 19,
    RunPositions = 20,
    UniqueCount = 21,
    SortScratch = 22,
    SortScratchBytes = 23,
    ScanScratch = 24,
    ScanScratchBytes = 25,
    OrderedExecutionStream = 26,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: WitnessInputCompactAbiArgumentKind,
    pub access: WitnessInputCompactAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputCompactAbi {
    CanonicalTupleCompactionV1 = 1,
}

impl WitnessInputCompactAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::CanonicalTupleCompactionV1 => "stwo_witness_input_compact_on",
        }
    }

    pub const fn arguments(self) -> &'static [WitnessInputCompactAbiArgument] {
        match self {
            Self::CanonicalTupleCompactionV1 => &ARGUMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputCompactEffectAbi {
    GatherStableLexicographicRleScatterV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputCompactRowDomain {
    CanonicalUniquePowerOfTwoPaddingV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputCompactFixedField {
    EdgeCount = 1,
    TupleWords = 2,
    KeyWords = 3,
    TotalRows = 4,
    SortRows = 5,
    ConsumerRows = 6,
    ConsumerInputCount = 7,
    EnablerSlot = 8,
    IotaSlot = 9,
    MultiplicitySlot = 10,
}

pub const WITNESS_INPUT_COMPACT_FIXED_ORDER: [WitnessInputCompactFixedField; 10] = [
    WitnessInputCompactFixedField::EdgeCount,
    WitnessInputCompactFixedField::TupleWords,
    WitnessInputCompactFixedField::KeyWords,
    WitnessInputCompactFixedField::TotalRows,
    WitnessInputCompactFixedField::SortRows,
    WitnessInputCompactFixedField::ConsumerRows,
    WitnessInputCompactFixedField::ConsumerInputCount,
    WitnessInputCompactFixedField::EnablerSlot,
    WitnessInputCompactFixedField::IotaSlot,
    WitnessInputCompactFixedField::MultiplicitySlot,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactSourceEffect {
    pub source_ordinal: u32,
    pub read_start_words: usize,
    pub read_len_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactOutputEffect {
    pub output_ordinal: u32,
    pub write_start_words: usize,
    pub write_len_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactScratchEffect {
    pub tuple_words: usize,
    pub sort_key_words_each: usize,
    pub sort_index_words_each: usize,
    pub run_words_each: usize,
    pub unique_count_words: usize,
    pub sort_temp_capacity_words: usize,
    pub scan_temp_capacity_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactEffectGeometry {
    pub sources: Vec<WitnessInputCompactSourceEffect>,
    pub descriptor_read_start_words: usize,
    pub descriptor_read_len_words: usize,
    pub outputs: Vec<WitnessInputCompactOutputEffect>,
    pub total_rows: u32,
    pub sort_rows: u32,
    pub consumer_rows: u32,
    pub tuple_words: u32,
    pub key_words: u32,
    pub multiplicity_slot: u32,
    pub enabler_slot: Option<u32>,
    pub iota_slot: Option<u32>,
    pub rejects_equal_key_distinct_tuple: bool,
    pub padding_source_unique_row: u32,
    pub padding_multiplicity: u32,
    pub scratch: WitnessInputCompactScratchEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputCompactIndexBuffer {
    A = 1,
    B = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputCompactKeyBuffer {
    A = 1,
    B = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactKernelLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub cluster: Option<[u32; 3]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessInputCompactKernelStage {
    Gather,
    ExtractKey {
        word: u32,
        indices: WitnessInputCompactIndexBuffer,
    },
    Heads {
        indices: WitnessInputCompactIndexBuffer,
    },
    ClearOutput,
    Scatter {
        indices: WitnessInputCompactIndexBuffer,
    },
    Finalize,
}

impl WitnessInputCompactKernelStage {
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Gather => "witness_input_compact_gather_kernel",
            Self::ExtractKey { .. } => "witness_input_compact_key_kernel",
            Self::Heads { .. } => "witness_input_compact_heads_kernel",
            Self::ClearOutput => "witness_input_compact_clear_output_kernel",
            Self::Scatter { .. } => "witness_input_compact_scatter_kernel",
            Self::Finalize => "witness_input_compact_finalize_kernel",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessInputCompactCubStage {
    StableRadixSortPairs {
        word: u32,
        keys_from: WitnessInputCompactKeyBuffer,
        keys_to: WitnessInputCompactKeyBuffer,
        indices_from: WitnessInputCompactIndexBuffer,
        indices_to: WitnessInputCompactIndexBuffer,
        begin_bit: u8,
        end_bit: u8,
    },
    InclusiveSum,
}

impl WitnessInputCompactCubStage {
    pub const fn api(self) -> &'static str {
        match self {
            Self::StableRadixSortPairs { .. } => "cub::DeviceRadixSort::SortPairs",
            Self::InclusiveSum => "cub::DeviceScan::InclusiveSum",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessInputCompactExecution {
    Kernel {
        stage: WitnessInputCompactKernelStage,
        launch: WitnessInputCompactKernelLaunch,
    },
    Cub {
        stage: WitnessInputCompactCubStage,
        library_managed_launch_geometry: bool,
        ordered_on_wrapper_stream: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactStage {
    pub ordinal: u32,
    pub execution: WitnessInputCompactExecution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputCompactContract {
    abi: WitnessInputCompactAbi,
    effect: WitnessInputCompactEffectAbi,
    row_domain: WitnessInputCompactRowDomain,
    requirements: WitnessInputCompactRequirements,
    descriptor_words: Box<[u32]>,
    fixed_words: [u32; 10],
    effect_geometry: WitnessInputCompactEffectGeometry,
    stages: Box<[WitnessInputCompactStage]>,
    final_indices: WitnessInputCompactIndexBuffer,
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    requirements_identity: [u8; 32],
    descriptor_identity: [u8; 32],
    fixed_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessInputCompactContract {
    pub fn compile(
        requirements: &WitnessInputCompactRequirements,
    ) -> Result<Self, WitnessInputCompactAuthorityError> {
        require_canonical(requirements)?;
        let descriptor_words = descriptor_words(requirements)?;
        let fixed_words = fixed_words(requirements)?;
        let (stages, final_indices) = stages(requirements)?;
        let effect_geometry = effect_geometry(requirements)?;
        let abi = WitnessInputCompactAbi::CanonicalTupleCompactionV1;
        let effect = WitnessInputCompactEffectAbi::GatherStableLexicographicRleScatterV1;
        let row_domain = WitnessInputCompactRowDomain::CanonicalUniquePowerOfTwoPaddingV1;
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE);
        let source_identity = source_identity(
            static_source_identity,
            wrapper_source_identity,
            &[BINDER_SOURCE, AUTHORITY_SOURCE, ABI_SOURCE, IDENTITY_SOURCE],
        );
        if [
            static_source_identity,
            wrapper_source_identity,
            source_identity,
        ]
        .contains(&ZERO_IDENTITY)
        {
            return Err(WitnessInputCompactAuthorityError::MissingStaticSourceIdentity);
        }
        let requirements_identity = requirements_identity(requirements)?;
        let descriptor_identity = descriptor_identity(&descriptor_words);
        let fixed_identity = fixed_identity(&fixed_words);
        let abi_identity = abi_identity(abi);
        let effect_identity = effect_identity(effect, row_domain, &effect_geometry)?;
        let launch_identity = launch_identity(&stages, final_indices)?;
        let identity = contract_identity([
            source_identity,
            requirements_identity,
            descriptor_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        ]);
        Ok(Self {
            abi,
            effect,
            row_domain,
            requirements: requirements.clone(),
            descriptor_words: descriptor_words.into_boxed_slice(),
            fixed_words,
            effect_geometry,
            stages: stages.into_boxed_slice(),
            final_indices,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            requirements_identity,
            descriptor_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), WitnessInputCompactAuthorityError> {
        if Self::compile(&self.requirements)? == *self {
            Ok(())
        } else {
            Err(WitnessInputCompactAuthorityError::InvalidCanonicalRequirements)
        }
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<WitnessInputCompactLinkedContract>, WitnessInputCompactAuthorityError> {
        self.validate()?;
        let Some(binding) = bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)?
        else {
            return Ok(None);
        };
        require_current_target_sm(
            target_sm,
            cuda_device_snapshot()
                .map_err(|_| WitnessInputCompactAuthorityError::CurrentDeviceUnavailable)?,
        )?;
        let sort_rows = u32_value(self.requirements.sort_rows)?;
        let sort_temp_bytes = checked_witness_input_compact_temp_bytes(
            stwo_backend_cuda_kernels::raw::stwo_witness_input_compact_sort_temp_bytes,
            sort_rows,
        )
        .map_err(WitnessInputCompactAuthorityError::SortScratchQueryFailed)?;
        let scan_temp_bytes = checked_witness_input_compact_temp_bytes(
            stwo_backend_cuda_kernels::raw::stwo_witness_input_compact_scan_temp_bytes,
            sort_rows,
        )
        .map_err(WitnessInputCompactAuthorityError::ScanScratchQueryFailed)?;
        linked_contract(self, binding, sort_temp_bytes, scan_temp_bytes).map(Some)
    }

    pub const fn abi(&self) -> WitnessInputCompactAbi {
        self.abi
    }
    pub const fn effect(&self) -> WitnessInputCompactEffectAbi {
        self.effect
    }
    pub const fn row_domain(&self) -> WitnessInputCompactRowDomain {
        self.row_domain
    }
    pub const fn requirements(&self) -> &WitnessInputCompactRequirements {
        &self.requirements
    }
    pub fn descriptor_words(&self) -> &[u32] {
        &self.descriptor_words
    }
    pub const fn fixed_words(&self) -> &[u32; 10] {
        &self.fixed_words
    }
    pub const fn effect_geometry(&self) -> &WitnessInputCompactEffectGeometry {
        &self.effect_geometry
    }
    pub fn stages(&self) -> &[WitnessInputCompactStage] {
        &self.stages
    }
    pub const fn final_indices(&self) -> WitnessInputCompactIndexBuffer {
        self.final_indices
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
    pub const fn descriptor_identity(&self) -> [u8; 32] {
        self.descriptor_identity
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
pub struct WitnessInputCompactLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    sort_temp_bytes: usize,
    scan_temp_bytes: usize,
    runtime_scratch_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessInputCompactLinkedContract {
    pub fn validate(
        &self,
        contract: &WitnessInputCompactContract,
    ) -> Result<(), WitnessInputCompactAuthorityError> {
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(WitnessInputCompactAuthorityError::StaticBuildUnavailable)?;
        if expected == *self {
            Ok(())
        } else {
            Err(WitnessInputCompactAuthorityError::StaticBuildMismatch)
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
    pub const fn sort_temp_bytes(&self) -> usize {
        self.sort_temp_bytes
    }
    pub const fn scan_temp_bytes(&self) -> usize {
        self.scan_temp_bytes
    }
    pub const fn runtime_scratch_identity(&self) -> [u8; 32] {
        self.runtime_scratch_identity
    }
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessInputCompactAuthorityError {
    MissingStaticSourceIdentity,
    InvalidCanonicalRequirements,
    InvalidRuntimeScratch,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    CurrentDeviceUnavailable,
    CurrentDeviceTargetSmMismatch { requested: u32, actual: u32 },
    UnsupportedTargetSm(u32),
    SortScratchQueryFailed(i32),
    ScanScratchQueryFailed(i32),
}

impl core::fmt::Display for WitnessInputCompactAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid witness-input compact authority: {self:?}"
        )
    }
}

impl std::error::Error for WitnessInputCompactAuthorityError {}

impl From<StaticBuildBindError> for WitnessInputCompactAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

fn current_target_sm(
    snapshot: CudaDeviceSnapshot,
) -> Result<u32, WitnessInputCompactAuthorityError> {
    if snapshot.count == 0
        || snapshot.current >= snapshot.count
        || snapshot.sm_major == 0
        || snapshot.sm_minor >= 10
    {
        return Err(WitnessInputCompactAuthorityError::CurrentDeviceUnavailable);
    }
    snapshot
        .sm_major
        .checked_mul(10)
        .and_then(|major| major.checked_add(snapshot.sm_minor))
        .ok_or(WitnessInputCompactAuthorityError::CurrentDeviceUnavailable)
}

fn require_current_target_sm(
    requested: u32,
    snapshot: CudaDeviceSnapshot,
) -> Result<(), WitnessInputCompactAuthorityError> {
    let actual = current_target_sm(snapshot)?;
    if requested == actual {
        Ok(())
    } else {
        Err(WitnessInputCompactAuthorityError::CurrentDeviceTargetSmMismatch { requested, actual })
    }
}

#[cfg(test)]
mod tests;
