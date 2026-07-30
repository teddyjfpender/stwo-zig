//! Address-free execution authority for one prepared generic witness feed.

use super::{
    witness_feed_workspace_requirements, PreparedWitnessFeedError, WitnessFeedLaunchMode,
    WitnessFeedWorkspaceRequirements, WITNESS_FEED_DESCRIPTOR_WORDS,
    WITNESS_FEED_PRIVATIZED_SHARED_BYTES,
};
use crate::backend::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};

mod geometry;
mod identity;

use geometry::{canonical_launch, canonical_ranges, destination_effects};
use identity::{
    abi_identity, combined_lut_identity, content_identity, contract_identity, digest, digest_words,
    effect_identity, launch_identity, lut_identity, requirements_identity, source_identity,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BLOCK_THREADS: u32 = 256;
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_witness_feed.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("authority.rs");
const GEOMETRY_SOURCE: &[u8] = include_bytes!("authority/geometry.rs");
const IDENTITY_SOURCE: &[u8] = include_bytes!("authority/identity.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/witness_feed_counts.cu");

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-wrapper-source-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-source-v1\0";
const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-requirements-v1\0";
const CONTENT_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-content-v1\0";
const DESCRIPTOR_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-descriptors-v1\0";
const LUT_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-lut-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-contract-v1\0";
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-static-build-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-linked-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedAbiArgumentKind {
    U32 = 1,
    DeviceConstPointerU32 = 2,
    DeviceConstPointerTableU32 = 3,
    DeviceMutPointerTableU32 = 4,
    CudaStream = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedAbiAccess {
    ReadSource = 1,
    RowCount = 2,
    ReadDescriptors = 3,
    DescriptorCount = 4,
    ReadLuts = 5,
    AtomicDestinations = 6,
    OrderedExecutionStream = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: WitnessFeedAbiArgumentKind,
    pub access: WitnessFeedAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedAbi {
    GlobalAtomicsV1 = 1,
    PrivatizedV1 = 2,
}

impl WitnessFeedAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::GlobalAtomicsV1 => "stwo_witness_feed_counts_on",
            Self::PrivatizedV1 => "stwo_witness_feed_counts_privatized_on",
        }
    }

    pub const fn arguments(self) -> &'static [WitnessFeedAbiArgument] {
        &ARGUMENTS
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedDescriptorField {
    WordBase = 0,
    WordCount = 1,
    TupleBits0 = 2,
    TupleBits1 = 3,
    TupleBits2 = 4,
    TupleBits3 = 5,
    TupleBits4 = 6,
    RelationIndex = 7,
    TableSize = 8,
    LutIndex = 9,
    DestinationIndex = 10,
    Kind = 11,
    SignedOffsetOrSmallTableSize = 12,
    SmallDestinationIndex = 13,
}

pub const WITNESS_FEED_DESCRIPTOR_FIELD_ORDER: [WitnessFeedDescriptorField;
    WITNESS_FEED_DESCRIPTOR_WORDS] = [
    WitnessFeedDescriptorField::WordBase,
    WitnessFeedDescriptorField::WordCount,
    WitnessFeedDescriptorField::TupleBits0,
    WitnessFeedDescriptorField::TupleBits1,
    WitnessFeedDescriptorField::TupleBits2,
    WitnessFeedDescriptorField::TupleBits3,
    WitnessFeedDescriptorField::TupleBits4,
    WitnessFeedDescriptorField::RelationIndex,
    WitnessFeedDescriptorField::TableSize,
    WitnessFeedDescriptorField::LutIndex,
    WitnessFeedDescriptorField::DestinationIndex,
    WitnessFeedDescriptorField::Kind,
    WitnessFeedDescriptorField::SignedOffsetOrSmallTableSize,
    WitnessFeedDescriptorField::SmallDestinationIndex,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WitnessFeedDescriptorKind {
    Fold = 0,
    MemoryIdDecode = 1,
    DependentXor = 2,
    Xor12 = 3,
}

impl WitnessFeedDescriptorKind {
    fn from_raw(raw: u32) -> Result<Self, WitnessFeedAuthorityError> {
        match raw {
            0 => Ok(Self::Fold),
            1 => Ok(Self::MemoryIdDecode),
            2 => Ok(Self::DependentXor),
            3 => Ok(Self::Xor12),
            _ => Err(WitnessFeedAuthorityError::InvalidDescriptorKind(raw)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedEffectAbi {
    WrappingAtomicAddU32V1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedRowDomain {
    pub row_count: u32,
    pub sub_words_per_row: u32,
    pub source_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedSourceRead {
    pub read_start_words: usize,
    pub read_len_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedLutRead {
    pub lut_ordinal: u32,
    pub read_start_words: usize,
    pub read_len_words: usize,
    pub content_identity: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WitnessFeedDestinationRange {
    pub start_words: usize,
    pub len_words: usize,
}

impl WitnessFeedDestinationRange {
    fn end_words(self) -> Result<usize, WitnessFeedAuthorityError> {
        self.start_words
            .checked_add(self.len_words)
            .ok_or(WitnessFeedAuthorityError::SizeOverflow)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessFeedDestinationEffect {
    pub destination_ordinal: u32,
    /// Complete in-place source-to-destination transition. Words outside
    /// `may_write_ranges` carry through unchanged in the same allocation.
    pub atomic_start_words: usize,
    pub atomic_len_words: usize,
    /// Canonical union of descriptor-addressable atomicAdd ranges.
    pub may_write_ranges: Vec<WitnessFeedDestinationRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessFeedEffectGeometry {
    pub row_domain: WitnessFeedRowDomain,
    pub source: WitnessFeedSourceRead,
    pub descriptor_words: usize,
    pub lut_reads: Vec<WitnessFeedLutRead>,
    pub destinations: Vec<WitnessFeedDestinationEffect>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedKernelLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub static_shared_bytes: u32,
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub cluster: Option<[u32; 3]>,
    mode: WitnessFeedLaunchMode,
}

impl WitnessFeedKernelLaunch {
    pub const fn symbol(self) -> &'static str {
        match self.mode {
            WitnessFeedLaunchMode::GlobalAtomics => "witness_feed_counts_kernel",
            WitnessFeedLaunchMode::Privatized => "witness_feed_counts_privatized_kernel",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessFeedContract {
    abi: WitnessFeedAbi,
    effect: WitnessFeedEffectAbi,
    launch_mode: WitnessFeedLaunchMode,
    requirements: WitnessFeedWorkspaceRequirements,
    descriptor_kinds: Vec<WitnessFeedDescriptorKind>,
    effect_geometry: WitnessFeedEffectGeometry,
    launch: WitnessFeedKernelLaunch,
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    requirements_identity: [u8; 32],
    descriptor_identity: [u8; 32],
    lut_identity: [u8; 32],
    content_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessFeedContract {
    pub fn compile(
        requirements: &WitnessFeedWorkspaceRequirements,
        descriptors: &[u32],
        luts: &[Vec<u32>],
        launch_mode: WitnessFeedLaunchMode,
    ) -> Result<Self, WitnessFeedAuthorityError> {
        let expected = witness_feed_workspace_requirements(
            requirements.row_count,
            requirements.sub_words_per_row,
            descriptors,
            luts,
            &requirements.multiplicity_words,
        )
        .map_err(map_requirements_error)?;
        if expected != *requirements {
            return Err(WitnessFeedAuthorityError::InvalidCanonicalRequirements);
        }
        let row_count = u32_value(requirements.row_count)?;
        let sub_words_per_row = u32_value(requirements.sub_words_per_row)?;
        let descriptor_kinds = descriptors
            .chunks_exact(WITNESS_FEED_DESCRIPTOR_WORDS)
            .map(|descriptor| WitnessFeedDescriptorKind::from_raw(descriptor[11]))
            .collect::<Result<Vec<_>, _>>()?;
        if descriptor_kinds.len() != requirements.descriptor_count {
            return Err(WitnessFeedAuthorityError::InvalidCanonicalRequirements);
        }
        let lut_identities = luts
            .iter()
            .enumerate()
            .map(|(ordinal, lut)| lut_identity(ordinal, lut))
            .collect::<Result<Vec<_>, _>>()?;
        let effect_geometry = WitnessFeedEffectGeometry {
            row_domain: WitnessFeedRowDomain {
                row_count,
                sub_words_per_row,
                source_words: requirements.source_words,
            },
            source: WitnessFeedSourceRead {
                read_start_words: 0,
                read_len_words: requirements.source_words,
            },
            descriptor_words: requirements.descriptor_words,
            lut_reads: requirements
                .lut_words
                .iter()
                .zip(&lut_identities)
                .enumerate()
                .map(|(ordinal, (&read_len_words, &content_identity))| {
                    Ok(WitnessFeedLutRead {
                        lut_ordinal: u32_value(ordinal)?,
                        read_start_words: 0,
                        read_len_words,
                        content_identity,
                    })
                })
                .collect::<Result<_, WitnessFeedAuthorityError>>()?,
            destinations: destination_effects(descriptors, requirements)?,
        };
        let abi = match launch_mode {
            WitnessFeedLaunchMode::GlobalAtomics => WitnessFeedAbi::GlobalAtomicsV1,
            WitnessFeedLaunchMode::Privatized => WitnessFeedAbi::PrivatizedV1,
        };
        let effect = WitnessFeedEffectAbi::WrappingAtomicAddU32V1;
        let launch = canonical_launch(row_count, launch_mode)?;
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE);
        let source_identity = source_identity(
            static_source_identity,
            wrapper_source_identity,
            &[
                BINDER_SOURCE,
                AUTHORITY_SOURCE,
                GEOMETRY_SOURCE,
                IDENTITY_SOURCE,
            ],
        );
        if [
            static_source_identity,
            wrapper_source_identity,
            source_identity,
        ]
        .contains(&ZERO_IDENTITY)
        {
            return Err(WitnessFeedAuthorityError::MissingStaticSourceIdentity);
        }
        let requirements_identity = requirements_identity(requirements)?;
        let descriptor_identity = digest_words(DESCRIPTOR_DOMAIN, descriptors)?;
        let lut_identity = combined_lut_identity(&lut_identities)?;
        let content_identity =
            content_identity(descriptor_identity, &descriptor_kinds, lut_identity)?;
        let abi_identity = abi_identity(abi);
        let effect_identity = effect_identity(effect, &effect_geometry)?;
        let launch_identity = launch_identity(launch);
        let identity = contract_identity([
            source_identity,
            requirements_identity,
            content_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        ]);
        let contract = Self {
            abi,
            effect,
            launch_mode,
            requirements: requirements.clone(),
            descriptor_kinds,
            effect_geometry,
            launch,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            requirements_identity,
            descriptor_identity,
            lut_identity,
            content_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), WitnessFeedAuthorityError> {
        let row_count = u32_value(self.requirements.row_count)?;
        if self.requirements.row_count == 0
            || self.requirements.sub_words_per_row == 0
            || self.requirements.source_words
                != self
                    .requirements
                    .row_count
                    .checked_mul(self.requirements.sub_words_per_row)
                    .ok_or(WitnessFeedAuthorityError::SizeOverflow)?
            || self.requirements.descriptor_count == 0
            || self.requirements.descriptor_words
                != self
                    .requirements
                    .descriptor_count
                    .checked_mul(WITNESS_FEED_DESCRIPTOR_WORDS)
                    .ok_or(WitnessFeedAuthorityError::SizeOverflow)?
            || self.requirements.multiplicity_words.is_empty()
            || self.descriptor_kinds.len() != self.requirements.descriptor_count
            || self.effect_geometry.row_domain.row_count != row_count
            || self.effect_geometry.row_domain.sub_words_per_row
                != u32_value(self.requirements.sub_words_per_row)?
            || self.effect_geometry.row_domain.source_words != self.requirements.source_words
            || self.effect_geometry.source
                != (WitnessFeedSourceRead {
                    read_start_words: 0,
                    read_len_words: self.requirements.source_words,
                })
            || self.effect_geometry.descriptor_words != self.requirements.descriptor_words
            || self.effect_geometry.lut_reads.len() != self.requirements.lut_words.len()
            || self.effect_geometry.destinations.len() != self.requirements.multiplicity_words.len()
            || self
                .effect_geometry
                .lut_reads
                .iter()
                .zip(&self.requirements.lut_words)
                .enumerate()
                .any(|(ordinal, (read, &words))| {
                    read.lut_ordinal as usize != ordinal
                        || read.read_start_words != 0
                        || read.read_len_words != words
                        || read.content_identity == ZERO_IDENTITY
                })
            || self
                .effect_geometry
                .destinations
                .iter()
                .zip(&self.requirements.multiplicity_words)
                .enumerate()
                .any(|(ordinal, (destination, &words))| {
                    destination.destination_ordinal as usize != ordinal
                        || destination.atomic_start_words != 0
                        || destination.atomic_len_words != words
                        || !canonical_ranges(&destination.may_write_ranges, words)
                })
            || self.launch != canonical_launch(row_count, self.launch_mode)?
            || self.abi
                != match self.launch_mode {
                    WitnessFeedLaunchMode::GlobalAtomics => WitnessFeedAbi::GlobalAtomicsV1,
                    WitnessFeedLaunchMode::Privatized => WitnessFeedAbi::PrivatizedV1,
                }
            || self.effect != WitnessFeedEffectAbi::WrappingAtomicAddU32V1
        {
            return Err(WitnessFeedAuthorityError::InvalidCanonicalRequirements);
        }
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE);
        let source_identity = source_identity(
            static_source_identity,
            wrapper_source_identity,
            &[
                BINDER_SOURCE,
                AUTHORITY_SOURCE,
                GEOMETRY_SOURCE,
                IDENTITY_SOURCE,
            ],
        );
        let requirements_identity = requirements_identity(&self.requirements)?;
        let content_identity = content_identity(
            self.descriptor_identity,
            &self.descriptor_kinds,
            self.lut_identity,
        )?;
        let abi_identity = abi_identity(self.abi);
        let effect_identity = effect_identity(self.effect, &self.effect_geometry)?;
        let launch_identity = launch_identity(self.launch);
        let identity = contract_identity([
            source_identity,
            requirements_identity,
            self.content_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        ]);
        if self.static_source_identity != static_source_identity
            || self.wrapper_source_identity != wrapper_source_identity
            || self.source_identity != source_identity
            || self.requirements_identity != requirements_identity
            || self.descriptor_identity == ZERO_IDENTITY
            || self.lut_identity == ZERO_IDENTITY
            || self.content_identity != content_identity
            || self.abi_identity != abi_identity
            || self.effect_identity != effect_identity
            || self.launch_identity != launch_identity
            || self.identity != identity
        {
            return Err(WitnessFeedAuthorityError::InvalidCanonicalRequirements);
        }
        Ok(())
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<WitnessFeedLinkedContract>, WitnessFeedAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked_contract(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn abi(&self) -> WitnessFeedAbi {
        self.abi
    }
    pub const fn effect(&self) -> WitnessFeedEffectAbi {
        self.effect
    }
    pub const fn launch_mode(&self) -> WitnessFeedLaunchMode {
        self.launch_mode
    }
    pub const fn requirements(&self) -> &WitnessFeedWorkspaceRequirements {
        &self.requirements
    }
    pub fn descriptor_kinds(&self) -> &[WitnessFeedDescriptorKind] {
        &self.descriptor_kinds
    }
    pub const fn effect_geometry(&self) -> &WitnessFeedEffectGeometry {
        &self.effect_geometry
    }
    pub const fn launch(&self) -> WitnessFeedKernelLaunch {
        self.launch
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
    pub const fn content_identity(&self) -> [u8; 32] {
        self.content_identity
    }
    pub const fn descriptor_identity(&self) -> [u8; 32] {
        self.descriptor_identity
    }
    pub const fn lut_identity(&self) -> [u8; 32] {
        self.lut_identity
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
pub struct WitnessFeedLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessFeedLinkedContract {
    pub fn validate(
        &self,
        contract: &WitnessFeedContract,
    ) -> Result<(), WitnessFeedAuthorityError> {
        if self.contract_identity != contract.identity() {
            return Err(WitnessFeedAuthorityError::StaticBuildMismatch);
        }
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(WitnessFeedAuthorityError::StaticBuildUnavailable)?;
        (*self == expected)
            .then_some(())
            .ok_or(WitnessFeedAuthorityError::StaticBuildMismatch)
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
pub enum WitnessFeedAuthorityError {
    MissingStaticSourceIdentity,
    InvalidCanonicalRequirements,
    InvalidDescriptorKind(u32),
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for WitnessFeedAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid witness-feed authority: {self:?}")
    }
}

impl std::error::Error for WitnessFeedAuthorityError {}

impl From<StaticBuildBindError> for WitnessFeedAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const ARGUMENTS: [WitnessFeedAbiArgument; 7] = [
    argument(
        0,
        "sub_words_dev",
        WitnessFeedAbiArgumentKind::DeviceConstPointerU32,
        WitnessFeedAbiAccess::ReadSource,
    ),
    argument(
        1,
        "column_length",
        WitnessFeedAbiArgumentKind::U32,
        WitnessFeedAbiAccess::RowCount,
    ),
    argument(
        2,
        "descs_dev",
        WitnessFeedAbiArgumentKind::DeviceConstPointerU32,
        WitnessFeedAbiAccess::ReadDescriptors,
    ),
    argument(
        3,
        "n_descs",
        WitnessFeedAbiArgumentKind::U32,
        WitnessFeedAbiAccess::DescriptorCount,
    ),
    argument(
        4,
        "luts_dev",
        WitnessFeedAbiArgumentKind::DeviceConstPointerTableU32,
        WitnessFeedAbiAccess::ReadLuts,
    ),
    argument(
        5,
        "counts_dev",
        WitnessFeedAbiArgumentKind::DeviceMutPointerTableU32,
        WitnessFeedAbiAccess::AtomicDestinations,
    ),
    argument(
        6,
        "stream",
        WitnessFeedAbiArgumentKind::CudaStream,
        WitnessFeedAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: WitnessFeedAbiArgumentKind,
    access: WitnessFeedAbiAccess,
) -> WitnessFeedAbiArgument {
    WitnessFeedAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn linked_contract(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> WitnessFeedLinkedContract {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    WitnessFeedLinkedContract {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

fn map_requirements_error(error: PreparedWitnessFeedError) -> WitnessFeedAuthorityError {
    match error {
        PreparedWitnessFeedError::RowCountOverflow | PreparedWitnessFeedError::SizeOverflow => {
            WitnessFeedAuthorityError::SizeOverflow
        }
        PreparedWitnessFeedError::InvalidDescriptorKind { kind, .. } => {
            WitnessFeedAuthorityError::InvalidDescriptorKind(kind)
        }
        _ => WitnessFeedAuthorityError::InvalidCanonicalRequirements,
    }
}

fn u32_value(value: usize) -> Result<u32, WitnessFeedAuthorityError> {
    u32::try_from(value).map_err(|_| WitnessFeedAuthorityError::SizeOverflow)
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
