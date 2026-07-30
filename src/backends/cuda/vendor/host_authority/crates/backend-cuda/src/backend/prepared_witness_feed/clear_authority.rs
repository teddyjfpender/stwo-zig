//! Address-free authority for the prepared batched multiplicity clear.

use super::{
    witness_feed_clear_workspace_requirements, PreparedWitnessFeedError,
    WitnessFeedClearWorkspaceRequirements,
};
use crate::backend::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BLOCK_THREADS: u32 = 256;
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_witness_feed.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("clear_authority.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/witness_feed_counts.cu");

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-wrapper-source-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-source-v1\0";
const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-requirements-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-contract-v1\0";
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-static-build-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-witness-feed-clear-linked-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedClearAbiArgumentKind {
    U32 = 1,
    DeviceConstPointerU32 = 2,
    DeviceMutPointerTableU32 = 3,
    CudaStream = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedClearAbiAccess {
    WriteDestinations = 1,
    ReadDestinationLengths = 2,
    DestinationCount = 3,
    MaximumDestinationWords = 4,
    OrderedExecutionStream = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedClearAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: WitnessFeedClearAbiArgumentKind,
    pub access: WitnessFeedClearAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedClearAbi {
    BatchedDestinationsV1 = 1,
}

impl WitnessFeedClearAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::BatchedDestinationsV1 => "stwo_witness_feed_clear_on",
        }
    }

    pub const fn arguments(self) -> &'static [WitnessFeedClearAbiArgument] {
        match self {
            Self::BatchedDestinationsV1 => &ARGUMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessFeedClearEffectAbi {
    ZeroEveryDestinationWordV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedClearDestinationEffect {
    pub destination_ordinal: u32,
    pub write_start_words: usize,
    pub write_len_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessFeedClearEffectGeometry {
    pub destinations: Vec<WitnessFeedClearDestinationEffect>,
    pub destination_lengths: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessFeedClearKernelLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub cluster: Option<[u32; 3]>,
}

impl WitnessFeedClearKernelLaunch {
    pub const fn symbol(self) -> &'static str {
        "witness_feed_clear_kernel"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessFeedClearContract {
    abi: WitnessFeedClearAbi,
    effect: WitnessFeedClearEffectAbi,
    requirements: WitnessFeedClearWorkspaceRequirements,
    effect_geometry: WitnessFeedClearEffectGeometry,
    launch: WitnessFeedClearKernelLaunch,
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    requirements_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessFeedClearContract {
    pub fn compile(
        requirements: &WitnessFeedClearWorkspaceRequirements,
    ) -> Result<Self, WitnessFeedClearAuthorityError> {
        let expected = witness_feed_clear_workspace_requirements(&requirements.destination_words)
            .map_err(|error| match error {
            PreparedWitnessFeedError::SizeOverflow => WitnessFeedClearAuthorityError::SizeOverflow,
            _ => WitnessFeedClearAuthorityError::InvalidCanonicalRequirements,
        })?;
        if expected != *requirements {
            return Err(WitnessFeedClearAuthorityError::InvalidCanonicalRequirements);
        }
        let destination_count = u32_value(requirements.destination_words.len())?;
        let max_words = u32_value(requirements.max_destination_words)?;
        let effect_geometry = WitnessFeedClearEffectGeometry {
            destinations: requirements
                .destination_words
                .iter()
                .enumerate()
                .map(|(ordinal, &write_len_words)| {
                    Ok(WitnessFeedClearDestinationEffect {
                        destination_ordinal: u32_value(ordinal)?,
                        write_start_words: 0,
                        write_len_words,
                    })
                })
                .collect::<Result<_, WitnessFeedClearAuthorityError>>()?,
            destination_lengths: requirements
                .destination_words
                .iter()
                .map(|&words| u32_value(words))
                .collect::<Result<_, _>>()?,
        };
        let launch = WitnessFeedClearKernelLaunch {
            grid: [ceil_div(max_words, BLOCK_THREADS)?, destination_count, 1],
            block: [BLOCK_THREADS, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
            cluster: None,
        };
        let abi = WitnessFeedClearAbi::BatchedDestinationsV1;
        let effect = WitnessFeedClearEffectAbi::ZeroEveryDestinationWordV1;
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE);
        let source_identity = source_identity(
            static_source_identity,
            wrapper_source_identity,
            &[BINDER_SOURCE, AUTHORITY_SOURCE],
        );
        if [
            static_source_identity,
            wrapper_source_identity,
            source_identity,
        ]
        .contains(&ZERO_IDENTITY)
        {
            return Err(WitnessFeedClearAuthorityError::MissingStaticSourceIdentity);
        }
        let requirements_identity = requirements_identity(requirements)?;
        let abi_identity = abi_identity(abi);
        let effect_identity = effect_identity(effect, &effect_geometry)?;
        let launch_identity = launch_identity(launch);
        let identity = contract_identity([
            source_identity,
            requirements_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        ]);
        Ok(Self {
            abi,
            effect,
            requirements: requirements.clone(),
            effect_geometry,
            launch,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            requirements_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), WitnessFeedClearAuthorityError> {
        (Self::compile(&self.requirements)? == *self)
            .then_some(())
            .ok_or(WitnessFeedClearAuthorityError::InvalidCanonicalRequirements)
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<WitnessFeedClearLinkedContract>, WitnessFeedClearAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked_contract(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn abi(&self) -> WitnessFeedClearAbi {
        self.abi
    }
    pub const fn effect(&self) -> WitnessFeedClearEffectAbi {
        self.effect
    }
    pub const fn requirements(&self) -> &WitnessFeedClearWorkspaceRequirements {
        &self.requirements
    }
    pub const fn effect_geometry(&self) -> &WitnessFeedClearEffectGeometry {
        &self.effect_geometry
    }
    pub const fn launch(&self) -> WitnessFeedClearKernelLaunch {
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
pub struct WitnessFeedClearLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessFeedClearLinkedContract {
    pub fn validate(
        &self,
        contract: &WitnessFeedClearContract,
    ) -> Result<(), WitnessFeedClearAuthorityError> {
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(WitnessFeedClearAuthorityError::StaticBuildUnavailable)?;
        (*self == expected)
            .then_some(())
            .ok_or(WitnessFeedClearAuthorityError::StaticBuildMismatch)
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
pub enum WitnessFeedClearAuthorityError {
    MissingStaticSourceIdentity,
    InvalidCanonicalRequirements,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for WitnessFeedClearAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid witness-feed clear authority: {self:?}")
    }
}

impl std::error::Error for WitnessFeedClearAuthorityError {}

impl From<StaticBuildBindError> for WitnessFeedClearAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const ARGUMENTS: [WitnessFeedClearAbiArgument; 5] = [
    argument(
        0,
        "destinations_dev",
        WitnessFeedClearAbiArgumentKind::DeviceMutPointerTableU32,
        WitnessFeedClearAbiAccess::WriteDestinations,
    ),
    argument(
        1,
        "lengths_dev",
        WitnessFeedClearAbiArgumentKind::DeviceConstPointerU32,
        WitnessFeedClearAbiAccess::ReadDestinationLengths,
    ),
    argument(
        2,
        "n_destinations",
        WitnessFeedClearAbiArgumentKind::U32,
        WitnessFeedClearAbiAccess::DestinationCount,
    ),
    argument(
        3,
        "max_words",
        WitnessFeedClearAbiArgumentKind::U32,
        WitnessFeedClearAbiAccess::MaximumDestinationWords,
    ),
    argument(
        4,
        "stream",
        WitnessFeedClearAbiArgumentKind::CudaStream,
        WitnessFeedClearAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: WitnessFeedClearAbiArgumentKind,
    access: WitnessFeedClearAbiAccess,
) -> WitnessFeedClearAbiArgument {
    WitnessFeedClearAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn linked_contract(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> WitnessFeedClearLinkedContract {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    WitnessFeedClearLinkedContract {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

fn requirements_identity(
    requirements: &WitnessFeedClearWorkspaceRequirements,
) -> Result<[u8; 32], WitnessFeedClearAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUIREMENTS_DOMAIN);
    for value in [
        requirements.destination_words.len(),
        requirements.destination_pointer_words,
        requirements.destination_length_words,
        requirements.max_destination_words,
    ] {
        hash_size(&mut hasher, value)?;
    }
    for &words in &requirements.destination_words {
        hash_size(&mut hasher, words)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

fn abi_identity(abi: WitnessFeedClearAbi) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    hasher.update(&[abi as u8]);
    hash_bytes(&mut hasher, abi.entry_symbol().as_bytes());
    for argument in abi.arguments() {
        hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn effect_identity(
    effect: WitnessFeedClearEffectAbi,
    geometry: &WitnessFeedClearEffectGeometry,
) -> Result<[u8; 32], WitnessFeedClearAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8]);
    hash_size(&mut hasher, geometry.destinations.len())?;
    for destination in &geometry.destinations {
        hasher.update(&destination.destination_ordinal.to_le_bytes());
        hash_size(&mut hasher, destination.write_start_words)?;
        hash_size(&mut hasher, destination.write_len_words)?;
    }
    hash_size(&mut hasher, geometry.destination_lengths.len())?;
    for length in &geometry.destination_lengths {
        hasher.update(&length.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn launch_identity(launch: WitnessFeedClearKernelLaunch) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    hash_bytes(&mut hasher, launch.symbol().as_bytes());
    for value in launch.grid.into_iter().chain(launch.block) {
        hasher.update(&value.to_le_bytes());
    }
    hasher.update(&launch.dynamic_shared_bytes.to_le_bytes());
    hasher.update(&[u8::from(launch.cooperative)]);
    hash_cluster(&mut hasher, launch.cluster);
    *hasher.finalize().as_bytes()
}

fn source_identity(
    static_source: [u8; 32],
    wrapper_source: [u8; 32],
    sources: &[&[u8]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_source);
    hasher.update(&wrapper_source);
    for source in sources {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

fn contract_identity(identities: [[u8; 32]; 5]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    for identity in identities {
        hasher.update(&identity);
    }
    *hasher.finalize().as_bytes()
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_bytes(&mut hasher, bytes);
    *hasher.finalize().as_bytes()
}

fn hash_cluster(hasher: &mut blake3::Hasher, cluster: Option<[u32; 3]>) {
    hasher.update(&[u8::from(cluster.is_some())]);
    for value in cluster.unwrap_or([0; 3]) {
        hasher.update(&value.to_le_bytes());
    }
}

fn ceil_div(value: u32, divisor: u32) -> Result<u32, WitnessFeedClearAuthorityError> {
    Ok(1 + (value - 1) / divisor)
}

fn u32_value(value: usize) -> Result<u32, WitnessFeedClearAuthorityError> {
    u32::try_from(value).map_err(|_| WitnessFeedClearAuthorityError::SizeOverflow)
}

fn hash_size(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), WitnessFeedClearAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| WitnessFeedClearAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
#[path = "clear_authority_tests.rs"]
mod tests;
