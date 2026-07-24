//! Exact authority for expanding the transcript draw `[z, alpha]`.
//!
//! This is deliberately separate from [`RelationExecutionAuthority`]: it
//! executes at the transcript boundary before the fused body and has its own
//! ABI, effects, launch, source identity, and linked-build receipt.

use super::super::super::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};

#[cfg(test)]
const ZERO_IDENTITY: [u8; 32] = [0; 32];
const SECURE_FIELD_WORDS: usize = 4;
const DRAWN_WORDS: usize = 2 * SECURE_FIELD_WORDS;
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-relation-challenge-expansion-static-build-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-relation-challenge-expansion-source-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-relation-challenge-expansion-contract-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-relation-challenge-expansion-linked-v1\0";

const AUTHORITY_SOURCE: &[u8] = include_bytes!("challenge.rs");
const RAW_FFI_SOURCE: &[u8] = include_bytes!("../../../../../backend-cuda-kernels/src/raw.rs");
const CUDA_SOURCE: &[u8] =
    include_bytes!("../../../../../backend-cuda-kernels/cuda/relation_graph.cu");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationChallengeValueRole {
    DrawnZAlpha = 1,
    AlphaPowers = 2,
    ChallengeZ = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationChallengeAccessKind {
    Read = 1,
    Write = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationChallengeAccess {
    pub role: RelationChallengeValueRole,
    pub kind: RelationChallengeAccessKind,
    pub words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationChallengeAbiArgumentKind {
    DeviceConstPointerU32 = 1,
    DeviceMutPointerU32 = 2,
    U32 = 3,
    CudaStream = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelationChallengeAbiAccess {
    ReadDrawnZAlpha = 1,
    WriteAlphaPowers = 2,
    AlphaPowerCount = 3,
    WriteChallengeZ = 4,
    OrderedExecutionStream = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationChallengeAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: RelationChallengeAbiArgumentKind,
    pub access: RelationChallengeAbiAccess,
}

pub const RELATION_CHALLENGE_ARGUMENTS: [RelationChallengeAbiArgument; 5] = [
    argument(
        0,
        "drawn_z_alpha",
        RelationChallengeAbiArgumentKind::DeviceConstPointerU32,
        RelationChallengeAbiAccess::ReadDrawnZAlpha,
    ),
    argument(
        1,
        "alpha_powers",
        RelationChallengeAbiArgumentKind::DeviceMutPointerU32,
        RelationChallengeAbiAccess::WriteAlphaPowers,
    ),
    argument(
        2,
        "n_alpha_powers",
        RelationChallengeAbiArgumentKind::U32,
        RelationChallengeAbiAccess::AlphaPowerCount,
    ),
    argument(
        3,
        "z",
        RelationChallengeAbiArgumentKind::DeviceMutPointerU32,
        RelationChallengeAbiAccess::WriteChallengeZ,
    ),
    argument(
        4,
        "stream",
        RelationChallengeAbiArgumentKind::CudaStream,
        RelationChallengeAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: RelationChallengeAbiArgumentKind,
    access: RelationChallengeAbiAccess,
) -> RelationChallengeAbiArgument {
    RelationChallengeAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationChallengeInvocationValue {
    Role(RelationChallengeValueRole),
    U32(u32),
    OrderedStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationChallengeInvocationArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub value: RelationChallengeInvocationValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationChallengeKernelLaunch {
    pub symbol: &'static str,
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub cluster: Option<[u32; 3]>,
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub accesses: Vec<RelationChallengeAccess>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationChallengeExpansionAuthority {
    max_alpha_powers: u32,
    invocation: Vec<RelationChallengeInvocationArgument>,
    accesses: Vec<RelationChallengeAccess>,
    child: RelationChallengeKernelLaunch,
    source_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl RelationChallengeExpansionAuthority {
    pub fn compile(max_alpha_powers: u32) -> Result<Self, RelationChallengeAuthorityError> {
        if max_alpha_powers == 0 {
            return Err(RelationChallengeAuthorityError::ZeroAlphaPowers);
        }
        validate_symbols()?;
        let alpha_words = usize::try_from(max_alpha_powers)
            .map_err(|_| RelationChallengeAuthorityError::SizeOverflow)?
            .checked_mul(SECURE_FIELD_WORDS)
            .ok_or(RelationChallengeAuthorityError::SizeOverflow)?;
        let accesses = vec![
            access(
                RelationChallengeValueRole::DrawnZAlpha,
                RelationChallengeAccessKind::Read,
                DRAWN_WORDS,
            ),
            access(
                RelationChallengeValueRole::AlphaPowers,
                RelationChallengeAccessKind::Write,
                alpha_words,
            ),
            access(
                RelationChallengeValueRole::ChallengeZ,
                RelationChallengeAccessKind::Write,
                SECURE_FIELD_WORDS,
            ),
        ];
        let invocation = RELATION_CHALLENGE_ARGUMENTS
            .iter()
            .zip([
                RelationChallengeInvocationValue::Role(RelationChallengeValueRole::DrawnZAlpha),
                RelationChallengeInvocationValue::Role(RelationChallengeValueRole::AlphaPowers),
                RelationChallengeInvocationValue::U32(max_alpha_powers),
                RelationChallengeInvocationValue::Role(RelationChallengeValueRole::ChallengeZ),
                RelationChallengeInvocationValue::OrderedStream,
            ])
            .map(|(abi, value)| RelationChallengeInvocationArgument {
                ordinal: abi.ordinal,
                name: abi.name,
                value,
            })
            .collect::<Vec<_>>();
        let child = RelationChallengeKernelLaunch {
            symbol: "relation_expand_challenges_kernel",
            grid: [1, 1, 1],
            block: [1, 1, 1],
            cluster: None,
            dynamic_shared_bytes: 0,
            cooperative: false,
            accesses: accesses.clone(),
        };
        let source_identity = source_identity();
        let abi_identity = hash_abi(&invocation)?;
        let effect_identity = hash_effect(&accesses)?;
        let launch_identity = hash_launch(&child)?;
        let identity = hash_contract(
            max_alpha_powers,
            source_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        );
        Ok(Self {
            max_alpha_powers,
            invocation,
            accesses,
            child,
            source_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), RelationChallengeAuthorityError> {
        let expected = Self::compile(self.max_alpha_powers)?;
        (*self == expected)
            .then_some(())
            .ok_or(RelationChallengeAuthorityError::ContractMismatch)
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<RelationChallengeLinkedAuthority>, RelationChallengeAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn max_alpha_powers(&self) -> u32 {
        self.max_alpha_powers
    }
    pub const fn drawn_words(&self) -> usize {
        DRAWN_WORDS
    }
    pub fn alpha_words(&self) -> Result<usize, RelationChallengeAuthorityError> {
        usize::try_from(self.max_alpha_powers)
            .map_err(|_| RelationChallengeAuthorityError::SizeOverflow)?
            .checked_mul(SECURE_FIELD_WORDS)
            .ok_or(RelationChallengeAuthorityError::SizeOverflow)
    }
    pub const fn z_words(&self) -> usize {
        SECURE_FIELD_WORDS
    }
    pub fn invocation(&self) -> &[RelationChallengeInvocationArgument] {
        &self.invocation
    }
    pub fn accesses(&self) -> &[RelationChallengeAccess] {
        &self.accesses
    }
    pub const fn child(&self) -> &RelationChallengeKernelLaunch {
        &self.child
    }
    pub const fn source_identity(&self) -> [u8; 32] {
        self.source_identity
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
pub struct RelationChallengeLinkedAuthority {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl RelationChallengeLinkedAuthority {
    pub fn validate_for_target(
        &self,
        authority: &RelationChallengeExpansionAuthority,
        target_sm: u32,
    ) -> Result<(), RelationChallengeAuthorityError> {
        if self.target_sm != target_sm {
            return Err(RelationChallengeAuthorityError::StaticBuildMismatch);
        }
        let expected = authority
            .bind_static_build(target_sm)?
            .ok_or(RelationChallengeAuthorityError::StaticBuildUnavailable)?;
        (*self == expected)
            .then_some(())
            .ok_or(RelationChallengeAuthorityError::StaticBuildMismatch)
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
pub enum RelationChallengeAuthorityError {
    ZeroAlphaPowers,
    MissingStaticSymbol(&'static str),
    ContractMismatch,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for RelationChallengeAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid Relation challenge authority: {self:?}")
    }
}

impl std::error::Error for RelationChallengeAuthorityError {}

impl From<StaticBuildBindError> for RelationChallengeAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const fn access(
    role: RelationChallengeValueRole,
    kind: RelationChallengeAccessKind,
    words: usize,
) -> RelationChallengeAccess {
    RelationChallengeAccess { role, kind, words }
}

fn validate_symbols() -> Result<(), RelationChallengeAuthorityError> {
    for (symbol, source) in [
        ("stwo_relation_expand_challenges_on", CUDA_SOURCE),
        ("relation_expand_challenges_kernel", CUDA_SOURCE),
        ("stwo_relation_expand_challenges_on", RAW_FFI_SOURCE),
    ] {
        if !contains(source, symbol.as_bytes()) {
            return Err(RelationChallengeAuthorityError::MissingStaticSymbol(symbol));
        }
    }
    Ok(())
}

fn source_identity() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&stwo_backend_cuda_kernels::static_cuda_source_identity());
    for source in [AUTHORITY_SOURCE, RAW_FFI_SOURCE, CUDA_SOURCE] {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

fn hash_abi(
    invocation: &[RelationChallengeInvocationArgument],
) -> Result<[u8; 32], RelationChallengeAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stwo-cuda-relation-challenge-abi-v1\0");
    hash_size(&mut hasher, invocation.len())?;
    for (abi, invocation) in RELATION_CHALLENGE_ARGUMENTS.iter().zip(invocation) {
        hasher.update(&[abi.ordinal, abi.kind as u8, abi.access as u8]);
        hash_bytes(&mut hasher, abi.name.as_bytes());
        hash_invocation_value(&mut hasher, invocation.value);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_effect(
    accesses: &[RelationChallengeAccess],
) -> Result<[u8; 32], RelationChallengeAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stwo-cuda-relation-challenge-effect-v1\0");
    hash_size(&mut hasher, accesses.len())?;
    for access in accesses {
        hasher.update(&[access.role as u8, access.kind as u8]);
        hash_size(&mut hasher, access.words)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_launch(
    launch: &RelationChallengeKernelLaunch,
) -> Result<[u8; 32], RelationChallengeAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stwo-cuda-relation-challenge-launch-v1\0");
    hash_bytes(&mut hasher, launch.symbol.as_bytes());
    for value in launch.grid.into_iter().chain(launch.block) {
        hasher.update(&value.to_le_bytes());
    }
    hasher.update(&launch.dynamic_shared_bytes.to_le_bytes());
    hasher.update(&[launch.cluster.is_some() as u8, launch.cooperative as u8]);
    Ok(*hasher.finalize().as_bytes())
}

fn hash_contract(
    max_alpha_powers: u32,
    source: [u8; 32],
    abi: [u8; 32],
    effect: [u8; 32],
    launch: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    hasher.update(&max_alpha_powers.to_le_bytes());
    for identity in [source, abi, effect, launch] {
        hasher.update(&identity);
    }
    *hasher.finalize().as_bytes()
}

fn linked(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> RelationChallengeLinkedAuthority {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    RelationChallengeLinkedAuthority {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

fn hash_invocation_value(hasher: &mut blake3::Hasher, value: RelationChallengeInvocationValue) {
    match value {
        RelationChallengeInvocationValue::Role(role) => {
            hasher.update(&[1, role as u8]);
        }
        RelationChallengeInvocationValue::U32(value) => {
            hasher.update(&[2]);
            hasher.update(&value.to_le_bytes());
        }
        RelationChallengeInvocationValue::OrderedStream => {
            hasher.update(&[3]);
        }
    }
}

fn hash_size(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), RelationChallengeAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| RelationChallengeAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

#[cfg(test)]
mod tests;
