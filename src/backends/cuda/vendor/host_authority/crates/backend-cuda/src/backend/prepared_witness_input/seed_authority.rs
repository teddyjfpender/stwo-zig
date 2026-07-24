//! Address-free authority for the prepared witness-input scalar seed.

use super::static_build::{bind_static_build, StaticBuildBindError, StaticBuildBinding};
use super::{
    witness_input_seed_requirements, PreparedWitnessInputGatherError, WitnessInputSeedRequirements,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BLOCK_THREADS: u32 = 256;
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_witness_input.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("seed_authority.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/witness_edge_gather.cu");

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-wrapper-source-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-source-v1\0";
const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-requirements-v1\0";
const FIXED_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-fixed-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-contract-v1\0";
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-static-build-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-witness-input-seed-linked-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputSeedAbiArgumentKind {
    U32 = 1,
    DeviceConstPointerU32 = 2,
    DeviceMutPointerTableU32 = 3,
    CudaStream = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputSeedAbiAccess {
    ReadScalarWords = 1,
    ScalarWordCount = 2,
    RealRowCount = 3,
    ConsumerRowCount = 4,
    WriteConsumerColumns = 5,
    IncludeEnabler = 6,
    IncludeIota = 7,
    OrderedExecutionStream = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputSeedAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: WitnessInputSeedAbiArgumentKind,
    pub access: WitnessInputSeedAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputSeedAbi {
    ScalarExpansionV1 = 1,
}

impl WitnessInputSeedAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::ScalarExpansionV1 => "stwo_witness_input_seed_on",
        }
    }

    pub const fn arguments(self) -> &'static [WitnessInputSeedAbiArgument] {
        match self {
            Self::ScalarExpansionV1 => &ARGUMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputSeedEffectAbi {
    RepeatScalarsAndWriteMechanicalTailV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputSeedRowDomain {
    RealPrefixWithPaddedScalarRowsV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputSeedFixedField {
    ScalarWords = 1,
    RealRows = 2,
    ConsumerRows = 3,
    IncludeEnabler = 4,
    IncludeIota = 5,
}

pub const WITNESS_INPUT_SEED_FIXED_ORDER: [WitnessInputSeedFixedField; 5] = [
    WitnessInputSeedFixedField::ScalarWords,
    WitnessInputSeedFixedField::RealRows,
    WitnessInputSeedFixedField::ConsumerRows,
    WitnessInputSeedFixedField::IncludeEnabler,
    WitnessInputSeedFixedField::IncludeIota,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessInputSeedColumnValue {
    RepeatedScalar(u32),
    Enabler,
    Iota,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputSeedColumnEffect {
    pub column_ordinal: u32,
    pub value: WitnessInputSeedColumnValue,
    pub written_words: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputSeedEffectGeometry {
    pub scalar_source_start_word: u32,
    pub scalar_source_words: u32,
    pub real_rows: u32,
    pub consumer_rows: u32,
    pub output_columns: Vec<WitnessInputSeedColumnEffect>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputSeedKernelLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub cluster: Option<[u32; 3]>,
}

impl WitnessInputSeedKernelLaunch {
    pub const fn symbol(self) -> &'static str {
        "witness_input_seed_kernel"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputSeedContract {
    abi: WitnessInputSeedAbi,
    effect: WitnessInputSeedEffectAbi,
    row_domain: WitnessInputSeedRowDomain,
    requirements: WitnessInputSeedRequirements,
    fixed_words: [u32; 5],
    effect_geometry: WitnessInputSeedEffectGeometry,
    launch: WitnessInputSeedKernelLaunch,
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    requirements_identity: [u8; 32],
    fixed_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessInputSeedContract {
    pub fn compile(
        requirements: &WitnessInputSeedRequirements,
    ) -> Result<Self, WitnessInputSeedAuthorityError> {
        require_canonical(requirements)?;
        let fixed_words = [
            u32_value(requirements.scalar_words)?,
            u32_value(requirements.n_real_rows)?,
            u32_value(requirements.consumer_rows)?,
            u32::from(requirements.include_enabler),
            u32::from(requirements.include_iota),
        ];
        let effect_geometry = effect_geometry(requirements)?;
        let launch = WitnessInputSeedKernelLaunch {
            grid: [fixed_words[2].div_ceil(BLOCK_THREADS), 1, 1],
            block: [BLOCK_THREADS, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
            cluster: None,
        };
        let abi = WitnessInputSeedAbi::ScalarExpansionV1;
        let effect = WitnessInputSeedEffectAbi::RepeatScalarsAndWriteMechanicalTailV1;
        let row_domain = WitnessInputSeedRowDomain::RealPrefixWithPaddedScalarRowsV1;
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
            return Err(WitnessInputSeedAuthorityError::MissingStaticSourceIdentity);
        }
        let requirements_identity = requirements_identity(requirements)?;
        let fixed_identity = fixed_identity(&fixed_words);
        let abi_identity = abi_identity(abi);
        let effect_identity = effect_identity(effect, row_domain, &effect_geometry)?;
        let launch_identity = launch_identity(launch);
        let identity = contract_identity([
            source_identity,
            requirements_identity,
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
            fixed_words,
            effect_geometry,
            launch,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            requirements_identity,
            fixed_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), WitnessInputSeedAuthorityError> {
        if Self::compile(&self.requirements)? == *self {
            Ok(())
        } else {
            Err(WitnessInputSeedAuthorityError::InvalidCanonicalRequirements)
        }
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<WitnessInputSeedLinkedContract>, WitnessInputSeedAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked_contract(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn abi(&self) -> WitnessInputSeedAbi {
        self.abi
    }
    pub const fn effect(&self) -> WitnessInputSeedEffectAbi {
        self.effect
    }
    pub const fn row_domain(&self) -> WitnessInputSeedRowDomain {
        self.row_domain
    }
    pub const fn requirements(&self) -> &WitnessInputSeedRequirements {
        &self.requirements
    }
    pub const fn fixed_words(&self) -> &[u32; 5] {
        &self.fixed_words
    }
    pub const fn effect_geometry(&self) -> &WitnessInputSeedEffectGeometry {
        &self.effect_geometry
    }
    pub const fn launch(&self) -> WitnessInputSeedKernelLaunch {
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
pub struct WitnessInputSeedLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessInputSeedLinkedContract {
    pub fn validate(
        &self,
        contract: &WitnessInputSeedContract,
    ) -> Result<(), WitnessInputSeedAuthorityError> {
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(WitnessInputSeedAuthorityError::StaticBuildUnavailable)?;
        if *self == expected {
            Ok(())
        } else {
            Err(WitnessInputSeedAuthorityError::StaticBuildMismatch)
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
pub enum WitnessInputSeedAuthorityError {
    MissingStaticSourceIdentity,
    InvalidCanonicalRequirements,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for WitnessInputSeedAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid witness-input seed authority: {self:?}")
    }
}

impl std::error::Error for WitnessInputSeedAuthorityError {}

impl From<StaticBuildBindError> for WitnessInputSeedAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const ARGUMENTS: [WitnessInputSeedAbiArgument; 8] = [
    argument(
        0,
        "scalars_dev",
        WitnessInputSeedAbiArgumentKind::DeviceConstPointerU32,
        WitnessInputSeedAbiAccess::ReadScalarWords,
    ),
    argument(
        1,
        "n_scalars",
        WitnessInputSeedAbiArgumentKind::U32,
        WitnessInputSeedAbiAccess::ScalarWordCount,
    ),
    argument(
        2,
        "n_real_rows",
        WitnessInputSeedAbiArgumentKind::U32,
        WitnessInputSeedAbiAccess::RealRowCount,
    ),
    argument(
        3,
        "consumer_rows",
        WitnessInputSeedAbiArgumentKind::U32,
        WitnessInputSeedAbiAccess::ConsumerRowCount,
    ),
    argument(
        4,
        "consumer_cols_dev",
        WitnessInputSeedAbiArgumentKind::DeviceMutPointerTableU32,
        WitnessInputSeedAbiAccess::WriteConsumerColumns,
    ),
    argument(
        5,
        "include_enabler",
        WitnessInputSeedAbiArgumentKind::U32,
        WitnessInputSeedAbiAccess::IncludeEnabler,
    ),
    argument(
        6,
        "include_iota",
        WitnessInputSeedAbiArgumentKind::U32,
        WitnessInputSeedAbiAccess::IncludeIota,
    ),
    argument(
        7,
        "stream",
        WitnessInputSeedAbiArgumentKind::CudaStream,
        WitnessInputSeedAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: WitnessInputSeedAbiArgumentKind,
    access: WitnessInputSeedAbiAccess,
) -> WitnessInputSeedAbiArgument {
    WitnessInputSeedAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn require_canonical(
    requirements: &WitnessInputSeedRequirements,
) -> Result<(), WitnessInputSeedAuthorityError> {
    let expected = witness_input_seed_requirements(
        requirements.scalar_words,
        requirements.n_real_rows,
        requirements.consumer_rows,
        requirements.include_enabler,
        requirements.include_iota,
    )
    .map_err(map_requirements_error)?;
    if expected == *requirements {
        Ok(())
    } else {
        Err(WitnessInputSeedAuthorityError::InvalidCanonicalRequirements)
    }
}

fn map_requirements_error(
    error: PreparedWitnessInputGatherError,
) -> WitnessInputSeedAuthorityError {
    match error {
        PreparedWitnessInputGatherError::SizeOverflow
        | PreparedWitnessInputGatherError::TotalRowsOverflow => {
            WitnessInputSeedAuthorityError::SizeOverflow
        }
        _ => WitnessInputSeedAuthorityError::InvalidCanonicalRequirements,
    }
}

fn effect_geometry(
    requirements: &WitnessInputSeedRequirements,
) -> Result<WitnessInputSeedEffectGeometry, WitnessInputSeedAuthorityError> {
    let mut output_columns = (0..requirements.scalar_words)
        .map(|scalar| {
            Ok(WitnessInputSeedColumnEffect {
                column_ordinal: u32_value(scalar)?,
                value: WitnessInputSeedColumnValue::RepeatedScalar(u32_value(scalar)?),
                written_words: u32_value(requirements.consumer_rows)?,
            })
        })
        .collect::<Result<Vec<_>, WitnessInputSeedAuthorityError>>()?;
    if requirements.include_enabler {
        output_columns.push(WitnessInputSeedColumnEffect {
            column_ordinal: u32_value(output_columns.len())?,
            value: WitnessInputSeedColumnValue::Enabler,
            written_words: u32_value(requirements.consumer_rows)?,
        });
    }
    if requirements.include_iota {
        output_columns.push(WitnessInputSeedColumnEffect {
            column_ordinal: u32_value(output_columns.len())?,
            value: WitnessInputSeedColumnValue::Iota,
            written_words: u32_value(requirements.consumer_rows)?,
        });
    }
    Ok(WitnessInputSeedEffectGeometry {
        scalar_source_start_word: 0,
        scalar_source_words: u32_value(requirements.scalar_words)?,
        real_rows: u32_value(requirements.n_real_rows)?,
        consumer_rows: u32_value(requirements.consumer_rows)?,
        output_columns,
    })
}

fn linked_contract(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> WitnessInputSeedLinkedContract {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    WitnessInputSeedLinkedContract {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

fn u32_value(value: usize) -> Result<u32, WitnessInputSeedAuthorityError> {
    u32::try_from(value).map_err(|_| WitnessInputSeedAuthorityError::SizeOverflow)
}

fn requirements_identity(
    requirements: &WitnessInputSeedRequirements,
) -> Result<[u8; 32], WitnessInputSeedAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUIREMENTS_DOMAIN);
    for value in [
        requirements.scalar_words,
        requirements.n_real_rows,
        requirements.consumer_rows,
        requirements.output_pointer_words,
        requirements.consumer_input_column_words.len(),
    ] {
        hash_size(&mut hasher, value)?;
    }
    for words in &requirements.consumer_input_column_words {
        hash_size(&mut hasher, *words)?;
    }
    hasher.update(&[
        u8::from(requirements.include_enabler),
        u8::from(requirements.include_iota),
    ]);
    Ok(*hasher.finalize().as_bytes())
}

fn fixed_identity(words: &[u32; 5]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FIXED_DOMAIN);
    for field in WITNESS_INPUT_SEED_FIXED_ORDER {
        hasher.update(&[field as u8]);
    }
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn abi_identity(abi: WitnessInputSeedAbi) -> [u8; 32] {
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
    effect: WitnessInputSeedEffectAbi,
    row_domain: WitnessInputSeedRowDomain,
    geometry: &WitnessInputSeedEffectGeometry,
) -> Result<[u8; 32], WitnessInputSeedAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8, row_domain as u8]);
    for value in [
        geometry.scalar_source_start_word,
        geometry.scalar_source_words,
        geometry.real_rows,
        geometry.consumer_rows,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    hash_size(&mut hasher, geometry.output_columns.len())?;
    for column in &geometry.output_columns {
        hasher.update(&column.column_ordinal.to_le_bytes());
        match column.value {
            WitnessInputSeedColumnValue::RepeatedScalar(scalar) => {
                hasher.update(&[1]);
                hasher.update(&scalar.to_le_bytes());
            }
            WitnessInputSeedColumnValue::Enabler => {
                hasher.update(&[2]);
            }
            WitnessInputSeedColumnValue::Iota => {
                hasher.update(&[3]);
            }
        }
        hasher.update(&column.written_words.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn launch_identity(launch: WitnessInputSeedKernelLaunch) -> [u8; 32] {
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

fn contract_identity(identities: [[u8; 32]; 6]) -> [u8; 32] {
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

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap().to_le_bytes());
    hasher.update(bytes);
}

fn hash_size(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), WitnessInputSeedAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| WitnessInputSeedAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests;
