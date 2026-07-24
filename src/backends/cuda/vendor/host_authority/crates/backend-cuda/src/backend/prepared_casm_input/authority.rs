//! Address-free authority for canonical row-major CASM witness ingress.

use super::{
    witness_casm_input_requirements, PreparedWitnessCasmInputError, WitnessCasmInputRequirements,
    WITNESS_CASM_STATE_WORDS,
};
use crate::backend::prepared_witness_input::static_build::{
    bind_static_build, StaticBuildBindError, StaticBuildBinding,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BLOCK_THREADS: u32 = 256;
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_casm_input.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("authority.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/witness_casm_input.cu");

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-wrapper-source-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-source-v1\0";
const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-requirements-v1\0";
const FIXED_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-fixed-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-contract-v1\0";
const STATIC_BUILD_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-static-build-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-witness-casm-input-linked-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessCasmInputAbiArgumentKind {
    U32 = 1,
    DeviceConstPointerU32 = 2,
    DeviceMutPointerU32 = 3,
    CudaStream = 4,
    OptionalDeviceMutPointerU32 = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessCasmInputAbiAccess {
    ReadRowMajorStates = 1,
    RealRowCount = 2,
    ConsumerRowCount = 3,
    WritePc = 4,
    WriteAp = 5,
    WriteFp = 6,
    WriteEnabler = 7,
    WriteOptionalIota = 8,
    OrderedExecutionStream = 9,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessCasmInputAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: WitnessCasmInputAbiArgumentKind,
    pub access: WitnessCasmInputAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessCasmInputAbi {
    RowMajorStateScatterV1 = 1,
}

impl WitnessCasmInputAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::RowMajorStateScatterV1 => "stwo_witness_casm_input_scatter_on",
        }
    }

    pub const fn arguments(self) -> &'static [WitnessCasmInputAbiArgument] {
        match self {
            Self::RowMajorStateScatterV1 => &ARGUMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessCasmInputEffectAbi {
    ScatterStateAndMechanicalColumnsV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessCasmInputRowDomain {
    RealPrefixWithRowZeroPaddingV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessCasmInputFixedField {
    StateWords = 1,
    RealRows = 2,
    ConsumerRows = 3,
    IncludeIota = 4,
}

pub const WITNESS_CASM_INPUT_FIXED_ORDER: [WitnessCasmInputFixedField; 4] = [
    WitnessCasmInputFixedField::StateWords,
    WitnessCasmInputFixedField::RealRows,
    WitnessCasmInputFixedField::ConsumerRows,
    WitnessCasmInputFixedField::IncludeIota,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessCasmInputColumnValue {
    StateWord(u8),
    Enabler,
    Iota,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessCasmInputColumnEffect {
    pub column_ordinal: u32,
    pub value: WitnessCasmInputColumnValue,
    pub written_words: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessCasmInputEffectGeometry {
    pub source_start_word: u32,
    pub source_rows: u32,
    pub state_words_per_row: u32,
    pub consumer_rows: u32,
    pub output_columns: Vec<WitnessCasmInputColumnEffect>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessCasmInputKernelLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
    pub cluster: Option<[u32; 3]>,
}

impl WitnessCasmInputKernelLaunch {
    pub const fn symbol(self) -> &'static str {
        "witness_casm_input_scatter_kernel"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessCasmInputContract {
    abi: WitnessCasmInputAbi,
    effect: WitnessCasmInputEffectAbi,
    row_domain: WitnessCasmInputRowDomain,
    requirements: WitnessCasmInputRequirements,
    fixed_words: [u32; 4],
    effect_geometry: WitnessCasmInputEffectGeometry,
    launch: WitnessCasmInputKernelLaunch,
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

impl WitnessCasmInputContract {
    pub fn compile(
        requirements: &WitnessCasmInputRequirements,
    ) -> Result<Self, WitnessCasmInputAuthorityError> {
        require_canonical(requirements)?;
        let fixed_words = [
            u32_value(WITNESS_CASM_STATE_WORDS)?,
            u32_value(requirements.n_real_rows)?,
            u32_value(requirements.consumer_rows)?,
            u32::from(requirements.include_iota),
        ];
        let effect_geometry = effect_geometry(requirements)?;
        let launch = WitnessCasmInputKernelLaunch {
            grid: [consumer_grid(fixed_words[2])?, 1, 1],
            block: [BLOCK_THREADS, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
            cluster: None,
        };
        let abi = WitnessCasmInputAbi::RowMajorStateScatterV1;
        let effect = WitnessCasmInputEffectAbi::ScatterStateAndMechanicalColumnsV1;
        let row_domain = WitnessCasmInputRowDomain::RealPrefixWithRowZeroPaddingV1;
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
            return Err(WitnessCasmInputAuthorityError::MissingStaticSourceIdentity);
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

    pub fn validate(&self) -> Result<(), WitnessCasmInputAuthorityError> {
        if Self::compile(&self.requirements)? == *self {
            Ok(())
        } else {
            Err(WitnessCasmInputAuthorityError::InvalidCanonicalRequirements)
        }
    }

    pub fn bind_static_build(
        &self,
        target_sm: u32,
    ) -> Result<Option<WitnessCasmInputLinkedContract>, WitnessCasmInputAuthorityError> {
        self.validate()?;
        bind_static_build(STATIC_BUILD_DOMAIN, self.identity, target_sm)
            .map(|binding| binding.map(|binding| linked_contract(self.identity, binding)))
            .map_err(Into::into)
    }

    pub const fn abi(&self) -> WitnessCasmInputAbi {
        self.abi
    }
    pub const fn effect(&self) -> WitnessCasmInputEffectAbi {
        self.effect
    }
    pub const fn row_domain(&self) -> WitnessCasmInputRowDomain {
        self.row_domain
    }
    pub const fn requirements(&self) -> &WitnessCasmInputRequirements {
        &self.requirements
    }
    pub const fn fixed_words(&self) -> &[u32; 4] {
        &self.fixed_words
    }
    pub const fn effect_geometry(&self) -> &WitnessCasmInputEffectGeometry {
        &self.effect_geometry
    }
    pub const fn launch(&self) -> WitnessCasmInputKernelLaunch {
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
pub struct WitnessCasmInputLinkedContract {
    contract_identity: [u8; 32],
    module_build_identity: [u8; 32],
    static_build_source_identity: [u8; 32],
    static_build_identity: [u8; 32],
    target_sm: u32,
    sm_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessCasmInputLinkedContract {
    pub fn validate(
        &self,
        contract: &WitnessCasmInputContract,
    ) -> Result<(), WitnessCasmInputAuthorityError> {
        let expected = contract
            .bind_static_build(self.target_sm)?
            .ok_or(WitnessCasmInputAuthorityError::StaticBuildUnavailable)?;
        if *self == expected {
            Ok(())
        } else {
            Err(WitnessCasmInputAuthorityError::StaticBuildMismatch)
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
pub enum WitnessCasmInputAuthorityError {
    MissingStaticSourceIdentity,
    InvalidCanonicalRequirements,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for WitnessCasmInputAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid witness CASM-input authority: {self:?}")
    }
}

impl std::error::Error for WitnessCasmInputAuthorityError {}

impl From<StaticBuildBindError> for WitnessCasmInputAuthorityError {
    fn from(error: StaticBuildBindError) -> Self {
        match error {
            StaticBuildBindError::UnsupportedTargetSm(sm) => Self::UnsupportedTargetSm(sm),
            StaticBuildBindError::BuildReceiptUnavailable => Self::StaticBuildUnavailable,
            StaticBuildBindError::InconsistentBuildMetadata
            | StaticBuildBindError::BuildReceiptMismatch => Self::StaticBuildMismatch,
        }
    }
}

const ARGUMENTS: [WitnessCasmInputAbiArgument; 9] = [
    argument(
        0,
        "rows_dev",
        WitnessCasmInputAbiArgumentKind::DeviceConstPointerU32,
        WitnessCasmInputAbiAccess::ReadRowMajorStates,
    ),
    argument(
        1,
        "n_real",
        WitnessCasmInputAbiArgumentKind::U32,
        WitnessCasmInputAbiAccess::RealRowCount,
    ),
    argument(
        2,
        "consumer_rows",
        WitnessCasmInputAbiArgumentKind::U32,
        WitnessCasmInputAbiAccess::ConsumerRowCount,
    ),
    argument(
        3,
        "pc_dev",
        WitnessCasmInputAbiArgumentKind::DeviceMutPointerU32,
        WitnessCasmInputAbiAccess::WritePc,
    ),
    argument(
        4,
        "ap_dev",
        WitnessCasmInputAbiArgumentKind::DeviceMutPointerU32,
        WitnessCasmInputAbiAccess::WriteAp,
    ),
    argument(
        5,
        "fp_dev",
        WitnessCasmInputAbiArgumentKind::DeviceMutPointerU32,
        WitnessCasmInputAbiAccess::WriteFp,
    ),
    argument(
        6,
        "enabler_dev",
        WitnessCasmInputAbiArgumentKind::DeviceMutPointerU32,
        WitnessCasmInputAbiAccess::WriteEnabler,
    ),
    argument(
        7,
        "iota_dev",
        WitnessCasmInputAbiArgumentKind::OptionalDeviceMutPointerU32,
        WitnessCasmInputAbiAccess::WriteOptionalIota,
    ),
    argument(
        8,
        "stream",
        WitnessCasmInputAbiArgumentKind::CudaStream,
        WitnessCasmInputAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: WitnessCasmInputAbiArgumentKind,
    access: WitnessCasmInputAbiAccess,
) -> WitnessCasmInputAbiArgument {
    WitnessCasmInputAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn require_canonical(
    requirements: &WitnessCasmInputRequirements,
) -> Result<(), WitnessCasmInputAuthorityError> {
    let expected =
        witness_casm_input_requirements(requirements.n_real_rows, requirements.include_iota)
            .map_err(map_requirements_error)?;
    if expected == *requirements {
        Ok(())
    } else {
        Err(WitnessCasmInputAuthorityError::InvalidCanonicalRequirements)
    }
}

fn map_requirements_error(error: PreparedWitnessCasmInputError) -> WitnessCasmInputAuthorityError {
    match error {
        PreparedWitnessCasmInputError::SizeOverflow => WitnessCasmInputAuthorityError::SizeOverflow,
        _ => WitnessCasmInputAuthorityError::InvalidCanonicalRequirements,
    }
}

fn effect_geometry(
    requirements: &WitnessCasmInputRequirements,
) -> Result<WitnessCasmInputEffectGeometry, WitnessCasmInputAuthorityError> {
    let written_words = u32_value(requirements.consumer_rows)?;
    let mut output_columns = (0..WITNESS_CASM_STATE_WORDS)
        .map(|word| {
            Ok(WitnessCasmInputColumnEffect {
                column_ordinal: u32_value(word)?,
                value: WitnessCasmInputColumnValue::StateWord(
                    u8::try_from(word).map_err(|_| WitnessCasmInputAuthorityError::SizeOverflow)?,
                ),
                written_words,
            })
        })
        .collect::<Result<Vec<_>, WitnessCasmInputAuthorityError>>()?;
    output_columns.push(WitnessCasmInputColumnEffect {
        column_ordinal: u32_value(output_columns.len())?,
        value: WitnessCasmInputColumnValue::Enabler,
        written_words,
    });
    if requirements.include_iota {
        output_columns.push(WitnessCasmInputColumnEffect {
            column_ordinal: u32_value(output_columns.len())?,
            value: WitnessCasmInputColumnValue::Iota,
            written_words,
        });
    }
    Ok(WitnessCasmInputEffectGeometry {
        source_start_word: 0,
        source_rows: u32_value(requirements.n_real_rows)?,
        state_words_per_row: u32_value(WITNESS_CASM_STATE_WORDS)?,
        consumer_rows: written_words,
        output_columns,
    })
}

fn consumer_grid(consumer_rows: u32) -> Result<u32, WitnessCasmInputAuthorityError> {
    if consumer_rows == 0 {
        return Err(WitnessCasmInputAuthorityError::InvalidCanonicalRequirements);
    }
    Ok(1 + (consumer_rows - 1) / BLOCK_THREADS)
}

fn linked_contract(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> WitnessCasmInputLinkedContract {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    WitnessCasmInputLinkedContract {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

fn u32_value(value: usize) -> Result<u32, WitnessCasmInputAuthorityError> {
    u32::try_from(value).map_err(|_| WitnessCasmInputAuthorityError::SizeOverflow)
}

fn requirements_identity(
    requirements: &WitnessCasmInputRequirements,
) -> Result<[u8; 32], WitnessCasmInputAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUIREMENTS_DOMAIN);
    for value in [
        requirements.n_real_rows,
        requirements.consumer_rows,
        requirements.staging_words,
        requirements.consumer_input_column_words.len(),
    ] {
        hash_size(&mut hasher, value)?;
    }
    hasher.update(&[u8::from(requirements.include_iota)]);
    for words in &requirements.consumer_input_column_words {
        hash_size(&mut hasher, *words)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

fn fixed_identity(words: &[u32; 4]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FIXED_DOMAIN);
    for field in WITNESS_CASM_INPUT_FIXED_ORDER {
        hasher.update(&[field as u8]);
    }
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn abi_identity(abi: WitnessCasmInputAbi) -> [u8; 32] {
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
    effect: WitnessCasmInputEffectAbi,
    row_domain: WitnessCasmInputRowDomain,
    geometry: &WitnessCasmInputEffectGeometry,
) -> Result<[u8; 32], WitnessCasmInputAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8, row_domain as u8]);
    for value in [
        geometry.source_start_word,
        geometry.source_rows,
        geometry.state_words_per_row,
        geometry.consumer_rows,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    hash_size(&mut hasher, geometry.output_columns.len())?;
    for column in &geometry.output_columns {
        hasher.update(&column.column_ordinal.to_le_bytes());
        match column.value {
            WitnessCasmInputColumnValue::StateWord(word) => {
                hasher.update(&[1, word]);
            }
            WitnessCasmInputColumnValue::Enabler => {
                hasher.update(&[2]);
            }
            WitnessCasmInputColumnValue::Iota => {
                hasher.update(&[3]);
            }
        }
        hasher.update(&column.written_words.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn launch_identity(launch: WitnessCasmInputKernelLaunch) -> [u8; 32] {
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
) -> Result<(), WitnessCasmInputAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| WitnessCasmInputAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests;
