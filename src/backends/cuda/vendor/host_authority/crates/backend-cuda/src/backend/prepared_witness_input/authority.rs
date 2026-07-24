//! Address-free source, ABI, effect, descriptor, and launch authority for the
//! prepared multi-producer witness-input gather.

mod linked;

pub use linked::WitnessInputGatherLinkedContract;

use super::{
    witness_input_gather_requirements, PreparedWitnessInputGatherError,
    WitnessInputGatherRequirements, WITNESS_INPUT_GATHER_DESCRIPTOR_WORDS,
    WITNESS_INPUT_GATHER_PACKED_LANES,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_witness_input.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("authority.rs");
const LINKED_SOURCE: &[u8] = include_bytes!("authority/linked.rs");
const WRAPPER_SOURCE: &[u8] =
    include_bytes!("../../../../backend-cuda-kernels/cuda/witness_edge_gather.cu");

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-wrapper-source-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-source-v1\0";
const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-requirements-v1\0";
const DESCRIPTOR_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-descriptors-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-witness-input-gather-contract-v1\0";
const BLOCK_THREADS: u32 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputGatherAbiArgumentKind {
    U32 = 1,
    DeviceConstPointerU32 = 2,
    DeviceConstPointerTableU32 = 3,
    DeviceMutPointerTableU32 = 4,
    CudaStream = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputGatherAbiAccess {
    ReadPackedProducerColumns = 1,
    ReadCanonicalEdgeDescriptors = 2,
    EdgeCount = 3,
    InputWidth = 4,
    TotalRealRows = 5,
    ConsumerRows = 6,
    WriteConsumerColumns = 7,
    IncludeEnabler = 8,
    IncludeIota = 9,
    OrderedExecutionStream = 10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: WitnessInputGatherAbiArgumentKind,
    pub access: WitnessInputGatherAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputGatherAbi {
    PackedEdgesV1 = 1,
}

impl WitnessInputGatherAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::PackedEdgesV1 => "stwo_witness_input_gather_on",
        }
    }

    pub const fn arguments(self) -> &'static [WitnessInputGatherAbiArgument] {
        match self {
            Self::PackedEdgesV1 => &ARGUMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputGatherEffectAbi {
    ReadPackedEdgesWritePaddedColumnsV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputGatherRowDomain {
    StackedPackedEdgesRepeatFirstPackedRowV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessInputGatherDescriptorField {
    ProducerRows = 1,
    WordBase = 2,
    WordsPerInstance = 3,
    InstanceCount = 4,
    DestinationRowOffset = 5,
}

pub const WITNESS_INPUT_GATHER_DESCRIPTOR_ORDER: [WitnessInputGatherDescriptorField; 5] = [
    WitnessInputGatherDescriptorField::ProducerRows,
    WitnessInputGatherDescriptorField::WordBase,
    WitnessInputGatherDescriptorField::WordsPerInstance,
    WitnessInputGatherDescriptorField::InstanceCount,
    WitnessInputGatherDescriptorField::DestinationRowOffset,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherPackedEdgeEffect {
    pub source_ordinal: u32,
    pub source_start_words: usize,
    pub source_len_words: usize,
    pub destination_row_offset: u32,
    pub destination_rows: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherOutputEffect {
    pub output_ordinal: u32,
    pub write_start_words: usize,
    pub write_len_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherEffectGeometry {
    pub edges: Vec<WitnessInputGatherPackedEdgeEffect>,
    pub descriptor_read_start_words: usize,
    pub descriptor_read_len_words: usize,
    pub output_writes: Vec<WitnessInputGatherOutputEffect>,
    pub packed_lanes: u32,
    pub input_columns: u32,
    pub output_columns: u32,
    pub total_real_rows: u32,
    pub consumer_rows: u32,
    pub include_enabler: bool,
    pub include_iota: bool,
    pub padding_source_edge: u32,
    pub padding_source_rows: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherWrapperLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
}

impl WitnessInputGatherWrapperLaunch {
    pub const fn audited_internal_kernel_symbol(self) -> &'static str {
        "witness_input_gather_kernel"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessInputGatherContract {
    abi: WitnessInputGatherAbi,
    effect: WitnessInputGatherEffectAbi,
    row_domain: WitnessInputGatherRowDomain,
    requirements: WitnessInputGatherRequirements,
    descriptor_words: Box<[u32]>,
    effect_geometry: WitnessInputGatherEffectGeometry,
    wrapper_launch: WitnessInputGatherWrapperLaunch,
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    source_identity: [u8; 32],
    requirements_identity: [u8; 32],
    descriptor_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl WitnessInputGatherContract {
    pub fn compile(
        requirements: &WitnessInputGatherRequirements,
    ) -> Result<Self, WitnessInputGatherAuthorityError> {
        require_canonical(requirements)?;
        let descriptor_words = descriptor_words(requirements)?;
        let effect_geometry = effect_geometry(requirements)?;
        let consumer_rows = u32_value(requirements.consumer_rows)?;
        let wrapper_launch = WitnessInputGatherWrapperLaunch {
            grid: [consumer_rows.div_ceil(BLOCK_THREADS), 1, 1],
            block: [BLOCK_THREADS, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
        };
        let abi = WitnessInputGatherAbi::PackedEdgesV1;
        let effect = WitnessInputGatherEffectAbi::ReadPackedEdgesWritePaddedColumnsV1;
        let row_domain = WitnessInputGatherRowDomain::StackedPackedEdgesRepeatFirstPackedRowV1;
        let static_source_identity = stwo_backend_cuda_kernels::static_cuda_source_identity();
        let wrapper_source_identity = digest(WRAPPER_SOURCE_DOMAIN, WRAPPER_SOURCE);
        let source_identity = source_identity_from(
            static_source_identity,
            wrapper_source_identity,
            BINDER_SOURCE,
            AUTHORITY_SOURCE,
            LINKED_SOURCE,
        );
        if [
            static_source_identity,
            wrapper_source_identity,
            source_identity,
        ]
        .contains(&ZERO_IDENTITY)
        {
            return Err(WitnessInputGatherAuthorityError::MissingStaticSourceIdentity);
        }
        let requirements_identity = requirements_identity(requirements)?;
        let descriptor_identity = descriptor_identity(&descriptor_words);
        let abi_identity = abi_identity(abi);
        let effect_identity =
            effect_identity(effect, row_domain, &effect_geometry, descriptor_identity)?;
        let launch_identity = launch_identity(wrapper_launch);
        let identity = contract_identity(
            source_identity,
            requirements_identity,
            descriptor_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        );
        Ok(Self {
            abi,
            effect,
            row_domain,
            requirements: requirements.clone(),
            descriptor_words: descriptor_words.into_boxed_slice(),
            effect_geometry,
            wrapper_launch,
            static_source_identity,
            wrapper_source_identity,
            source_identity,
            requirements_identity,
            descriptor_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub fn validate(&self) -> Result<(), WitnessInputGatherAuthorityError> {
        let exact = Self::compile(&self.requirements)?;
        if self == &exact {
            Ok(())
        } else {
            Err(WitnessInputGatherAuthorityError::InvalidCanonicalRequirements)
        }
    }

    pub const fn abi(&self) -> WitnessInputGatherAbi {
        self.abi
    }

    pub const fn effect(&self) -> WitnessInputGatherEffectAbi {
        self.effect
    }

    pub const fn row_domain(&self) -> WitnessInputGatherRowDomain {
        self.row_domain
    }

    pub const fn requirements(&self) -> &WitnessInputGatherRequirements {
        &self.requirements
    }

    pub fn descriptor_words(&self) -> &[u32] {
        &self.descriptor_words
    }

    pub const fn effect_geometry(&self) -> &WitnessInputGatherEffectGeometry {
        &self.effect_geometry
    }

    pub const fn wrapper_launch(&self) -> WitnessInputGatherWrapperLaunch {
        self.wrapper_launch
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessInputGatherAuthorityError {
    MissingStaticSourceIdentity,
    InvalidCanonicalRequirements,
    SizeOverflow,
    StaticBuildUnavailable,
    StaticBuildMismatch,
    UnsupportedTargetSm(u32),
}

impl core::fmt::Display for WitnessInputGatherAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid witness-input gather authority: {self:?}"
        )
    }
}

impl std::error::Error for WitnessInputGatherAuthorityError {}

const ARGUMENTS: [WitnessInputGatherAbiArgument; 10] = [
    argument(
        0,
        "producer_subs_dev",
        WitnessInputGatherAbiArgumentKind::DeviceConstPointerTableU32,
        WitnessInputGatherAbiAccess::ReadPackedProducerColumns,
    ),
    argument(
        1,
        "edge_descs_dev",
        WitnessInputGatherAbiArgumentKind::DeviceConstPointerU32,
        WitnessInputGatherAbiAccess::ReadCanonicalEdgeDescriptors,
    ),
    argument(
        2,
        "n_edges",
        WitnessInputGatherAbiArgumentKind::U32,
        WitnessInputGatherAbiAccess::EdgeCount,
    ),
    argument(
        3,
        "input_width",
        WitnessInputGatherAbiArgumentKind::U32,
        WitnessInputGatherAbiAccess::InputWidth,
    ),
    argument(
        4,
        "total_real_rows",
        WitnessInputGatherAbiArgumentKind::U32,
        WitnessInputGatherAbiAccess::TotalRealRows,
    ),
    argument(
        5,
        "consumer_rows",
        WitnessInputGatherAbiArgumentKind::U32,
        WitnessInputGatherAbiAccess::ConsumerRows,
    ),
    argument(
        6,
        "consumer_cols_dev",
        WitnessInputGatherAbiArgumentKind::DeviceMutPointerTableU32,
        WitnessInputGatherAbiAccess::WriteConsumerColumns,
    ),
    argument(
        7,
        "include_enabler",
        WitnessInputGatherAbiArgumentKind::U32,
        WitnessInputGatherAbiAccess::IncludeEnabler,
    ),
    argument(
        8,
        "include_iota",
        WitnessInputGatherAbiArgumentKind::U32,
        WitnessInputGatherAbiAccess::IncludeIota,
    ),
    argument(
        9,
        "stream",
        WitnessInputGatherAbiArgumentKind::CudaStream,
        WitnessInputGatherAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: WitnessInputGatherAbiArgumentKind,
    access: WitnessInputGatherAbiAccess,
) -> WitnessInputGatherAbiArgument {
    WitnessInputGatherAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn require_canonical(
    requirements: &WitnessInputGatherRequirements,
) -> Result<(), WitnessInputGatherAuthorityError> {
    let edges = requirements
        .edges
        .iter()
        .map(|plan| plan.edge)
        .collect::<Vec<_>>();
    let expected = witness_input_gather_requirements(
        &edges,
        requirements.include_enabler,
        requirements.include_iota,
    )
    .map_err(map_requirements_error)?;
    if &expected == requirements {
        Ok(())
    } else {
        Err(WitnessInputGatherAuthorityError::InvalidCanonicalRequirements)
    }
}

fn map_requirements_error(
    error: PreparedWitnessInputGatherError,
) -> WitnessInputGatherAuthorityError {
    match error {
        PreparedWitnessInputGatherError::ProducerRowsOverflow(_)
        | PreparedWitnessInputGatherError::InputWidthOverflow(_)
        | PreparedWitnessInputGatherError::WordBaseOverflow(_)
        | PreparedWitnessInputGatherError::InstanceCountOverflow(_)
        | PreparedWitnessInputGatherError::SizeOverflow
        | PreparedWitnessInputGatherError::TotalRowsOverflow => {
            WitnessInputGatherAuthorityError::SizeOverflow
        }
        _ => WitnessInputGatherAuthorityError::InvalidCanonicalRequirements,
    }
}

fn descriptor_words(
    requirements: &WitnessInputGatherRequirements,
) -> Result<Vec<u32>, WitnessInputGatherAuthorityError> {
    let mut words = Vec::with_capacity(requirements.descriptor_words);
    for plan in &requirements.edges {
        words.extend([
            u32_value(plan.edge.producer_rows)?,
            u32_value(plan.edge.word_base)?,
            u32_value(plan.edge.words_per_instance)?,
            u32_value(plan.edge.n_instances)?,
            u32_value(plan.destination_row_offset)?,
        ]);
    }
    if words.len()
        != requirements
            .edges
            .len()
            .checked_mul(WITNESS_INPUT_GATHER_DESCRIPTOR_WORDS)
            .ok_or(WitnessInputGatherAuthorityError::SizeOverflow)?
    {
        return Err(WitnessInputGatherAuthorityError::InvalidCanonicalRequirements);
    }
    Ok(words)
}

fn effect_geometry(
    requirements: &WitnessInputGatherRequirements,
) -> Result<WitnessInputGatherEffectGeometry, WitnessInputGatherAuthorityError> {
    let output_columns = requirements.consumer_input_column_words.len();
    Ok(WitnessInputGatherEffectGeometry {
        edges: requirements
            .edges
            .iter()
            .enumerate()
            .map(|(source_ordinal, plan)| {
                let source_start_words = plan
                    .edge
                    .word_base
                    .checked_mul(plan.edge.producer_rows)
                    .ok_or(WitnessInputGatherAuthorityError::SizeOverflow)?;
                let source_len_words = plan
                    .edge
                    .words_per_instance
                    .checked_mul(plan.edge.n_instances)
                    .and_then(|words| words.checked_mul(plan.edge.producer_rows))
                    .ok_or(WitnessInputGatherAuthorityError::SizeOverflow)?;
                if source_start_words
                    .checked_add(source_len_words)
                    .ok_or(WitnessInputGatherAuthorityError::SizeOverflow)?
                    != plan.required_source_words
                {
                    return Err(WitnessInputGatherAuthorityError::InvalidCanonicalRequirements);
                }
                Ok(WitnessInputGatherPackedEdgeEffect {
                    source_ordinal: u32_value(source_ordinal)?,
                    source_start_words,
                    source_len_words,
                    destination_row_offset: u32_value(plan.destination_row_offset)?,
                    destination_rows: u32_value(plan.destination_rows)?,
                })
            })
            .collect::<Result<Vec<_>, WitnessInputGatherAuthorityError>>()?,
        descriptor_read_start_words: 0,
        descriptor_read_len_words: requirements.descriptor_words,
        output_writes: (0..output_columns)
            .map(|output_ordinal| {
                Ok(WitnessInputGatherOutputEffect {
                    output_ordinal: u32_value(output_ordinal)?,
                    write_start_words: 0,
                    write_len_words: requirements.consumer_rows,
                })
            })
            .collect::<Result<Vec<_>, WitnessInputGatherAuthorityError>>()?,
        packed_lanes: u32_value(WITNESS_INPUT_GATHER_PACKED_LANES)?,
        input_columns: u32_value(requirements.input_width)?,
        output_columns: u32_value(output_columns)?,
        total_real_rows: u32_value(requirements.total_real_rows)?,
        consumer_rows: u32_value(requirements.consumer_rows)?,
        include_enabler: requirements.include_enabler,
        include_iota: requirements.include_iota,
        padding_source_edge: 0,
        padding_source_rows: u32_value(WITNESS_INPUT_GATHER_PACKED_LANES)?,
    })
}

fn u32_value(value: usize) -> Result<u32, WitnessInputGatherAuthorityError> {
    u32::try_from(value).map_err(|_| WitnessInputGatherAuthorityError::SizeOverflow)
}

fn requirements_identity(
    requirements: &WitnessInputGatherRequirements,
) -> Result<[u8; 32], WitnessInputGatherAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUIREMENTS_DOMAIN);
    hash_size(&mut hasher, requirements.edges.len())?;
    for plan in &requirements.edges {
        for value in [
            plan.edge.producer_rows,
            plan.edge.word_base,
            plan.edge.words_per_instance,
            plan.edge.n_instances,
            plan.destination_row_offset,
            plan.destination_rows,
            plan.required_source_words,
        ] {
            hash_size(&mut hasher, value)?;
        }
    }
    for value in [
        requirements.input_width,
        requirements.total_real_rows,
        requirements.consumer_rows,
        requirements.source_pointer_words,
        requirements.descriptor_words,
        requirements.output_pointer_words,
    ] {
        hash_size(&mut hasher, value)?;
    }
    hasher.update(&[
        u8::from(requirements.include_enabler),
        u8::from(requirements.include_iota),
    ]);
    hash_size(&mut hasher, requirements.consumer_input_column_words.len())?;
    for &words in &requirements.consumer_input_column_words {
        hash_size(&mut hasher, words)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

fn descriptor_identity(words: &[u32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DESCRIPTOR_DOMAIN);
    hash_len(&mut hasher, WITNESS_INPUT_GATHER_DESCRIPTOR_ORDER.len());
    for field in WITNESS_INPUT_GATHER_DESCRIPTOR_ORDER {
        hasher.update(&[field as u8]);
    }
    hash_len(&mut hasher, words.len());
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn abi_identity(abi: WitnessInputGatherAbi) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    hasher.update(&[abi as u8]);
    hash_bytes(&mut hasher, abi.entry_symbol().as_bytes());
    hash_len(&mut hasher, abi.arguments().len());
    for argument in abi.arguments() {
        hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn effect_identity(
    effect: WitnessInputGatherEffectAbi,
    row_domain: WitnessInputGatherRowDomain,
    geometry: &WitnessInputGatherEffectGeometry,
    descriptors: [u8; 32],
) -> Result<[u8; 32], WitnessInputGatherAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8, row_domain as u8]);
    hasher.update(&descriptors);
    hash_size(&mut hasher, geometry.edges.len())?;
    for edge in &geometry.edges {
        hasher.update(&edge.source_ordinal.to_le_bytes());
        hash_size(&mut hasher, edge.source_start_words)?;
        hash_size(&mut hasher, edge.source_len_words)?;
        hasher.update(&edge.destination_row_offset.to_le_bytes());
        hasher.update(&edge.destination_rows.to_le_bytes());
    }
    hash_size(&mut hasher, geometry.descriptor_read_start_words)?;
    hash_size(&mut hasher, geometry.descriptor_read_len_words)?;
    hash_size(&mut hasher, geometry.output_writes.len())?;
    for output in &geometry.output_writes {
        hasher.update(&output.output_ordinal.to_le_bytes());
        hash_size(&mut hasher, output.write_start_words)?;
        hash_size(&mut hasher, output.write_len_words)?;
    }
    for value in [
        geometry.packed_lanes,
        geometry.input_columns,
        geometry.output_columns,
        geometry.total_real_rows,
        geometry.consumer_rows,
        geometry.padding_source_edge,
        geometry.padding_source_rows,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    hasher.update(&[
        u8::from(geometry.include_enabler),
        u8::from(geometry.include_iota),
    ]);
    Ok(*hasher.finalize().as_bytes())
}

fn launch_identity(launch: WitnessInputGatherWrapperLaunch) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    hash_bytes(
        &mut hasher,
        launch.audited_internal_kernel_symbol().as_bytes(),
    );
    for value in launch.grid.into_iter().chain(launch.block) {
        hasher.update(&value.to_le_bytes());
    }
    hasher.update(&launch.dynamic_shared_bytes.to_le_bytes());
    hasher.update(&[u8::from(launch.cooperative)]);
    *hasher.finalize().as_bytes()
}

fn source_identity_from(
    static_source: [u8; 32],
    wrapper_source: [u8; 32],
    binder: &[u8],
    authority: &[u8],
    linked: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_source);
    hasher.update(&wrapper_source);
    hash_bytes(&mut hasher, binder);
    hash_bytes(&mut hasher, authority);
    hash_bytes(&mut hasher, linked);
    *hasher.finalize().as_bytes()
}

fn contract_identity(
    source: [u8; 32],
    requirements: [u8; 32],
    descriptors: [u8; 32],
    abi: [u8; 32],
    effect: [u8; 32],
    launch: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    for identity in [source, requirements, descriptors, abi, effect, launch] {
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

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_len(hasher: &mut blake3::Hasher, value: usize) {
    hasher.update(
        &u64::try_from(value)
            .expect("authority source metadata length fits u64")
            .to_le_bytes(),
    );
}

fn hash_size(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), WitnessInputGatherAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| WitnessInputGatherAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests;
