//! Static source, ABI, effect, and launch contract for prepared native EC-op.
//!
//! The raw entry is one ordered composite primitive which submits the chain,
//! normalization, and padding kernels. This contract deliberately does not
//! claim executable module authority: the linked static CUDA archive exposes
//! a collision-resistant source-set identity, but no target/build/binary
//! identity that can populate a compiled proof module.

use super::{
    ec_op_workspace_requirements, EcOpMultiplicityGeometry, EcOpWorkspaceRequirements,
    EC_OP_LOOKUP_WORDS_PER_ROW, EC_OP_PARTIAL_INPUT_COLUMNS, EC_OP_PARTIAL_REAL_ROUNDS,
    EC_OP_TRACE_COLUMNS,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_ec_op.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("authority.rs");

const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-static-ec-op-source-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-static-ec-op-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-static-ec-op-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-static-ec-op-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-static-ec-op-contract-v1\0";

const CHAIN_BLOCK: u32 = 16;
const NORMALIZE_BLOCK: u32 = 64;
const PADDING_BLOCK: u32 = 64;
const NORMALIZE_ROUND_TILE: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EcOpAbiArgumentKind {
    U32 = 1,
    DevicePointerU32 = 2,
    DevicePointerTableU32 = 3,
    HostPointerTableU32 = 4,
    CudaStream = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EcOpAbiAccess {
    Read = 1,
    Write = 2,
    AtomicAddU32 = 3,
    ExecutionTableShape = 4,
    RowCount = 5,
    PartialRowCount = 6,
    DestinationWords = 7,
    OrderedExecutionStream = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcOpAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: EcOpAbiArgumentKind,
    pub access: EcOpAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EcOpCompositeAbi {
    ProjectiveChainNormalizePaddingV1 = 1,
}

impl EcOpCompositeAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::ProjectiveChainNormalizePaddingV1 => "ec_op_builtin_witness_on",
        }
    }

    pub const fn arguments(self) -> &'static [EcOpAbiArgument] {
        match self {
            Self::ProjectiveChainNormalizePaddingV1 => &ARGUMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EcOpEffectAbi {
    FullTraceLookupPartialAndAtomicMultiplicitiesV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EcOpKernelStage {
    ProjectiveChain = 1,
    NormalizeRoundTiles = 2,
    PartialInputPadding = 3,
}

impl EcOpKernelStage {
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::ProjectiveChain => "ec_op_projective_chain_kernel",
            Self::NormalizeRoundTiles => "ec_op_normalize_round_tiles_kernel",
            Self::PartialInputPadding => "partial_input_padding_kernel",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcOpKernelLaunch {
    pub stage: EcOpKernelStage,
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcOpExecutionTableShape {
    pub n_addresses: usize,
    pub n_big: usize,
    pub n_small: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcOpCompositeContract {
    abi: EcOpCompositeAbi,
    effect: EcOpEffectAbi,
    execution_tables: EcOpExecutionTableShape,
    requirements: EcOpWorkspaceRequirements,
    launches: [EcOpKernelLaunch; 3],
    source_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl EcOpCompositeContract {
    pub fn compile(
        requirements: &EcOpWorkspaceRequirements,
        execution_tables: EcOpExecutionTableShape,
    ) -> Result<Self, EcOpAuthorityError> {
        let expected = ec_op_workspace_requirements(
            requirements.row_count,
            EcOpMultiplicityGeometry {
                address_count_words: requirements.address_count_words,
                big_count_words: requirements.big_count_words,
                small_count_words: requirements.small_count_words,
                range_check_8_count_words: requirements.range_check_8_count_words,
            },
        )
        .map_err(|_| EcOpAuthorityError::InvalidWorkspaceGeometry)?;
        if expected != *requirements
            || requirements.address_count_words < execution_tables.n_addresses.saturating_sub(1)
            || requirements.big_count_words < execution_tables.n_big
            || requirements.small_count_words < execution_tables.n_small
            || requirements.range_check_8_count_words < 256
        {
            return Err(EcOpAuthorityError::InvalidWorkspaceGeometry);
        }
        for value in [
            execution_tables.n_addresses,
            execution_tables.n_big,
            execution_tables.n_small,
        ] {
            u32::try_from(value).map_err(|_| EcOpAuthorityError::SizeOverflow)?;
        }

        let abi = EcOpCompositeAbi::ProjectiveChainNormalizePaddingV1;
        let effect = EcOpEffectAbi::FullTraceLookupPartialAndAtomicMultiplicitiesV1;
        let row_count =
            u32::try_from(requirements.row_count).map_err(|_| EcOpAuthorityError::SizeOverflow)?;
        let partial_row_count = u32::try_from(requirements.partial_row_count)
            .map_err(|_| EcOpAuthorityError::SizeOverflow)?;
        let launches = launches(row_count, partial_row_count)?;
        let source_identity = source_identity();
        if source_identity == ZERO_IDENTITY {
            return Err(EcOpAuthorityError::MissingStaticSourceIdentity);
        }
        let abi_identity = abi_identity(abi);
        let effect_identity = effect_identity(effect, requirements, execution_tables)?;
        let launch_identity = launch_identity(&launches);
        let identity = contract_identity(
            source_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        );
        Ok(Self {
            abi,
            effect,
            execution_tables,
            requirements: requirements.clone(),
            launches,
            source_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub const fn abi(&self) -> EcOpCompositeAbi {
        self.abi
    }

    pub const fn effect(&self) -> EcOpEffectAbi {
        self.effect
    }

    pub const fn execution_tables(&self) -> EcOpExecutionTableShape {
        self.execution_tables
    }

    pub const fn requirements(&self) -> &EcOpWorkspaceRequirements {
        &self.requirements
    }

    pub const fn launches(&self) -> &[EcOpKernelLaunch; 3] {
        &self.launches
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EcOpAuthorityError {
    MissingStaticSourceIdentity,
    InvalidWorkspaceGeometry,
    SizeOverflow,
}

impl core::fmt::Display for EcOpAuthorityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid static EC-op contract: {self:?}")
    }
}

impl std::error::Error for EcOpAuthorityError {}

const ARGUMENTS: [EcOpAbiArgument; 19] = [
    argument(
        0,
        "execution_tables",
        EcOpAbiArgumentKind::DevicePointerTableU32,
        EcOpAbiAccess::Read,
    ),
    argument(
        1,
        "n_addresses",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::ExecutionTableShape,
    ),
    argument(
        2,
        "n_big",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::ExecutionTableShape,
    ),
    argument(
        3,
        "n_small",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::ExecutionTableShape,
    ),
    argument(
        4,
        "segment_start_source",
        EcOpAbiArgumentKind::DevicePointerU32,
        EcOpAbiAccess::Read,
    ),
    argument(
        5,
        "row_count",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::RowCount,
    ),
    argument(
        6,
        "trace_columns_host",
        EcOpAbiArgumentKind::HostPointerTableU32,
        EcOpAbiAccess::Write,
    ),
    argument(
        7,
        "lookup_words",
        EcOpAbiArgumentKind::DevicePointerU32,
        EcOpAbiAccess::Write,
    ),
    argument(
        8,
        "partial_input_columns_host",
        EcOpAbiArgumentKind::HostPointerTableU32,
        EcOpAbiAccess::Write,
    ),
    argument(
        9,
        "partial_row_count",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::PartialRowCount,
    ),
    argument(
        10,
        "address_counts",
        EcOpAbiArgumentKind::DevicePointerU32,
        EcOpAbiAccess::AtomicAddU32,
    ),
    argument(
        11,
        "address_count_words",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::DestinationWords,
    ),
    argument(
        12,
        "big_counts",
        EcOpAbiArgumentKind::DevicePointerU32,
        EcOpAbiAccess::AtomicAddU32,
    ),
    argument(
        13,
        "big_count_words",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::DestinationWords,
    ),
    argument(
        14,
        "small_counts",
        EcOpAbiArgumentKind::DevicePointerU32,
        EcOpAbiAccess::AtomicAddU32,
    ),
    argument(
        15,
        "small_count_words",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::DestinationWords,
    ),
    argument(
        16,
        "range_check_8_counts",
        EcOpAbiArgumentKind::DevicePointerU32,
        EcOpAbiAccess::AtomicAddU32,
    ),
    argument(
        17,
        "range_check_8_count_words",
        EcOpAbiArgumentKind::U32,
        EcOpAbiAccess::DestinationWords,
    ),
    argument(
        18,
        "stream",
        EcOpAbiArgumentKind::CudaStream,
        EcOpAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: EcOpAbiArgumentKind,
    access: EcOpAbiAccess,
) -> EcOpAbiArgument {
    EcOpAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn launches(
    row_count: u32,
    partial_row_count: u32,
) -> Result<[EcOpKernelLaunch; 3], EcOpAuthorityError> {
    let padding_rows = partial_row_count
        .checked_sub(
            row_count
                .checked_mul(EC_OP_PARTIAL_REAL_ROUNDS as u32)
                .ok_or(EcOpAuthorityError::SizeOverflow)?,
        )
        .ok_or(EcOpAuthorityError::InvalidWorkspaceGeometry)?;
    Ok([
        launch(
            EcOpKernelStage::ProjectiveChain,
            [row_count.div_ceil(CHAIN_BLOCK), 1, 1],
            CHAIN_BLOCK,
        ),
        launch(
            EcOpKernelStage::NormalizeRoundTiles,
            [
                row_count.div_ceil(NORMALIZE_BLOCK),
                (EC_OP_PARTIAL_REAL_ROUNDS as u32) / NORMALIZE_ROUND_TILE,
                1,
            ],
            NORMALIZE_BLOCK,
        ),
        launch(
            EcOpKernelStage::PartialInputPadding,
            [padding_rows.div_ceil(PADDING_BLOCK), 1, 1],
            PADDING_BLOCK,
        ),
    ])
}

const fn launch(stage: EcOpKernelStage, grid: [u32; 3], block: u32) -> EcOpKernelLaunch {
    EcOpKernelLaunch {
        stage,
        grid,
        block: [block, 1, 1],
        dynamic_shared_bytes: 0,
        cooperative: false,
    }
}

fn source_identity() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&stwo_backend_cuda_kernels::static_cuda_source_identity());
    hash_bytes(&mut hasher, BINDER_SOURCE);
    hash_bytes(&mut hasher, AUTHORITY_SOURCE);
    *hasher.finalize().as_bytes()
}

fn abi_identity(abi: EcOpCompositeAbi) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    hasher.update(&[abi as u8]);
    hash_bytes(&mut hasher, abi.entry_symbol().as_bytes());
    let arguments = abi.arguments();
    hash_len(&mut hasher, arguments.len());
    for argument in arguments {
        hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn effect_identity(
    effect: EcOpEffectAbi,
    requirements: &EcOpWorkspaceRequirements,
    tables: EcOpExecutionTableShape,
) -> Result<[u8; 32], EcOpAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8]);
    for value in [tables.n_addresses, tables.n_big, tables.n_small] {
        hash_len_value(&mut hasher, value)?;
    }
    hash_len_value(&mut hasher, requirements.row_count)?;
    hash_len_value(&mut hasher, EC_OP_TRACE_COLUMNS)?;
    hash_len_value(&mut hasher, requirements.lookup_words)?;
    hash_len_value(&mut hasher, EC_OP_LOOKUP_WORDS_PER_ROW)?;
    hash_len_value(&mut hasher, requirements.partial_row_count)?;
    hash_len_value(&mut hasher, EC_OP_PARTIAL_INPUT_COLUMNS)?;
    for words in [
        requirements.address_count_words,
        requirements.big_count_words,
        requirements.small_count_words,
        requirements.range_check_8_count_words,
    ] {
        hash_len_value(&mut hasher, words)?;
    }
    hash_bytes(
        &mut hasher,
        b"read exact execution-table data and segment start",
    );
    hash_bytes(
        &mut hasher,
        b"write complete trace lookup and partial-input ranges",
    );
    hash_bytes(
        &mut hasher,
        b"atomicAdd u32 full declared multiplicity destinations",
    );
    Ok(*hasher.finalize().as_bytes())
}

fn launch_identity(launches: &[EcOpKernelLaunch; 3]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    hash_len(&mut hasher, launches.len());
    for launch in launches {
        hasher.update(&[launch.stage as u8]);
        hash_bytes(&mut hasher, launch.stage.symbol().as_bytes());
        for value in launch.grid.into_iter().chain(launch.block) {
            hasher.update(&value.to_le_bytes());
        }
        hasher.update(&launch.dynamic_shared_bytes.to_le_bytes());
        hasher.update(&[u8::from(launch.cooperative)]);
    }
    *hasher.finalize().as_bytes()
}

fn contract_identity(
    source: [u8; 32],
    abi: [u8; 32],
    effect: [u8; 32],
    launch: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    hasher.update(&source);
    hasher.update(&abi);
    hasher.update(&effect);
    hasher.update(&launch);
    *hasher.finalize().as_bytes()
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_len(hasher: &mut blake3::Hasher, value: usize) {
    hasher.update(
        &u64::try_from(value)
            .expect("EC-op authority metadata length fits u64")
            .to_le_bytes(),
    );
}

fn hash_len_value(hasher: &mut blake3::Hasher, value: usize) -> Result<(), EcOpAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| EcOpAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> EcOpWorkspaceRequirements {
        ec_op_workspace_requirements(
            32,
            EcOpMultiplicityGeometry {
                address_count_words: 511,
                big_count_words: 128,
                small_count_words: 64,
                range_check_8_count_words: 256,
            },
        )
        .unwrap()
    }

    fn tables() -> EcOpExecutionTableShape {
        EcOpExecutionTableShape {
            n_addresses: 512,
            n_big: 128,
            n_small: 64,
        }
    }

    #[test]
    fn exact_composite_contract_is_stable_and_complete() {
        type RawEcOp = unsafe extern "C" fn(
            *const *const u32,
            u32,
            u32,
            u32,
            *const u32,
            u32,
            *const *mut u32,
            *mut u32,
            *const *mut u32,
            u32,
            *mut u32,
            u32,
            *mut u32,
            u32,
            *mut u32,
            u32,
            *mut u32,
            u32,
            *mut core::ffi::c_void,
        ) -> i32;
        let _: RawEcOp = stwo_backend_cuda_kernels::raw::ec_op_builtin_witness_on;

        let contract = EcOpCompositeContract::compile(&requirements(), tables()).unwrap();
        assert_eq!(contract.abi().arguments().len(), 19);
        assert_eq!(contract.abi().entry_symbol(), "ec_op_builtin_witness_on");
        assert_eq!(contract.launches()[0].grid, [2, 1, 1]);
        assert_eq!(contract.launches()[0].block, [16, 1, 1]);
        assert_eq!(contract.launches()[1].grid, [1, 63, 1]);
        assert_eq!(contract.launches()[1].block, [64, 1, 1]);
        assert_eq!(contract.launches()[2].grid, [2, 1, 1]);
        assert_eq!(contract.launches()[2].block, [64, 1, 1]);
        for identity in [
            contract.source_identity(),
            contract.abi_identity(),
            contract.effect_identity(),
            contract.launch_identity(),
            contract.identity(),
        ] {
            assert_ne!(identity, ZERO_IDENTITY);
        }

        let source = include_str!("../../../../backend-cuda-kernels/cuda/ec_op_witness.cu");
        for required in [
            "constexpr uint32_t EC_OP_CHAIN_BLOCK = 16;",
            "constexpr uint32_t EC_OP_NORMALIZE_BLOCK = 64;",
            "constexpr uint32_t EC_OP_PADDING_BLOCK = 64;",
            "constexpr uint32_t EC_OP_NORMALIZE_ROUND_TILE = 4;",
            "extern \"C\" int ec_op_builtin_witness_on(",
        ] {
            assert!(
                source.contains(required),
                "missing EC-op authority: {required}"
            );
        }
        let chain = source.find("ec_op_projective_chain_kernel<<<").unwrap();
        let normalize = source
            .find("ec_op_normalize_round_tiles_kernel<<<")
            .unwrap();
        let padding = source.find("partial_input_padding_kernel<<<").unwrap();
        assert!(chain < normalize && normalize < padding);
    }

    #[test]
    fn composite_contract_rejects_every_geometry_drift() {
        let baseline = EcOpCompositeContract::compile(&requirements(), tables()).unwrap();
        let mut changed = requirements();
        changed.lookup_words -= 1;
        assert_eq!(
            EcOpCompositeContract::compile(&changed, tables()),
            Err(EcOpAuthorityError::InvalidWorkspaceGeometry)
        );
        let mut table_drift = tables();
        table_drift.n_big += 1;
        assert_eq!(
            EcOpCompositeContract::compile(&requirements(), table_drift),
            Err(EcOpAuthorityError::InvalidWorkspaceGeometry)
        );
        assert_ne!(
            baseline.identity(),
            EcOpCompositeContract::compile(
                &ec_op_workspace_requirements(
                    64,
                    EcOpMultiplicityGeometry {
                        address_count_words: 511,
                        big_count_words: 128,
                        small_count_words: 64,
                        range_check_8_count_words: 256,
                    },
                )
                .unwrap(),
                tables(),
            )
            .unwrap()
            .identity()
        );
    }
}
