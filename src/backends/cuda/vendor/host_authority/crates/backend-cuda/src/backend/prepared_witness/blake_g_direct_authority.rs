//! Static source, ABI, effect, and launch authority for direct Blake-G.
//!
//! The entry is a linked ordinary-CUDA wrapper around one 256-thread kernel.
//! This contract intentionally carries no recorded-witness AOT, cubin, target,
//! or loaded-module identity. A runtime must bind the linked static module
//! receipt separately before treating this source contract as executable.

use super::jit_witness::isa::WitnessProgram;
use super::{
    blake_g_fusion_program_is_exact, BG_FUSED_PROGRAM_IDENTITY, BG_FUSED_SEMANTIC_HASH,
    BG_N_DATA_INPUTS, BG_N_LOOKUP_WORDS, BG_N_RECORDED_INPUTS, BG_N_SUB_WORDS, BG_N_TRACE,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_witness.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("blake_g_direct_authority.rs");
const PREPARED_FEED_SOURCE: &[u8] = include_bytes!("../prepared_witness_feed.rs");
const LUT_CONTENT_SOURCE: &[u8] = include_bytes!("../prepared_witness_feed/blake_g_lut_content.rs");

const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-static-blake-g-direct-source-v2\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-static-blake-g-direct-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-static-blake-g-direct-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-static-blake-g-direct-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-static-blake-g-direct-contract-v1\0";

pub const BLAKE_G_DIRECT_BLOCK_THREADS: u32 = 256;
pub const BLAKE_G_DIRECT_LUT_WORDS: [usize; 4] = [1 << 16, 1 << 8, 1 << 14, 1 << 18];
pub const BLAKE_G_DIRECT_COUNT_WORDS: [usize; 5] = [2 << 16, 16 << 20, 1 << 8, 1 << 14, 1 << 18];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlakeGDirectLut {
    Xor8 = 1,
    Xor4 = 2,
    Xor7 = 3,
    Xor9 = 4,
}

pub const BLAKE_G_DIRECT_LUT_ORDER: [BlakeGDirectLut; 4] = [
    BlakeGDirectLut::Xor8,
    BlakeGDirectLut::Xor4,
    BlakeGDirectLut::Xor7,
    BlakeGDirectLut::Xor9,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlakeGDirectCountDestination {
    Xor8 = 1,
    Xor12 = 2,
    Xor4 = 3,
    Xor7 = 4,
    Xor9 = 5,
}

pub const BLAKE_G_DIRECT_COUNT_ORDER: [BlakeGDirectCountDestination; 5] = [
    BlakeGDirectCountDestination::Xor8,
    BlakeGDirectCountDestination::Xor12,
    BlakeGDirectCountDestination::Xor4,
    BlakeGDirectCountDestination::Xor7,
    BlakeGDirectCountDestination::Xor9,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlakeGDirectAbiArgumentKind {
    U32 = 1,
    HostConstDevicePointerTableU32 = 2,
    HostMutDevicePointerTableU32 = 3,
    CudaStream = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlakeGDirectAbiAccess {
    ReadSixInputColumns = 1,
    RealRowCount = 2,
    PaddedRowCount = 3,
    WriteFiftyThreeTraceColumns = 4,
    ReadFourCanonicalLuts = 5,
    AtomicAddFiveCanonicalCountDestinations = 6,
    OrderedExecutionStream = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlakeGDirectAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: BlakeGDirectAbiArgumentKind,
    pub access: BlakeGDirectAbiAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlakeGDirectCompositeAbi {
    FusedDirectV1 = 1,
}

impl BlakeGDirectCompositeAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::FusedDirectV1 => "blake_g_write_trace_fused_direct_into_on",
        }
    }

    pub const fn arguments(self) -> &'static [BlakeGDirectAbiArgument] {
        match self {
            Self::FusedDirectV1 => &ARGUMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlakeGDirectEffectAbi {
    SixInputsFourLutsFiftyThreeTraceFiveCountsSynthesizedEnablerV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlakeGDirectRowDomain {
    /// Reads, writes, and count transitions cover `0..padded_rows`.
    ///
    /// There is no shard start/local-length authority in V1.
    MonolithicFullPaddedRowsV1 = 1,
}

/// Audited launch facts implemented inside the callable host wrapper.
///
/// This is not a generic `CUfunction` launch descriptor: the internal kernel
/// has by-value struct parameters and internal linkage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlakeGDirectWrapperLaunch {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub dynamic_shared_bytes: u32,
    pub cooperative: bool,
}

impl BlakeGDirectWrapperLaunch {
    /// Internal kernel whose launch facts this wrapper receipt audits.
    pub const fn audited_internal_kernel_symbol(self) -> &'static str {
        "blake_g_write_trace_fused_scalar_kernel"
    }
}

/// Exact host-verifiable contract for one direct Blake-G launch geometry.
///
/// Private fields make this an admission receipt: callers can inspect but
/// cannot forge a green source/effect identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlakeGDirectCompositeContract {
    abi: BlakeGDirectCompositeAbi,
    effect: BlakeGDirectEffectAbi,
    row_domain: BlakeGDirectRowDomain,
    program_identity: [u8; 32],
    n_real_rows: usize,
    padded_rows: usize,
    input_column_words: [usize; BG_N_DATA_INPUTS],
    trace_column_words: [usize; BG_N_TRACE],
    lut_words: [usize; 4],
    count_words: [usize; 5],
    wrapper_launch: BlakeGDirectWrapperLaunch,
    source_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    launch_identity: [u8; 32],
    identity: [u8; 32],
}

impl BlakeGDirectCompositeContract {
    pub fn compile(
        program: &WitnessProgram,
        n_real_rows: usize,
        padded_rows: usize,
    ) -> Result<Self, BlakeGDirectAuthorityError> {
        if !blake_g_fusion_program_is_exact(program) {
            return Err(BlakeGDirectAuthorityError::ProgramIdentityMismatch);
        }
        Self::compile_admitted(ProgramMetadata::from(program), n_real_rows, padded_rows)
    }

    fn compile_admitted(
        program: ProgramMetadata<'_>,
        n_real_rows: usize,
        padded_rows: usize,
    ) -> Result<Self, BlakeGDirectAuthorityError> {
        validate_program(program)?;
        if padded_rows == 0 {
            return Err(BlakeGDirectAuthorityError::ZeroPaddedRows);
        }
        if n_real_rows > padded_rows {
            return Err(BlakeGDirectAuthorityError::RealRowsExceedPadded {
                n_real_rows,
                padded_rows,
            });
        }
        let n_real_u32 =
            u32::try_from(n_real_rows).map_err(|_| BlakeGDirectAuthorityError::SizeOverflow)?;
        let padded_u32 =
            u32::try_from(padded_rows).map_err(|_| BlakeGDirectAuthorityError::SizeOverflow)?;
        let abi = BlakeGDirectCompositeAbi::FusedDirectV1;
        let effect =
            BlakeGDirectEffectAbi::SixInputsFourLutsFiftyThreeTraceFiveCountsSynthesizedEnablerV1;
        let row_domain = BlakeGDirectRowDomain::MonolithicFullPaddedRowsV1;
        let wrapper_launch = BlakeGDirectWrapperLaunch {
            grid: [padded_u32.div_ceil(BLAKE_G_DIRECT_BLOCK_THREADS), 1, 1],
            block: [BLAKE_G_DIRECT_BLOCK_THREADS, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
        };
        let source_identity = source_identity();
        if source_identity == ZERO_IDENTITY {
            return Err(BlakeGDirectAuthorityError::MissingStaticSourceIdentity);
        }
        let abi_identity = abi_identity(abi);
        let effect_identity = effect_identity(effect, program.identity, n_real_u32, padded_u32);
        let launch_identity = launch_identity(wrapper_launch);
        let identity = contract_identity(
            source_identity,
            abi_identity,
            effect_identity,
            launch_identity,
        );
        Ok(Self {
            abi,
            effect,
            row_domain,
            program_identity: program.identity,
            n_real_rows,
            padded_rows,
            input_column_words: [padded_rows; BG_N_DATA_INPUTS],
            trace_column_words: [padded_rows; BG_N_TRACE],
            lut_words: BLAKE_G_DIRECT_LUT_WORDS,
            count_words: BLAKE_G_DIRECT_COUNT_WORDS,
            wrapper_launch,
            source_identity,
            abi_identity,
            effect_identity,
            launch_identity,
            identity,
        })
    }

    pub const fn abi(self) -> BlakeGDirectCompositeAbi {
        self.abi
    }

    pub const fn effect(self) -> BlakeGDirectEffectAbi {
        self.effect
    }

    pub const fn row_domain(self) -> BlakeGDirectRowDomain {
        self.row_domain
    }

    pub const fn program_identity(self) -> [u8; 32] {
        self.program_identity
    }

    pub const fn n_real_rows(self) -> usize {
        self.n_real_rows
    }

    pub const fn padded_rows(self) -> usize {
        self.padded_rows
    }

    pub const fn input_column_words(&self) -> &[usize; BG_N_DATA_INPUTS] {
        &self.input_column_words
    }

    pub const fn trace_column_words(&self) -> &[usize; BG_N_TRACE] {
        &self.trace_column_words
    }

    pub const fn lut_words(self) -> [usize; 4] {
        self.lut_words
    }

    pub const fn lut_order(self) -> [BlakeGDirectLut; 4] {
        BLAKE_G_DIRECT_LUT_ORDER
    }

    pub const fn count_words(self) -> [usize; 5] {
        self.count_words
    }

    pub const fn count_order(self) -> [BlakeGDirectCountDestination; 5] {
        BLAKE_G_DIRECT_COUNT_ORDER
    }

    pub const fn wrapper_launch(self) -> BlakeGDirectWrapperLaunch {
        self.wrapper_launch
    }

    pub const fn source_identity(self) -> [u8; 32] {
        self.source_identity
    }

    pub const fn abi_identity(self) -> [u8; 32] {
        self.abi_identity
    }

    pub const fn effect_identity(self) -> [u8; 32] {
        self.effect_identity
    }

    pub const fn launch_identity(self) -> [u8; 32] {
        self.launch_identity
    }

    pub const fn identity(self) -> [u8; 32] {
        self.identity
    }

    pub(crate) fn validate_bound_geometry(
        &self,
        n_real_rows: usize,
        padded_rows: usize,
        input_column_words: &[usize],
        trace_column_words: &[usize],
    ) -> Result<(), BlakeGDirectAuthorityError> {
        if n_real_rows == self.n_real_rows
            && padded_rows == self.padded_rows
            && input_column_words == self.input_column_words
            && trace_column_words == self.trace_column_words
        {
            Ok(())
        } else {
            Err(BlakeGDirectAuthorityError::BindingGeometryMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlakeGDirectAuthorityError {
    MissingStaticSourceIdentity,
    ProgramIdentityMismatch,
    ZeroPaddedRows,
    RealRowsExceedPadded {
        n_real_rows: usize,
        padded_rows: usize,
    },
    BindingGeometryMismatch,
    SizeOverflow,
}

impl core::fmt::Display for BlakeGDirectAuthorityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid static direct Blake-G contract: {self:?}"
        )
    }
}

impl std::error::Error for BlakeGDirectAuthorityError {}

#[derive(Clone, Copy)]
struct ProgramMetadata<'a> {
    label: &'a str,
    identity: [u8; 32],
    semantic_hash: u64,
    n_inputs: u32,
    n_cols: u32,
    n_mult_tables: u32,
    n_lookup_words: u32,
    n_sub_words: u32,
}

impl<'a> From<&'a WitnessProgram> for ProgramMetadata<'a> {
    fn from(program: &'a WitnessProgram) -> Self {
        Self {
            label: &program.label,
            identity: program.semantic_identity(),
            semantic_hash: program.semantic_hash(),
            n_inputs: program.n_inputs,
            n_cols: program.n_cols,
            n_mult_tables: program.n_mult_tables,
            n_lookup_words: program.n_lookup_words,
            n_sub_words: program.n_sub_words,
        }
    }
}

fn validate_program(program: ProgramMetadata<'_>) -> Result<(), BlakeGDirectAuthorityError> {
    let exact = program.label == "blake_g"
        && program.identity == BG_FUSED_PROGRAM_IDENTITY
        && program.semantic_hash == BG_FUSED_SEMANTIC_HASH
        && program.n_inputs as usize == BG_N_RECORDED_INPUTS
        && program.n_cols as usize == BG_N_TRACE
        && program.n_mult_tables == 0
        && program.n_lookup_words as usize == BG_N_LOOKUP_WORDS
        && program.n_sub_words as usize == BG_N_SUB_WORDS;
    if exact {
        Ok(())
    } else {
        Err(BlakeGDirectAuthorityError::ProgramIdentityMismatch)
    }
}

const ARGUMENTS: [BlakeGDirectAbiArgument; 7] = [
    argument(
        0,
        "input_cols_host",
        BlakeGDirectAbiArgumentKind::HostConstDevicePointerTableU32,
        BlakeGDirectAbiAccess::ReadSixInputColumns,
    ),
    argument(
        1,
        "n_rows",
        BlakeGDirectAbiArgumentKind::U32,
        BlakeGDirectAbiAccess::RealRowCount,
    ),
    argument(
        2,
        "column_length",
        BlakeGDirectAbiArgumentKind::U32,
        BlakeGDirectAbiAccess::PaddedRowCount,
    ),
    argument(
        3,
        "trace_cols_host",
        BlakeGDirectAbiArgumentKind::HostMutDevicePointerTableU32,
        BlakeGDirectAbiAccess::WriteFiftyThreeTraceColumns,
    ),
    argument(
        4,
        "luts_host",
        BlakeGDirectAbiArgumentKind::HostConstDevicePointerTableU32,
        BlakeGDirectAbiAccess::ReadFourCanonicalLuts,
    ),
    argument(
        5,
        "counts_host",
        BlakeGDirectAbiArgumentKind::HostMutDevicePointerTableU32,
        BlakeGDirectAbiAccess::AtomicAddFiveCanonicalCountDestinations,
    ),
    argument(
        6,
        "stream",
        BlakeGDirectAbiArgumentKind::CudaStream,
        BlakeGDirectAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: BlakeGDirectAbiArgumentKind,
    access: BlakeGDirectAbiAccess,
) -> BlakeGDirectAbiArgument {
    BlakeGDirectAbiArgument {
        ordinal,
        name,
        kind,
        access,
    }
}

fn source_identity() -> [u8; 32] {
    source_identity_from(
        stwo_backend_cuda_kernels::static_cuda_source_identity(),
        BINDER_SOURCE,
        AUTHORITY_SOURCE,
        PREPARED_FEED_SOURCE,
        LUT_CONTENT_SOURCE,
    )
}

fn source_identity_from(
    static_cuda_source_identity: [u8; 32],
    binder_source: &[u8],
    authority_source: &[u8],
    prepared_feed_source: &[u8],
    lut_content_source: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_cuda_source_identity);
    for source in [
        binder_source,
        authority_source,
        prepared_feed_source,
        lut_content_source,
    ] {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

fn abi_identity(abi: BlakeGDirectCompositeAbi) -> [u8; 32] {
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
    effect: BlakeGDirectEffectAbi,
    program_identity: [u8; 32],
    n_real_rows: u32,
    padded_rows: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8]);
    hasher.update(&program_identity);
    hasher.update(&n_real_rows.to_le_bytes());
    hasher.update(&padded_rows.to_le_bytes());
    hash_usize_array(&mut hasher, &[padded_rows as usize; BG_N_DATA_INPUTS]);
    hash_usize_array(&mut hasher, &[padded_rows as usize; BG_N_TRACE]);
    hash_usize_array(&mut hasher, &BLAKE_G_DIRECT_LUT_WORDS);
    hash_usize_array(&mut hasher, &BLAKE_G_DIRECT_COUNT_WORDS);
    hasher.update(&BLAKE_G_DIRECT_LUT_ORDER.map(|binding| binding as u8));
    hasher.update(&BLAKE_G_DIRECT_COUNT_ORDER.map(|binding| binding as u8));
    hasher.update(&[BlakeGDirectRowDomain::MonolithicFullPaddedRowsV1 as u8]);
    hash_bytes(
        &mut hasher,
        b"read six padded input columns and four canonical LUTs",
    );
    hash_bytes(
        &mut hasher,
        b"write all 53 padded trace columns; trace[52]=u32(row<n_real)",
    );
    hash_bytes(
        &mut hasher,
        b"atomicAdd u32 sixteen canonical xor edges into five declared count slabs",
    );
    hash_bytes(
        &mut hasher,
        b"monolithic only: all padding rows participate; no shard start or local row domain",
    );
    *hasher.finalize().as_bytes()
}

fn launch_identity(launch: BlakeGDirectWrapperLaunch) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    hash_bytes(
        &mut hasher,
        BlakeGDirectCompositeAbi::FusedDirectV1
            .entry_symbol()
            .as_bytes(),
    );
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

fn hash_usize_array(hasher: &mut blake3::Hasher, values: &[usize]) {
    hash_len(hasher, values.len());
    for &value in values {
        hash_len(hasher, value);
    }
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_len(hasher: &mut blake3::Hasher, value: usize) {
    hasher.update(
        &u64::try_from(value)
            .expect("direct Blake-G authority extent fits u64")
            .to_le_bytes(),
    );
}

#[cfg(test)]
mod tests;
