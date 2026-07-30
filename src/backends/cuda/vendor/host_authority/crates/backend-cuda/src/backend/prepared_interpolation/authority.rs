//! Static source, ABI, and effect authority for prepared Base interpolation.
//!
//! This is deliberately narrower than a generic kernel manifest. The prepared
//! interpolation wrapper owns a composite primitive: immutable descriptor
//! upload during setup, optional device copies, then one raw B2N entry which
//! may launch several kernels. A consumer can bind exact buffers through an
//! effect contract without pretending that this composite is one AOT kernel.

use core::ops::Range;

use super::{
    b2n_chunk_ranges, b2n_stage_intervals, is_supported_interpolation_log_size,
    InterpolationLaunchMode,
};

const ZERO_IDENTITY: [u8; 32] = [0; 32];
const BINDER_SOURCE: &[u8] = include_bytes!("../prepared_interpolation.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("authority.rs");

const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-static-interpolation-source-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-static-interpolation-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-static-interpolation-effect-v1\0";
const PRIMITIVE_DOMAIN: &[u8] = b"stwo-cuda-static-interpolation-primitive-v1\0";
const BATCH_DOMAIN: &[u8] = b"stwo-cuda-static-interpolation-batch-v1\0";

/// Device ABI kind for one ordered raw-wrapper argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InterpolationAbiArgumentKind {
    U32 = 1,
    DevicePointerU32 = 2,
    DevicePointerTableU32 = 3,
    CudaStream = 4,
}

/// Semantic role of one raw-wrapper argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InterpolationAbiAccess {
    Read = 1,
    ReadWrite = 2,
    TraceLogSize = 3,
    ColumnCount = 4,
    TwiddleWordCount = 5,
    EvaluationDomainSize = 6,
    OrderedExecutionStream = 7,
}

/// One argument in exact C ABI order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterpolationAbiArgument {
    pub ordinal: u8,
    pub name: &'static str,
    pub kind: InterpolationAbiArgumentKind,
    pub access: InterpolationAbiAccess,
}

/// Typed raw-wrapper ABI. The stage-wise variant includes the preceding exact
/// device-to-device copies in its composite primitive semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InterpolationPrimitiveAbi {
    StageWiseCopyThenInPlaceV1 = 1,
    StageFusedOutOfPlaceV1 = 2,
}

impl InterpolationPrimitiveAbi {
    pub const fn entry_symbol(self) -> &'static str {
        match self {
            Self::StageWiseCopyThenInPlaceV1 => "stwo_ntt_b2n_columns_on",
            Self::StageFusedOutOfPlaceV1 => "stwo_ntt_b2n_columns_out_of_place_on",
        }
    }

    pub const fn arguments(self) -> &'static [InterpolationAbiArgument] {
        match self {
            Self::StageWiseCopyThenInPlaceV1 => &STAGE_WISE_ARGUMENTS,
            Self::StageFusedOutOfPlaceV1 => &STAGE_FUSED_ARGUMENTS,
        }
    }

    pub const fn copies_distinct_inputs_before_entry(self) -> bool {
        matches!(self, Self::StageWiseCopyThenInPlaceV1)
    }
}

/// Typed memory semantics shared by both qualified launch modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InterpolationEffectAbi {
    PairedFullRangeB2nWithTwiddleSuffixV1 = 1,
}

/// Collision-resistant authority for one static composite primitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterpolationPrimitiveAuthority {
    mode: InterpolationLaunchMode,
    abi: InterpolationPrimitiveAbi,
    effect: InterpolationEffectAbi,
    source_identity: [u8; 32],
    abi_identity: [u8; 32],
    effect_identity: [u8; 32],
    identity: [u8; 32],
}

impl InterpolationPrimitiveAuthority {
    fn compile(mode: InterpolationLaunchMode) -> Result<Self, InterpolationAuthorityError> {
        let abi = match mode {
            InterpolationLaunchMode::StageWiseCopyThenInPlace => {
                InterpolationPrimitiveAbi::StageWiseCopyThenInPlaceV1
            }
            InterpolationLaunchMode::StageFusedOutOfPlace => {
                InterpolationPrimitiveAbi::StageFusedOutOfPlaceV1
            }
        };
        let effect = InterpolationEffectAbi::PairedFullRangeB2nWithTwiddleSuffixV1;
        let source_identity = source_identity();
        if source_identity == ZERO_IDENTITY {
            return Err(InterpolationAuthorityError::MissingStaticSourceIdentity);
        }
        let abi_identity = abi_identity(abi);
        let effect_identity = effect_identity(effect, mode);
        let mut hasher = blake3::Hasher::new();
        hasher.update(PRIMITIVE_DOMAIN);
        hasher.update(&[mode as u8, abi as u8, effect as u8]);
        hasher.update(&source_identity);
        hasher.update(&abi_identity);
        hasher.update(&effect_identity);
        let identity = *hasher.finalize().as_bytes();
        Ok(Self {
            mode,
            abi,
            effect,
            source_identity,
            abi_identity,
            effect_identity,
            identity,
        })
    }

    pub const fn mode(self) -> InterpolationLaunchMode {
        self.mode
    }

    pub const fn abi(self) -> InterpolationPrimitiveAbi {
        self.abi
    }

    pub const fn effect(self) -> InterpolationEffectAbi {
        self.effect
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

    pub const fn identity(self) -> [u8; 32] {
        self.identity
    }
}

/// Static authority specialized to one same-shape interpolation batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpolationBatchAuthority {
    primitive: InterpolationPrimitiveAuthority,
    log_size: u32,
    column_count: usize,
    value_words: usize,
    evaluation_domain_size: u32,
    stage_intervals: Vec<u32>,
    chunks: Vec<Range<usize>>,
    identity: [u8; 32],
}

impl InterpolationBatchAuthority {
    pub fn compile(
        mode: InterpolationLaunchMode,
        log_size: u32,
        column_count: usize,
    ) -> Result<Self, InterpolationAuthorityError> {
        if !is_supported_interpolation_log_size(log_size) {
            return Err(InterpolationAuthorityError::InvalidLogSize(log_size));
        }
        if column_count == 0 {
            return Err(InterpolationAuthorityError::EmptyBatch);
        }
        u32::try_from(column_count)
            .map_err(|_| InterpolationAuthorityError::ColumnCountOverflow(column_count))?;
        let value_words = 1usize
            .checked_shl(log_size)
            .ok_or(InterpolationAuthorityError::SizeOverflow)?;
        let evaluation_domain_size = 1u32
            .checked_shl(log_size - 1)
            .ok_or(InterpolationAuthorityError::SizeOverflow)?;
        let stage_intervals = match mode {
            InterpolationLaunchMode::StageWiseCopyThenInPlace => {
                vec![1; usize::try_from(log_size).expect("u32 log fits usize")]
            }
            InterpolationLaunchMode::StageFusedOutOfPlace => b2n_stage_intervals(log_size)
                .ok_or(InterpolationAuthorityError::InvalidLogSize(log_size))?,
        };
        let chunks = b2n_chunk_ranges(column_count);
        let primitive = InterpolationPrimitiveAuthority::compile(mode)?;
        let identity = batch_identity(
            primitive.identity(),
            log_size,
            column_count,
            value_words,
            evaluation_domain_size,
            &stage_intervals,
            &chunks,
        );
        Ok(Self {
            primitive,
            log_size,
            column_count,
            value_words,
            evaluation_domain_size,
            stage_intervals,
            chunks,
            identity,
        })
    }

    pub const fn primitive(&self) -> InterpolationPrimitiveAuthority {
        self.primitive
    }

    pub const fn log_size(&self) -> u32 {
        self.log_size
    }

    pub const fn column_count(&self) -> usize {
        self.column_count
    }

    pub const fn value_words(&self) -> usize {
        self.value_words
    }

    pub const fn evaluation_domain_size(&self) -> u32 {
        self.evaluation_domain_size
    }

    pub fn stage_intervals(&self) -> &[u32] {
        &self.stage_intervals
    }

    pub fn chunks(&self) -> &[Range<usize>] {
        &self.chunks
    }

    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InterpolationAuthorityError {
    MissingStaticSourceIdentity,
    EmptyBatch,
    InvalidLogSize(u32),
    ColumnCountOverflow(usize),
    SizeOverflow,
}

impl core::fmt::Display for InterpolationAuthorityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid static interpolation authority: {self:?}")
    }
}

impl std::error::Error for InterpolationAuthorityError {}

const STAGE_WISE_ARGUMENTS: [InterpolationAbiArgument; 7] = [
    argument(
        0,
        "device_values",
        InterpolationAbiArgumentKind::DevicePointerTableU32,
        InterpolationAbiAccess::ReadWrite,
    ),
    argument(
        1,
        "log_n",
        InterpolationAbiArgumentKind::U32,
        InterpolationAbiAccess::TraceLogSize,
    ),
    argument(
        2,
        "num_poly",
        InterpolationAbiArgumentKind::U32,
        InterpolationAbiAccess::ColumnCount,
    ),
    argument(
        3,
        "g_twiddles",
        InterpolationAbiArgumentKind::DevicePointerU32,
        InterpolationAbiAccess::Read,
    ),
    argument(
        4,
        "twiddles_size",
        InterpolationAbiArgumentKind::U32,
        InterpolationAbiAccess::TwiddleWordCount,
    ),
    argument(
        5,
        "eval_domain_size",
        InterpolationAbiArgumentKind::U32,
        InterpolationAbiAccess::EvaluationDomainSize,
    ),
    argument(
        6,
        "stream",
        InterpolationAbiArgumentKind::CudaStream,
        InterpolationAbiAccess::OrderedExecutionStream,
    ),
];

const STAGE_FUSED_ARGUMENTS: [InterpolationAbiArgument; 8] = [
    argument(
        0,
        "inputs",
        InterpolationAbiArgumentKind::DevicePointerTableU32,
        InterpolationAbiAccess::Read,
    ),
    argument(
        1,
        "outputs",
        InterpolationAbiArgumentKind::DevicePointerTableU32,
        InterpolationAbiAccess::ReadWrite,
    ),
    argument(
        2,
        "log_n",
        InterpolationAbiArgumentKind::U32,
        InterpolationAbiAccess::TraceLogSize,
    ),
    argument(
        3,
        "num_poly",
        InterpolationAbiArgumentKind::U32,
        InterpolationAbiAccess::ColumnCount,
    ),
    argument(
        4,
        "g_twiddles",
        InterpolationAbiArgumentKind::DevicePointerU32,
        InterpolationAbiAccess::Read,
    ),
    argument(
        5,
        "twiddles_size",
        InterpolationAbiArgumentKind::U32,
        InterpolationAbiAccess::TwiddleWordCount,
    ),
    argument(
        6,
        "eval_domain_size",
        InterpolationAbiArgumentKind::U32,
        InterpolationAbiAccess::EvaluationDomainSize,
    ),
    argument(
        7,
        "stream",
        InterpolationAbiArgumentKind::CudaStream,
        InterpolationAbiAccess::OrderedExecutionStream,
    ),
];

const fn argument(
    ordinal: u8,
    name: &'static str,
    kind: InterpolationAbiArgumentKind,
    access: InterpolationAbiAccess,
) -> InterpolationAbiArgument {
    InterpolationAbiArgument {
        ordinal,
        name,
        kind,
        access,
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

fn abi_identity(abi: InterpolationPrimitiveAbi) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    hasher.update(&[abi as u8]);
    hash_bytes(&mut hasher, abi.entry_symbol().as_bytes());
    hash_len(&mut hasher, abi.arguments().len());
    for argument in abi.arguments() {
        hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
    }
    hasher.update(&[u8::from(abi.copies_distinct_inputs_before_entry())]);
    *hasher.finalize().as_bytes()
}

fn effect_identity(effect: InterpolationEffectAbi, mode: InterpolationLaunchMode) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8, mode as u8]);
    hash_bytes(
        &mut hasher,
        b"read full evaluation; write normalized full coefficient; read inverse-twiddle suffix",
    );
    hash_bytes(
        &mut hasher,
        b"allow exact paired alias; forbid partial alias and cross-column alias",
    );
    *hasher.finalize().as_bytes()
}

fn batch_identity(
    primitive_identity: [u8; 32],
    log_size: u32,
    column_count: usize,
    value_words: usize,
    evaluation_domain_size: u32,
    stage_intervals: &[u32],
    chunks: &[Range<usize>],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BATCH_DOMAIN);
    hasher.update(&primitive_identity);
    hasher.update(&log_size.to_le_bytes());
    hash_len_value(&mut hasher, column_count);
    hash_len_value(&mut hasher, value_words);
    hasher.update(&evaluation_domain_size.to_le_bytes());
    hash_len(&mut hasher, stage_intervals.len());
    for interval in stage_intervals {
        hasher.update(&interval.to_le_bytes());
    }
    hash_len(&mut hasher, chunks.len());
    for chunk in chunks {
        hash_len_value(&mut hasher, chunk.start);
        hash_len_value(&mut hasher, chunk.end);
    }
    *hasher.finalize().as_bytes()
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_len(hasher: &mut blake3::Hasher, length: usize) {
    hash_len_value(hasher, length);
}

fn hash_len_value(hasher: &mut blake3::Hasher, value: usize) {
    hasher.update(
        &u64::try_from(value)
            .expect("interpolation authority extent fits u64")
            .to_le_bytes(),
    );
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use super::*;

    #[test]
    fn raw_function_items_match_the_sealed_abi() {
        let _: unsafe extern "C" fn(
            *const *mut u32,
            u32,
            u32,
            *mut u32,
            u32,
            u32,
            *mut c_void,
        ) -> i32 = stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_columns_on;
        let _: unsafe extern "C" fn(
            *const *const u32,
            *const *mut u32,
            u32,
            u32,
            *const u32,
            u32,
            u32,
            *mut c_void,
        ) -> i32 = stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_columns_out_of_place_on;
    }

    #[test]
    fn batch_authority_covers_exact_static_shape() {
        let authority = InterpolationBatchAuthority::compile(
            InterpolationLaunchMode::StageFusedOutOfPlace,
            17,
            65_536,
        )
        .unwrap();
        assert_eq!(authority.value_words(), 1 << 17);
        assert_eq!(authority.evaluation_domain_size(), 1 << 16);
        assert_eq!(authority.stage_intervals(), &[9, 8]);
        assert_eq!(authority.chunks(), &[0..65_535, 65_535..65_536]);
        assert_eq!(
            authority.primitive().abi().entry_symbol(),
            "stwo_ntt_b2n_columns_out_of_place_on"
        );
        for identity in [
            authority.primitive().source_identity(),
            authority.primitive().abi_identity(),
            authority.primitive().effect_identity(),
            authority.primitive().identity(),
            authority.identity(),
        ] {
            assert_ne!(identity, ZERO_IDENTITY);
        }
    }

    #[test]
    fn identity_changes_with_every_dynamic_shape_axis() {
        let baseline = InterpolationBatchAuthority::compile(
            InterpolationLaunchMode::StageWiseCopyThenInPlace,
            17,
            4,
        )
        .unwrap();
        let changed_mode = InterpolationBatchAuthority::compile(
            InterpolationLaunchMode::StageFusedOutOfPlace,
            17,
            4,
        )
        .unwrap();
        let changed_log = InterpolationBatchAuthority::compile(
            InterpolationLaunchMode::StageWiseCopyThenInPlace,
            18,
            4,
        )
        .unwrap();
        let changed_columns = InterpolationBatchAuthority::compile(
            InterpolationLaunchMode::StageWiseCopyThenInPlace,
            17,
            5,
        )
        .unwrap();
        assert_ne!(baseline.identity(), changed_mode.identity());
        assert_ne!(baseline.identity(), changed_log.identity());
        assert_ne!(baseline.identity(), changed_columns.identity());
    }

    #[test]
    fn unsupported_shapes_fail_closed() {
        assert_eq!(
            InterpolationBatchAuthority::compile(
                InterpolationLaunchMode::StageWiseCopyThenInPlace,
                2,
                1,
            ),
            Err(InterpolationAuthorityError::InvalidLogSize(2))
        );
        assert_eq!(
            InterpolationBatchAuthority::compile(
                InterpolationLaunchMode::StageWiseCopyThenInPlace,
                17,
                0,
            ),
            Err(InterpolationAuthorityError::EmptyBatch)
        );
    }
}
