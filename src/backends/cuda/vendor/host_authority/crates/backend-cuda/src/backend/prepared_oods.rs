//! Arena-native, transcript-driven out-of-domain sampling.
//!
//! Setup fixes the proof's column/mask topology and uploads only immutable
//! descriptors. [`PreparedOodsGraph::launch`] derives the random circle point
//! from a device transcript parameter, evaluates resident coefficient columns,
//! and writes canonical proof-order samples directly into the transcript input.

use core::ffi::c_void;
use std::collections::{BTreeMap, BTreeSet};

use num_traits::One;
use stwo::core::circle::{CirclePoint, CirclePointIndex, Coset};
use stwo::core::constraints::coset_vanishing_derivative;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::poly::circle::CanonicCoset;
use stwo_backend_cuda_kernels::raw as cuda_raw;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};

#[path = "prepared_oods/authority.rs"]
mod authority;
#[path = "prepared_oods/evaluation_launch.rs"]
mod evaluation_launch;
#[path = "prepared_oods/pass_collapse.rs"]
mod pass_collapse;
#[cfg(test)]
#[path = "prepared_oods/pass_collapse_tests.rs"]
mod pass_collapse_tests;
pub use authority::{
    OodsExecutionAbi, OodsExecutionAbiAccess, OodsExecutionAbiArgument,
    OodsExecutionAbiArgumentKind, OodsExecutionAccess, OodsExecutionAccessKind,
    OodsExecutionAuthority, OodsExecutionAuthorityError, OodsExecutionColumn,
    OodsExecutionHostCall, OodsExecutionHostCallKind, OodsExecutionInvocation,
    OodsExecutionInvocationArgument, OodsExecutionInvocationValue, OodsExecutionKernelLaunch,
    OodsExecutionLinkedAuthority, OodsExecutionScratch, OodsExecutionValueLayout,
    OodsExecutionValueOwnership, OodsExecutionValueRole,
};
pub use pass_collapse::{
    oods_canonical_sample_order, OodsCanonicalSample, OodsPassCollapseBatchReceipt,
    OodsPassCollapseCohortReceipt, OodsPassCollapseCohortRejection, OodsPassCollapseError,
    OodsPassCollapseGroupReceipt, OodsPassCollapseIdentity, OodsPassCollapseProgram,
    OodsPassCollapseReceipt, OODS_COLLAPSED_AUX_SHARED_QM31, OODS_COLLAPSED_CORE_SHARED_QM31,
    OODS_COLLAPSED_DYNAMIC_SHARED_BYTES, OODS_CUDA_DEFAULT_DYNAMIC_SHARED_LIMIT_BYTES,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const SECURE_WORDS: usize = 4;
const SECURE_POINT_WORDS: usize = 2 * SECURE_WORDS;
const BASE_POINT_WORDS: usize = 2;
const REDUCTION_RADIX: usize = 512;
const REDUCTION_LOG: u32 = 9;
const POINTER_WORDS: usize = core::mem::size_of::<*const u32>().div_ceil(WORD_BYTES);

pub const OODS_PARAMETER_WORDS: usize = SECURE_WORDS;
pub const OODS_POINTER_ALIGNMENT_WORDS: usize = core::mem::align_of::<*const u32>() / WORD_BYTES;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OodsSourceKind {
    Coefficients,
    Evaluations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsWorkspaceConfig {
    /// Log size of the PCS lifting domain used by proof_driver's point fold.
    pub lifting_log_size: u32,
    /// `max_log_degree_bound` used to turn component-relative mask offsets into points.
    pub mask_log_size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OodsMaskTopology<'a> {
    /// Component-framework row offsets relative to `CanonicCoset(mask_log_size).step()`.
    SignedOffsets(&'a [isize]),
    /// Already-discovered group offsets from the OODS base point.
    OffsetPoints(&'a [CirclePoint<BaseField>]),
}

impl OodsMaskTopology<'_> {
    pub const fn len(self) -> usize {
        match self {
            Self::SignedOffsets(offsets) => offsets.len(),
            Self::OffsetPoints(points) => points.len(),
        }
    }

    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsColumnTopology<'a> {
    /// Source buffer size. For coefficient sources this is the polynomial's
    /// coefficient log; for evaluation sources it is the evaluation-domain log.
    pub log_size: u32,
    /// Domain log used by the canonical PCS point fold before evaluation.
    pub evaluation_log_size: u32,
    pub masks: OodsMaskTopology<'a>,
    pub source_kind: OodsSourceKind,
}

impl<'a> OodsColumnTopology<'a> {
    /// Coefficient source whose source and evaluation domains have the same log size.
    /// PCS callers with a nonzero blowup must use [`Self::coefficient_signed_offsets`].
    pub const fn signed_offsets(log_size: u32, offsets: &'a [isize]) -> Self {
        Self {
            log_size,
            evaluation_log_size: log_size,
            masks: OodsMaskTopology::SignedOffsets(offsets),
            source_kind: OodsSourceKind::Coefficients,
        }
    }

    pub const fn coefficient_signed_offsets(
        coefficient_log_size: u32,
        evaluation_log_size: u32,
        offsets: &'a [isize],
    ) -> Self {
        Self {
            log_size: coefficient_log_size,
            evaluation_log_size,
            masks: OodsMaskTopology::SignedOffsets(offsets),
            source_kind: OodsSourceKind::Coefficients,
        }
    }

    /// Coefficient source whose source and evaluation domains have the same log size.
    /// PCS callers with a nonzero blowup must use [`Self::coefficient_offset_points`].
    pub const fn offset_points(log_size: u32, points: &'a [CirclePoint<BaseField>]) -> Self {
        Self {
            log_size,
            evaluation_log_size: log_size,
            masks: OodsMaskTopology::OffsetPoints(points),
            source_kind: OodsSourceKind::Coefficients,
        }
    }

    pub const fn coefficient_offset_points(
        coefficient_log_size: u32,
        evaluation_log_size: u32,
        points: &'a [CirclePoint<BaseField>],
    ) -> Self {
        Self {
            log_size: coefficient_log_size,
            evaluation_log_size,
            masks: OodsMaskTopology::OffsetPoints(points),
            source_kind: OodsSourceKind::Coefficients,
        }
    }

    pub const fn evaluation_signed_offsets(log_size: u32, offsets: &'a [isize]) -> Self {
        Self {
            log_size,
            evaluation_log_size: log_size,
            masks: OodsMaskTopology::SignedOffsets(offsets),
            source_kind: OodsSourceKind::Evaluations,
        }
    }

    pub const fn evaluation_offset_points(
        log_size: u32,
        points: &'a [CirclePoint<BaseField>],
    ) -> Self {
        Self {
            log_size,
            evaluation_log_size: log_size,
            masks: OodsMaskTopology::OffsetPoints(points),
            source_kind: OodsSourceKind::Evaluations,
        }
    }

    fn offset_point(
        self,
        mask_step: CirclePoint<BaseField>,
        mask: usize,
    ) -> CirclePoint<BaseField> {
        match self.masks {
            OodsMaskTopology::SignedOffsets(offsets) => {
                let offset = offsets[mask];
                if offset >= 0 {
                    mask_step.mul(offset as u128)
                } else {
                    mask_step.conjugate().mul(offset.unsigned_abs() as u128)
                }
            }
            OodsMaskTopology::OffsetPoints(points) => points[mask],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OodsCoefficientColumn<'a> {
    pub coefficients: ArenaSlice,
    pub topology: OodsColumnTopology<'a>,
}

#[derive(Clone, Copy, Debug)]
pub enum OodsColumnSource {
    Coefficients(ArenaSlice),
    Evaluations(ArenaSlice),
}

impl OodsColumnSource {
    fn slice(self) -> ArenaSlice {
        match self {
            Self::Coefficients(slice) | Self::Evaluations(slice) => slice,
        }
    }

    const fn kind(self) -> OodsSourceKind {
        match self {
            Self::Coefficients(_) => OodsSourceKind::Coefficients,
            Self::Evaluations(_) => OodsSourceKind::Evaluations,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OodsPolynomialColumn<'a> {
    pub source: OodsColumnSource,
    pub topology: OodsColumnTopology<'a>,
}

/// Canonical proof-order sample range for one committed column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsColumnSampleRange {
    pub source_log_size: u32,
    pub evaluation_log_size: u32,
    pub first_sample: usize,
    pub sample_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsLogGroupRequirements {
    pub log_size: u32,
    pub descriptor_offset: usize,
    pub factor_offset_words: usize,
    pub sample_count: usize,
    pub first_pass_blocks: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsEvaluationGroupRequirements {
    pub log_size: u32,
    pub offset_point: CirclePoint<BaseField>,
    pub descriptor_offset: usize,
    pub factor_offset_words: usize,
    pub sample_count: usize,
    pub reduction_blocks: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsWorkspaceRequirements {
    pub config: OodsWorkspaceConfig,
    pub column_ranges: Vec<OodsColumnSampleRange>,
    pub groups: Vec<OodsLogGroupRequirements>,
    pub evaluation_groups: Vec<OodsEvaluationGroupRequirements>,
    pub sample_count: usize,
    pub source_pointer_words: usize,
    pub offset_point_words: usize,
    pub fold_count_words: usize,
    pub output_index_words: usize,
    pub factor_words: usize,
    pub scratch_a_words: usize,
    pub scratch_b_words: usize,
    pub sample_point_words: usize,
    pub sampled_value_words: usize,
    pub evaluation_point_words: usize,
    pub barycentric_numerator_words: usize,
    pub barycentric_weight_words: usize,
    pub barycentric_scale_words: usize,
    pub barycentric_partial_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsWorkspaceSlots {
    pub source_pointers: ArenaSlotId,
    pub offset_points: ArenaSlotId,
    pub fold_counts: ArenaSlotId,
    pub output_indices: ArenaSlotId,
    pub folding_factors: ArenaSlotId,
    pub scratch_a: ArenaSlotId,
    pub scratch_b: ArenaSlotId,
    /// Canonical `[CirclePoint<SecureField>; sample_count]` quotient input.
    pub sample_points: ArenaSlotId,
    /// Canonical `[SecureField; sample_count]` transcript input.
    pub sampled_values: ArenaSlotId,
    /// Folded points indexed in immutable launch-descriptor order.
    pub evaluation_points: ArenaSlotId,
    pub barycentric_numerators: ArenaSlotId,
    pub barycentric_weights: ArenaSlotId,
    pub barycentric_scales: ArenaSlotId,
    pub barycentric_partials: ArenaSlotId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedOodsError {
    InvalidLiftingLogSize(u32),
    InvalidMaskLogSize(u32),
    EmptySamples,
    TooManySamples(usize),
    InvalidColumnLogSize {
        column: usize,
        log_size: u32,
        lifting_log_size: u32,
    },
    InvalidEvaluationLogSize {
        column: usize,
        source_log_size: u32,
        evaluation_log_size: u32,
        lifting_log_size: u32,
    },
    InvalidOffsetPoint {
        column: usize,
        mask: usize,
    },
    SourceKindMismatch {
        column: usize,
        topology: OodsSourceKind,
        source: OodsSourceKind,
    },
    SizeOverflow,
    DuplicateSlot(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    SourceAliasesWorkspace(ArenaSlotId),
    SourceTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    ParameterTooSmall(usize),
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedSlot {
        slot: ArenaSlotId,
        alignment_words: usize,
    },
    PassCollapseProgramIdentity,
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedOodsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA OODS workspace: {self:?}")
    }
}

impl std::error::Error for PreparedOodsError {}

impl From<ArenaError> for PreparedOodsError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedOodsError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

pub fn oods_workspace_requirements(
    config: OodsWorkspaceConfig,
    columns: &[OodsColumnTopology<'_>],
) -> Result<OodsWorkspaceRequirements, PreparedOodsError> {
    if !(1..=30).contains(&config.lifting_log_size) {
        return Err(PreparedOodsError::InvalidLiftingLogSize(
            config.lifting_log_size,
        ));
    }
    if !(1..=config.lifting_log_size).contains(&config.mask_log_size) {
        return Err(PreparedOodsError::InvalidMaskLogSize(config.mask_log_size));
    }

    let mask_step = CanonicCoset::new(config.mask_log_size).step();
    let mut column_ranges = Vec::with_capacity(columns.len());
    let mut coefficients_by_log = BTreeMap::<u32, usize>::new();
    let mut evaluations_by_point =
        BTreeMap::<(u32, u32, u32), (CirclePoint<BaseField>, usize)>::new();
    let mut sample_count = 0usize;
    for (column, topology) in columns.iter().enumerate() {
        if topology.log_size == 0
            || (!topology.masks.is_empty() && topology.log_size > config.lifting_log_size)
        {
            return Err(PreparedOodsError::InvalidColumnLogSize {
                column,
                log_size: topology.log_size,
                lifting_log_size: config.lifting_log_size,
            });
        }
        if !topology.masks.is_empty()
            && (topology.evaluation_log_size < topology.log_size
                || topology.evaluation_log_size > config.lifting_log_size
                || (topology.source_kind == OodsSourceKind::Evaluations
                    && topology.evaluation_log_size != topology.log_size))
        {
            return Err(PreparedOodsError::InvalidEvaluationLogSize {
                column,
                source_log_size: topology.log_size,
                evaluation_log_size: topology.evaluation_log_size,
                lifting_log_size: config.lifting_log_size,
            });
        }
        column_ranges.push(OodsColumnSampleRange {
            source_log_size: topology.log_size,
            evaluation_log_size: topology.evaluation_log_size,
            first_sample: sample_count,
            sample_count: topology.masks.len(),
        });
        if let OodsMaskTopology::OffsetPoints(points) = topology.masks {
            for (mask, point) in points.iter().enumerate() {
                if point.x.square() + point.y.square() != BaseField::one() {
                    return Err(PreparedOodsError::InvalidOffsetPoint { column, mask });
                }
            }
        }
        for mask in 0..topology.masks.len() {
            match topology.source_kind {
                OodsSourceKind::Coefficients => {
                    let count = coefficients_by_log.entry(topology.log_size).or_default();
                    *count = count
                        .checked_add(1)
                        .ok_or(PreparedOodsError::SizeOverflow)?;
                }
                OodsSourceKind::Evaluations => {
                    let point = topology.offset_point(mask_step, mask);
                    let entry = evaluations_by_point
                        .entry((topology.log_size, point.x.0, point.y.0))
                        .or_insert((point, 0));
                    entry.1 = entry
                        .1
                        .checked_add(1)
                        .ok_or(PreparedOodsError::SizeOverflow)?;
                }
            }
            sample_count = sample_count
                .checked_add(1)
                .ok_or(PreparedOodsError::SizeOverflow)?;
        }
    }
    if sample_count == 0 {
        return Err(PreparedOodsError::EmptySamples);
    }
    if sample_count > u16::MAX as usize {
        return Err(PreparedOodsError::TooManySamples(sample_count));
    }

    let mut groups = Vec::with_capacity(coefficients_by_log.len());
    let mut evaluation_groups = Vec::with_capacity(evaluations_by_point.len());
    let mut descriptor_offset = 0usize;
    let mut factor_offset_words = 0usize;
    let mut scratch_a_words = SECURE_WORDS;
    let mut scratch_b_words = SECURE_WORDS;
    for (log_size, log_sample_count) in coefficients_by_log {
        let coefficient_size = pow2(log_size)?;
        let first_pass_blocks = coefficient_size.div_ceil(REDUCTION_RADIX);
        let group_factor_words = log_sample_count
            .checked_mul(log_size as usize)
            .and_then(|count| count.checked_mul(SECURE_WORDS))
            .ok_or(PreparedOodsError::SizeOverflow)?;
        let group_scratch_a = log_sample_count
            .checked_mul(first_pass_blocks)
            .and_then(|count| count.checked_mul(SECURE_WORDS))
            .ok_or(PreparedOodsError::SizeOverflow)?;
        let second_pass_blocks = first_pass_blocks.div_ceil(REDUCTION_RADIX).max(1);
        let group_scratch_b = log_sample_count
            .checked_mul(second_pass_blocks)
            .and_then(|count| count.checked_mul(SECURE_WORDS))
            .ok_or(PreparedOodsError::SizeOverflow)?;
        groups.push(OodsLogGroupRequirements {
            log_size,
            descriptor_offset,
            factor_offset_words,
            sample_count: log_sample_count,
            first_pass_blocks,
        });
        descriptor_offset = descriptor_offset
            .checked_add(log_sample_count)
            .ok_or(PreparedOodsError::SizeOverflow)?;
        factor_offset_words = factor_offset_words
            .checked_add(group_factor_words)
            .ok_or(PreparedOodsError::SizeOverflow)?;
        scratch_a_words = scratch_a_words.max(group_scratch_a);
        scratch_b_words = scratch_b_words.max(group_scratch_b);
    }

    let mut barycentric_numerator_words = SECURE_WORDS;
    let mut barycentric_weight_words = SECURE_WORDS;
    let mut barycentric_partial_words = SECURE_WORDS;
    for ((log_size, ..), (offset_point, log_sample_count)) in evaluations_by_point {
        let evaluation_size = pow2(log_size)?;
        let reduction_blocks = evaluation_size.div_ceil(256).min(1024);
        let group_factor_words = log_sample_count
            .checked_mul(log_size as usize)
            .and_then(|count| count.checked_mul(SECURE_WORDS))
            .ok_or(PreparedOodsError::SizeOverflow)?;
        evaluation_groups.push(OodsEvaluationGroupRequirements {
            log_size,
            offset_point,
            descriptor_offset,
            factor_offset_words,
            sample_count: log_sample_count,
            reduction_blocks,
        });
        descriptor_offset = descriptor_offset
            .checked_add(log_sample_count)
            .ok_or(PreparedOodsError::SizeOverflow)?;
        factor_offset_words = factor_offset_words
            .checked_add(group_factor_words)
            .ok_or(PreparedOodsError::SizeOverflow)?;
        let evaluation_words = checked_mul(evaluation_size, SECURE_WORDS)?;
        let partial_words = log_sample_count
            .checked_mul(reduction_blocks)
            .and_then(|count| count.checked_mul(SECURE_WORDS))
            .ok_or(PreparedOodsError::SizeOverflow)?;
        barycentric_numerator_words = barycentric_numerator_words.max(evaluation_words);
        barycentric_weight_words = barycentric_weight_words.max(evaluation_words);
        barycentric_partial_words = barycentric_partial_words.max(partial_words);
    }
    debug_assert_eq!(descriptor_offset, sample_count);

    Ok(OodsWorkspaceRequirements {
        config,
        column_ranges,
        groups,
        evaluation_groups,
        sample_count,
        source_pointer_words: checked_mul(sample_count, POINTER_WORDS)?,
        offset_point_words: checked_mul(sample_count, BASE_POINT_WORDS)?,
        fold_count_words: sample_count,
        output_index_words: sample_count,
        factor_words: factor_offset_words,
        scratch_a_words,
        scratch_b_words,
        sample_point_words: checked_mul(sample_count, SECURE_POINT_WORDS)?,
        sampled_value_words: checked_mul(sample_count, SECURE_WORDS)?,
        evaluation_point_words: checked_mul(sample_count, SECURE_POINT_WORDS)?,
        barycentric_numerator_words,
        barycentric_weight_words,
        barycentric_scale_words: 2 * SECURE_WORDS,
        barycentric_partial_words,
    })
}

impl OodsWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &OodsWorkspaceSlots,
    ) -> Result<Vec<OodsArenaSlotRequirement>, PreparedOodsError> {
        let requirements = vec![
            slot(
                slots.source_pointers,
                self.source_pointer_words,
                OODS_POINTER_ALIGNMENT_WORDS,
            ),
            slot(slots.offset_points, self.offset_point_words, 1),
            slot(slots.fold_counts, self.fold_count_words, 1),
            slot(slots.output_indices, self.output_index_words, 1),
            slot(slots.folding_factors, self.factor_words, SECURE_WORDS),
            slot(slots.scratch_a, self.scratch_a_words, SECURE_WORDS),
            slot(slots.scratch_b, self.scratch_b_words, SECURE_WORDS),
            slot(slots.sample_points, self.sample_point_words, SECURE_WORDS),
            slot(slots.sampled_values, self.sampled_value_words, SECURE_WORDS),
            slot(
                slots.evaluation_points,
                self.evaluation_point_words,
                SECURE_WORDS,
            ),
            slot(
                slots.barycentric_numerators,
                self.barycentric_numerator_words,
                SECURE_WORDS,
            ),
            slot(
                slots.barycentric_weights,
                self.barycentric_weight_words,
                SECURE_WORDS,
            ),
            slot(
                slots.barycentric_scales,
                self.barycentric_scale_words,
                SECURE_WORDS,
            ),
            slot(
                slots.barycentric_partials,
                self.barycentric_partial_words,
                SECURE_WORDS,
            ),
        ];
        let mut seen = BTreeSet::new();
        for requirement in &requirements {
            if !seen.insert(requirement.id) {
                return Err(PreparedOodsError::DuplicateSlot(requirement.id));
            }
        }
        Ok(requirements)
    }
}

fn slot(id: ArenaSlotId, len_words: usize, alignment_words: usize) -> OodsArenaSlotRequirement {
    OodsArenaSlotRequirement {
        id,
        len_words,
        alignment_words,
    }
}

#[derive(Clone, Debug)]
struct OodsLaunchGroup {
    requirements: OodsLogGroupRequirements,
}

#[derive(Clone, Debug)]
struct OodsEvaluationLaunchGroup {
    requirements: OodsEvaluationGroupRequirements,
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    si0: cuda_raw::CudaSecureField,
    vanishing_rotation: cuda_raw::CirclePointBaseField,
}

/// Stable OODS launch object. Launch performs no allocation, transfer, sync, or
/// default-stream work and can be called during CUDA graph capture.
pub struct PreparedOodsGraph<'a> {
    arena: &'a DeviceArena,
    requirements: OodsWorkspaceRequirements,
    parameter: ArenaSlice,
    source_pointers: ArenaSlice,
    offset_points: ArenaSlice,
    fold_counts: ArenaSlice,
    output_indices: ArenaSlice,
    folding_factors: ArenaSlice,
    scratch_a: ArenaSlice,
    scratch_b: ArenaSlice,
    sample_points: ArenaSlice,
    sampled_values: ArenaSlice,
    evaluation_points: ArenaSlice,
    barycentric_numerators: ArenaSlice,
    barycentric_weights: ArenaSlice,
    barycentric_scales: ArenaSlice,
    barycentric_partials: ArenaSlice,
    groups: Vec<OodsLaunchGroup>,
    evaluation_groups: Vec<OodsEvaluationLaunchGroup>,
    pass_collapse: Option<OodsPassCollapseProgram>,
}

impl<'a> PreparedOodsGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        config: OodsWorkspaceConfig,
        columns: &[OodsCoefficientColumn<'_>],
        oods_point_parameter: ArenaSlice,
        slots: &OodsWorkspaceSlots,
    ) -> Result<Self, PreparedOodsError> {
        let columns: Vec<_> = columns
            .iter()
            .map(|column| OodsPolynomialColumn {
                source: OodsColumnSource::Coefficients(column.coefficients),
                topology: column.topology,
            })
            .collect();
        Self::prepare_mixed(arena, config, &columns, oods_point_parameter, slots)
    }

    pub fn prepare_mixed(
        arena: &'a DeviceArena,
        config: OodsWorkspaceConfig,
        columns: &[OodsPolynomialColumn<'_>],
        oods_point_parameter: ArenaSlice,
        slots: &OodsWorkspaceSlots,
    ) -> Result<Self, PreparedOodsError> {
        Self::prepare_mixed_with_pass_collapse(
            arena,
            config,
            columns,
            oods_point_parameter,
            slots,
            None,
        )
    }

    pub fn prepare_mixed_pass_collapsed(
        arena: &'a DeviceArena,
        config: OodsWorkspaceConfig,
        columns: &[OodsPolynomialColumn<'_>],
        oods_point_parameter: ArenaSlice,
        slots: &OodsWorkspaceSlots,
        program: &OodsPassCollapseProgram,
    ) -> Result<Self, PreparedOodsError> {
        Self::prepare_mixed_with_pass_collapse(
            arena,
            config,
            columns,
            oods_point_parameter,
            slots,
            Some(program),
        )
    }

    fn prepare_mixed_with_pass_collapse(
        arena: &'a DeviceArena,
        config: OodsWorkspaceConfig,
        columns: &[OodsPolynomialColumn<'_>],
        oods_point_parameter: ArenaSlice,
        slots: &OodsWorkspaceSlots,
        pass_collapse: Option<&OodsPassCollapseProgram>,
    ) -> Result<Self, PreparedOodsError> {
        let topology: Vec<_> = columns.iter().map(|column| column.topology).collect();
        let ordinary_requirements = oods_workspace_requirements(config, &topology)?;
        let pass_collapse = pass_collapse
            .map(|program| {
                program
                    .validate_against(config, &topology)
                    .map_err(|_| PreparedOodsError::PassCollapseProgramIdentity)?;
                Ok::<_, PreparedOodsError>(program.clone())
            })
            .transpose()?;
        let requirements = pass_collapse
            .as_ref()
            .map(|program| program.collapsed_requirements().clone())
            .unwrap_or(ordinary_requirements);
        let slot_requirements = requirements.arena_slot_requirements(slots)?;
        let workspace_ids: BTreeSet<_> = slot_requirements.iter().map(|entry| entry.id).collect();
        let context_token = arena.context().identity_token();

        if oods_point_parameter.context_token() != context_token {
            return Err(PreparedOodsError::ContextMismatch(
                oods_point_parameter.id(),
            ));
        }
        if oods_point_parameter.len_words() < OODS_PARAMETER_WORDS {
            return Err(PreparedOodsError::ParameterTooSmall(
                oods_point_parameter.len_words(),
            ));
        }
        if workspace_ids.contains(&oods_point_parameter.id()) {
            return Err(PreparedOodsError::SourceAliasesWorkspace(
                oods_point_parameter.id(),
            ));
        }
        for (column, source) in columns.iter().enumerate() {
            let source_slice = source.source.slice();
            if source.source.kind() != source.topology.source_kind {
                return Err(PreparedOodsError::SourceKindMismatch {
                    column,
                    topology: source.topology.source_kind,
                    source: source.source.kind(),
                });
            }
            if source_slice.context_token() != context_token {
                return Err(PreparedOodsError::ContextMismatch(source_slice.id()));
            }
            if workspace_ids.contains(&source_slice.id()) {
                return Err(PreparedOodsError::SourceAliasesWorkspace(source_slice.id()));
            }
            let required_words = pow2(source.topology.log_size)?;
            if source_slice.len_words() < required_words {
                return Err(PreparedOodsError::SourceTooSmall {
                    slot: source_slice.id(),
                    required_words,
                    actual_words: source_slice.len_words(),
                });
            }
            debug_assert_eq!(source.topology, topology[column]);
        }

        let source_pointers = bind_slot(
            arena,
            slots.source_pointers,
            requirements.source_pointer_words,
            OODS_POINTER_ALIGNMENT_WORDS,
        )?;
        let offset_points = bind_slot(
            arena,
            slots.offset_points,
            requirements.offset_point_words,
            1,
        )?;
        let fold_counts = bind_slot(arena, slots.fold_counts, requirements.fold_count_words, 1)?;
        let output_indices = bind_slot(
            arena,
            slots.output_indices,
            requirements.output_index_words,
            1,
        )?;
        let folding_factors = bind_slot(
            arena,
            slots.folding_factors,
            requirements.factor_words,
            SECURE_WORDS,
        )?;
        let scratch_a = bind_slot(
            arena,
            slots.scratch_a,
            requirements.scratch_a_words,
            SECURE_WORDS,
        )?;
        let scratch_b = bind_slot(
            arena,
            slots.scratch_b,
            requirements.scratch_b_words,
            SECURE_WORDS,
        )?;
        let sample_points = bind_slot(
            arena,
            slots.sample_points,
            requirements.sample_point_words,
            SECURE_WORDS,
        )?;
        let sampled_values = bind_slot(
            arena,
            slots.sampled_values,
            requirements.sampled_value_words,
            SECURE_WORDS,
        )?;
        let evaluation_points = bind_slot(
            arena,
            slots.evaluation_points,
            requirements.evaluation_point_words,
            SECURE_WORDS,
        )?;
        let barycentric_numerators = bind_slot(
            arena,
            slots.barycentric_numerators,
            requirements.barycentric_numerator_words,
            SECURE_WORDS,
        )?;
        let barycentric_weights = bind_slot(
            arena,
            slots.barycentric_weights,
            requirements.barycentric_weight_words,
            SECURE_WORDS,
        )?;
        let barycentric_scales = bind_slot(
            arena,
            slots.barycentric_scales,
            requirements.barycentric_scale_words,
            SECURE_WORDS,
        )?;
        let barycentric_partials = bind_slot(
            arena,
            slots.barycentric_partials,
            requirements.barycentric_partial_words,
            SECURE_WORDS,
        )?;

        let canonical_samples = pass_collapse::canonical_sample_order_unchecked(config, &topology);

        let mut pointers = Vec::with_capacity(requirements.sample_count);
        let mut offsets = Vec::with_capacity(requirements.sample_count);
        let mut folds = Vec::with_capacity(requirements.sample_count);
        let mut indices = Vec::with_capacity(requirements.sample_count);
        for sample in &canonical_samples {
            pointers.push(columns[sample.column_index].source.slice().as_u32_ptr() as usize);
            offsets.push(cuda_raw::CirclePointBaseField {
                x: sample.offset_point.x.0,
                y: sample.offset_point.y.0,
            });
            folds.push(config.lifting_log_size - sample.evaluation_log_size);
            indices.push(
                u32::try_from(sample.output_index).map_err(|_| PreparedOodsError::SizeOverflow)?,
            );
        }
        let collapsed_descriptor_offsets = pass_collapse
            .as_ref()
            .map(|program| {
                program
                    .identity()
                    .evaluation_groups
                    .iter()
                    .map(|group| {
                        u32::try_from(group.descriptor_offset)
                            .map_err(|_| PreparedOodsError::SizeOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let mut uploads = vec![
            PendingUpload::pointers(source_pointers, &pointers),
            PendingUpload::base_points(offset_points, &offsets),
            PendingUpload::u32(fold_counts, &folds),
            PendingUpload::u32(output_indices, &indices),
        ];
        if let Some(descriptor_offsets) = &collapsed_descriptor_offsets {
            uploads.push(PendingUpload::u32(barycentric_scales, descriptor_offsets));
        }
        upload_and_sync(arena, &uploads)?;

        let groups = requirements
            .groups
            .iter()
            .cloned()
            .map(|requirements| OodsLaunchGroup { requirements })
            .collect();
        let evaluation_groups = requirements
            .evaluation_groups
            .iter()
            .cloned()
            .map(|requirements| {
                let domain = CanonicCoset::new(requirements.log_size).circle_domain();
                let p0 = domain.at(0).into_ef::<SecureField>();
                let si0 = SecureField::one()
                    / ((p0.y * SecureField::from(-2))
                        * coset_vanishing_derivative(
                            Coset::new(CirclePointIndex::generator(), requirements.log_size),
                            p0,
                        ));
                let coset = CanonicCoset::new(requirements.log_size).coset;
                let vanishing_rotation =
                    coset.initial.conjugate() + coset.step_size.half().to_point();
                OodsEvaluationLaunchGroup {
                    half_coset_initial_index: domain.half_coset.initial_index.0 as u32,
                    half_coset_step_size: domain.half_coset.step_size.0 as u32,
                    si0: raw_secure(si0),
                    vanishing_rotation: raw_base_point(vanishing_rotation),
                    requirements,
                }
            })
            .collect();

        Ok(Self {
            arena,
            requirements,
            parameter: oods_point_parameter,
            source_pointers,
            offset_points,
            fold_counts,
            output_indices,
            folding_factors,
            scratch_a,
            scratch_b,
            sample_points,
            sampled_values,
            evaluation_points,
            barycentric_numerators,
            barycentric_weights,
            barycentric_scales,
            barycentric_partials,
            groups,
            evaluation_groups,
            pass_collapse,
        })
    }

    pub fn requirements(&self) -> &OodsWorkspaceRequirements {
        &self.requirements
    }

    pub fn column_ranges(&self) -> &[OodsColumnSampleRange] {
        &self.requirements.column_ranges
    }

    pub fn pass_collapse_program(&self) -> Option<&OodsPassCollapseProgram> {
        self.pass_collapse.as_ref()
    }

    pub const fn sample_points_destination(&self) -> ArenaSlice {
        self.sample_points
    }

    pub const fn sampled_values_destination(&self) -> ArenaSlice {
        self.sampled_values
    }

    pub const fn oods_point_parameter_source(&self) -> ArenaSlice {
        self.parameter
    }

    pub fn launch(&self) -> Result<(), PreparedOodsError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        for group in &self.groups {
            self.launch_group(group, stream)?;
        }
        if let Some(program) = &self.pass_collapse {
            self.launch_collapsed_evaluation_groups(program, stream)?;
        } else {
            for group in &self.evaluation_groups {
                self.launch_evaluation_group(group, stream)?;
            }
        }
        Ok(())
    }

    fn launch_group(
        &self,
        group: &OodsLaunchGroup,
        stream: *mut c_void,
    ) -> Result<(), PreparedOodsError> {
        let group = &group.requirements;
        let count = to_u32(group.sample_count)?;
        let descriptor_offset = group.descriptor_offset;
        let factor_offset = group.factor_offset_words / SECURE_WORDS;
        let pointers = unsafe {
            self.source_pointers
                .as_u32_ptr()
                .cast::<*const u32>()
                .add(descriptor_offset)
        };
        let offsets = unsafe {
            self.offset_points
                .as_u32_ptr()
                .cast::<cuda_raw::CirclePointBaseField>()
                .add(descriptor_offset)
        };
        let fold_counts = unsafe { self.fold_counts.as_u32_ptr().add(descriptor_offset) };
        let output_indices = unsafe { self.output_indices.as_u32_ptr().add(descriptor_offset) };
        let factors = unsafe {
            self.folding_factors
                .as_u32_ptr()
                .cast::<cuda_raw::CudaSecureField>()
                .add(factor_offset)
        };

        let code = unsafe {
            cuda_raw::stwo_oods_derive_points_on(
                self.parameter
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                offsets,
                fold_counts,
                output_indices,
                count,
                group.log_size,
                self.sample_points.as_u32_ptr(),
                self.evaluation_points
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>()
                    .add(2 * descriptor_offset)
                    .cast::<u32>(),
                factors,
                stream,
            )
        };
        check_cuda("prepared_oods_derive_points", code)?;

        let coefficient_size = to_u32(pow2(group.log_size)?)?;
        let code = unsafe {
            cuda_raw::stwo_oods_eval_first_on(
                pointers,
                coefficient_size,
                count,
                factors,
                self.scratch_a
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                stream,
            )
        };
        check_cuda("prepared_oods_eval_first", code)?;

        let mut current = self.scratch_a;
        let mut current_size = group.first_pass_blocks;
        let mut current_stride = group.first_pass_blocks;
        let mut next = self.scratch_b;
        let mut factor_index = group.log_size.saturating_sub(REDUCTION_LOG + 1);
        while current_size > 1 {
            let next_size = current_size.div_ceil(REDUCTION_RADIX);
            let code = unsafe {
                cuda_raw::stwo_oods_eval_reduce_on(
                    current.as_u32_ptr().cast::<cuda_raw::CudaSecureField>(),
                    to_u32(current_size)?,
                    to_u32(current_stride)?,
                    factor_index,
                    group.log_size,
                    count,
                    factors,
                    next.as_u32_ptr().cast::<cuda_raw::CudaSecureField>(),
                    to_u32(next_size)?,
                    stream,
                )
            };
            check_cuda("prepared_oods_eval_reduce", code)?;
            let consumed = current_size.ilog2().min(REDUCTION_LOG);
            current = next;
            current_size = next_size;
            current_stride = next_size;
            next = if next.id() == self.scratch_a.id() {
                self.scratch_b
            } else {
                self.scratch_a
            };
            if current_size > 1 {
                factor_index = factor_index
                    .checked_sub(consumed)
                    .ok_or(PreparedOodsError::SizeOverflow)?;
            }
        }

        let code = unsafe {
            cuda_raw::stwo_oods_store_results_on(
                current.as_u32_ptr().cast::<cuda_raw::CudaSecureField>(),
                to_u32(current_stride)?,
                output_indices,
                count,
                self.sampled_values
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                stream,
            )
        };
        check_cuda("prepared_oods_store_results", code)?;
        Ok(())
    }
}

enum HostUpload<'a> {
    U32(&'a [u32]),
    Pointers(&'a [usize]),
    BasePoints(&'a [cuda_raw::CirclePointBaseField]),
}

struct PendingUpload<'a> {
    destination: ArenaSlice,
    source: HostUpload<'a>,
}

impl<'a> PendingUpload<'a> {
    fn u32(destination: ArenaSlice, source: &'a [u32]) -> Self {
        Self {
            destination,
            source: HostUpload::U32(source),
        }
    }

    fn pointers(destination: ArenaSlice, source: &'a [usize]) -> Self {
        Self {
            destination,
            source: HostUpload::Pointers(source),
        }
    }

    fn base_points(destination: ArenaSlice, source: &'a [cuda_raw::CirclePointBaseField]) -> Self {
        Self {
            destination,
            source: HostUpload::BasePoints(source),
        }
    }

    fn bytes(&self) -> (*const c_void, usize) {
        match self.source {
            HostUpload::U32(values) => typed_bytes(values),
            HostUpload::Pointers(values) => typed_bytes(values),
            HostUpload::BasePoints(values) => typed_bytes(values),
        }
    }
}

fn upload_and_sync(
    arena: &DeviceArena,
    uploads: &[PendingUpload<'_>],
) -> Result<(), PreparedOodsError> {
    for upload in uploads {
        let (source, bytes) = upload.bytes();
        unsafe {
            arena
                .context()
                .memcpy_h2d_async(upload.destination.as_void_ptr(), source, bytes)?;
        }
    }
    arena.context().sync()?;
    Ok(())
}

fn typed_bytes<T>(values: &[T]) -> (*const c_void, usize) {
    (values.as_ptr().cast(), core::mem::size_of_val(values))
}

fn raw_secure(value: SecureField) -> cuda_raw::CudaSecureField {
    let [a, b, c, d] = value.to_m31_array();
    cuda_raw::CudaSecureField {
        a: a.0,
        b: b.0,
        c: c.0,
        d: d.0,
    }
}

fn raw_base_point(point: CirclePoint<BaseField>) -> cuda_raw::CirclePointBaseField {
    cuda_raw::CirclePointBaseField {
        x: point.x.0,
        y: point.y.0,
    }
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedOodsError> {
    let slice = arena.bind(id)?;
    if slice.len_words() < required_words {
        return Err(PreparedOodsError::SlotTooSmall {
            slot: id,
            required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedOodsError::MisalignedSlot {
            slot: id,
            alignment_words,
        });
    }
    // Pooled slots may be larger than any single logical buffer; expose only
    // the logical extent so no consumer derives sizes from the pooled surplus.
    Ok(slice.truncated(required_words))
}

fn pow2(log_size: u32) -> Result<usize, PreparedOodsError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedOodsError::SizeOverflow)
}

fn checked_mul(lhs: usize, rhs: usize) -> Result<usize, PreparedOodsError> {
    lhs.checked_mul(rhs).ok_or(PreparedOodsError::SizeOverflow)
}

fn to_u32(value: usize) -> Result<u32, PreparedOodsError> {
    u32::try_from(value).map_err(|_| PreparedOodsError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology<'a>(log_size: u32, mask_offsets: &'a [isize]) -> OodsColumnTopology<'a> {
        OodsColumnTopology::signed_offsets(log_size, mask_offsets)
    }

    #[test]
    fn requirements_preserve_proof_order_and_group_by_source_log() {
        let requirements = oods_workspace_requirements(
            OodsWorkspaceConfig {
                lifting_log_size: 20,
                mask_log_size: 17,
            },
            &[
                topology(18, &[-1, 0, 2]),
                topology(20, &[0]),
                topology(18, &[7, 8]),
                topology(25, &[]),
            ],
        )
        .unwrap();

        assert_eq!(requirements.sample_count, 6);
        assert_eq!(
            requirements.column_ranges,
            vec![
                OodsColumnSampleRange {
                    source_log_size: 18,
                    evaluation_log_size: 18,
                    first_sample: 0,
                    sample_count: 3,
                },
                OodsColumnSampleRange {
                    source_log_size: 20,
                    evaluation_log_size: 20,
                    first_sample: 3,
                    sample_count: 1,
                },
                OodsColumnSampleRange {
                    source_log_size: 18,
                    evaluation_log_size: 18,
                    first_sample: 4,
                    sample_count: 2,
                },
                OodsColumnSampleRange {
                    source_log_size: 25,
                    evaluation_log_size: 25,
                    first_sample: 6,
                    sample_count: 0,
                },
            ]
        );
        assert_eq!(
            requirements
                .groups
                .iter()
                .map(|group| (group.log_size, group.sample_count, group.descriptor_offset))
                .collect::<Vec<_>>(),
            vec![(18, 5, 0), (20, 1, 5)]
        );
        assert_eq!(requirements.sample_point_words, 6 * SECURE_POINT_WORDS);
        assert_eq!(requirements.sampled_value_words, 6 * SECURE_WORDS);

        assert_eq!(
            oods_workspace_requirements(
                OodsWorkspaceConfig {
                    lifting_log_size: 20,
                    mask_log_size: 17,
                },
                &[topology(21, &[0])],
            ),
            Err(PreparedOodsError::InvalidColumnLogSize {
                column: 0,
                log_size: 21,
                lifting_log_size: 20,
            })
        );
    }

    #[test]
    fn requirements_use_bounded_reduction_scratch_not_full_columns() {
        let requirements = oods_workspace_requirements(
            OodsWorkspaceConfig {
                lifting_log_size: 24,
                mask_log_size: 21,
            },
            &[topology(24, &[0, 1, -1])],
        )
        .unwrap();

        let full_secure_columns = 3 * (1usize << 24) * SECURE_WORDS;
        assert_eq!(requirements.groups[0].first_pass_blocks, 1 << 15);
        assert_eq!(requirements.scratch_a_words, 3 * (1 << 15) * SECURE_WORDS);
        assert_eq!(requirements.scratch_b_words, 3 * 64 * SECURE_WORDS);
        assert!(requirements.scratch_a_words < full_secure_columns / 100);
    }

    #[test]
    fn duplicate_workspace_slot_is_rejected() {
        let requirements = oods_workspace_requirements(
            OodsWorkspaceConfig {
                lifting_log_size: 8,
                mask_log_size: 6,
            },
            &[topology(8, &[0])],
        )
        .unwrap();
        let slots = OodsWorkspaceSlots {
            source_pointers: ArenaSlotId(1),
            offset_points: ArenaSlotId(1),
            fold_counts: ArenaSlotId(2),
            output_indices: ArenaSlotId(3),
            folding_factors: ArenaSlotId(4),
            scratch_a: ArenaSlotId(5),
            scratch_b: ArenaSlotId(6),
            sample_points: ArenaSlotId(7),
            sampled_values: ArenaSlotId(8),
            evaluation_points: ArenaSlotId(9),
            barycentric_numerators: ArenaSlotId(10),
            barycentric_weights: ArenaSlotId(11),
            barycentric_scales: ArenaSlotId(12),
            barycentric_partials: ArenaSlotId(13),
        };
        assert_eq!(
            requirements.arena_slot_requirements(&slots),
            Err(PreparedOodsError::DuplicateSlot(ArenaSlotId(1)))
        );
    }

    #[test]
    fn explicit_offset_points_are_accepted_without_signed_row_metadata() {
        let step = CanonicCoset::new(8).step();
        let points = [CirclePoint::zero(), step, step.conjugate().mul(7)];
        let requirements = oods_workspace_requirements(
            OodsWorkspaceConfig {
                lifting_log_size: 10,
                mask_log_size: 8,
            },
            &[OodsColumnTopology::offset_points(9, &points)],
        )
        .unwrap();
        assert_eq!(requirements.sample_count, 3);

        let invalid = [CirclePoint {
            x: BaseField::from(2),
            y: BaseField::from(3),
        }];
        assert_eq!(
            oods_workspace_requirements(
                OodsWorkspaceConfig {
                    lifting_log_size: 10,
                    mask_log_size: 8,
                },
                &[OodsColumnTopology::offset_points(9, &invalid)],
            ),
            Err(PreparedOodsError::InvalidOffsetPoint { column: 0, mask: 0 })
        );
    }

    #[test]
    fn coefficient_and_evaluation_logs_are_distinct_and_validated() {
        let offsets = [0];
        let topology = [OodsColumnTopology::coefficient_signed_offsets(
            4, 5, &offsets,
        )];
        let requirements = oods_workspace_requirements(
            OodsWorkspaceConfig {
                lifting_log_size: 24,
                mask_log_size: 9,
            },
            &topology,
        )
        .unwrap();
        assert_eq!(requirements.groups[0].log_size, 4);
        assert_eq!(requirements.column_ranges[0].source_log_size, 4);
        assert_eq!(requirements.column_ranges[0].evaluation_log_size, 5);

        let invalid = [OodsColumnTopology::coefficient_signed_offsets(
            5, 4, &offsets,
        )];
        assert!(matches!(
            oods_workspace_requirements(
                OodsWorkspaceConfig {
                    lifting_log_size: 24,
                    mask_log_size: 9,
                },
                &invalid,
            ),
            Err(PreparedOodsError::InvalidEvaluationLogSize { .. })
        ));
    }
}
