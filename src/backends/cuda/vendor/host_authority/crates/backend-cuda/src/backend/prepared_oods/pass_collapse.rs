//! Shape-sealed accounting for collapsing OODS barycentric weight preparation.
//!
//! The executable kernel is deliberately a separate promotion boundary. This
//! module proves which canonical evaluation groups it must cover, the immutable
//! descriptor order it must preserve, and the exact launch, logical-request,
//! and workspace deltas before a production constructor may select it.

use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;

use super::{
    oods_workspace_requirements, OodsColumnSampleRange, OodsColumnTopology,
    OodsEvaluationGroupRequirements, OodsLogGroupRequirements, OodsSourceKind, OodsWorkspaceConfig,
    OodsWorkspaceRequirements, PreparedOodsError, SECURE_WORDS, WORD_BYTES,
};

const SECURE_BYTES: usize = SECURE_WORDS * WORD_BYTES;
const LEGACY_WEIGHT_KERNELS_PER_GROUP: usize = 4;
const EVALUATION_KERNELS_PER_GROUP: usize = 2;
const DERIVE_KERNELS_PER_GROUP: usize = 1;
const REDUCTION_RADIX: usize = 512;
const CUDA_GRID_Y_LIMIT: usize = u16::MAX as usize;
pub const OODS_COLLAPSED_CORE_SHARED_QM31: usize = 1024 + 992 + 1024;
pub const OODS_COLLAPSED_AUX_SHARED_QM31: usize = 4;
pub const OODS_COLLAPSED_DYNAMIC_SHARED_BYTES: usize =
    (OODS_COLLAPSED_CORE_SHARED_QM31 + OODS_COLLAPSED_AUX_SHARED_QM31) * SECURE_BYTES;
pub const OODS_CUDA_DEFAULT_DYNAMIC_SHARED_LIMIT_BYTES: usize = 48 * 1024;
const _: () =
    assert!(OODS_COLLAPSED_DYNAMIC_SHARED_BYTES <= OODS_CUDA_DEFAULT_DYNAMIC_SHARED_LIMIT_BYTES);

/// One source/mask pair in the exact descriptor order uploaded by production.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OodsCanonicalSample {
    pub source_kind: OodsSourceKind,
    pub source_log_size: u32,
    pub evaluation_log_size: u32,
    pub column_index: usize,
    pub mask_index: usize,
    pub offset_point: CirclePoint<BaseField>,
    pub output_index: usize,
}

/// Immutable identity sealed by [`OodsPassCollapseProgram`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsPassCollapseIdentity {
    pub config: OodsWorkspaceConfig,
    pub column_ranges: Vec<OodsColumnSampleRange>,
    pub coefficient_groups: Vec<OodsLogGroupRequirements>,
    pub evaluation_groups: Vec<OodsEvaluationGroupRequirements>,
    pub canonical_samples: Vec<OodsCanonicalSample>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsPassCollapseGroupReceipt {
    pub log_size: u32,
    pub offset_point: CirclePoint<BaseField>,
    pub descriptor_offset: usize,
    pub sample_count: usize,
    pub domain_rows: usize,
    pub legacy_weight_kernel_launches: usize,
    pub legacy_weight_logical_bytes: usize,
    pub collapsed_weight_logical_bytes: usize,
    pub logical_bytes_removed: usize,
}

/// Consecutive evaluation-point groups that share one domain log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsPassCollapseCohortReceipt {
    pub log_size: u32,
    pub first_group: usize,
    pub group_count: usize,
    pub sample_count: usize,
    pub domain_rows: usize,
    pub full_cohort_weight_bytes: usize,
    pub full_cohort_fusion_admitted: bool,
    pub max_groups_per_launch: usize,
    pub legacy_weight_kernel_launches: usize,
    pub collapsed_weight_kernel_launches: usize,
    pub logical_bytes_removed: usize,
    pub batches: Vec<OodsPassCollapseBatchReceipt>,
    pub full_cohort_rejection: Option<OodsPassCollapseCohortRejection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsPassCollapseBatchReceipt {
    pub first_group: usize,
    pub group_count: usize,
    pub log_size: u32,
    pub weight_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OodsPassCollapseCohortRejection {
    WorkspaceCapacity {
        required_weight_words: usize,
        available_weight_words: usize,
    },
    CudaGridY {
        group_count: usize,
        limit: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsPassCollapseReceipt {
    pub coefficient_group_count: usize,
    pub evaluation_group_count: usize,
    pub covered_evaluation_group_count: usize,
    pub evaluation_sample_count: usize,
    pub groups: Vec<OodsPassCollapseGroupReceipt>,
    pub same_log_cohorts: Vec<OodsPassCollapseCohortReceipt>,
    pub unchanged_coefficient_kernel_launches: usize,
    pub unchanged_evaluation_kernel_launches: usize,
    pub legacy_weight_kernel_launches: usize,
    pub collapsed_weight_kernel_launches: usize,
    pub kernel_launches_removed: usize,
    pub legacy_total_kernel_launches: usize,
    pub collapsed_total_kernel_launches: usize,
    pub legacy_weight_logical_bytes: usize,
    pub collapsed_weight_logical_bytes: usize,
    pub logical_bytes_removed: usize,
    pub legacy_workspace_bytes: usize,
    pub collapsed_workspace_bytes: usize,
    pub workspace_bytes_removed: usize,
    /// Final weights remain global because every column in the group reuses them.
    pub retained_weight_bytes: usize,
    pub legacy_scale_evaluations: usize,
    pub collapsed_scale_evaluations: usize,
    pub additional_scale_evaluations: usize,
    pub legacy_scale_secure_squares: usize,
    pub collapsed_scale_secure_squares: usize,
    pub large_kernel_dynamic_shared_bytes: usize,
    pub cuda_default_dynamic_shared_limit_bytes: usize,
    pub dynamic_shared_admitted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OodsPassCollapseError {
    Oods(PreparedOodsError),
    NoEvaluationGroups,
    InvalidDescriptorCoverage,
    InsufficientNonExpandingWorkspace,
    ProgramIdentity,
    SizeOverflow,
}

impl core::fmt::Display for OodsPassCollapseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid OODS pass-collapse program: {self:?}")
    }
}

impl std::error::Error for OodsPassCollapseError {}

impl From<PreparedOodsError> for OodsPassCollapseError {
    fn from(value: PreparedOodsError) -> Self {
        Self::Oods(value)
    }
}

/// Compiled, address-free proof that a shape is eligible for weight-pass collapse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodsPassCollapseProgram {
    identity: OodsPassCollapseIdentity,
    ordinary_requirements: OodsWorkspaceRequirements,
    collapsed_requirements: OodsWorkspaceRequirements,
    receipt: OodsPassCollapseReceipt,
}

impl OodsPassCollapseProgram {
    pub fn compile(
        config: OodsWorkspaceConfig,
        columns: &[OodsColumnTopology<'_>],
    ) -> Result<Self, OodsPassCollapseError> {
        let ordinary_requirements = oods_workspace_requirements(config, columns)?;
        if ordinary_requirements.evaluation_groups.is_empty() {
            return Err(OodsPassCollapseError::NoEvaluationGroups);
        }
        let canonical_samples = canonical_sample_order_unchecked(config, columns);
        validate_descriptor_coverage(&ordinary_requirements, &canonical_samples)?;

        let identity = OodsPassCollapseIdentity {
            config,
            column_ranges: ordinary_requirements.column_ranges.clone(),
            coefficient_groups: ordinary_requirements.groups.clone(),
            evaluation_groups: ordinary_requirements.evaluation_groups.clone(),
            canonical_samples,
        };
        let mut collapsed_requirements = ordinary_requirements.clone();
        // Keep a nonempty aligned compatibility slot until the executable arena
        // API deletes the numerator role entirely.
        collapsed_requirements.barycentric_numerator_words = SECURE_WORDS;
        // The retired scale slot becomes an immutable u32 descriptor-offset
        // table for flattened cohort launches.
        collapsed_requirements.barycentric_scale_words = ordinary_requirements
            .evaluation_groups
            .len()
            .max(SECURE_WORDS);
        let schedule = compile_cohort_schedule(
            &ordinary_requirements,
            collapsed_requirements.barycentric_numerator_words,
            collapsed_requirements.barycentric_scale_words,
        )?;
        collapsed_requirements.barycentric_weight_words = schedule.weight_words;
        let receipt = compile_receipt(&ordinary_requirements, &collapsed_requirements, schedule)?;
        Ok(Self {
            identity,
            ordinary_requirements,
            collapsed_requirements,
            receipt,
        })
    }

    pub fn validate_against(
        &self,
        config: OodsWorkspaceConfig,
        columns: &[OodsColumnTopology<'_>],
    ) -> Result<(), OodsPassCollapseError> {
        let candidate = Self::compile(config, columns)?;
        if candidate.identity != self.identity
            || candidate.ordinary_requirements != self.ordinary_requirements
            || candidate.collapsed_requirements != self.collapsed_requirements
            || candidate.receipt != self.receipt
        {
            return Err(OodsPassCollapseError::ProgramIdentity);
        }
        Ok(())
    }

    pub fn identity(&self) -> &OodsPassCollapseIdentity {
        &self.identity
    }

    pub fn ordinary_requirements(&self) -> &OodsWorkspaceRequirements {
        &self.ordinary_requirements
    }

    pub fn collapsed_requirements(&self) -> &OodsWorkspaceRequirements {
        &self.collapsed_requirements
    }

    pub fn receipt(&self) -> &OodsPassCollapseReceipt {
        &self.receipt
    }
}

/// Independent CPU oracle for the production descriptor upload order.
pub fn oods_canonical_sample_order(
    config: OodsWorkspaceConfig,
    columns: &[OodsColumnTopology<'_>],
) -> Result<Vec<OodsCanonicalSample>, PreparedOodsError> {
    oods_workspace_requirements(config, columns)?;
    Ok(canonical_sample_order_unchecked(config, columns))
}

pub(super) fn canonical_sample_order_unchecked(
    config: OodsWorkspaceConfig,
    columns: &[OodsColumnTopology<'_>],
) -> Vec<OodsCanonicalSample> {
    let mask_step = CanonicCoset::new(config.mask_log_size).step();
    let mut samples = Vec::new();
    let mut output_index = 0usize;
    for (column_index, topology) in columns.iter().copied().enumerate() {
        for mask_index in 0..topology.masks.len() {
            samples.push(OodsCanonicalSample {
                source_kind: topology.source_kind,
                source_log_size: topology.log_size,
                evaluation_log_size: topology.evaluation_log_size,
                column_index,
                mask_index,
                offset_point: topology.offset_point(mask_step, mask_index),
                output_index: output_index + mask_index,
            });
        }
        output_index += topology.masks.len();
    }
    samples.sort_unstable_by_key(|sample| match sample.source_kind {
        OodsSourceKind::Coefficients => (0, sample.source_log_size, 0, 0, sample.output_index),
        OodsSourceKind::Evaluations => (
            1,
            sample.source_log_size,
            sample.offset_point.x.0,
            sample.offset_point.y.0,
            sample.output_index,
        ),
    });
    samples
}

fn validate_descriptor_coverage(
    requirements: &OodsWorkspaceRequirements,
    samples: &[OodsCanonicalSample],
) -> Result<(), OodsPassCollapseError> {
    if samples.len() != requirements.sample_count {
        return Err(OodsPassCollapseError::InvalidDescriptorCoverage);
    }
    let mut next = 0usize;
    for group in &requirements.groups {
        if group.descriptor_offset != next
            || samples
                .get(next..next + group.sample_count)
                .ok_or(OodsPassCollapseError::InvalidDescriptorCoverage)?
                .iter()
                .any(|sample| {
                    sample.source_kind != OodsSourceKind::Coefficients
                        || sample.source_log_size != group.log_size
                })
        {
            return Err(OodsPassCollapseError::InvalidDescriptorCoverage);
        }
        next = checked_add(next, group.sample_count)?;
    }
    for group in &requirements.evaluation_groups {
        if group.descriptor_offset != next
            || samples
                .get(next..next + group.sample_count)
                .ok_or(OodsPassCollapseError::InvalidDescriptorCoverage)?
                .iter()
                .any(|sample| {
                    sample.source_kind != OodsSourceKind::Evaluations
                        || sample.source_log_size != group.log_size
                        || sample.offset_point != group.offset_point
                })
        {
            return Err(OodsPassCollapseError::InvalidDescriptorCoverage);
        }
        next = checked_add(next, group.sample_count)?;
    }
    if next != samples.len() {
        return Err(OodsPassCollapseError::InvalidDescriptorCoverage);
    }
    Ok(())
}

fn compile_receipt(
    ordinary: &OodsWorkspaceRequirements,
    collapsed: &OodsWorkspaceRequirements,
    schedule: OodsPassCollapseSchedule,
) -> Result<OodsPassCollapseReceipt, OodsPassCollapseError> {
    let mut groups = Vec::with_capacity(ordinary.evaluation_groups.len());
    for group in &ordinary.evaluation_groups {
        let domain_rows = checked_pow2(group.log_size)?;
        let legacy_weight_logical_bytes = checked_add(
            checked_mul(8, checked_mul(domain_rows, SECURE_BYTES)?)?,
            2 * SECURE_BYTES,
        )?;
        let collapsed_weight_logical_bytes = checked_mul(domain_rows, SECURE_BYTES)?;
        groups.push(OodsPassCollapseGroupReceipt {
            log_size: group.log_size,
            offset_point: group.offset_point,
            descriptor_offset: group.descriptor_offset,
            sample_count: group.sample_count,
            domain_rows,
            legacy_weight_kernel_launches: LEGACY_WEIGHT_KERNELS_PER_GROUP,
            legacy_weight_logical_bytes,
            collapsed_weight_logical_bytes,
            logical_bytes_removed: legacy_weight_logical_bytes
                .checked_sub(collapsed_weight_logical_bytes)
                .ok_or(OodsPassCollapseError::SizeOverflow)?,
        });
    }
    let same_log_cohorts = schedule.cohorts;
    let coefficient_launches = ordinary.groups.iter().try_fold(0usize, |total, group| {
        checked_add(total, coefficient_group_launches(group))
    })?;
    let evaluation_group_count = groups.len();
    let unchanged_evaluation_kernel_launches = checked_mul(
        evaluation_group_count,
        DERIVE_KERNELS_PER_GROUP + EVALUATION_KERNELS_PER_GROUP,
    )?;
    let legacy_weight_kernel_launches =
        checked_mul(evaluation_group_count, LEGACY_WEIGHT_KERNELS_PER_GROUP)?;
    let collapsed_weight_kernel_launches = checked_sum(
        same_log_cohorts
            .iter()
            .map(|cohort| cohort.collapsed_weight_kernel_launches),
    )?;
    let legacy_weight_logical_bytes =
        checked_sum(groups.iter().map(|group| group.legacy_weight_logical_bytes))?;
    let collapsed_weight_logical_bytes = checked_sum(
        groups
            .iter()
            .map(|group| group.collapsed_weight_logical_bytes),
    )?;
    let legacy_workspace_bytes = workspace_bytes(ordinary)?;
    let collapsed_workspace_bytes = workspace_bytes(collapsed)?;
    let retained_weight_bytes = checked_mul(collapsed.barycentric_weight_words, WORD_BYTES)?;
    let legacy_scale_evaluations = evaluation_group_count;
    let collapsed_scale_evaluations = ordinary
        .evaluation_groups
        .iter()
        .try_fold(0usize, |sum, group| {
            checked_add(sum, weight_ctas(group.log_size)?)
        })?;
    let legacy_scale_secure_squares = ordinary
        .evaluation_groups
        .iter()
        .try_fold(0usize, |sum, group| {
            checked_add(sum, group.log_size.saturating_sub(1) as usize)
        })?;
    let collapsed_scale_secure_squares =
        ordinary
            .evaluation_groups
            .iter()
            .try_fold(0usize, |sum, group| {
                checked_add(
                    sum,
                    checked_mul(
                        weight_ctas(group.log_size)?,
                        group.log_size.saturating_sub(1) as usize,
                    )?,
                )
            })?;
    Ok(OodsPassCollapseReceipt {
        coefficient_group_count: ordinary.groups.len(),
        evaluation_group_count,
        covered_evaluation_group_count: evaluation_group_count,
        evaluation_sample_count: ordinary
            .evaluation_groups
            .iter()
            .try_fold(0usize, |total, group| {
                checked_add(total, group.sample_count)
            })?,
        groups,
        same_log_cohorts,
        unchanged_coefficient_kernel_launches: coefficient_launches,
        unchanged_evaluation_kernel_launches,
        legacy_weight_kernel_launches,
        collapsed_weight_kernel_launches,
        kernel_launches_removed: legacy_weight_kernel_launches
            .checked_sub(collapsed_weight_kernel_launches)
            .ok_or(OodsPassCollapseError::SizeOverflow)?,
        legacy_total_kernel_launches: checked_add(
            coefficient_launches,
            checked_add(
                unchanged_evaluation_kernel_launches,
                legacy_weight_kernel_launches,
            )?,
        )?,
        collapsed_total_kernel_launches: checked_add(
            coefficient_launches,
            checked_add(
                unchanged_evaluation_kernel_launches,
                collapsed_weight_kernel_launches,
            )?,
        )?,
        legacy_weight_logical_bytes,
        collapsed_weight_logical_bytes,
        logical_bytes_removed: legacy_weight_logical_bytes
            .checked_sub(collapsed_weight_logical_bytes)
            .ok_or(OodsPassCollapseError::SizeOverflow)?,
        legacy_workspace_bytes,
        collapsed_workspace_bytes,
        workspace_bytes_removed: legacy_workspace_bytes
            .checked_sub(collapsed_workspace_bytes)
            .ok_or(OodsPassCollapseError::SizeOverflow)?,
        retained_weight_bytes,
        legacy_scale_evaluations,
        collapsed_scale_evaluations,
        additional_scale_evaluations: collapsed_scale_evaluations
            .checked_sub(legacy_scale_evaluations)
            .ok_or(OodsPassCollapseError::SizeOverflow)?,
        legacy_scale_secure_squares,
        collapsed_scale_secure_squares,
        large_kernel_dynamic_shared_bytes: OODS_COLLAPSED_DYNAMIC_SHARED_BYTES,
        cuda_default_dynamic_shared_limit_bytes: OODS_CUDA_DEFAULT_DYNAMIC_SHARED_LIMIT_BYTES,
        dynamic_shared_admitted: OODS_COLLAPSED_DYNAMIC_SHARED_BYTES
            <= OODS_CUDA_DEFAULT_DYNAMIC_SHARED_LIMIT_BYTES,
    })
}

fn weight_ctas(log_size: u32) -> Result<usize, OodsPassCollapseError> {
    let rows = checked_pow2(log_size)?;
    Ok(if rows < 1024 {
        rows.div_ceil(256)
    } else {
        rows / 1024
    })
}

struct OodsPassCollapseSchedule {
    cohorts: Vec<OodsPassCollapseCohortReceipt>,
    weight_words: usize,
}

fn compile_cohort_schedule(
    requirements: &OodsWorkspaceRequirements,
    collapsed_numerator_words: usize,
    collapsed_metadata_words: usize,
) -> Result<OodsPassCollapseSchedule, OodsPassCollapseError> {
    let legacy_words = checked_add(
        checked_add(
            requirements.barycentric_numerator_words,
            requirements.barycentric_weight_words,
        )?,
        requirements.barycentric_scale_words,
    )?;
    let fixed_collapsed_words = checked_add(collapsed_numerator_words, collapsed_metadata_words)?;
    let available_weight_words = legacy_words
        .checked_sub(fixed_collapsed_words)
        .ok_or(OodsPassCollapseError::InsufficientNonExpandingWorkspace)?;

    let mut cohorts = Vec::new();
    let mut first_group = 0usize;
    let mut weight_words = SECURE_WORDS;
    while first_group < requirements.evaluation_groups.len() {
        let log_size = requirements.evaluation_groups[first_group].log_size;
        let mut end_group = first_group + 1;
        while end_group < requirements.evaluation_groups.len()
            && requirements.evaluation_groups[end_group].log_size == log_size
        {
            end_group += 1;
        }

        let group_count = end_group - first_group;
        let rows_per_group = checked_pow2(log_size)?;
        let group_weight_words = checked_mul(rows_per_group, SECURE_WORDS)?;
        if group_weight_words > available_weight_words {
            return Err(OodsPassCollapseError::InsufficientNonExpandingWorkspace);
        }
        let max_groups_per_launch = (available_weight_words / group_weight_words)
            .min(CUDA_GRID_Y_LIMIT)
            .max(1);
        let full_weight_words = checked_mul(group_count, group_weight_words)?;
        let full_cohort_fusion_admitted = group_count <= max_groups_per_launch;
        let full_cohort_rejection = if group_count > CUDA_GRID_Y_LIMIT {
            Some(OodsPassCollapseCohortRejection::CudaGridY {
                group_count,
                limit: CUDA_GRID_Y_LIMIT,
            })
        } else if full_weight_words > available_weight_words {
            Some(OodsPassCollapseCohortRejection::WorkspaceCapacity {
                required_weight_words: full_weight_words,
                available_weight_words,
            })
        } else {
            None
        };

        let mut batches = Vec::new();
        let mut batch_first = first_group;
        while batch_first < end_group {
            let batch_group_count = max_groups_per_launch.min(end_group - batch_first);
            let batch_weight_words = checked_mul(batch_group_count, group_weight_words)?;
            weight_words = weight_words.max(batch_weight_words);
            batches.push(OodsPassCollapseBatchReceipt {
                first_group: batch_first,
                group_count: batch_group_count,
                log_size,
                weight_words: batch_weight_words,
            });
            batch_first += batch_group_count;
        }

        let sample_count = requirements.evaluation_groups[first_group..end_group]
            .iter()
            .try_fold(0usize, |sum, group| checked_add(sum, group.sample_count))?;
        let domain_rows = checked_mul(group_count, rows_per_group)?;
        let logical_bytes_removed = checked_add(
            checked_mul(7, checked_mul(domain_rows, SECURE_BYTES)?)?,
            checked_mul(group_count, 2 * SECURE_BYTES)?,
        )?;
        cohorts.push(OodsPassCollapseCohortReceipt {
            log_size,
            first_group,
            group_count,
            sample_count,
            domain_rows,
            full_cohort_weight_bytes: checked_mul(full_weight_words, WORD_BYTES)?,
            full_cohort_fusion_admitted,
            max_groups_per_launch,
            legacy_weight_kernel_launches: checked_mul(
                group_count,
                LEGACY_WEIGHT_KERNELS_PER_GROUP,
            )?,
            collapsed_weight_kernel_launches: batches.len(),
            logical_bytes_removed,
            batches,
            full_cohort_rejection,
        });
        first_group = end_group;
    }

    Ok(OodsPassCollapseSchedule {
        cohorts,
        weight_words,
    })
}

fn coefficient_group_launches(group: &OodsLogGroupRequirements) -> usize {
    let mut reductions = 0usize;
    let mut rows = group.first_pass_blocks;
    while rows > 1 {
        rows = rows.div_ceil(REDUCTION_RADIX);
        reductions += 1;
    }
    DERIVE_KERNELS_PER_GROUP + 1 + reductions + 1
}

fn workspace_bytes(
    requirements: &OodsWorkspaceRequirements,
) -> Result<usize, OodsPassCollapseError> {
    checked_mul(
        checked_add(
            checked_add(
                requirements.barycentric_numerator_words,
                requirements.barycentric_weight_words,
            )?,
            requirements.barycentric_scale_words,
        )?,
        WORD_BYTES,
    )
}

fn checked_pow2(log_size: u32) -> Result<usize, OodsPassCollapseError> {
    1usize
        .checked_shl(log_size)
        .ok_or(OodsPassCollapseError::SizeOverflow)
}

fn checked_add(lhs: usize, rhs: usize) -> Result<usize, OodsPassCollapseError> {
    lhs.checked_add(rhs)
        .ok_or(OodsPassCollapseError::SizeOverflow)
}

fn checked_mul(lhs: usize, rhs: usize) -> Result<usize, OodsPassCollapseError> {
    lhs.checked_mul(rhs)
        .ok_or(OodsPassCollapseError::SizeOverflow)
}

fn checked_sum(values: impl IntoIterator<Item = usize>) -> Result<usize, OodsPassCollapseError> {
    values
        .into_iter()
        .try_fold(0usize, |sum, value| checked_add(sum, value))
}
