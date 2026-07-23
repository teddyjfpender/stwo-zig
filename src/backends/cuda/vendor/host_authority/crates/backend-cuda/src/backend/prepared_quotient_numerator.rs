//! Prepared, arena-native FRI quotient numerator construction.
//!
//! Setup freezes the two distinct reference orders: Fiat-Shamir powers follow
//! tree/column/mask order, while accumulation follows stable evaluation-log
//! order. Replay consumes canonical device OODS points and values, derives the
//! periodicity terms, and writes the exact lifted partial numerators expected
//! by [`super::prepared_quotient::PreparedQuotientGraph`].
//!
//! gpu-lab-cohesion-review: public shape types and one validated preparation
//! constructor remain together; planning, binding, launch, candidates, and
//! tests are split below by durable responsibility.

mod bindings;
mod launch;
mod plan;
mod prepacked;
mod run_sum;
mod single_write;

use core::ffi::c_void;
use std::collections::{BTreeMap, BTreeSet};

use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};
use super::prepared_quotient::{QuotientNumeratorSource, QuotientSampleConstants};
use super::quotient_numerator_prepacked_terms::QuotientNumeratorPrepackedTermError;
use super::quotient_numerator_run_sum::{
    QuotientNumeratorRunSumError, QuotientNumeratorRunSumReceipt,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const SECURE_WORDS: usize = 4;
const SECURE_POINT_WORDS: usize = 8;
const RUNTIME_TERM_WORDS: usize = 5;
const BATCH_TERM_WORDS: usize = 3;
const LINE_COEFFICIENT_WORDS: usize = 3 * SECURE_WORDS;
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);

pub const QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<*mut u32>() / WORD_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorWorkspaceConfig {
    pub lifting_log_size: u32,
    pub log_blowup_factor: u32,
    /// Maximum transient words used to materialize coefficient-form columns.
    pub max_lde_tile_words: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum QuotientNumeratorColumnSource {
    /// Full committed LDE in bit-reversed circle-domain order.
    Evaluation(ArenaSlice),
    /// Circle coefficients. Replay materializes the committed LDE into the tile.
    Coefficients(ArenaSlice),
}

impl QuotientNumeratorColumnSource {
    fn slice(self) -> ArenaSlice {
        match self {
            Self::Evaluation(slice) | Self::Coefficients(slice) => slice,
        }
    }

    fn is_coefficients(self) -> bool {
        matches!(self, Self::Coefficients(_))
    }

    fn kind(self) -> QuotientNumeratorSourceKind {
        if self.is_coefficients() {
            QuotientNumeratorSourceKind::Coefficients
        } else {
            QuotientNumeratorSourceKind::Evaluation
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientNumeratorSourceKind {
    Evaluation,
    Coefficients,
}

/// One canonical OODS entry. `shape_point` is the fixed discovery point used
/// only to identify equal symbolic points and reproduce the planned stable
/// `(x, y)` group order; replay reads the actual point from `input_index`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientOodsSample {
    pub input_index: u32,
    pub shape_point: CirclePoint<SecureField>,
}

/// Columns must be supplied in the exact flattened PCS tree/column order.
#[derive(Clone, Debug)]
pub struct QuotientNumeratorColumn {
    pub coefficient_log_size: u32,
    pub source: QuotientNumeratorColumnSource,
    pub samples: Vec<QuotientOodsSample>,
}

/// Address-free topology used by the proof arena planner before device slots
/// exist. [`PreparedQuotientNumeratorGraph::prepare`] validates that the bound
/// sources have this exact shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorColumnTopology {
    pub coefficient_log_size: u32,
    pub source_kind: QuotientNumeratorSourceKind,
    pub samples: Vec<QuotientOodsSample>,
}

impl From<&QuotientNumeratorColumn> for QuotientNumeratorColumnTopology {
    fn from(column: &QuotientNumeratorColumn) -> Self {
        Self {
            coefficient_log_size: column.coefficient_log_size,
            source_kind: column.source.kind(),
            samples: column.samples.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct QuotientNumeratorDestination {
    pub log_size: u32,
    pub coordinates: [ArenaSlice; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorGroupRequirements {
    pub shape_point: CirclePoint<SecureField>,
    pub log_size: u32,
    pub value_words: usize,
    /// Distinct sampled coefficient columns contributing to this output.
    /// Zero means the group can consume retained evaluations exclusively.
    pub coefficient_source_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorBatchRequirements {
    pub evaluation_log_size: u32,
    pub source_count: usize,
    pub coefficient_count: usize,
    pub term_count: usize,
    pub lde_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorWorkspaceRequirements {
    pub config: QuotientNumeratorWorkspaceConfig,
    pub input_sample_count: usize,
    pub term_count: usize,
    pub groups: Vec<QuotientNumeratorGroupRequirements>,
    pub batches: Vec<QuotientNumeratorBatchRequirements>,
    pub runtime_term_words: usize,
    pub group_term_index_words: usize,
    pub group_offset_words: usize,
    pub line_coefficient_words: usize,
    pub term_point_words: usize,
    pub batch_term_words: usize,
    pub batch_group_offset_words: usize,
    pub batch_source_pointer_words: usize,
    pub coefficient_pointer_words: usize,
    pub coefficient_size_words: usize,
    pub coefficient_output_pointer_words: usize,
    pub output_pointer_words: usize,
    pub output_log_size_words: usize,
    pub lde_tile_words: usize,
    pub forward_twiddle_words: usize,
    pub max_output_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorWorkspaceSlots {
    pub runtime_terms: ArenaSlotId,
    pub group_term_indices: ArenaSlotId,
    pub group_offsets: ArenaSlotId,
    pub line_coefficients: ArenaSlotId,
    pub term_points: ArenaSlotId,
    pub batch_terms: ArenaSlotId,
    pub batch_group_offsets: ArenaSlotId,
    pub batch_source_ptrs: ArenaSlotId,
    pub output_ptrs: ArenaSlotId,
    pub output_log_sizes: ArenaSlotId,
    pub coefficient_ptrs: Option<ArenaSlotId>,
    pub coefficient_sizes: Option<ArenaSlotId>,
    pub coefficient_output_ptrs: Option<ArenaSlotId>,
    pub lde_tile: Option<ArenaSlotId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedQuotientNumeratorError {
    InvalidLiftingLogSize(u32),
    InvalidBlowup {
        lifting_log_size: u32,
        log_blowup_factor: u32,
    },
    EmptyTerms,
    TooManyTerms(usize),
    TooManyGroups(usize),
    ColumnLogTooLarge {
        column: usize,
        log_size: u32,
        maximum: u32,
    },
    TileTooSmall {
        column: usize,
        required_words: usize,
        available_words: usize,
    },
    DestinationCountMismatch {
        expected: usize,
        actual: usize,
    },
    DestinationLogMismatch {
        group: usize,
        expected: u32,
        actual: u32,
    },
    OptionalSlotShapeMismatch,
    DuplicateSlot(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    AliasedExternalSlot(ArenaSlotId),
    ExternalAliasesWorkspace(ArenaSlotId),
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedSlot {
        slot: ArenaSlotId,
        alignment_words: usize,
    },
    InputTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    SourceTooSmall {
        column: usize,
        required_words: usize,
        actual_words: usize,
    },
    ForwardTwiddlesTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    PrepackedLayout(QuotientNumeratorPrepackedTermError),
    PrepackedScheduleInvariant(&'static str),
    GroupDirectScheduleInvariant(&'static str),
    RunSumScheduleInvariant(&'static str),
    RunSumPlan(QuotientNumeratorRunSumError),
    PrepackedDeviceStatus(u32),
    SizeOverflow,
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedQuotientNumeratorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "invalid prepared CUDA quotient numerator workspace: {self:?}"
        )
    }
}

impl std::error::Error for PreparedQuotientNumeratorError {}

impl From<ArenaError> for PreparedQuotientNumeratorError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedQuotientNumeratorError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl From<QuotientNumeratorPrepackedTermError> for PreparedQuotientNumeratorError {
    fn from(value: QuotientNumeratorPrepackedTermError) -> Self {
        Self::PrepackedLayout(value)
    }
}

impl From<QuotientNumeratorRunSumError> for PreparedQuotientNumeratorError {
    fn from(value: QuotientNumeratorRunSumError) -> Self {
        Self::RunSumPlan(value)
    }
}

pub(super) use plan::build_plan;
pub use plan::quotient_numerator_workspace_requirements;
#[cfg(test)]
pub(super) use plan::NumeratorPlan;

struct PreparedBatch {
    evaluation_log_size: u32,
    source_ptr_offset: usize,
    coefficient_offset: usize,
    coefficient_count: usize,
    term_offset: usize,
    group_offset: usize,
}

#[derive(Clone, Copy)]
struct PreparedGroupDirectRange {
    term_begin: u32,
    term_end: u32,
    group_b_term: u32,
}

/// Exact quotient-numerator launch schedule sealed by the prepared constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedNumeratorSchedule {
    LegacyBatches,
    SingleWriteCandidate,
    StagedPackedSingleWrite {
        packed_output_rows: u64,
    },
    StagedGroupDirect {
        output_rows: u64,
    },
    #[doc(hidden)]
    StagedPrepackedSingleWrite {
        packed_output_rows: u64,
    },
    HybridCandidate {
        eligible_groups: usize,
        legacy_groups: usize,
    },
}

/// Setup receipt for the dormant prepacked quotient schedule.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedPrepackedQuotientNumeratorReceipt {
    pub plan_identity: [u8; 32],
    pub source_count: u32,
    pub used_words: u64,
    pub status_offset_words: usize,
}

use self::bindings::{
    bind_optional, bind_slot, checked_mul, pow2, require_words, upload_and_sync, upload_ptrs,
    upload_u32, upload_u64,
};
use self::run_sum::PreparedRunSumBinding;

/// Stable quotient numerator launch object. [`Self::launch`] performs no host
/// transfer, allocation, synchronization, or default-stream operation.
pub struct PreparedQuotientNumeratorGraph<'a> {
    arena: &'a DeviceArena,
    requirements: QuotientNumeratorWorkspaceRequirements,
    destinations: Vec<QuotientNumeratorDestination>,
    oods_sample_points: ArenaSlice,
    oods_sample_values: ArenaSlice,
    random_coefficient: ArenaSlice,
    sample_points_destination: ArenaSlice,
    first_linear_terms_destination: ArenaSlice,
    forward_twiddles: ArenaSlice,
    runtime_terms: ArenaSlice,
    group_term_indices: ArenaSlice,
    group_offsets: ArenaSlice,
    line_coefficients: ArenaSlice,
    term_points: ArenaSlice,
    batch_terms: ArenaSlice,
    batch_group_offsets: ArenaSlice,
    batch_source_ptrs: ArenaSlice,
    output_ptrs: ArenaSlice,
    output_log_sizes: ArenaSlice,
    coefficient_ptrs: Option<ArenaSlice>,
    coefficient_sizes: Option<ArenaSlice>,
    coefficient_output_ptrs: Option<ArenaSlice>,
    lde_tile: Option<ArenaSlice>,
    batches: Vec<PreparedBatch>,
    schedule: PreparedNumeratorSchedule,
    group_direct_ranges: Option<Vec<PreparedGroupDirectRange>>,
    group_direct_run_sum: Option<PreparedRunSumBinding>,
    prepacked: Option<PreparedPrepackedBinding>,
}

#[derive(Clone, Copy)]
struct PreparedPrepackedBinding {
    receipt: PreparedPrepackedQuotientNumeratorReceipt,
}

impl<'a> PreparedQuotientNumeratorGraph<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        arena: &'a DeviceArena,
        config: QuotientNumeratorWorkspaceConfig,
        columns: &[QuotientNumeratorColumn],
        oods_sample_points: ArenaSlice,
        oods_sample_values: ArenaSlice,
        random_coefficient: ArenaSlice,
        sample_points_destination: ArenaSlice,
        first_linear_terms_destination: ArenaSlice,
        destinations: &[QuotientNumeratorDestination],
        forward_twiddles: ArenaSlice,
        slots: &QuotientNumeratorWorkspaceSlots,
    ) -> Result<Self, PreparedQuotientNumeratorError> {
        let topology = columns
            .iter()
            .map(QuotientNumeratorColumnTopology::from)
            .collect::<Vec<_>>();
        let plan = build_plan(config, &topology)?;
        let requirements = &plan.requirements;
        if destinations.len() != requirements.groups.len() {
            return Err(PreparedQuotientNumeratorError::DestinationCountMismatch {
                expected: requirements.groups.len(),
                actual: destinations.len(),
            });
        }
        for (group, (destination, requirement)) in
            destinations.iter().zip(&requirements.groups).enumerate()
        {
            if destination.log_size != requirement.log_size {
                return Err(PreparedQuotientNumeratorError::DestinationLogMismatch {
                    group,
                    expected: requirement.log_size,
                    actual: destination.log_size,
                });
            }
        }

        let slot_requirements = requirements.arena_slot_requirements(slots)?;
        let workspace_ids: BTreeSet<_> = slot_requirements
            .iter()
            .map(|requirement| requirement.id)
            .collect();
        let context_token = arena.context().identity_token();
        let mut external_ids = BTreeSet::new();
        let external = [
            oods_sample_points,
            oods_sample_values,
            random_coefficient,
            sample_points_destination,
            first_linear_terms_destination,
            forward_twiddles,
        ]
        .into_iter()
        .chain(columns.iter().map(|column| column.source.slice()))
        .chain(
            destinations
                .iter()
                .flat_map(|destination| destination.coordinates),
        );
        for slice in external {
            if slice.context_token() != context_token {
                return Err(PreparedQuotientNumeratorError::ContextMismatch(slice.id()));
            }
            if workspace_ids.contains(&slice.id()) {
                return Err(PreparedQuotientNumeratorError::ExternalAliasesWorkspace(
                    slice.id(),
                ));
            }
            if !external_ids.insert(slice.id()) {
                return Err(PreparedQuotientNumeratorError::AliasedExternalSlot(
                    slice.id(),
                ));
            }
        }

        require_words(
            oods_sample_points,
            checked_mul(requirements.input_sample_count, SECURE_POINT_WORDS)?,
        )?;
        require_words(
            oods_sample_values,
            checked_mul(requirements.input_sample_count, SECURE_WORDS)?,
        )?;
        require_words(random_coefficient, SECURE_WORDS)?;
        require_words(
            sample_points_destination,
            checked_mul(requirements.groups.len(), SECURE_POINT_WORDS)?,
        )?;
        require_words(
            first_linear_terms_destination,
            checked_mul(requirements.groups.len(), SECURE_WORDS)?,
        )?;
        if forward_twiddles.len_words() < requirements.forward_twiddle_words {
            return Err(PreparedQuotientNumeratorError::ForwardTwiddlesTooSmall {
                required_words: requirements.forward_twiddle_words,
                actual_words: forward_twiddles.len_words(),
            });
        }
        for (column_index, column) in columns.iter().enumerate() {
            let required = match column.source {
                QuotientNumeratorColumnSource::Evaluation(_) => {
                    pow2(column.coefficient_log_size + config.log_blowup_factor)?
                }
                QuotientNumeratorColumnSource::Coefficients(_) => {
                    pow2(column.coefficient_log_size)?
                }
            };
            if column.source.slice().len_words() < required {
                return Err(PreparedQuotientNumeratorError::SourceTooSmall {
                    column: column_index,
                    required_words: required,
                    actual_words: column.source.slice().len_words(),
                });
            }
        }
        for (destination, group) in destinations.iter().zip(&requirements.groups) {
            for coordinate in destination.coordinates {
                if coordinate.len_words() < group.value_words {
                    return Err(PreparedQuotientNumeratorError::InputTooSmall {
                        slot: coordinate.id(),
                        required_words: group.value_words,
                        actual_words: coordinate.len_words(),
                    });
                }
            }
        }

        let runtime_terms = bind_slot(
            arena,
            slots.runtime_terms,
            requirements.runtime_term_words,
            1,
        )?;
        let group_term_indices = bind_slot(
            arena,
            slots.group_term_indices,
            requirements.group_term_index_words,
            1,
        )?;
        let group_offsets = bind_slot(
            arena,
            slots.group_offsets,
            requirements.group_offset_words,
            1,
        )?;
        let line_coefficients = bind_slot(
            arena,
            slots.line_coefficients,
            requirements.line_coefficient_words,
            1,
        )?;
        let term_points = bind_slot(arena, slots.term_points, requirements.term_point_words, 1)?;
        let batch_terms = bind_slot(arena, slots.batch_terms, requirements.batch_term_words, 1)?;
        let batch_group_offsets = bind_slot(
            arena,
            slots.batch_group_offsets,
            requirements.batch_group_offset_words,
            2,
        )?;
        let batch_source_ptrs = bind_slot(
            arena,
            slots.batch_source_ptrs,
            requirements.batch_source_pointer_words,
            QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
        )?;
        let output_ptrs = bind_slot(
            arena,
            slots.output_ptrs,
            requirements.output_pointer_words,
            QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
        )?;
        let output_log_sizes = bind_slot(
            arena,
            slots.output_log_sizes,
            requirements.output_log_size_words,
            1,
        )?;
        let coefficient_ptrs = bind_optional(
            arena,
            slots.coefficient_ptrs,
            requirements.coefficient_pointer_words,
            QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
        )?;
        let coefficient_sizes = bind_optional(
            arena,
            slots.coefficient_sizes,
            requirements.coefficient_size_words,
            1,
        )?;
        let coefficient_output_ptrs = bind_optional(
            arena,
            slots.coefficient_output_ptrs,
            requirements.coefficient_output_pointer_words,
            QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
        )?;
        let lde_tile = bind_optional(arena, slots.lde_tile, requirements.lde_tile_words, 1)?;

        let runtime_words = plan
            .terms
            .iter()
            .flat_map(|term| {
                let period = term.period.unwrap_or(CirclePoint {
                    x: BaseField::from(0),
                    y: BaseField::from(0),
                });
                [
                    term.sample_index,
                    term.exponent,
                    u32::from(term.period.is_some()),
                    period.x.0,
                    period.y.0,
                ]
            })
            .collect::<Vec<_>>();
        let batch_term_words = plan
            .batches
            .iter()
            .flat_map(|batch| batch.terms.iter().copied())
            .collect::<Vec<_>>();
        let batch_group_words = plan
            .batches
            .iter()
            .flat_map(|batch| batch.group_offsets.iter().copied())
            .collect::<Vec<_>>();
        let output_pointers = (0..4)
            .flat_map(|coordinate| {
                destinations.iter().map(move |destination| {
                    destination.coordinates[coordinate].as_u32_ptr() as usize
                })
            })
            .collect::<Vec<_>>();

        let mut source_pointers = Vec::new();
        let mut coefficient_pointers = Vec::new();
        let mut coefficient_size_values = Vec::new();
        let mut coefficient_output_pointers = Vec::new();
        let mut prepared_batches = Vec::with_capacity(plan.batches.len());
        let mut term_offset = 0usize;
        let mut group_offset = 0usize;
        for batch in &plan.batches {
            let source_ptr_offset = source_pointers.len();
            let coefficient_offset = coefficient_pointers.len();
            let eval_words = pow2(batch.evaluation_log_size)?;
            let coefficient_local: BTreeMap<_, _> = batch
                .coefficient_columns
                .iter()
                .copied()
                .enumerate()
                .map(|(local, column)| (column, local))
                .collect();
            for &column in &batch.columns {
                let pointer = match columns[column].source {
                    QuotientNumeratorColumnSource::Evaluation(slice) => slice.as_u32_ptr(),
                    QuotientNumeratorColumnSource::Coefficients(_) => unsafe {
                        lde_tile
                            .expect("coefficient slot shape validated")
                            .as_u32_ptr()
                            .add(coefficient_local[&column] * eval_words)
                    },
                };
                source_pointers.push(pointer as usize);
            }
            for (local, &column) in batch.coefficient_columns.iter().enumerate() {
                coefficient_pointers.push(columns[column].source.slice().as_u32_ptr() as usize);
                coefficient_size_values.push(
                    u32::try_from(pow2(columns[column].coefficient_log_size)?)
                        .map_err(|_| PreparedQuotientNumeratorError::SizeOverflow)?,
                );
                coefficient_output_pointers.push(unsafe {
                    lde_tile
                        .expect("coefficient slot shape validated")
                        .as_u32_ptr()
                        .add(local * eval_words) as usize
                });
            }
            prepared_batches.push(PreparedBatch {
                evaluation_log_size: batch.evaluation_log_size,
                source_ptr_offset,
                coefficient_offset,
                coefficient_count: batch.coefficient_columns.len(),
                term_offset,
                group_offset,
            });
            term_offset += batch.terms.len() / BATCH_TERM_WORDS;
            group_offset += batch.group_offsets.len();
        }

        let mut uploads = vec![
            upload_u32(runtime_terms, runtime_words),
            upload_u32(group_term_indices, plan.group_term_indices),
            upload_u32(group_offsets, plan.group_offsets),
            upload_u32(batch_terms, batch_term_words),
            upload_u32(batch_group_offsets, batch_group_words),
            upload_ptrs(batch_source_ptrs, source_pointers),
            upload_ptrs(output_ptrs, output_pointers),
            upload_u32(
                output_log_sizes,
                requirements
                    .groups
                    .iter()
                    .map(|group| group.log_size)
                    .collect(),
            ),
        ];
        if let (Some(ptrs), Some(sizes), Some(outputs)) =
            (coefficient_ptrs, coefficient_sizes, coefficient_output_ptrs)
        {
            uploads.extend([
                upload_ptrs(ptrs, coefficient_pointers),
                upload_u32(sizes, coefficient_size_values),
                upload_ptrs(outputs, coefficient_output_pointers),
            ]);
        }
        upload_and_sync(arena, &uploads)?;

        Ok(Self {
            arena,
            requirements: plan.requirements,
            destinations: destinations.to_vec(),
            oods_sample_points,
            oods_sample_values,
            random_coefficient,
            sample_points_destination,
            first_linear_terms_destination,
            forward_twiddles,
            runtime_terms,
            group_term_indices,
            group_offsets,
            line_coefficients,
            term_points,
            batch_terms,
            batch_group_offsets,
            batch_source_ptrs,
            output_ptrs,
            output_log_sizes,
            coefficient_ptrs,
            coefficient_sizes,
            coefficient_output_ptrs,
            lde_tile,
            batches: prepared_batches,
            schedule: PreparedNumeratorSchedule::LegacyBatches,
            group_direct_ranges: None,
            group_direct_run_sum: None,
            prepacked: None,
        })
    }

    pub fn requirements(&self) -> &QuotientNumeratorWorkspaceRequirements {
        &self.requirements
    }

    pub fn destinations(&self) -> &[QuotientNumeratorDestination] {
        &self.destinations
    }

    /// Actual schedule selected by the constructor; launch cannot change it.
    pub fn schedule(&self) -> PreparedNumeratorSchedule {
        self.schedule
    }

    /// Exact staged-plan identity and dead-extent binding, if the test-only
    /// prepacked schedule was selected.
    #[doc(hidden)]
    pub fn prepacked_receipt(&self) -> Option<PreparedPrepackedQuotientNumeratorReceipt> {
        self.prepacked.map(|binding| binding.receipt)
    }

    /// Sealed setup proof for the dormant native-domain run-sum candidate.
    #[doc(hidden)]
    pub fn group_direct_run_sum_receipt(&self) -> Option<&QuotientNumeratorRunSumReceipt> {
        self.group_direct_run_sum
            .as_ref()
            .map(|binding| &binding.receipt)
    }

    /// Setup-only adapter for [`super::prepared_quotient::PreparedQuotientGraph::prepare`].
    pub fn quotient_sources(&self) -> Vec<QuotientNumeratorSource> {
        self.requirements
            .groups
            .iter()
            .zip(&self.destinations)
            .map(|(group, destination)| QuotientNumeratorSource {
                constants: QuotientSampleConstants {
                    sample_point: group.shape_point,
                    first_linear_term_acc: SecureField::from(0u32),
                },
                log_size: group.log_size,
                coordinates: destination.coordinates,
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "prepared_quotient_numerator_tests.rs"]
mod tests;
