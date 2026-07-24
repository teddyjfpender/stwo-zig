//! Dormant coefficient-inclusive single-write quotient-numerator plan.
//!
//! Setup gives each sampled coefficient column one persistent LDE range, then
//! flattens the legacy batches into one group-major descriptor stream. Nothing
//! here owns device addresses or changes the production schedule.
//!
//! The host oracle treats each coefficient LDE as an already materialized
//! canonical image. Coefficient-to-LDE arithmetic and bit-reversed domain order
//! remain an independent native-CUDA differential gate before activation.

use std::collections::{BTreeMap, BTreeSet};

use super::prepared_quotient_numerator::{
    build_plan, PreparedQuotientNumeratorError, QuotientNumeratorColumnTopology,
    QuotientNumeratorSourceKind, QuotientNumeratorWorkspaceConfig,
    QuotientNumeratorWorkspaceRequirements,
};

const TERM_WORDS: usize = 3;
const SECURE_BYTES: u64 = 16;
const FACTOR32_TILE_COLUMNS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorStagedLde {
    column: usize,
    evaluation_log_size: u32,
    staging_role: QuotientNumeratorStagingRole,
    role_offset_words: usize,
    offset_words: usize,
    len_words: usize,
}

impl QuotientNumeratorStagedLde {
    pub fn column(self) -> usize {
        self.column
    }

    pub fn evaluation_log_size(self) -> u32 {
        self.evaluation_log_size
    }

    pub fn staging_role(self) -> QuotientNumeratorStagingRole {
        self.staging_role
    }

    /// Offset inside [`Self::staging_role`]. Native preparation binds the
    /// primary and overflow roles independently; no LDE may cross a role.
    pub fn role_offset_words(self) -> usize {
        self.role_offset_words
    }

    pub fn role_end_words(self) -> usize {
        self.role_offset_words
            .checked_add(self.len_words)
            .expect("private construction validates the staged role end")
    }

    pub fn offset_words(self) -> usize {
        self.offset_words
    }

    pub fn len_words(self) -> usize {
        self.len_words
    }

    pub fn end_words(self) -> usize {
        self.offset_words
            .checked_add(self.len_words)
            .expect("private construction validates the staged LDE end")
    }
}

/// Physical ownership of a staged coefficient LDE.
///
/// `Primary` reuses the factor-32 quotient tile. `Overflow` is live only in
/// the quotient epoch and must alias an epoch-disjoint released commitment
/// slab; it is never an independently allocated third slab.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum QuotientNumeratorStagingRole {
    Primary,
    Overflow(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorStagedLdeLaunch {
    evaluation_log_size: u32,
    first_lde: usize,
    lde_count: usize,
}

impl QuotientNumeratorStagedLdeLaunch {
    pub fn evaluation_log_size(self) -> u32 {
        self.evaluation_log_size
    }

    pub fn first_lde(self) -> usize {
        self.first_lde
    }

    pub fn lde_count(self) -> usize {
        self.lde_count
    }
}

/// Exact prepared-call order. Every LDE sublaunch precedes the sole
/// group-major numerator accumulation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientNumeratorStagedOperation {
    MaterializeLdes(QuotientNumeratorStagedLdeLaunch),
    AccumulatePackedRows {
        group_count: usize,
        term_count: usize,
        packed_output_rows: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientNumeratorStagedSource {
    Evaluation {
        column: usize,
        evaluation_log_size: u32,
    },
    StagedCoefficient(QuotientNumeratorStagedLde),
}

impl QuotientNumeratorStagedSource {
    pub fn column(self) -> usize {
        match self {
            Self::Evaluation { column, .. } => column,
            Self::StagedCoefficient(lde) => lde.column,
        }
    }

    pub fn evaluation_log_size(self) -> u32 {
        match self {
            Self::Evaluation {
                evaluation_log_size,
                ..
            } => evaluation_log_size,
            Self::StagedCoefficient(lde) => lde.evaluation_log_size(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorStagedSingleWriteReport {
    pub group_count: usize,
    pub term_count: usize,
    pub source_count: usize,
    pub coefficient_source_count: usize,
    /// Exact baseline compiled from the supplied config. The resident caller
    /// supplies its sealed factor-32 `max_lde_tile_words` value.
    pub factor32_batch_count: usize,
    /// Factor-32 read/modify/write passes over coefficient-backed groups. The
    /// current kernel launches every batch, including batches with no term for
    /// a particular coefficient-backed group, and still writes that group.
    pub factor32_accumulation_passes: usize,
    /// Factor-32 zero/single-write initialization plus accumulation passes.
    pub factor32_total_output_passes: usize,
    pub candidate_output_passes: usize,
    pub output_rows: usize,
    pub coefficient_output_rows: usize,
    pub factor32_logical_output_bytes: u64,
    pub candidate_logical_output_bytes: u64,
    pub logical_output_bytes_saved: u64,
    /// Rows launched by the rectangular `(max_rows, groups)` single-write
    /// kernel. Inactive rows return before the canonical term loop.
    pub rectangular_launch_rows: u64,
    pub inactive_rectangular_launch_rows: u64,
    /// Exact descriptor-loop iterations performed by useful output rows.
    pub useful_row_terms: u64,
    /// Hypothetical term capacity of the rectangular grid. This is an upper
    /// bound for shape comparison, not a claim that early-return rows execute
    /// the term loop.
    pub rectangular_row_term_capacity: u64,
    /// Worst-case comparisons in the packed row-to-group binary search.
    pub packed_binary_search_comparisons_per_row_max: u32,
    pub packed_binary_search_comparisons_max: u64,
    /// Persistent words holding every sampled coefficient column's full LDE.
    pub total_staging_words: usize,
    /// Peak transient factor-32 tile already required by the legacy plan.
    pub factor32_staging_words: usize,
    /// Words actually occupied inside the existing factor-32 tile role.
    pub primary_staging_words: usize,
    /// Unused tail of the existing factor-32 tile. It cannot be added to the
    /// overflow capacity because no individual LDE may straddle roles.
    pub unused_factor32_staging_words: usize,
    /// Exact second-role size after assigning whole LDEs. This is the amount
    /// that must fit an epoch-disjoint released commitment slab.
    pub overflow_staging_words: usize,
    /// Number of separately owned overflow roles. Each staged LDE belongs to
    /// exactly one role and can never straddle two released commitment slabs.
    pub overflow_staging_role_count: usize,
    pub max_overflow_staging_role_words: usize,
    /// Arithmetic footprint delta; it may be smaller than `overflow` because
    /// the primary role can retain an unusable tail smaller than the next LDE.
    pub incremental_staging_words_over_factor32: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorStagedSingleWritePlan {
    requirements: QuotientNumeratorWorkspaceRequirements,
    coefficient_ldes: Vec<QuotientNumeratorStagedLde>,
    operations: Vec<QuotientNumeratorStagedOperation>,
    sources: Vec<QuotientNumeratorStagedSource>,
    group_offsets: Vec<u32>,
    packed_group_row_offsets: Vec<u64>,
    term_descriptors: Vec<u32>,
    report: QuotientNumeratorStagedSingleWriteReport,
}

impl QuotientNumeratorStagedSingleWritePlan {
    pub fn requirements(&self) -> &QuotientNumeratorWorkspaceRequirements {
        &self.requirements
    }

    /// LDE launches execute in this order into disjoint cumulative ranges.
    pub fn coefficient_ldes(&self) -> &[QuotientNumeratorStagedLde] {
        &self.coefficient_ldes
    }

    pub fn operations(&self) -> &[QuotientNumeratorStagedOperation] {
        &self.operations
    }

    /// Exact legacy batch/source order with coefficient addresses replaced by
    /// their persistent staged ranges.
    pub fn sources(&self) -> &[QuotientNumeratorStagedSource] {
        &self.sources
    }

    pub fn group_offsets(&self) -> &[u32] {
        &self.group_offsets
    }

    /// Prefix sum of exact output rows. Packed row `r` belongs to the unique
    /// group `g` satisfying `offsets[g] <= r < offsets[g + 1]`.
    pub fn packed_group_row_offsets(&self) -> &[u64] {
        &self.packed_group_row_offsets
    }

    pub fn packed_output_rows(&self) -> u64 {
        *self
            .packed_group_row_offsets
            .last()
            .expect("private construction always emits the terminal row offset")
    }

    /// Host oracle for the native packed-grid mapping. Its branch structure is
    /// intentionally identical to the CUDA kernel's binary search.
    pub fn packed_row_location(&self, packed_row: u64) -> Option<(usize, u64)> {
        packed_row_location(&self.packed_group_row_offsets, packed_row)
    }

    /// Group-major `[source, term, source_log_size]`. Inside each group the
    /// stream is the exact concatenation of legacy batches and in-batch terms.
    pub fn term_descriptors(&self) -> &[u32] {
        &self.term_descriptors
    }

    pub fn report(&self) -> QuotientNumeratorStagedSingleWriteReport {
        self.report
    }

    /// Exact used extent of each dense overflow role, in role-index order.
    pub fn overflow_role_words(&self) -> Vec<usize> {
        let mut roles = vec![0; self.report.overflow_staging_role_count];
        for lde in &self.coefficient_ldes {
            if let QuotientNumeratorStagingRole::Overflow(role) = lde.staging_role() {
                roles[usize::from(role)] = roles[usize::from(role)].max(lde.role_end_words());
            }
        }
        roles
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotientNumeratorStagedSingleWriteError {
    Base(PreparedQuotientNumeratorError),
    DuplicateSourceColumn(usize),
    DuplicateCoefficientColumn(usize),
    Factor32ConfigMismatch {
        expected_words: usize,
        actual_words: usize,
    },
    Factor32TileOverflow,
    InsufficientOverflowCapacity {
        column: usize,
        required_words: usize,
    },
    OverflowCapacitiesNotDescending,
    OverflowBindingCountMismatch {
        expected: usize,
        actual: usize,
    },
    StagingSizeOverflow {
        column: usize,
        evaluation_log_size: u32,
    },
    DescriptorInvariant(&'static str),
}

impl core::fmt::Display for QuotientNumeratorStagedSingleWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "invalid staged single-write quotient numerator: {self:?}"
        )
    }
}

impl std::error::Error for QuotientNumeratorStagedSingleWriteError {}

impl From<PreparedQuotientNumeratorError> for QuotientNumeratorStagedSingleWriteError {
    fn from(value: PreparedQuotientNumeratorError) -> Self {
        Self::Base(value)
    }
}

pub fn quotient_numerator_staged_single_write_plan(
    config: QuotientNumeratorWorkspaceConfig,
    columns: &[QuotientNumeratorColumnTopology],
) -> Result<QuotientNumeratorStagedSingleWritePlan, QuotientNumeratorStagedSingleWriteError> {
    quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        columns,
        &[usize::MAX],
    )
}

/// Compile the same immutable manifest while constraining every overflow LDE
/// to one named physical-role capacity supplied by the resident arena planner.
pub fn quotient_numerator_staged_single_write_plan_with_overflow_capacities(
    config: QuotientNumeratorWorkspaceConfig,
    columns: &[QuotientNumeratorColumnTopology],
    overflow_capacities_words: &[usize],
) -> Result<QuotientNumeratorStagedSingleWritePlan, QuotientNumeratorStagedSingleWriteError> {
    if overflow_capacities_words
        .windows(2)
        .any(|pair| pair[0] < pair[1])
    {
        return Err(QuotientNumeratorStagedSingleWriteError::OverflowCapacitiesNotDescending);
    }
    let legacy = build_plan(config, columns)?;
    let factor32_words = 1usize
        .checked_shl(config.lifting_log_size)
        .and_then(|words| words.checked_mul(FACTOR32_TILE_COLUMNS))
        .ok_or(QuotientNumeratorStagedSingleWriteError::Factor32TileOverflow)?;
    if config.max_lde_tile_words != factor32_words {
        return Err(
            QuotientNumeratorStagedSingleWriteError::Factor32ConfigMismatch {
                expected_words: factor32_words,
                actual_words: config.max_lde_tile_words,
            },
        );
    }
    let coefficient_entries = legacy.batches.iter().flat_map(|batch| {
        batch
            .coefficient_columns
            .iter()
            .map(|&column| (column, batch.evaluation_log_size))
    });
    let coefficient_ldes = coefficient_staging_layout(
        coefficient_entries,
        legacy.requirements.lde_tile_words,
        overflow_capacities_words,
    )?;
    let mut operations = Vec::new();
    let mut first_lde = 0usize;
    for batch in &legacy.batches {
        if batch.coefficient_columns.is_empty() {
            continue;
        }
        let count = batch.coefficient_columns.len();
        operations.push(QuotientNumeratorStagedOperation::MaterializeLdes(
            QuotientNumeratorStagedLdeLaunch {
                evaluation_log_size: batch.evaluation_log_size,
                first_lde,
                lde_count: count,
            },
        ));
        first_lde = first_lde.checked_add(count).ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "LDE launch range overflowed",
            ),
        )?;
    }
    if first_lde != coefficient_ldes.len() {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "LDE launch manifest lost or duplicated a staged column",
            ),
        );
    }
    let staged_by_column = coefficient_ldes
        .iter()
        .map(|lde| (lde.column(), *lde))
        .collect::<BTreeMap<_, _>>();

    let mut sources = Vec::new();
    let mut batch_source_bases = Vec::with_capacity(legacy.batches.len());
    let mut seen_sources = BTreeSet::new();
    for batch in &legacy.batches {
        batch_source_bases.push(sources.len());
        for &column in &batch.columns {
            if !seen_sources.insert(column) {
                return Err(QuotientNumeratorStagedSingleWriteError::DuplicateSourceColumn(column));
            }
            let evaluation_log_size = columns[column]
                .coefficient_log_size
                .checked_add(config.log_blowup_factor)
                .ok_or(
                    QuotientNumeratorStagedSingleWriteError::StagingSizeOverflow {
                        column,
                        evaluation_log_size: columns[column].coefficient_log_size,
                    },
                )?;
            let source = match columns[column].source_kind {
                QuotientNumeratorSourceKind::Evaluation => {
                    QuotientNumeratorStagedSource::Evaluation {
                        column,
                        evaluation_log_size,
                    }
                }
                QuotientNumeratorSourceKind::Coefficients => {
                    let lde = *staged_by_column.get(&column).ok_or(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "sampled coefficient column has no staged LDE",
                        ),
                    )?;
                    if lde.evaluation_log_size() != evaluation_log_size {
                        return Err(
                            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                                "staged LDE log differs from source topology",
                            ),
                        );
                    }
                    QuotientNumeratorStagedSource::StagedCoefficient(lde)
                }
            };
            if source.evaluation_log_size() != evaluation_log_size {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "source evaluation log differs from topology",
                    ),
                );
            }
            sources.push(source);
        }
    }
    if staged_by_column.len() != coefficient_ldes.len() {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "coefficient staging map lost a column",
            ),
        );
    }

    let mut group_offsets = Vec::with_capacity(legacy.requirements.groups.len() + 1);
    let mut term_descriptors = Vec::with_capacity(
        legacy
            .requirements
            .term_count
            .checked_mul(TERM_WORDS)
            .ok_or(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "term word count overflowed",
                ),
            )?,
    );
    for group in 0..legacy.requirements.groups.len() {
        group_offsets.push(descriptor_count(&term_descriptors)?);
        for (batch, &source_base) in legacy.batches.iter().zip(&batch_source_bases) {
            let begin = batch.group_offsets[group] as usize;
            let end = batch.group_offsets[group + 1] as usize;
            for descriptor in
                batch.terms[begin * TERM_WORDS..end * TERM_WORDS].chunks_exact(TERM_WORDS)
            {
                let local_source = descriptor[0] as usize;
                if local_source >= batch.columns.len() {
                    return Err(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "batch-local source is out of bounds",
                        ),
                    );
                }
                let source = source_base.checked_add(local_source).ok_or(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "global source index overflowed",
                    ),
                )?;
                term_descriptors.extend([
                    u32::try_from(source).map_err(|_| {
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "global source index exceeds u32",
                        )
                    })?,
                    descriptor[1],
                    descriptor[2],
                ]);
            }
        }
    }
    group_offsets.push(descriptor_count(&term_descriptors)?);
    if group_offsets != legacy.group_offsets {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "flattened group offsets differ from legacy",
            ),
        );
    }
    if term_descriptors.len() / TERM_WORDS != legacy.requirements.term_count {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "flattening lost or duplicated terms",
            ),
        );
    }

    let packed_group_row_offsets = packed_group_row_offsets(&legacy.requirements)?;
    let packed_output_rows = *packed_group_row_offsets.last().ok_or(
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
            "packed row manifest has no terminal offset",
        ),
    )?;
    operations.push(QuotientNumeratorStagedOperation::AccumulatePackedRows {
        group_count: legacy.requirements.groups.len(),
        term_count: legacy.requirements.term_count,
        packed_output_rows,
    });
    let report = build_report(&legacy.requirements, &coefficient_ldes, &group_offsets)?;
    Ok(QuotientNumeratorStagedSingleWritePlan {
        requirements: legacy.requirements,
        coefficient_ldes,
        operations,
        sources,
        group_offsets,
        packed_group_row_offsets,
        term_descriptors,
        report,
    })
}

fn coefficient_staging_layout(
    entries: impl IntoIterator<Item = (usize, u32)>,
    primary_capacity_words: usize,
    overflow_capacities_words: &[usize],
) -> Result<Vec<QuotientNumeratorStagedLde>, QuotientNumeratorStagedSingleWriteError> {
    if overflow_capacities_words
        .windows(2)
        .any(|pair| pair[0] < pair[1])
    {
        return Err(QuotientNumeratorStagedSingleWriteError::OverflowCapacitiesNotDescending);
    }
    let mut seen = BTreeSet::new();
    let mut offset_words = 0usize;
    let mut primary_offset_words = 0usize;
    let mut overflow_offsets_words = vec![0usize; overflow_capacities_words.len()];
    let mut overflow_role = 0usize;
    let mut overflow_started = false;
    let mut ldes = Vec::new();
    for (column, evaluation_log_size) in entries {
        if !seen.insert(column) {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DuplicateCoefficientColumn(column),
            );
        }
        let len_words = 1usize.checked_shl(evaluation_log_size).ok_or(
            QuotientNumeratorStagedSingleWriteError::StagingSizeOverflow {
                column,
                evaluation_log_size,
            },
        )?;
        let next = offset_words.checked_add(len_words).ok_or(
            QuotientNumeratorStagedSingleWriteError::StagingSizeOverflow {
                column,
                evaluation_log_size,
            },
        )?;
        let primary_next = primary_offset_words.checked_add(len_words).ok_or(
            QuotientNumeratorStagedSingleWriteError::StagingSizeOverflow {
                column,
                evaluation_log_size,
            },
        )?;
        let (staging_role, role_offset_words) =
            if !overflow_started && primary_next <= primary_capacity_words {
                let role_offset = primary_offset_words;
                primary_offset_words = primary_next;
                (QuotientNumeratorStagingRole::Primary, role_offset)
            } else {
                overflow_started = true;
                loop {
                    let Some((&capacity, role_offset)) = overflow_capacities_words
                        .get(overflow_role)
                        .zip(overflow_offsets_words.get_mut(overflow_role))
                    else {
                        return Err(
                            QuotientNumeratorStagedSingleWriteError::InsufficientOverflowCapacity {
                                column,
                                required_words: len_words,
                            },
                        );
                    };
                    let role_next = role_offset.checked_add(len_words).ok_or(
                        QuotientNumeratorStagedSingleWriteError::StagingSizeOverflow {
                            column,
                            evaluation_log_size,
                        },
                    )?;
                    if role_next <= capacity {
                        let offset = *role_offset;
                        *role_offset = role_next;
                        let role = u16::try_from(overflow_role).map_err(|_| {
                            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                                "overflow role index exceeds u16",
                            )
                        })?;
                        break (QuotientNumeratorStagingRole::Overflow(role), offset);
                    }
                    if *role_offset == 0 {
                        return Err(
                            QuotientNumeratorStagedSingleWriteError::InsufficientOverflowCapacity {
                                column,
                                required_words: len_words,
                            },
                        );
                    }
                    overflow_role = overflow_role.checked_add(1).ok_or(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "overflow role index overflowed",
                        ),
                    )?;
                }
            };
        ldes.push(QuotientNumeratorStagedLde {
            column,
            evaluation_log_size,
            staging_role,
            role_offset_words,
            offset_words,
            len_words,
        });
        offset_words = next;
    }
    Ok(ldes)
}

fn descriptor_count(words: &[u32]) -> Result<u32, QuotientNumeratorStagedSingleWriteError> {
    u32::try_from(words.len() / TERM_WORDS).map_err(|_| {
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant("term count exceeds u32")
    })
}

fn packed_group_row_offsets(
    requirements: &QuotientNumeratorWorkspaceRequirements,
) -> Result<Vec<u64>, QuotientNumeratorStagedSingleWriteError> {
    let mut offsets = Vec::with_capacity(requirements.groups.len() + 1);
    let mut rows = 0u64;
    offsets.push(rows);
    for group in &requirements.groups {
        let group_rows = u64::try_from(group.value_words).map_err(|_| {
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "group row count exceeds u64",
            )
        })?;
        if group_rows == 0 {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "packed row manifest contains an empty group",
                ),
            );
        }
        rows = rows.checked_add(group_rows).ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "packed output row count overflowed",
            ),
        )?;
        offsets.push(rows);
    }
    Ok(offsets)
}

fn packed_row_location(offsets: &[u64], packed_row: u64) -> Option<(usize, u64)> {
    let &total_rows = offsets.last()?;
    let group_count = offsets.len().checked_sub(1)?;
    if group_count == 0 || offsets[0] != 0 || packed_row >= total_rows {
        return None;
    }
    let mut low = 0usize;
    let mut high = group_count;
    while low < high {
        let middle = low + (high - low) / 2;
        if packed_row < offsets[middle + 1] {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let row = packed_row.checked_sub(offsets[low])?;
    (row < offsets[low + 1] - offsets[low]).then_some((low, row))
}

fn build_report(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    ldes: &[QuotientNumeratorStagedLde],
    group_offsets: &[u32],
) -> Result<QuotientNumeratorStagedSingleWriteReport, QuotientNumeratorStagedSingleWriteError> {
    if group_offsets.len() != requirements.groups.len() + 1
        || group_offsets.first().copied() != Some(0)
        || group_offsets.last().copied() != u32::try_from(requirements.term_count).ok()
    {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "packed report group offsets do not cover every term",
            ),
        );
    }
    let output_rows = requirements.groups.iter().try_fold(0usize, |rows, group| {
        rows.checked_add(group.value_words).ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "output row count overflowed",
            ),
        )
    })?;
    let coefficient_output_rows = requirements.groups.iter().try_fold(0usize, |rows, group| {
        if group.coefficient_source_count == 0 {
            Ok(rows)
        } else {
            rows.checked_add(group.value_words).ok_or(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "coefficient output row count overflowed",
                ),
            )
        }
    })?;
    let total_staging_words = ldes.last().map_or(0, |lde| lde.end_words());
    let primary_staging_words = ldes
        .iter()
        .filter(|lde| lde.staging_role() == QuotientNumeratorStagingRole::Primary)
        .map(|lde| lde.role_end_words())
        .max()
        .unwrap_or(0);
    let mut overflow_roles = BTreeMap::<u16, usize>::new();
    for lde in ldes {
        if let QuotientNumeratorStagingRole::Overflow(role) = lde.staging_role() {
            overflow_roles
                .entry(role)
                .and_modify(|words| *words = (*words).max(lde.role_end_words()))
                .or_insert_with(|| lde.role_end_words());
        }
    }
    let overflow_staging_words = overflow_roles.values().try_fold(0usize, |total, &words| {
        total.checked_add(words).ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "overflow staging word count overflowed",
            ),
        )
    })?;
    let overflow_staging_role_count = overflow_roles
        .keys()
        .next_back()
        .map_or(0, |&role| usize::from(role) + 1);
    if overflow_staging_role_count != overflow_roles.len() {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "overflow staging roles are not dense",
            ),
        );
    }
    let max_overflow_staging_role_words = overflow_roles.values().copied().max().unwrap_or(0);
    if primary_staging_words > requirements.lde_tile_words
        || primary_staging_words
            .checked_add(overflow_staging_words)
            .is_none_or(|words| words != total_staging_words)
    {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "segmented staging accounting does not reconcile",
            ),
        );
    }
    let unused_factor32_staging_words = requirements
        .lde_tile_words
        .checked_sub(primary_staging_words)
        .ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "primary staging exceeds the factor-32 role",
            ),
        )?;
    let incremental_staging_words_over_factor32 =
        total_staging_words.saturating_sub(requirements.lde_tile_words);
    let factor32_accumulation_passes = (coefficient_output_rows != 0)
        .then_some(requirements.batches.len())
        .unwrap_or(0);
    let factor32_total_output_passes = factor32_accumulation_passes.checked_add(1).ok_or(
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
            "factor-32 pass count overflowed",
        ),
    )?;
    let candidate_logical_output_bytes = bytes(output_rows, SECURE_BYTES)?;
    let factor32_passes_u64 = u64::try_from(factor32_accumulation_passes).map_err(|_| {
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
            "factor-32 pass count exceeds u64",
        )
    })?;
    let factor32_rmw_bytes = bytes(coefficient_output_rows, 2 * SECURE_BYTES)?
        .checked_mul(factor32_passes_u64)
        .ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "factor-32 output byte count overflowed",
            ),
        )?;
    let factor32_logical_output_bytes = candidate_logical_output_bytes
        .checked_add(factor32_rmw_bytes)
        .ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "factor-32 output byte count overflowed",
            ),
        )?;
    let output_rows_u64 = u64::try_from(output_rows).map_err(|_| {
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant("output row count exceeds u64")
    })?;
    let max_output_size_u64 = u64::try_from(requirements.max_output_size).map_err(|_| {
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
            "maximum output size exceeds u64",
        )
    })?;
    let group_count_u64 = u64::try_from(requirements.groups.len()).map_err(|_| {
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant("group count exceeds u64")
    })?;
    let rectangular_launch_rows = max_output_size_u64.checked_mul(group_count_u64).ok_or(
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
            "rectangular launch row count overflowed",
        ),
    )?;
    let inactive_rectangular_launch_rows =
        rectangular_launch_rows.checked_sub(output_rows_u64).ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "useful rows exceed the rectangular launch grid",
            ),
        )?;
    let useful_row_terms =
        requirements
            .groups
            .iter()
            .enumerate()
            .try_fold(0u64, |total, (group, requirements)| {
                let terms = u64::from(group_offsets[group + 1] - group_offsets[group]);
                let rows = u64::try_from(requirements.value_words).map_err(|_| {
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "group row count exceeds u64",
                    )
                })?;
                total
                    .checked_add(rows.checked_mul(terms).ok_or(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "useful row-term count overflowed",
                        ),
                    )?)
                    .ok_or(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "useful row-term count overflowed",
                        ),
                    )
            })?;
    let rectangular_row_term_capacity = max_output_size_u64
        .checked_mul(u64::try_from(requirements.term_count).map_err(|_| {
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant("term count exceeds u64")
        })?)
        .ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "rectangular row-term capacity overflowed",
            ),
        )?;
    let packed_binary_search_comparisons_per_row_max = usize::BITS
        .checked_sub(requirements.groups.len().leading_zeros())
        .ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "packed binary-search comparison bound underflowed",
            ),
        )?;
    let packed_binary_search_comparisons_max = output_rows_u64
        .checked_mul(u64::from(packed_binary_search_comparisons_per_row_max))
        .ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "packed binary-search comparison count overflowed",
            ),
        )?;

    Ok(QuotientNumeratorStagedSingleWriteReport {
        group_count: requirements.groups.len(),
        term_count: requirements.term_count,
        source_count: requirements
            .batches
            .iter()
            .try_fold(0usize, |count, batch| {
                count.checked_add(batch.source_count).ok_or(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "source count overflowed",
                    ),
                )
            })?,
        coefficient_source_count: ldes.len(),
        factor32_batch_count: requirements.batches.len(),
        factor32_accumulation_passes,
        factor32_total_output_passes,
        candidate_output_passes: 1,
        output_rows,
        coefficient_output_rows,
        factor32_logical_output_bytes,
        candidate_logical_output_bytes,
        logical_output_bytes_saved: factor32_rmw_bytes,
        rectangular_launch_rows,
        inactive_rectangular_launch_rows,
        useful_row_terms,
        rectangular_row_term_capacity,
        packed_binary_search_comparisons_per_row_max,
        packed_binary_search_comparisons_max,
        total_staging_words,
        factor32_staging_words: requirements.lde_tile_words,
        primary_staging_words,
        unused_factor32_staging_words,
        overflow_staging_words,
        overflow_staging_role_count,
        max_overflow_staging_role_words,
        incremental_staging_words_over_factor32,
    })
}

fn bytes(rows: usize, bytes_per_row: u64) -> Result<u64, QuotientNumeratorStagedSingleWriteError> {
    u64::try_from(rows)
        .ok()
        .and_then(|rows| rows.checked_mul(bytes_per_row))
        .ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "logical output byte count overflowed",
            ),
        )
}

#[cfg(test)]
#[path = "quotient_numerator_staged_single_write_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "quotient_numerator_staged_single_write_admission_tests.rs"]
mod admission_tests;
