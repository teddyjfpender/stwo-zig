//! Candidate single-write quotient numerator schedules.
//!
//! Neither candidate is selected by the resident prover. The full candidate
//! requires retained evaluations; the hybrid candidate gives evaluation-only
//! groups one write and leaves coefficient-backed groups on the legacy chain.
//!
//! gpu-lab-cohesion-review: public accounting, descriptor packing, and their
//! shared invariants stay together so one review can prove every reported
//! byte maps to the exact schedule that will execute.

use super::prepared_quotient_numerator::{
    build_plan, PreparedQuotientNumeratorError, QuotientNumeratorColumnTopology,
    QuotientNumeratorWorkspaceConfig, QuotientNumeratorWorkspaceRequirements,
};

pub const QUOTIENT_NUMERATOR_SINGLE_WRITE_TERM_WORDS: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientNumeratorSingleWriteEligibility {
    Eligible,
    RequiresRetainedEvaluations {
        coefficient_columns: usize,
        coefficient_batches: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorSingleWriteReport {
    pub eligibility: QuotientNumeratorSingleWriteEligibility,
    pub group_count: usize,
    pub term_count: usize,
    pub source_count: usize,
    pub legacy_batch_count: usize,
    /// Zero plus one read/modify/write pass per legacy batch.
    pub legacy_output_passes: usize,
    pub candidate_output_passes: usize,
    pub output_rows: usize,
    /// Logical output loads and stores issued by the current kernels. This is
    /// not an HBM-counter measurement and excludes source/descriptor reads.
    pub legacy_logical_output_bytes: u64,
    pub candidate_logical_output_bytes: u64,
    pub legacy_descriptor_bytes: u64,
    pub candidate_descriptor_bytes: u64,
    /// Replay performs no descriptor construction or host transfer after setup.
    pub candidate_warm_host_preparation_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorSingleWritePlan {
    requirements: QuotientNumeratorWorkspaceRequirements,
    source_columns: Vec<usize>,
    group_offsets: Vec<u32>,
    term_descriptors: Vec<u32>,
    report: QuotientNumeratorSingleWriteReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorHybridReport {
    pub group_count: usize,
    pub eligible_group_count: usize,
    pub legacy_group_count: usize,
    pub legacy_batch_count: usize,
    pub eligible_output_rows: usize,
    pub legacy_output_rows: usize,
    pub legacy_logical_output_bytes: u64,
    pub hybrid_logical_output_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorHybridBatch {
    pub term_offset: usize,
    pub term_count: usize,
    pub group_offset: usize,
}

/// Setup-only descriptor partition. Canonical group IDs are retained in
/// `schedule_groups`; only the private accumulation tables are reordered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorHybridPlan {
    requirements: QuotientNumeratorWorkspaceRequirements,
    schedule_groups: Vec<usize>,
    source_columns: Vec<usize>,
    packed_terms: Vec<u32>,
    packed_group_offsets: Vec<u32>,
    batches: Vec<QuotientNumeratorHybridBatch>,
    report: QuotientNumeratorHybridReport,
}

impl QuotientNumeratorHybridPlan {
    pub fn requirements(&self) -> &QuotientNumeratorWorkspaceRequirements {
        &self.requirements
    }

    /// Eligible canonical groups first, then coefficient-backed groups; both
    /// partitions are individually in canonical order.
    pub fn schedule_groups(&self) -> &[usize] {
        &self.schedule_groups
    }

    pub fn source_columns(&self) -> &[usize] {
        &self.source_columns
    }

    /// The init descriptors followed by each compact legacy batch.
    pub fn packed_terms(&self) -> &[u32] {
        &self.packed_terms
    }

    /// Init offsets for all scheduled groups followed by compact offsets for
    /// every legacy batch.
    pub fn packed_group_offsets(&self) -> &[u32] {
        &self.packed_group_offsets
    }

    pub fn batches(&self) -> &[QuotientNumeratorHybridBatch] {
        &self.batches
    }

    pub fn report(&self) -> QuotientNumeratorHybridReport {
        self.report
    }
}

impl QuotientNumeratorSingleWritePlan {
    pub fn requirements(&self) -> &QuotientNumeratorWorkspaceRequirements {
        &self.requirements
    }

    /// Indices into the caller's canonical column slice. Pointer-table order
    /// is stable legacy batch order: `(evaluation_log_size, column_index)`.
    pub fn source_columns(&self) -> &[usize] {
        &self.source_columns
    }

    pub fn group_offsets(&self) -> &[u32] {
        &self.group_offsets
    }

    /// Group-major `[source, term, source_log_size]` words. Terms inside each
    /// group retain the exact legacy batch order and stable in-batch order.
    pub fn term_descriptors(&self) -> &[u32] {
        &self.term_descriptors
    }

    pub fn report(&self) -> QuotientNumeratorSingleWriteReport {
        self.report
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotientNumeratorSingleWriteError {
    Base(PreparedQuotientNumeratorError),
    NoEligibleGroups,
    RequiresRetainedEvaluations {
        coefficient_columns: usize,
        coefficient_batches: usize,
    },
    DescriptorInvariant(&'static str),
}

impl core::fmt::Display for QuotientNumeratorSingleWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Base(error) => error.fmt(f),
            Self::NoEligibleGroups => {
                write!(f, "hybrid quotient numerator has no evaluation-only groups")
            }
            Self::RequiresRetainedEvaluations {
                coefficient_columns,
                coefficient_batches,
            } => write!(
                f,
                "single-write quotient numerator requires retained evaluations; \
                 {coefficient_columns} coefficient columns remain in \
                 {coefficient_batches} batches"
            ),
            Self::DescriptorInvariant(message) => {
                write!(f, "invalid single-write quotient descriptor: {message}")
            }
        }
    }
}

impl std::error::Error for QuotientNumeratorSingleWriteError {}

impl From<PreparedQuotientNumeratorError> for QuotientNumeratorSingleWriteError {
    fn from(value: PreparedQuotientNumeratorError) -> Self {
        Self::Base(value)
    }
}

pub fn quotient_numerator_single_write_report(
    config: QuotientNumeratorWorkspaceConfig,
    columns: &[QuotientNumeratorColumnTopology],
) -> Result<QuotientNumeratorSingleWriteReport, QuotientNumeratorSingleWriteError> {
    let plan = build_plan(config, columns)?;
    report(&plan.requirements)
}

pub fn quotient_numerator_single_write_plan(
    config: QuotientNumeratorWorkspaceConfig,
    columns: &[QuotientNumeratorColumnTopology],
) -> Result<QuotientNumeratorSingleWritePlan, QuotientNumeratorSingleWriteError> {
    let legacy = build_plan(config, columns)?;
    let report = report(&legacy.requirements)?;
    if let QuotientNumeratorSingleWriteEligibility::RequiresRetainedEvaluations {
        coefficient_columns,
        coefficient_batches,
    } = report.eligibility
    {
        return Err(
            QuotientNumeratorSingleWriteError::RequiresRetainedEvaluations {
                coefficient_columns,
                coefficient_batches,
            },
        );
    }

    let mut source_columns = Vec::with_capacity(report.source_count);
    let mut batch_source_bases = Vec::with_capacity(legacy.batches.len());
    for batch in &legacy.batches {
        batch_source_bases.push(source_columns.len());
        source_columns.extend(batch.columns.iter().copied());
    }

    let mut group_offsets = Vec::with_capacity(report.group_count + 1);
    let mut term_descriptors = Vec::with_capacity(
        report
            .term_count
            .checked_mul(QUOTIENT_NUMERATOR_SINGLE_WRITE_TERM_WORDS)
            .ok_or(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                "term word count overflowed",
            ))?,
    );
    for group in 0..report.group_count {
        group_offsets.push(descriptor_count(&term_descriptors)?);
        for (batch, &source_base) in legacy.batches.iter().zip(&batch_source_bases) {
            let begin = batch.group_offsets[group] as usize;
            let end = batch.group_offsets[group + 1] as usize;
            for descriptor in batch.terms[begin * 3..end * 3].chunks_exact(3) {
                let local_source = descriptor[0] as usize;
                if local_source >= batch.columns.len() {
                    return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                        "batch-local source is out of bounds",
                    ));
                }
                let source = source_base.checked_add(local_source).ok_or(
                    QuotientNumeratorSingleWriteError::DescriptorInvariant(
                        "global source index overflowed",
                    ),
                )?;
                term_descriptors.extend([
                    u32::try_from(source).map_err(|_| {
                        QuotientNumeratorSingleWriteError::DescriptorInvariant(
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
    if term_descriptors.len() / 3 != report.term_count {
        return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "flattening lost or duplicated terms",
        ));
    }

    Ok(QuotientNumeratorSingleWritePlan {
        requirements: legacy.requirements,
        source_columns,
        group_offsets,
        term_descriptors,
        report,
    })
}

/// Partitions output ownership without changing canonical proof order. The
/// single-write init owns every output once: eligible groups receive their
/// complete numerator and legacy groups receive zero through empty spans.
/// The legacy batches then read/modify/write only the trailing legacy groups.
pub fn quotient_numerator_hybrid_plan(
    config: QuotientNumeratorWorkspaceConfig,
    columns: &[QuotientNumeratorColumnTopology],
) -> Result<QuotientNumeratorHybridPlan, QuotientNumeratorSingleWriteError> {
    let legacy = build_plan(config, columns)?;
    let eligible_groups = legacy
        .requirements
        .groups
        .iter()
        .enumerate()
        .filter_map(|(group, requirement)| {
            (requirement.coefficient_source_count == 0).then_some(group)
        })
        .collect::<Vec<_>>();
    if eligible_groups.is_empty() {
        return Err(QuotientNumeratorSingleWriteError::NoEligibleGroups);
    }
    let legacy_groups = legacy
        .requirements
        .groups
        .iter()
        .enumerate()
        .filter_map(|(group, requirement)| {
            (requirement.coefficient_source_count != 0).then_some(group)
        })
        .collect::<Vec<_>>();
    let schedule_groups = eligible_groups
        .iter()
        .chain(&legacy_groups)
        .copied()
        .collect::<Vec<_>>();
    if schedule_groups.len() != legacy.requirements.groups.len() {
        return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "group partition is incomplete",
        ));
    }

    let mut source_columns = Vec::new();
    let mut batch_source_bases = Vec::with_capacity(legacy.batches.len());
    for batch in &legacy.batches {
        batch_source_bases.push(source_columns.len());
        source_columns.extend(batch.columns.iter().copied());
    }

    let mut packed_terms = Vec::with_capacity(legacy.requirements.batch_term_words);
    let mut packed_group_offsets = Vec::with_capacity(legacy.requirements.batch_group_offset_words);
    for &group in &schedule_groups {
        packed_group_offsets.push(descriptor_count(&packed_terms)?);
        if legacy_groups.binary_search(&group).is_ok() {
            continue;
        }
        for (batch, &source_base) in legacy.batches.iter().zip(&batch_source_bases) {
            let begin = batch.group_offsets[group] as usize;
            let end = batch.group_offsets[group + 1] as usize;
            for descriptor in batch.terms[begin * 3..end * 3].chunks_exact(3) {
                let local_source = descriptor[0] as usize;
                let Some(&column) = batch.columns.get(local_source) else {
                    return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                        "batch-local source is out of bounds",
                    ));
                };
                if columns[column].source_kind
                    != super::prepared_quotient_numerator::QuotientNumeratorSourceKind::Evaluation
                {
                    return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                        "single-write descriptor references a coefficient source",
                    ));
                }
                let source = source_base.checked_add(local_source).ok_or(
                    QuotientNumeratorSingleWriteError::DescriptorInvariant(
                        "global source index overflowed",
                    ),
                )?;
                packed_terms.extend([
                    u32::try_from(source).map_err(|_| {
                        QuotientNumeratorSingleWriteError::DescriptorInvariant(
                            "global source index exceeds u32",
                        )
                    })?,
                    descriptor[1],
                    descriptor[2],
                ]);
            }
        }
    }
    packed_group_offsets.push(descriptor_count(&packed_terms)?);

    let mut batches = Vec::with_capacity(legacy.batches.len());
    for batch in &legacy.batches {
        let term_offset = packed_terms.len() / QUOTIENT_NUMERATOR_SINGLE_WRITE_TERM_WORDS;
        if legacy_groups.is_empty() {
            batches.push(QuotientNumeratorHybridBatch {
                term_offset,
                term_count: 0,
                group_offset: 0,
            });
            continue;
        }
        let group_offset = packed_group_offsets.len();
        for &group in &legacy_groups {
            packed_group_offsets.push(
                u32::try_from(
                    packed_terms.len() / QUOTIENT_NUMERATOR_SINGLE_WRITE_TERM_WORDS - term_offset,
                )
                .map_err(|_| {
                    QuotientNumeratorSingleWriteError::DescriptorInvariant(
                        "legacy term count exceeds u32",
                    )
                })?,
            );
            let begin = batch.group_offsets[group] as usize;
            let end = batch.group_offsets[group + 1] as usize;
            packed_terms.extend_from_slice(&batch.terms[begin * 3..end * 3]);
        }
        let term_count =
            packed_terms.len() / QUOTIENT_NUMERATOR_SINGLE_WRITE_TERM_WORDS - term_offset;
        packed_group_offsets.push(u32::try_from(term_count).map_err(|_| {
            QuotientNumeratorSingleWriteError::DescriptorInvariant("legacy term count exceeds u32")
        })?);
        batches.push(QuotientNumeratorHybridBatch {
            term_offset,
            term_count,
            group_offset,
        });
    }

    if packed_terms.len() != legacy.requirements.batch_term_words {
        return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "hybrid partition lost or duplicated terms",
        ));
    }
    if packed_group_offsets.len() > legacy.requirements.batch_group_offset_words {
        return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "hybrid offsets exceed the legacy arena slot",
        ));
    }
    let eligible_output_rows = output_rows(&legacy.requirements, &eligible_groups)?;
    let legacy_output_rows = output_rows(&legacy.requirements, &legacy_groups)?;
    let output_rows = eligible_output_rows.checked_add(legacy_output_rows).ok_or(
        QuotientNumeratorSingleWriteError::DescriptorInvariant("output row count overflowed"),
    )?;
    let batch_count = legacy.batches.len();
    let legacy_logical_output_bytes = logical_output_bytes(output_rows, batch_count, output_rows)?;
    let hybrid_logical_output_bytes =
        logical_output_bytes(output_rows, batch_count, legacy_output_rows)?;

    Ok(QuotientNumeratorHybridPlan {
        requirements: legacy.requirements,
        schedule_groups,
        source_columns,
        packed_terms,
        packed_group_offsets,
        batches,
        report: QuotientNumeratorHybridReport {
            group_count: eligible_groups.len() + legacy_groups.len(),
            eligible_group_count: eligible_groups.len(),
            legacy_group_count: legacy_groups.len(),
            legacy_batch_count: batch_count,
            eligible_output_rows,
            legacy_output_rows,
            legacy_logical_output_bytes,
            hybrid_logical_output_bytes,
        },
    })
}

fn output_rows(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    groups: &[usize],
) -> Result<usize, QuotientNumeratorSingleWriteError> {
    groups.iter().try_fold(0usize, |rows, &group| {
        rows.checked_add(requirements.groups[group].value_words)
            .ok_or(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                "output row count overflowed",
            ))
    })
}

fn logical_output_bytes(
    output_rows: usize,
    batches: usize,
    rmw_rows: usize,
) -> Result<u64, QuotientNumeratorSingleWriteError> {
    let init = u64::try_from(output_rows)
        .ok()
        .and_then(|rows| rows.checked_mul(16));
    let rmw = u64::try_from(rmw_rows)
        .ok()
        .and_then(|rows| rows.checked_mul(32))
        .and_then(|bytes| bytes.checked_mul(batches as u64));
    init.and_then(|bytes| rmw.and_then(|rmw| bytes.checked_add(rmw)))
        .ok_or(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "logical output byte count overflowed",
        ))
}

fn descriptor_count(words: &[u32]) -> Result<u32, QuotientNumeratorSingleWriteError> {
    u32::try_from(words.len() / QUOTIENT_NUMERATOR_SINGLE_WRITE_TERM_WORDS).map_err(|_| {
        QuotientNumeratorSingleWriteError::DescriptorInvariant("term count exceeds u32")
    })
}

fn report(
    requirements: &QuotientNumeratorWorkspaceRequirements,
) -> Result<QuotientNumeratorSingleWriteReport, QuotientNumeratorSingleWriteError> {
    let coefficient_columns = requirements
        .batches
        .iter()
        .map(|batch| batch.coefficient_count)
        .sum::<usize>();
    let coefficient_batches = requirements
        .batches
        .iter()
        .filter(|batch| batch.coefficient_count != 0)
        .count();
    let eligibility = if coefficient_columns == 0 {
        QuotientNumeratorSingleWriteEligibility::Eligible
    } else {
        QuotientNumeratorSingleWriteEligibility::RequiresRetainedEvaluations {
            coefficient_columns,
            coefficient_batches,
        }
    };
    let batches = requirements.batches.len();
    let groups = requirements.groups.len();
    let sources = requirements
        .batches
        .iter()
        .map(|batch| batch.source_count)
        .sum::<usize>();
    let rows = requirements
        .groups
        .iter()
        .try_fold(0usize, |sum, group| sum.checked_add(group.value_words))
        .ok_or(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "output row count overflowed",
        ))?;
    let rows = u64::try_from(rows).map_err(|_| {
        QuotientNumeratorSingleWriteError::DescriptorInvariant("output rows exceed u64")
    })?;
    let batches_u64 = u64::try_from(batches).map_err(|_| {
        QuotientNumeratorSingleWriteError::DescriptorInvariant("batch count exceeds u64")
    })?;
    let legacy_output_bytes = rows.checked_mul(16 + 32 * batches_u64).ok_or(
        QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "legacy output byte count overflowed",
        ),
    )?;
    let candidate_output_bytes =
        rows.checked_mul(16)
            .ok_or(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                "candidate output byte count overflowed",
            ))?;
    let term_bytes = u64::try_from(requirements.term_count)
        .ok()
        .and_then(|terms| terms.checked_mul(12))
        .ok_or(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "term descriptor byte count overflowed",
        ))?;
    let pointer_bytes = u64::try_from(sources)
        .ok()
        .and_then(|count| count.checked_mul(core::mem::size_of::<usize>() as u64))
        .ok_or(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "source pointer byte count overflowed",
        ))?;
    let legacy_offset_bytes = u64::try_from(batches)
        .ok()
        .and_then(|count| count.checked_mul((groups as u64 + 1) * 4))
        .ok_or(QuotientNumeratorSingleWriteError::DescriptorInvariant(
            "legacy offset byte count overflowed",
        ))?;
    let candidate_offset_bytes = (groups as u64 + 1) * 4;

    Ok(QuotientNumeratorSingleWriteReport {
        eligibility,
        group_count: groups,
        term_count: requirements.term_count,
        source_count: sources,
        legacy_batch_count: batches,
        legacy_output_passes: batches + 1,
        candidate_output_passes: 1,
        output_rows: rows as usize,
        legacy_logical_output_bytes: legacy_output_bytes,
        candidate_logical_output_bytes: candidate_output_bytes,
        legacy_descriptor_bytes: term_bytes + pointer_bytes + legacy_offset_bytes,
        candidate_descriptor_bytes: term_bytes + pointer_bytes + candidate_offset_bytes,
        candidate_warm_host_preparation_bytes: 0,
    })
}

#[cfg(test)]
#[path = "quotient_numerator_single_write_tests.rs"]
mod tests;
