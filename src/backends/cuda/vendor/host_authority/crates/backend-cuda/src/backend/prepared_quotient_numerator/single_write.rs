//! Single-write schedule integration.

use core::ffi::c_void;
use core::ops::Range;

use super::*;
use crate::backend::quotient_numerator_single_write::{
    quotient_numerator_hybrid_plan, quotient_numerator_single_write_plan,
    QuotientNumeratorSingleWriteError,
};
use crate::backend::quotient_numerator_staged_single_write::{
    quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    QuotientNumeratorStagedOperation, QuotientNumeratorStagedSingleWriteError,
    QuotientNumeratorStagedSource, QuotientNumeratorStagingRole,
};

#[derive(Clone, Copy)]
enum GroupDirectLaunch {
    Direct,
    RawTiled(u32),
    ContributionTiled,
}

pub(super) fn derive_group_direct_ranges(
    group_offsets: &[u32],
    term_descriptors: &[u32],
    group_log_sizes: &[u32],
) -> Result<Vec<PreparedGroupDirectRange>, QuotientNumeratorStagedSingleWriteError> {
    if term_descriptors.len() % BATCH_TERM_WORDS != 0 {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "direct term descriptors are not word aligned",
            ),
        );
    }
    let term_count = u32::try_from(term_descriptors.len() / BATCH_TERM_WORDS).map_err(|_| {
        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
            "direct term count exceeds u32",
        )
    })?;
    if group_offsets.len() != group_log_sizes.len().saturating_add(1) {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "direct group offsets and log sizes differ",
            ),
        );
    }
    if group_offsets.first() != Some(&0) || group_offsets.last() != Some(&term_count) {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "direct group offsets do not span every term",
            ),
        );
    }
    group_offsets
        .windows(2)
        .zip(group_log_sizes)
        .map(|(offsets, &group_log_size)| {
            if offsets[0] >= offsets[1] || offsets[1] > term_count {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "direct group has an invalid term range",
                    ),
                );
            }
            let begin = offsets[0] as usize * BATCH_TERM_WORDS;
            let end = offsets[1] as usize * BATCH_TERM_WORDS;
            let mut descriptors = term_descriptors[begin..end].chunks_exact(BATCH_TERM_WORDS);
            let first = descriptors.next().ok_or(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "direct group has no representative term",
                ),
            )?;
            if first[2] > group_log_size {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "direct descriptor source log exceeds its group",
                    ),
                );
            }
            let mut group_b_term = first[1];
            let mut previous_source_log = first[2];
            for descriptor in descriptors {
                if descriptor[2] > group_log_size {
                    return Err(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "direct descriptor source log exceeds its group",
                        ),
                    );
                } else if descriptor[2] < previous_source_log {
                    return Err(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "direct group source logs are not monotone",
                        ),
                    );
                }
                previous_source_log = descriptor[2];
                group_b_term = group_b_term.min(descriptor[1]);
            }
            Ok(PreparedGroupDirectRange {
                term_begin: offsets[0],
                term_end: offsets[1],
                group_b_term,
            })
        })
        .collect()
}

fn validate_group_direct_representatives(
    ranges: &[PreparedGroupDirectRange],
    canonical: &crate::backend::prepared_quotient_numerator::plan::NumeratorPlan,
) -> Result<(), QuotientNumeratorStagedSingleWriteError> {
    if ranges.len() != canonical.requirements.groups.len()
        || canonical.group_offsets.len() != ranges.len() + 1
    {
        return Err(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "direct ranges do not cover canonical group representatives",
            ),
        );
    }
    for (group, range) in ranges.iter().enumerate() {
        let offset = usize::try_from(canonical.group_offsets[group]).map_err(|_| {
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "canonical group offset exceeds usize",
            )
        })?;
        let representative = canonical.group_term_indices.get(offset).ok_or(
            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                "canonical group representative is missing",
            ),
        )?;
        if range.group_b_term != *representative {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "direct group-B representative differs from canonical ownership",
                ),
            );
        }
    }
    Ok(())
}

impl<'a> PreparedQuotientNumeratorGraph<'a> {
    /// Experimental all-evaluation schedule. Setup reuses the validated legacy
    /// arena bindings and replaces only the flattened term descriptor payload.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_single_write_candidate(
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
    ) -> Result<Self, QuotientNumeratorSingleWriteError> {
        let topology = columns
            .iter()
            .map(QuotientNumeratorColumnTopology::from)
            .collect::<Vec<_>>();
        let candidate = quotient_numerator_single_write_plan(config, &topology)?;
        let mut prepared = Self::prepare(
            arena,
            config,
            columns,
            oods_sample_points,
            oods_sample_values,
            random_coefficient,
            sample_points_destination,
            first_linear_terms_destination,
            destinations,
            forward_twiddles,
            slots,
        )?;
        if candidate.requirements() != prepared.requirements() {
            return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                "candidate and prepared requirements differ",
            ));
        }
        upload_and_sync(
            arena,
            &[upload_u32(
                prepared.batch_terms,
                candidate.term_descriptors().to_vec(),
            )],
        )?;
        prepared.schedule = PreparedNumeratorSchedule::SingleWriteCandidate;
        Ok(prepared)
    }

    /// Experimental split schedule: evaluation-only groups are single-write;
    /// coefficient-backed groups retain the exact legacy batch chain.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_hybrid_candidate(
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
    ) -> Result<Self, QuotientNumeratorSingleWriteError> {
        let topology = columns
            .iter()
            .map(QuotientNumeratorColumnTopology::from)
            .collect::<Vec<_>>();
        let candidate = quotient_numerator_hybrid_plan(config, &topology)?;
        let mut prepared = Self::prepare(
            arena,
            config,
            columns,
            oods_sample_points,
            oods_sample_values,
            random_coefficient,
            sample_points_destination,
            first_linear_terms_destination,
            destinations,
            forward_twiddles,
            slots,
        )?;
        if candidate.requirements() != prepared.requirements() {
            return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                "hybrid and prepared requirements differ",
            ));
        }
        if candidate.batches().len() != prepared.batches.len() {
            return Err(QuotientNumeratorSingleWriteError::DescriptorInvariant(
                "hybrid and prepared batch counts differ",
            ));
        }
        let output_pointers = (0..4)
            .flat_map(|coordinate| {
                candidate.schedule_groups().iter().map(move |&group| {
                    destinations[group].coordinates[coordinate].as_u32_ptr() as usize
                })
            })
            .collect::<Vec<_>>();
        let output_log_sizes = candidate
            .schedule_groups()
            .iter()
            .map(|&group| prepared.requirements.groups[group].log_size)
            .collect::<Vec<_>>();
        upload_and_sync(
            arena,
            &[
                upload_u32(prepared.batch_terms, candidate.packed_terms().to_vec()),
                upload_u32(
                    prepared.batch_group_offsets,
                    candidate.packed_group_offsets().to_vec(),
                ),
                upload_ptrs(prepared.output_ptrs, output_pointers),
                upload_u32(prepared.output_log_sizes, output_log_sizes),
            ],
        )?;
        for (batch, placement) in prepared.batches.iter_mut().zip(candidate.batches()) {
            batch.term_offset = placement.term_offset;
            batch.group_offset = placement.group_offset;
        }
        let report = candidate.report();
        prepared.schedule = PreparedNumeratorSchedule::HybridCandidate {
            eligible_groups: report.eligible_group_count,
            legacy_groups: report.legacy_group_count,
        };
        Ok(prepared)
    }

    /// Replacement-v1 coefficient-inclusive schedule. Every coefficient LDE
    /// is materialized once into the primary factor-32 tile or one exact
    /// epoch-released overflow role, then one packed 1-D launch writes every
    /// quotient numerator exactly once. Overflow roles must be distinct and
    /// may not name any live workspace, source, destination, OODS, or twiddle
    /// slot.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_staged_packed_single_write(
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
        overflow_roles: &[ArenaSlice],
    ) -> Result<Self, QuotientNumeratorStagedSingleWriteError> {
        let topology = columns
            .iter()
            .map(QuotientNumeratorColumnTopology::from)
            .collect::<Vec<_>>();
        let canonical = build_plan(config, &topology)?;
        let overflow_capacities = overflow_roles
            .iter()
            .map(|role| role.len_words())
            .collect::<Vec<_>>();
        let candidate = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
            config,
            &topology,
            &overflow_capacities,
        )?;
        Self::prepare_staged_packed_single_write_from_plan(
            arena,
            config,
            columns,
            oods_sample_points,
            oods_sample_values,
            random_coefficient,
            sample_points_destination,
            first_linear_terms_destination,
            destinations,
            forward_twiddles,
            slots,
            overflow_roles,
            &canonical,
            &candidate,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_staged_packed_single_write_from_plan(
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
        overflow_roles: &[ArenaSlice],
        canonical: &crate::backend::prepared_quotient_numerator::plan::NumeratorPlan,
        candidate: &crate::backend::quotient_numerator_staged_single_write::QuotientNumeratorStagedSingleWritePlan,
    ) -> Result<Self, QuotientNumeratorStagedSingleWriteError> {
        if candidate.requirements() != &canonical.requirements
            || candidate.group_offsets() != canonical.group_offsets.as_slice()
        {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "staged and canonical numerator manifests differ",
                ),
            );
        }

        let expected_columns = canonical
            .batches
            .iter()
            .flat_map(|batch| batch.coefficient_columns.iter().copied())
            .collect::<Vec<_>>();
        if candidate
            .coefficient_ldes()
            .iter()
            .map(|lde| lde.column())
            .ne(expected_columns.iter().copied())
        {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "staged LDE order differs from canonical batch order",
                ),
            );
        }
        let mut operations = candidate.operations().iter();
        let mut first_lde = 0usize;
        for batch in canonical
            .batches
            .iter()
            .filter(|batch| !batch.coefficient_columns.is_empty())
        {
            let Some(QuotientNumeratorStagedOperation::MaterializeLdes(launch)) = operations.next()
            else {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "staged LDE launch order differs from canonical batches",
                    ),
                );
            };
            if launch.evaluation_log_size() != batch.evaluation_log_size
                || launch.first_lde() != first_lde
                || launch.lde_count() != batch.coefficient_columns.len()
            {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "staged LDE launch geometry differs from canonical batch",
                    ),
                );
            }
            first_lde += launch.lde_count();
        }
        match operations.next() {
            Some(QuotientNumeratorStagedOperation::AccumulatePackedRows {
                group_count,
                term_count,
                packed_output_rows,
            }) if *group_count == canonical.requirements.groups.len()
                && *term_count == canonical.requirements.term_count
                && *packed_output_rows == candidate.packed_output_rows() => {}
            _ => {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "staged packed launch geometry differs from canonical manifest",
                    ),
                )
            }
        }
        if operations.next().is_some() || first_lde != candidate.coefficient_ldes().len() {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "staged operation manifest has trailing or missing work",
                ),
            );
        }

        let expected_overflow_roles = candidate.overflow_role_words();
        if expected_overflow_roles.len() != overflow_roles.len() {
            return Err(
                QuotientNumeratorStagedSingleWriteError::OverflowBindingCountMismatch {
                    expected: expected_overflow_roles.len(),
                    actual: overflow_roles.len(),
                },
            );
        }
        for (required, role) in expected_overflow_roles.iter().zip(overflow_roles) {
            if *required > role.len_words() {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "staged overflow binding is smaller than its sealed used extent",
                    ),
                );
            }
        }

        let workspace_ids = canonical
            .requirements
            .arena_slot_requirements(slots)?
            .into_iter()
            .map(|requirement| requirement.id)
            .collect::<BTreeSet<_>>();
        let external_ids = [
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
        )
        .map(ArenaSlice::id)
        .collect::<BTreeSet<_>>();
        let context_token = arena.context().identity_token();
        for role in overflow_roles {
            if role.context_token() != context_token {
                return Err(PreparedQuotientNumeratorError::ContextMismatch(role.id()).into());
            }
        }
        validate_staged_overflow_role_ids(&workspace_ids, &external_ids, overflow_roles)?;

        let mut prepared = Self::prepare(
            arena,
            config,
            columns,
            oods_sample_points,
            oods_sample_values,
            random_coefficient,
            sample_points_destination,
            first_linear_terms_destination,
            destinations,
            forward_twiddles,
            slots,
        )?;
        if candidate.requirements() != prepared.requirements()
            || prepared.batches.len() != canonical.batches.len()
        {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "staged and prepared numerator requirements differ",
                ),
            );
        }
        for (prepared_batch, canonical_batch) in prepared.batches.iter().zip(&canonical.batches) {
            if prepared_batch.evaluation_log_size != canonical_batch.evaluation_log_size
                || prepared_batch.coefficient_count != canonical_batch.coefficient_columns.len()
            {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "prepared coefficient batch differs from staged LDE manifest",
                    ),
                );
            }
        }

        if candidate.coefficient_ldes().is_empty() != prepared.lde_tile.is_none() {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "staged coefficient manifest and primary LDE role presence differ",
                ),
            );
        }
        let primary = prepared.lde_tile;
        let role_slice = |role| -> Result<ArenaSlice, QuotientNumeratorStagedSingleWriteError> {
            match role {
                QuotientNumeratorStagingRole::Primary => primary.ok_or(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "staged coefficient manifest has no primary LDE role",
                    ),
                ),
                QuotientNumeratorStagingRole::Overflow(index) => {
                    overflow_roles.get(usize::from(index)).copied().ok_or(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "staged LDE names a missing overflow role",
                        ),
                    )
                }
            }
        };
        let coefficient_output_pointers = candidate
            .coefficient_ldes()
            .iter()
            .map(|lde| {
                let role = role_slice(lde.staging_role())?;
                if lde.role_end_words() > role.len_words() {
                    return Err(
                        QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                            "staged LDE crosses its physical role extent",
                        ),
                    );
                }
                Ok(unsafe { role.as_u32_ptr().add(lde.role_offset_words()) as usize })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source_pointers = candidate
            .sources()
            .iter()
            .map(|source| match *source {
                QuotientNumeratorStagedSource::Evaluation { column, .. } => {
                    let QuotientNumeratorColumnSource::Evaluation(slice) = columns[column].source
                    else {
                        return Err(
                            QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                                "staged evaluation source is not a retained evaluation",
                            ),
                        );
                    };
                    Ok(slice.as_u32_ptr() as usize)
                }
                QuotientNumeratorStagedSource::StagedCoefficient(lde) => {
                    let role = role_slice(lde.staging_role())?;
                    Ok(unsafe { role.as_u32_ptr().add(lde.role_offset_words()) as usize })
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut uploads = vec![
            upload_u32(prepared.batch_terms, candidate.term_descriptors().to_vec()),
            upload_u64(
                prepared.batch_group_offsets,
                candidate.packed_group_row_offsets().to_vec(),
            ),
            upload_ptrs(prepared.batch_source_ptrs, source_pointers),
        ];
        match (
            prepared.coefficient_output_ptrs,
            coefficient_output_pointers.is_empty(),
        ) {
            (Some(slot), false) => uploads.push(upload_ptrs(slot, coefficient_output_pointers)),
            (None, true) => {}
            _ => {
                return Err(
                    QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                        "staged coefficient outputs and pointer-table presence differ",
                    ),
                )
            }
        }
        upload_and_sync(arena, &uploads)?;
        prepared.schedule = PreparedNumeratorSchedule::StagedPackedSingleWrite {
            packed_output_rows: candidate.packed_output_rows(),
        };
        Ok(prepared)
    }

    /// Staged direct-group schedule. Every captured launch owns one exact group
    /// and receives its term range and output pointers as scalar facts.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_staged_group_direct(
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
        overflow_roles: &[ArenaSlice],
    ) -> Result<Self, QuotientNumeratorStagedSingleWriteError> {
        let topology = columns
            .iter()
            .map(QuotientNumeratorColumnTopology::from)
            .collect::<Vec<_>>();
        let canonical = build_plan(config, &topology)?;
        let overflow_capacities = overflow_roles
            .iter()
            .map(|role| role.len_words())
            .collect::<Vec<_>>();
        let candidate = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
            config,
            &topology,
            &overflow_capacities,
        )?;
        let group_log_sizes = candidate
            .requirements()
            .groups
            .iter()
            .map(|group| group.log_size)
            .collect::<Vec<_>>();
        let ranges = derive_group_direct_ranges(
            candidate.group_offsets(),
            candidate.term_descriptors(),
            &group_log_sizes,
        )?;
        validate_group_direct_representatives(&ranges, &canonical)?;
        let mut prepared = Self::prepare_staged_packed_single_write_from_plan(
            arena,
            config,
            columns,
            oods_sample_points,
            oods_sample_values,
            random_coefficient,
            sample_points_destination,
            first_linear_terms_destination,
            destinations,
            forward_twiddles,
            slots,
            overflow_roles,
            &canonical,
            &candidate,
        )?;
        if candidate.requirements() != prepared.requirements()
            || ranges.len() != prepared.requirements.groups.len()
        {
            return Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "direct group manifest differs from staged packed ownership",
                ),
            );
        }
        let expected_packed_schedule = PreparedNumeratorSchedule::StagedPackedSingleWrite {
            packed_output_rows: candidate.packed_output_rows(),
        };
        if prepared.schedule != expected_packed_schedule
            || prepared.group_direct_ranges.is_some()
            || prepared.group_direct_run_sum.is_some()
        {
            return Err(
                PreparedQuotientNumeratorError::GroupDirectScheduleInvariant(
                    "staged packed preparation did not yield an unclaimed direct schedule",
                )
                .into(),
            );
        }
        prepared.group_direct_ranges = Some(ranges);
        prepared.schedule = PreparedNumeratorSchedule::StagedGroupDirect {
            output_rows: candidate.packed_output_rows(),
        };
        prepared.bind_group_direct_run_sum(&candidate, columns, overflow_roles)?;
        Ok(prepared)
    }

    pub(super) fn launch_single_write_candidate(
        &self,
        group_offsets: ArenaSlice,
        group_count: u32,
        max_output_size: u32,
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        let output_table = |coordinate: usize| unsafe {
            self.output_ptrs
                .as_u32_ptr()
                .cast::<*mut u32>()
                .add(coordinate * self.requirements.groups.len())
        };
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_single_write_on(
                group_offsets.as_u32_ptr(),
                self.batch_terms.as_u32_ptr(),
                group_count,
                max_output_size,
                self.batch_source_ptrs.as_u32_ptr().cast(),
                self.line_coefficients.as_u32_ptr().cast(),
                self.output_log_sizes.as_u32_ptr(),
                output_table(0),
                output_table(1),
                output_table(2),
                output_table(3),
                stream,
            )
        };
        check_cuda("prepared_quotient_numerator_single_write", code)?;
        Ok(())
    }

    pub(super) fn launch_packed_single_write(
        &self,
        packed_output_rows: u64,
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        let group_count = u32::try_from(self.requirements.groups.len()).map_err(|_| {
            PreparedQuotientNumeratorError::TooManyGroups(self.requirements.groups.len())
        })?;
        let output_table = |coordinate: usize| unsafe {
            self.output_ptrs
                .as_u32_ptr()
                .cast::<*mut u32>()
                .add(coordinate * self.requirements.groups.len())
        };
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_packed_single_write_on(
                self.batch_group_offsets.as_u32_ptr().cast(),
                self.group_offsets.as_u32_ptr(),
                self.batch_terms.as_u32_ptr(),
                group_count,
                packed_output_rows,
                self.batch_source_ptrs.as_u32_ptr().cast(),
                self.line_coefficients.as_u32_ptr().cast(),
                self.output_log_sizes.as_u32_ptr(),
                output_table(0),
                output_table(1),
                output_table(2),
                output_table(3),
                stream,
            )
        };
        check_cuda("prepared_quotient_numerator_packed_single_write", code)?;
        Ok(())
    }

    pub(super) fn launch_group_direct(
        &self,
        ranges: &[PreparedGroupDirectRange],
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        self.launch_group_direct_variant(ranges, stream, GroupDirectLaunch::Direct)
    }

    pub(super) fn launch_group_direct_span(
        &self,
        ranges: &[PreparedGroupDirectRange],
        groups: Range<usize>,
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        self.launch_group_direct_variant_span(ranges, groups, stream, GroupDirectLaunch::Direct)
    }

    pub(super) fn launch_group_direct_tiled(
        &self,
        ranges: &[PreparedGroupDirectRange],
        tile_words: u32,
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        self.launch_group_direct_variant(ranges, stream, GroupDirectLaunch::RawTiled(tile_words))
    }

    pub(super) fn launch_group_direct_contribution_tiled(
        &self,
        ranges: &[PreparedGroupDirectRange],
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        self.launch_group_direct_variant(ranges, stream, GroupDirectLaunch::ContributionTiled)
    }

    fn launch_group_direct_variant(
        &self,
        ranges: &[PreparedGroupDirectRange],
        stream: *mut c_void,
        variant: GroupDirectLaunch,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        self.launch_group_direct_variant_span(ranges, 0..ranges.len(), stream, variant)
    }

    fn launch_group_direct_variant_span(
        &self,
        ranges: &[PreparedGroupDirectRange],
        groups: Range<usize>,
        stream: *mut c_void,
        variant: GroupDirectLaunch,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        if ranges.len() != self.requirements.groups.len()
            || ranges.len() != self.destinations.len()
            || groups.start > groups.end
            || groups.end > ranges.len()
        {
            return Err(
                PreparedQuotientNumeratorError::GroupDirectScheduleInvariant(
                    "group-direct range, group, destination, and span shapes differ",
                ),
            );
        }
        for group_index in groups {
            let range = &ranges[group_index];
            let group = &self.requirements.groups[group_index];
            let destination = &self.destinations[group_index];
            let code = unsafe {
                let descriptors = self.batch_terms.as_u32_ptr();
                let sources = self.batch_source_ptrs.as_u32_ptr().cast();
                let coefficients = self.line_coefficients.as_u32_ptr().cast();
                let group_b = self
                    .line_coefficients
                    .as_u32_ptr()
                    .add(range.group_b_term as usize * LINE_COEFFICIENT_WORDS)
                    .cast();
                match variant {
                    GroupDirectLaunch::Direct => {
                        stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_group_direct_on(
                            descriptors,
                            range.term_begin,
                            range.term_end,
                            group.log_size,
                            sources,
                            coefficients,
                            group_b,
                            destination.coordinates[0].as_u32_ptr(),
                            destination.coordinates[1].as_u32_ptr(),
                            destination.coordinates[2].as_u32_ptr(),
                            destination.coordinates[3].as_u32_ptr(),
                            stream,
                        )
                    }
                    GroupDirectLaunch::RawTiled(tile_words) => {
                        stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_group_direct_tiled_on(
                            descriptors,
                            range.term_begin,
                            range.term_end,
                            group.log_size,
                            sources,
                            coefficients,
                            group_b,
                            destination.coordinates[0].as_u32_ptr(),
                            destination.coordinates[1].as_u32_ptr(),
                            destination.coordinates[2].as_u32_ptr(),
                            destination.coordinates[3].as_u32_ptr(),
                            tile_words,
                            stream,
                        )
                    }
                    GroupDirectLaunch::ContributionTiled => {
                        stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_group_direct_contribution_tiled_on(
                        descriptors,
                        range.term_begin,
                        range.term_end,
                        group.log_size,
                        sources,
                        coefficients,
                        group_b,
                        destination.coordinates[0].as_u32_ptr(),
                        destination.coordinates[1].as_u32_ptr(),
                        destination.coordinates[2].as_u32_ptr(),
                        destination.coordinates[3].as_u32_ptr(),
                        stream,
                    )
                    }
                }
            };
            check_cuda(
                match variant {
                    GroupDirectLaunch::Direct => "prepared_quotient_numerator_group_direct",
                    GroupDirectLaunch::RawTiled(_) => {
                        "prepared_quotient_numerator_group_direct_tiled"
                    }
                    GroupDirectLaunch::ContributionTiled => {
                        "prepared_quotient_numerator_group_direct_contribution_tiled"
                    }
                },
                code,
            )?;
        }
        Ok(())
    }
}

fn validate_staged_overflow_role_ids(
    workspace_ids: &BTreeSet<ArenaSlotId>,
    external_ids: &BTreeSet<ArenaSlotId>,
    overflow_roles: &[ArenaSlice],
) -> Result<(), QuotientNumeratorStagedSingleWriteError> {
    let mut role_ids = BTreeSet::new();
    for role in overflow_roles {
        if workspace_ids.contains(&role.id()) {
            return Err(PreparedQuotientNumeratorError::ExternalAliasesWorkspace(role.id()).into());
        }
        if external_ids.contains(&role.id()) || !role_ids.insert(role.id()) {
            return Err(PreparedQuotientNumeratorError::AliasedExternalSlot(role.id()).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod staged_binding_tests {
    use stwo::core::circle::CirclePoint;
    use stwo::core::fields::qm31::SecureField;

    use super::*;

    #[test]
    fn group_direct_upload_and_binding_share_one_candidate_object() {
        let source = include_str!("single_write.rs");
        let start = source.find("pub fn prepare_staged_group_direct").unwrap();
        let end = source[start..]
            .find("pub(super) fn launch_single_write_candidate")
            .map(|offset| start + offset)
            .unwrap();
        let direct = &source[start..end];
        assert!(direct.contains("prepare_staged_packed_single_write_from_plan"));
        assert!(!direct.contains("Self::prepare_staged_packed_single_write("));

        let helper_start = source
            .find("fn prepare_staged_packed_single_write_from_plan")
            .unwrap();
        let helper_end = source[helper_start..]
            .find("/// Staged direct-group schedule")
            .map(|offset| helper_start + offset)
            .unwrap();
        let helper = &source[helper_start..helper_end];
        assert!(helper.contains("candidate.term_descriptors().to_vec()"));
        assert!(helper.contains("candidate.packed_group_row_offsets().to_vec()"));
    }

    #[test]
    fn group_b_representative_is_sealed_to_canonical_first_term() {
        let point = CirclePoint {
            x: SecureField::from(0),
            y: SecureField::from(0),
        };
        let topology = [4, 4, 6]
            .into_iter()
            .enumerate()
            .map(
                |(input_index, coefficient_log_size)| QuotientNumeratorColumnTopology {
                    coefficient_log_size,
                    source_kind: QuotientNumeratorSourceKind::Evaluation,
                    samples: vec![QuotientOodsSample {
                        input_index: input_index as u32,
                        shape_point: point,
                    }],
                },
            )
            .collect::<Vec<_>>();
        let config = QuotientNumeratorWorkspaceConfig {
            lifting_log_size: 30,
            log_blowup_factor: 1,
            max_lde_tile_words: 32usize << 30,
        };
        let canonical = build_plan(config, &topology).unwrap();
        let staged = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
            config,
            &topology,
            &[usize::MAX],
        )
        .unwrap();
        let mut ranges = derive_group_direct_ranges(
            staged.group_offsets(),
            staged.term_descriptors(),
            &staged
                .requirements()
                .groups
                .iter()
                .map(|group| group.log_size)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        validate_group_direct_representatives(&ranges, &canonical).unwrap();
        ranges[0].group_b_term ^= 1;
        assert!(matches!(
            validate_group_direct_representatives(&ranges, &canonical),
            Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "direct group-B representative differs from canonical ownership"
                )
            )
        ));
    }

    #[test]
    fn direct_group_ranges_choose_minimum_global_term() {
        let descriptors = [0, 8, 0, 1, 2, 1, 2, 5, 1];
        let ranges = derive_group_direct_ranges(&[0, 3], &descriptors, &[1]).unwrap();
        let range = ranges[0];
        assert_eq!(
            [range.term_begin, range.term_end, range.group_b_term],
            [0, 3, 2]
        );
    }

    #[test]
    fn direct_group_ranges_seal_monotone_source_log_runs_per_group() {
        let descriptors = [0, 8, 3, 1, 2, 4, 2, 5, 2, 3, 7, 2];
        let ranges = derive_group_direct_ranges(&[0, 2, 4], &descriptors, &[4, 2]).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].term_begin, 0);
        assert_eq!(ranges[0].term_end, 2);
        assert_eq!(ranges[1].term_begin, 2);
        assert_eq!(ranges[1].term_end, 4);

        assert!(matches!(
            derive_group_direct_ranges(&[0, 3], &descriptors[..9], &[4]),
            Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "direct group source logs are not monotone"
                )
            )
        ));
    }

    #[test]
    fn direct_group_ranges_bound_source_logs_and_admit_scalar_group() {
        let scalar = [0, 4, 0];
        assert!(derive_group_direct_ranges(&[0, 1], &scalar, &[0]).is_ok());

        let out_of_bounds = [0, 4, 2];
        assert!(matches!(
            derive_group_direct_ranges(&[0, 1], &out_of_bounds, &[1]),
            Err(
                QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(
                    "direct descriptor source log exceeds its group"
                )
            )
        ));
        assert!(derive_group_direct_ranges(&[0, 1], &scalar, &[]).is_err());
    }

    #[test]
    fn direct_group_ranges_reject_malformed_manifests() {
        let descriptors = [0, 8, 0, 1, 2, 0, 2, 5, 0];
        for (offsets, terms) in [
            (&[][..], &[][..]),
            (&[1][..], &[][..]),
            (&[0][..], &[0, 8][..]),
            (&[0, 2][..], &descriptors[..]),
            (&[0, 0][..], &[][..]),
            (&[0, 4, 3][..], &descriptors[..]),
            (&[0, 2, 1, 3][..], &descriptors[..]),
        ] {
            let group_log_sizes = vec![0; offsets.len().saturating_sub(1)];
            assert!(matches!(
                derive_group_direct_ranges(offsets, terms, &group_log_sizes),
                Err(QuotientNumeratorStagedSingleWriteError::DescriptorInvariant(_))
            ));
        }
    }

    #[test]
    fn overflow_roles_reject_source_destination_and_twiddle_aliases() {
        let workspace_ids = BTreeSet::new();
        let source = ArenaSlice::dangling_for_test(11, 16);
        let destination = ArenaSlice::dangling_for_test(12, 16);
        let twiddles = ArenaSlice::dangling_for_test(13, 16);
        for external in [source, destination, twiddles] {
            let id = external.id();
            let external_ids = BTreeSet::from([id]);
            assert!(matches!(
                validate_staged_overflow_role_ids(&workspace_ids, &external_ids, &[external]),
                Err(QuotientNumeratorStagedSingleWriteError::Base(
                    PreparedQuotientNumeratorError::AliasedExternalSlot(actual)
                )) if actual == id
            ));
        }
    }

    #[test]
    fn overflow_roles_reject_workspace_and_role_aliases() {
        let workspace_id = ArenaSlotId(21);
        let workspace_ids = BTreeSet::from([workspace_id]);
        let workspace_role = ArenaSlice::dangling_for_test(21, 16);
        assert!(matches!(
            validate_staged_overflow_role_ids(&workspace_ids, &BTreeSet::new(), &[workspace_role]),
            Err(QuotientNumeratorStagedSingleWriteError::Base(
                PreparedQuotientNumeratorError::ExternalAliasesWorkspace(actual)
            )) if actual == workspace_id
        ));

        let duplicate = ArenaSlice::dangling_for_test(22, 16);
        assert!(matches!(
            validate_staged_overflow_role_ids(
                &BTreeSet::new(),
                &BTreeSet::new(),
                &[duplicate, duplicate],
            ),
            Err(QuotientNumeratorStagedSingleWriteError::Base(
                PreparedQuotientNumeratorError::AliasedExternalSlot(ArenaSlotId(22))
            ))
        ));
    }
}
