//! Dormant native-domain run-sum binding and launch.

use core::ffi::c_void;

use super::*;
use crate::backend::quotient_numerator_run_sum::{
    quotient_numerator_run_sum_plan, QuotientNumeratorRunSumError,
    QuotientNumeratorRunSumExpansionEntry, QuotientNumeratorRunSumExpansionManifest,
    QuotientNumeratorRunSumLiveness, QuotientNumeratorRunSumReceipt,
};
use crate::backend::quotient_numerator_staged_single_write::QuotientNumeratorStagedSingleWritePlan;

#[derive(Clone)]
pub(super) struct PreparedRunSumBinding {
    pub(super) receipt: QuotientNumeratorRunSumReceipt,
    target_group_b_term: u32,
    raw_manifest: stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunManifest,
}

#[derive(Clone, Copy)]
struct RunSumLiveSlice {
    slice: ArenaSlice,
    destination: Option<(usize, usize)>,
}

struct RunSumScheduleProof {
    liveness: QuotientNumeratorRunSumLiveness,
}

const _: () = assert!(
    core::mem::size_of::<QuotientNumeratorRunSumExpansionEntry>()
        == core::mem::size_of::<stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunEntry>()
);
const _: () = assert!(
    core::mem::align_of::<QuotientNumeratorRunSumExpansionEntry>()
        == core::mem::align_of::<stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunEntry>()
);
const _: () = assert!(
    core::mem::size_of::<QuotientNumeratorRunSumExpansionManifest>()
        == core::mem::size_of::<stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunManifest>()
);
const _: () = assert!(
    core::mem::align_of::<QuotientNumeratorRunSumExpansionManifest>()
        == core::mem::align_of::<stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunManifest>()
);
const _: () = assert!(
    core::mem::offset_of!(QuotientNumeratorRunSumExpansionManifest, entries)
        == core::mem::offset_of!(
            stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunManifest,
            runs
        )
);

fn raw_manifest(
    manifest: &QuotientNumeratorRunSumExpansionManifest,
) -> stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunManifest {
    let mut raw = stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunManifest {
        run_count: manifest.run_count,
        direct_term_begin: manifest.direct_term_begin,
        direct_term_end: manifest.direct_term_end,
        target_log_size: manifest.target_group_log_size,
        ..Default::default()
    };
    for (destination, source) in raw.runs.iter_mut().zip(&manifest.entries) {
        *destination = stwo_backend_cuda_kernels::raw::CudaQuotientNativeRunEntry {
            term_begin: source.term_begin,
            term_end: source.term_end,
            source_log_size: source.source_log_size,
            scratch_offset_words: source.scratch_offset_words,
        };
    }
    raw
}

fn checked_byte_range(
    slice: ArenaSlice,
    len_words: usize,
) -> Result<(usize, usize), PreparedQuotientNumeratorError> {
    if len_words > slice.len_words() {
        return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
            "run-sum physical range exceeds its bound slice",
        ));
    }
    let bytes = len_words
        .checked_mul(WORD_BYTES)
        .ok_or(PreparedQuotientNumeratorError::SizeOverflow)?;
    let start = slice.as_u32_ptr() as usize;
    let end = start
        .checked_add(bytes)
        .ok_or(PreparedQuotientNumeratorError::SizeOverflow)?;
    Ok((start, end))
}

fn scratch_is_physically_disjoint(
    victim_group: usize,
    scratch_words: usize,
    destinations: &[QuotientNumeratorDestination],
    live_slices: &[RunSumLiveSlice],
) -> Result<bool, PreparedQuotientNumeratorError> {
    let victim = destinations.get(victim_group).ok_or(
        PreparedQuotientNumeratorError::RunSumScheduleInvariant(
            "run-sum victim destination is missing",
        ),
    )?;
    for (coordinate, scratch) in victim.coordinates.iter().copied().enumerate() {
        let scratch_range = checked_byte_range(scratch, scratch_words)?;
        for live in live_slices {
            if live.destination == Some((victim_group, coordinate)) {
                continue;
            }
            let live_range = checked_byte_range(live.slice, live.slice.len_words())?;
            if scratch_range.0 < live_range.1 && live_range.0 < scratch_range.1 {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn live_slices(
    prepared: &PreparedQuotientNumeratorGraph<'_>,
    columns: &[QuotientNumeratorColumn],
    overflow_roles: &[ArenaSlice],
) -> Vec<RunSumLiveSlice> {
    let mut live = Vec::new();
    for slice in [
        prepared.oods_sample_points,
        prepared.oods_sample_values,
        prepared.random_coefficient,
        prepared.sample_points_destination,
        prepared.first_linear_terms_destination,
        prepared.forward_twiddles,
        prepared.runtime_terms,
        prepared.group_term_indices,
        prepared.group_offsets,
        prepared.line_coefficients,
        prepared.term_points,
        prepared.batch_terms,
        prepared.batch_group_offsets,
        prepared.batch_source_ptrs,
        prepared.output_ptrs,
        prepared.output_log_sizes,
    ]
    .into_iter()
    .chain(prepared.coefficient_ptrs)
    .chain(prepared.coefficient_sizes)
    .chain(prepared.coefficient_output_ptrs)
    .chain(prepared.lde_tile)
    .chain(columns.iter().map(|column| column.source.slice()))
    .chain(overflow_roles.iter().copied())
    {
        live.push(RunSumLiveSlice {
            slice,
            destination: None,
        });
    }
    for (group, destination) in prepared.destinations.iter().enumerate() {
        for (coordinate, slice) in destination.coordinates.iter().copied().enumerate() {
            live.push(RunSumLiveSlice {
                slice,
                destination: Some((group, coordinate)),
            });
        }
    }
    live
}

impl RunSumScheduleProof {
    fn seal(
        staged: &QuotientNumeratorStagedSingleWritePlan,
        ranges: &[PreparedGroupDirectRange],
        destinations: &[QuotientNumeratorDestination],
        target_group: usize,
        victim_group: usize,
    ) -> Result<Self, PreparedQuotientNumeratorError> {
        let groups = &staged.requirements().groups;
        if ranges.len() != groups.len()
            || destinations.len() != groups.len()
            || target_group >= groups.len()
            || victim_group >= groups.len()
            || target_group >= victim_group
        {
            return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                "run-sum schedule has invalid group ownership",
            ));
        }
        let descriptors = staged.term_descriptors();
        if descriptors.len() % BATCH_TERM_WORDS != 0 {
            return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                "run-sum schedule descriptors are not word aligned",
            ));
        }
        let term_count = u32::try_from(descriptors.len() / BATCH_TERM_WORDS)
            .map_err(|_| PreparedQuotientNumeratorError::SizeOverflow)?;
        if ranges.first().map(|range| range.term_begin) != Some(0)
            || ranges.last().map(|range| range.term_end) != Some(term_count)
            || ranges
                .iter()
                .any(|range| range.term_begin >= range.term_end)
            || ranges
                .windows(2)
                .any(|pair| pair[0].term_end != pair[1].term_begin)
        {
            return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                "run-sum schedule is not one canonical group span",
            ));
        }

        let mut destination_ids = BTreeSet::new();
        for (group, (requirement, destination)) in groups.iter().zip(destinations).enumerate() {
            let logical_words = 1usize
                .checked_shl(requirement.log_size)
                .ok_or(PreparedQuotientNumeratorError::SizeOverflow)?;
            if destination.log_size != requirement.log_size
                || requirement.value_words != logical_words
            {
                return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                    "run-sum destination is not a full logical group image",
                ));
            }
            for coordinate in destination.coordinates {
                if coordinate.len_words() < logical_words {
                    return Err(PreparedQuotientNumeratorError::InputTooSmall {
                        slot: coordinate.id(),
                        required_words: logical_words,
                        actual_words: coordinate.len_words(),
                    });
                }
                if !destination_ids.insert(coordinate.id()) {
                    return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                        "run-sum destination identities are not unique",
                    ));
                }
            }
            if ranges[group].term_begin != staged.group_offsets()[group]
                || ranges[group].term_end != staged.group_offsets()[group + 1]
            {
                return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                    "run-sum direct ranges differ from the staged object",
                ));
            }
        }

        let capacities = std::array::from_fn(|coordinate| {
            destinations[victim_group].coordinates[coordinate]
                .len_words()
                .min(groups[victim_group].value_words)
        });
        Ok(Self {
            // Construction is private to the prepared StagedGroupDirect
            // schedule. Its launch walks group indices on the arena stream,
            // substitutes target in place, overwrites the later victim once,
            // and returns only after all remaining producers are enqueued.
            liveness: QuotientNumeratorRunSumLiveness {
                same_stream_canonical_group_order: true,
                external_destination_ids_unique: true,
                victim_unread_before_own_producer: true,
                victim_fully_overwritten_by_own_producer: true,
                downstream_consumers_after_all_group_producers: true,
                victim_coordinate_capacity_words: capacities,
            },
        })
    }

    fn liveness(&self) -> QuotientNumeratorRunSumLiveness {
        self.liveness
    }
}

fn select_binding(
    staged: &QuotientNumeratorStagedSingleWritePlan,
    ranges: &[PreparedGroupDirectRange],
    destinations: &[QuotientNumeratorDestination],
    live_slices: &[RunSumLiveSlice],
) -> Result<Option<PreparedRunSumBinding>, PreparedQuotientNumeratorError> {
    let groups = &staged.requirements().groups;
    if ranges.len() != groups.len() || destinations.len() != groups.len() {
        return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
            "run-sum range, group, and destination counts differ",
        ));
    }

    for target_group in 0..groups.len() {
        for victim_group in target_group + 1..groups.len() {
            let proof = RunSumScheduleProof::seal(
                staged,
                ranges,
                destinations,
                target_group,
                victim_group,
            )?;
            let capacities = proof.liveness().victim_coordinate_capacity_words;
            let receipt = match quotient_numerator_run_sum_plan(
                staged,
                target_group,
                victim_group,
                proof.liveness(),
            ) {
                Ok(receipt) => receipt,
                Err(error) if run_sum_shape_is_ineligible(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let range = ranges[target_group];
            if receipt.target_term_begin != range.term_begin
                || receipt.target_term_end != range.term_end
                || receipt.target_group_log_size != groups[target_group].log_size
                || receipt.victim_group_log_size != groups[victim_group].log_size
                || receipt.victim_coordinate_capacity_words != capacities
            {
                return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                    "run-sum receipt differs from sealed direct ownership",
                ));
            }
            if !scratch_is_physically_disjoint(
                victim_group,
                receipt.scratch_words_per_coordinate,
                destinations,
                live_slices,
            )? {
                continue;
            }
            if receipt.add_units_saved == 0 {
                continue;
            }
            return Ok(Some(PreparedRunSumBinding {
                target_group_b_term: range.group_b_term,
                raw_manifest: raw_manifest(&receipt.manifest),
                receipt,
            }));
        }
    }
    Ok(None)
}

fn run_sum_shape_is_ineligible(error: &QuotientNumeratorRunSumError) -> bool {
    matches!(
        error,
        QuotientNumeratorRunSumError::UnsupportedAggregatedSourceLogZero
            | QuotientNumeratorRunSumError::SingletonAggregatedRun { .. }
            | QuotientNumeratorRunSumError::TooManyRuns { .. }
            | QuotientNumeratorRunSumError::VictimCoordinateTooSmall { .. }
            | QuotientNumeratorRunSumError::DescriptorInvariant(
                "target has no reusable lower-log run"
                    | "target has no nonempty terminal full-domain direct suffix"
            )
    )
}

impl PreparedQuotientNumeratorGraph<'_> {
    pub(super) fn bind_group_direct_run_sum(
        &mut self,
        staged: &QuotientNumeratorStagedSingleWritePlan,
        columns: &[QuotientNumeratorColumn],
        overflow_roles: &[ArenaSlice],
    ) -> Result<(), PreparedQuotientNumeratorError> {
        if !matches!(
            self.schedule,
            PreparedNumeratorSchedule::StagedGroupDirect { .. }
        ) {
            return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                "run-sum binding requires the sealed group-direct schedule",
            ));
        }
        let live = live_slices(self, columns, overflow_roles);
        let ranges = self.group_direct_ranges.as_deref().ok_or(
            PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                "run-sum binding requires sealed direct ranges",
            ),
        )?;
        self.group_direct_run_sum = select_binding(staged, ranges, &self.destinations, &live)?;
        Ok(())
    }

    pub(super) fn validate_group_direct_run_sum(
        &self,
    ) -> Result<bool, PreparedQuotientNumeratorError> {
        let ranges = self.group_direct_ranges.as_deref().ok_or(
            PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                "run-sum candidate has no sealed direct ranges",
            ),
        )?;
        let Some(binding) = self.group_direct_run_sum.as_ref() else {
            return Ok(false);
        };
        let receipt = &binding.receipt;
        if receipt.target_group >= ranges.len()
            || receipt.victim_group >= ranges.len()
            || receipt.target_group >= receipt.victim_group
        {
            return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                "run-sum receipt has invalid target/victim ownership",
            ));
        }
        let target = ranges[receipt.target_group];
        if target.term_begin != receipt.target_term_begin
            || target.term_end != receipt.target_term_end
            || target.group_b_term != binding.target_group_b_term
        {
            return Err(PreparedQuotientNumeratorError::RunSumScheduleInvariant(
                "run-sum receipt no longer matches direct ownership",
            ));
        }
        Ok(true)
    }

    pub(super) fn launch_bound_group_direct_run_sum(
        &self,
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        let binding = self
            .group_direct_run_sum
            .as_ref()
            .expect("validated run-sum binding");
        let receipt = &binding.receipt;
        let ranges = self
            .group_direct_ranges
            .as_deref()
            .expect("validated run-sum ranges");
        let victim = &self.destinations[receipt.victim_group];

        for group_index in 0..ranges.len() {
            if group_index != receipt.target_group {
                self.launch_group_direct_span(ranges, group_index..group_index + 1, stream)?;
                continue;
            }
            for run in receipt.manifest.active_entries() {
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_precompute_quotient_numerator_native_run_on(
                        self.batch_terms.as_u32_ptr(),
                        run.term_begin,
                        run.term_end,
                        run.source_log_size,
                        self.batch_source_ptrs.as_u32_ptr().cast(),
                        self.line_coefficients.as_u32_ptr().cast(),
                        victim.coordinates[0].as_u32_ptr(),
                        victim.coordinates[1].as_u32_ptr(),
                        victim.coordinates[2].as_u32_ptr(),
                        victim.coordinates[3].as_u32_ptr(),
                        run.scratch_offset_words,
                        stream,
                    )
                };
                check_cuda("prepared_quotient_numerator_native_run_precompute", code)?;
            }
            let target = &self.destinations[group_index];
            let group_b = unsafe {
                self.line_coefficients
                    .as_u32_ptr()
                    .add(binding.target_group_b_term as usize * LINE_COEFFICIENT_WORDS)
                    .cast()
            };
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_expand_quotient_numerator_native_run_sums_on(
                    &binding.raw_manifest,
                    self.batch_terms.as_u32_ptr(),
                    self.batch_source_ptrs.as_u32_ptr().cast(),
                    self.line_coefficients.as_u32_ptr().cast(),
                    group_b,
                    victim.coordinates[0].as_u32_ptr(),
                    victim.coordinates[1].as_u32_ptr(),
                    victim.coordinates[2].as_u32_ptr(),
                    victim.coordinates[3].as_u32_ptr(),
                    target.coordinates[0].as_u32_ptr(),
                    target.coordinates[1].as_u32_ptr(),
                    target.coordinates[2].as_u32_ptr(),
                    target.coordinates[3].as_u32_ptr(),
                    stream,
                )
            };
            check_cuda("prepared_quotient_numerator_native_run_expand", code)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use stwo::core::circle::{CirclePoint, SECURE_FIELD_CIRCLE_GEN};
    use stwo::core::fields::qm31::SecureField;

    use super::super::single_write::derive_group_direct_ranges;
    use super::*;
    use crate::backend::exec_context::{ArenaLayout, ArenaRangeSpec, ArenaSlotSpec};
    use crate::backend::prepared_quotient_numerator::{
        QuotientNumeratorColumnTopology, QuotientNumeratorSourceKind,
        QuotientNumeratorWorkspaceConfig, QuotientOodsSample,
    };
    use crate::backend::quotient_numerator_staged_single_write::quotient_numerator_staged_single_write_plan;

    fn staged() -> QuotientNumeratorStagedSingleWritePlan {
        let point = CirclePoint {
            x: SecureField::from(0),
            y: SecureField::from(0),
        };
        let mut topology = [4, 4, 6, 6, 8]
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
        topology.push(QuotientNumeratorColumnTopology {
            coefficient_log_size: 8,
            source_kind: QuotientNumeratorSourceKind::Evaluation,
            samples: vec![QuotientOodsSample {
                input_index: 5,
                shape_point: SECURE_FIELD_CIRCLE_GEN,
            }],
        });
        quotient_numerator_staged_single_write_plan(
            QuotientNumeratorWorkspaceConfig {
                lifting_log_size: 30,
                log_blowup_factor: 1,
                max_lde_tile_words: 32usize << 30,
            },
            &topology,
        )
        .unwrap()
    }

    fn ranges(staged: &QuotientNumeratorStagedSingleWritePlan) -> Vec<PreparedGroupDirectRange> {
        derive_group_direct_ranges(
            staged.group_offsets(),
            staged.term_descriptors(),
            &staged
                .requirements()
                .groups
                .iter()
                .map(|group| group.log_size)
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn destinations(
        staged: &QuotientNumeratorStagedSingleWritePlan,
    ) -> Vec<QuotientNumeratorDestination> {
        staged
            .requirements()
            .groups
            .iter()
            .enumerate()
            .map(|(group, requirement)| QuotientNumeratorDestination {
                log_size: requirement.log_size,
                coordinates: std::array::from_fn(|coordinate| {
                    let id = 100 + (group * 4 + coordinate) as u32;
                    ArenaSlice::dangling_at_for_test(
                        id,
                        1_024 + (group * 4 + coordinate) * 1_024,
                        requirement.value_words + 17,
                    )
                }),
            })
            .collect()
    }

    fn destination_live_slices(
        destinations: &[QuotientNumeratorDestination],
    ) -> Vec<RunSumLiveSlice> {
        destinations
            .iter()
            .enumerate()
            .flat_map(|(group, destination)| {
                destination
                    .coordinates
                    .into_iter()
                    .enumerate()
                    .map(move |(coordinate, slice)| RunSumLiveSlice {
                        slice,
                        destination: Some((group, coordinate)),
                    })
            })
            .collect()
    }

    #[test]
    fn selector_uses_logical_capacity_and_raw_manifest_is_semantically_exact() {
        let staged = staged();
        let ranges = ranges(&staged);
        let destinations = destinations(&staged);
        assert_eq!(destinations.len(), 2);
        let live = destination_live_slices(&destinations);
        let binding = select_binding(&staged, &ranges, &destinations, &live)
            .unwrap()
            .unwrap();
        assert_eq!(
            (binding.receipt.target_group, binding.receipt.victim_group),
            (0, 1)
        );
        assert_eq!(
            binding.receipt.victim_coordinate_capacity_words,
            [staged.requirements().groups[1].value_words; 4]
        );
        assert_eq!(
            binding.raw_manifest.run_count,
            binding.receipt.manifest.run_count
        );
        assert_eq!(
            binding.raw_manifest.direct_term_begin,
            binding.receipt.manifest.direct_term_begin
        );
        assert_eq!(
            binding.raw_manifest.direct_term_end,
            binding.receipt.manifest.direct_term_end
        );
        assert_eq!(
            binding.raw_manifest.target_log_size,
            binding.receipt.manifest.target_group_log_size
        );
        for (raw, semantic) in binding
            .raw_manifest
            .runs
            .iter()
            .zip(&binding.receipt.manifest.entries)
        {
            assert_eq!(
                [
                    raw.term_begin,
                    raw.term_end,
                    raw.source_log_size,
                    raw.scratch_offset_words,
                ],
                [
                    semantic.term_begin,
                    semantic.term_end,
                    semantic.source_log_size,
                    semantic.scratch_offset_words,
                ]
            );
        }
    }

    #[test]
    fn reused_physical_range_with_distinct_ids_withholds_binding() {
        const VICTIM: ArenaSlotId = ArenaSlotId(201);
        const ALIAS: ArenaSlotId = ArenaSlotId(202);
        let reused = [
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: VICTIM,
                    offset_words: 0,
                    len_words: 256,
                    alignment_words: 1,
                },
                live_mask: 0b01,
            },
            ArenaRangeSpec {
                slot: ArenaSlotSpec {
                    id: ALIAS,
                    offset_words: 0,
                    len_words: 256,
                    alignment_words: 1,
                },
                live_mask: 0b10,
            },
        ];
        let layout = unsafe { ArenaLayout::new_reused(256, &reused) }.unwrap();
        let slice = |id| {
            let spec = layout.slot(id).unwrap();
            ArenaSlice::dangling_at_for_test(id.0, spec.offset_words, spec.len_words)
        };

        let staged = staged();
        let ranges = ranges(&staged);
        let mut destinations = destinations(&staged);
        destinations[1].coordinates[0] = slice(VICTIM);
        let mut live = destination_live_slices(&destinations);
        live.push(RunSumLiveSlice {
            slice: slice(ALIAS),
            destination: None,
        });
        assert!(select_binding(&staged, &ranges, &destinations, &live)
            .unwrap()
            .is_none());
    }

    #[test]
    fn launch_source_keeps_precompute_at_target_and_has_no_hot_host_work() {
        let source = include_str!("run_sum.rs");
        let start = source
            .find("pub(super) fn launch_bound_group_direct_run_sum")
            .unwrap();
        let method = &source[start..source.find("\n#[cfg(test)]").unwrap()];
        let groups = method.find("for group_index in 0..ranges.len()").unwrap();
        let precompute = method
            .find("stwo_precompute_quotient_numerator_native_run_on")
            .unwrap();
        let expand = method
            .find("stwo_expand_quotient_numerator_native_run_sums_on")
            .unwrap();
        assert!(groups < precompute);
        assert!(precompute < expand);
        assert_eq!(
            method
                .matches("stwo_precompute_quotient_numerator_native_run_on")
                .count(),
            1
        );
        for forbidden in ["memcpy", "synchronize", "to_vec", "collect::<", "alloc"] {
            assert!(!method.contains(forbidden), "{forbidden}");
        }
        assert!(!run_sum_shape_is_ineligible(
            &QuotientNumeratorRunSumError::SizeOverflow
        ));
    }
}
