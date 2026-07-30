//! Test-only prepared binding for the prepacked quotient hot loop.

use core::ffi::c_void;

use super::*;
use crate::backend::quotient_numerator_prepacked_terms::{
    quotient_numerator_prepacked_plan_identity, quotient_numerator_prepacked_term_layout,
};
use crate::backend::quotient_numerator_staged_single_write::{
    quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    QuotientNumeratorStagedSingleWriteError,
};

impl<'a> PreparedQuotientNumeratorGraph<'a> {
    /// Test-only hot-loop replacement over the exact staged source manifest.
    ///
    /// The preparation kernel runs after group finalization, the last reader of
    /// `term_points`, and reuses only that dead extent. Production constructors
    /// do not select this schedule. Call [`Self::observe_prepacked_status`]
    /// after eager completion or every captured replay before accepting output.
    /// The quotient launch must therefore end its graph segment: embedding
    /// downstream commitments in the same graph would consume output before
    /// the host can observe the fail-closed status.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_staged_prepacked_single_write_candidate(
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
        let overflow_capacities = overflow_roles
            .iter()
            .map(|role| role.len_words())
            .collect::<Vec<_>>();
        let plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
            config,
            &topology,
            &overflow_capacities,
        )?;
        let layout = quotient_numerator_prepacked_term_layout(&plan)
            .map_err(PreparedQuotientNumeratorError::from)?;
        let plan_identity = quotient_numerator_prepacked_plan_identity(&plan)
            .map_err(PreparedQuotientNumeratorError::from)?;
        let source_count = u32::try_from(plan.sources().len())
            .map_err(|_| PreparedQuotientNumeratorError::SizeOverflow)?;
        let used_words = u64::try_from(layout.used_words)
            .map_err(|_| PreparedQuotientNumeratorError::SizeOverflow)?;
        let packed_output_rows = plan.packed_output_rows();

        let mut prepared = Self::prepare_staged_packed_single_write(
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
        )?;
        if prepared.schedule
            != (PreparedNumeratorSchedule::StagedPackedSingleWrite { packed_output_rows })
        {
            return Err(PreparedQuotientNumeratorError::PrepackedScheduleInvariant(
                "staged runtime and prepacked plan differ",
            )
            .into());
        }
        prepared.prepacked = Some(PreparedPrepackedBinding {
            receipt: PreparedPrepackedQuotientNumeratorReceipt {
                plan_identity,
                source_count,
                used_words,
                status_offset_words: layout.status_offset_words,
            },
        });
        prepared.schedule =
            PreparedNumeratorSchedule::StagedPrepackedSingleWrite { packed_output_rows };
        Ok(prepared)
    }

    pub(super) fn prepare_prepacked_terms(
        &self,
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        let binding =
            self.prepacked
                .ok_or(PreparedQuotientNumeratorError::PrepackedScheduleInvariant(
                    "prepacked schedule has no sealed binding",
                ))?;
        let group_count = u32::try_from(self.requirements.groups.len()).map_err(|_| {
            PreparedQuotientNumeratorError::TooManyGroups(self.requirements.groups.len())
        })?;
        let term_count = u32::try_from(self.requirements.term_count).map_err(|_| {
            PreparedQuotientNumeratorError::TooManyTerms(self.requirements.term_count)
        })?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_prepare_quotient_numerator_prepacked_terms_on(
                self.group_offsets.as_u32_ptr(),
                self.batch_terms.as_u32_ptr(),
                group_count,
                term_count,
                self.batch_source_ptrs.as_u32_ptr().cast(),
                binding.receipt.source_count,
                self.line_coefficients.as_u32_ptr().cast(),
                self.term_points.as_u32_ptr(),
                binding.receipt.used_words,
                stream,
            )
        };
        check_cuda("prepared_quotient_numerator_prepacked_terms", code)?;
        Ok(())
    }

    pub(super) fn launch_prepacked_single_write(
        &self,
        packed_output_rows: u64,
        stream: *mut c_void,
    ) -> Result<(), PreparedQuotientNumeratorError> {
        let binding =
            self.prepacked
                .ok_or(PreparedQuotientNumeratorError::PrepackedScheduleInvariant(
                    "prepacked schedule has no sealed binding",
                ))?;
        let group_count = u32::try_from(self.requirements.groups.len()).map_err(|_| {
            PreparedQuotientNumeratorError::TooManyGroups(self.requirements.groups.len())
        })?;
        let term_count = u32::try_from(self.requirements.term_count).map_err(|_| {
            PreparedQuotientNumeratorError::TooManyTerms(self.requirements.term_count)
        })?;
        let output_table = |coordinate: usize| unsafe {
            self.output_ptrs
                .as_u32_ptr()
                .cast::<*mut u32>()
                .add(coordinate * self.requirements.groups.len())
        };
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::
                stwo_accumulate_quotient_numerator_prepacked_single_write_on(
                    self.batch_group_offsets.as_u32_ptr().cast(),
                    self.group_offsets.as_u32_ptr(),
                    group_count,
                    term_count,
                    packed_output_rows,
                    self.term_points.as_u32_ptr(),
                    binding.receipt.used_words,
                    self.output_log_sizes.as_u32_ptr(),
                    output_table(0),
                    output_table(1),
                    output_table(2),
                    output_table(3),
                    stream,
                )
        };
        check_cuda("prepared_quotient_numerator_prepacked_single_write", code)?;
        Ok(())
    }

    /// Status fence for the test-only prepacked schedule.
    ///
    /// This copies one word and synchronizes the proof stream. The captured
    /// schedule resets that word before every replay; callers must obtain `Ok`
    /// here at the quotient boundary before reading, committing, or otherwise
    /// consuming any candidate output.
    ///
    /// The stack destination may be pageable: the existing copy helper can
    /// stage that transfer, and the immediate stream sync completes it before
    /// the stack word is read or dropped. This boundary path does not claim
    /// overlap with device work.
    #[doc(hidden)]
    pub fn observe_prepacked_status(&self) -> Result<(), PreparedQuotientNumeratorError> {
        let binding =
            self.prepacked
                .ok_or(PreparedQuotientNumeratorError::PrepackedScheduleInvariant(
                    "status observation requires the prepacked schedule",
                ))?;
        let mut status = 0u32;
        let source = unsafe {
            self.term_points
                .as_u32_ptr()
                .add(binding.receipt.status_offset_words)
        };
        unsafe {
            self.arena.context().memcpy_d2h_async(
                (&mut status as *mut u32).cast(),
                source.cast(),
                core::mem::size_of::<u32>(),
            )?;
        }
        self.arena.context().sync()?;
        if status != 0 {
            return Err(PreparedQuotientNumeratorError::PrepackedDeviceStatus(
                status,
            ));
        }
        Ok(())
    }
}
