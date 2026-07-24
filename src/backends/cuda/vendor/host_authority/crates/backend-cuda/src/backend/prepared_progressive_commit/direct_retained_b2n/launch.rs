//! Stream-ordered launch surface for a prepared direct-retained graph.

use super::*;

impl PreparedDirectRetainedB2nGraph<'_> {
    pub fn launch(&self) -> Result<(), DirectRetainedB2nError> {
        for batch in &self.batches {
            self.launch_b2n_batch(*batch)?;
            self.launch_n2b_batch(*batch, false)?;
        }
        Ok(())
    }

    pub(in crate::backend::prepared_progressive_commit) fn launch_batch_materialized(
        &self,
        batch_index: u32,
    ) -> Result<(), DirectRetainedB2nError> {
        let batch = self.batch(batch_index)?;
        self.launch_b2n_batch(batch)?;
        self.launch_n2b_batch(batch, false)
    }

    /// Produce the exact input image for the candidate fixed16 final interval.
    pub(in crate::backend::prepared_progressive_commit) fn launch_batch_before_final_interval(
        &self,
        batch_index: u32,
    ) -> Result<(), DirectRetainedB2nError> {
        let batch = self.batch(batch_index)?;
        self.launch_b2n_batch(batch)?;
        let eval_domain_size = 1u32
            .checked_shl(batch.retained_log_size - 1)
            .ok_or(DirectRetainedB2nError::SizeOverflow)?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::
                stwo_ntt_n2b_columns_from_stage_two_before_final_interval_on(
                    batch.output_pointers.as_u32_ptr().cast(),
                    batch.retained_log_size,
                    batch.columns,
                    self.forward_twiddles.as_u32_ptr(),
                    self.forward_twiddle_words,
                    eval_domain_size,
                    self.arena.context().stream_raw().as_ptr(),
                )
        };
        check_cuda("direct_retained_n2b_before_final_interval", code)?;
        Ok(())
    }

    /// Complete only the final interval for a canonical pointer-table suffix;
    /// its circle butterfly is owned by the paired compact remainder sink.
    pub(in crate::backend::prepared_progressive_commit) fn launch_final_interval_before_circle(
        &self,
        batch_index: u32,
        first_in_batch: u32,
        columns: u32,
    ) -> Result<ArenaSlice, DirectRetainedB2nError> {
        let batch = self.batch(batch_index)?;
        let end = first_in_batch
            .checked_add(columns)
            .filter(|&end| columns != 0 && end <= batch.columns)
            .ok_or(DirectRetainedB2nError::InvalidProgram)?;
        let offset_words = usize::try_from(first_in_batch)
            .ok()
            .and_then(|value| value.checked_mul(POINTER_WORDS))
            .ok_or(DirectRetainedB2nError::SizeOverflow)?;
        let pointer_words = usize::try_from(end - first_in_batch)
            .ok()
            .and_then(|value| value.checked_mul(POINTER_WORDS))
            .ok_or(DirectRetainedB2nError::SizeOverflow)?;
        let pointers = batch
            .output_pointers
            .checked_subslice(offset_words, pointer_words)
            .map_err(super::super::super::prepared_commit::PreparedCommitError::from)?;
        let eval_domain_size = 1u32
            .checked_shl(batch.retained_log_size - 1)
            .ok_or(DirectRetainedB2nError::SizeOverflow)?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_ntt_n2b_columns_final_interval_before_circle_on(
                pointers.as_u32_ptr().cast(),
                batch.retained_log_size,
                columns,
                self.forward_twiddles.as_u32_ptr(),
                self.forward_twiddle_words,
                eval_domain_size,
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        check_cuda("direct_retained_n2b_final_interval_before_circle", code)?;
        Ok(pointers)
    }

    fn batch(&self, batch_index: u32) -> Result<PreparedBatch, DirectRetainedB2nError> {
        self.batches
            .get(batch_index as usize)
            .copied()
            .filter(|batch| batch.batch_index == batch_index)
            .ok_or(DirectRetainedB2nError::InvalidProgram)
    }

    fn launch_b2n_batch(&self, batch: PreparedBatch) -> Result<(), DirectRetainedB2nError> {
        let eval_domain_size = 1u32
            .checked_shl(batch.source_log_size - 1)
            .ok_or(DirectRetainedB2nError::SizeOverflow)?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_columns_to_retained_on(
                batch.input_pointers.as_u32_ptr().cast(),
                batch.output_pointers.as_u32_ptr().cast(),
                batch.source_log_size,
                batch.columns,
                self.inverse_twiddles.as_u32_ptr(),
                self.inverse_twiddle_words,
                eval_domain_size,
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        check_cuda("direct_retained_b2n", code)?;
        Ok(())
    }

    fn launch_n2b_batch(
        &self,
        batch: PreparedBatch,
        before_circle: bool,
    ) -> Result<(), DirectRetainedB2nError> {
        let eval_domain_size = 1u32
            .checked_shl(batch.retained_log_size - 1)
            .ok_or(DirectRetainedB2nError::SizeOverflow)?;
        let stream = self.arena.context().stream_raw().as_ptr();
        let code = unsafe {
            if before_circle {
                stwo_backend_cuda_kernels::raw::stwo_ntt_n2b_columns_from_stage_two_before_circle_on(
                    batch.output_pointers.as_u32_ptr().cast(),
                    batch.retained_log_size,
                    batch.columns,
                    self.forward_twiddles.as_u32_ptr(),
                    self.forward_twiddle_words,
                    eval_domain_size,
                    stream,
                )
            } else {
                stwo_backend_cuda_kernels::raw::stwo_ntt_n2b_columns_from_stage_two_on(
                    batch.output_pointers.as_u32_ptr().cast(),
                    batch.retained_log_size,
                    batch.columns,
                    self.forward_twiddles.as_u32_ptr(),
                    self.forward_twiddle_words,
                    eval_domain_size,
                    stream,
                )
            }
        };
        check_cuda("direct_retained_n2b_stage_two", code)?;
        Ok(())
    }

    pub fn launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = DirectRetainedB2nLaunchKind> + '_ {
        self.batches.iter().copied().map(|batch| {
            batch.launch_kind(
                self.role,
                self.inverse_twiddle_words,
                self.forward_twiddle_words,
            )
        })
    }

    pub fn commit_cache_key(&self) -> u64 {
        self.commit_cache_key
    }

    pub fn retained_evaluations(&self) -> &[ArenaSlice] {
        &self.retained_evaluations
    }

    pub(in crate::backend::prepared_progressive_commit) fn prepared_batches(
        &self,
    ) -> &[PreparedBatch] {
        &self.batches
    }

    pub(in crate::backend::prepared_progressive_commit) fn forward_twiddles(
        &self,
    ) -> (ArenaSlice, u32) {
        (self.forward_twiddles, self.forward_twiddle_words)
    }

    /// Recheck pairwise-disjoint terminal outputs at the opt-in boundary.
    pub(in crate::backend::prepared_progressive_commit) fn validate_terminal_output_disjoint(
        &self,
    ) -> Result<(), DirectRetainedB2nError> {
        for (index, &output) in self.retained_evaluations.iter().enumerate() {
            let range = address_range(output)?;
            for &other in &self.retained_evaluations[index + 1..] {
                if output.id() == other.id() || ranges_overlap(range, address_range(other)?) {
                    return Err(DirectRetainedB2nError::InvalidAlias {
                        first: output.id(),
                        second: other.id(),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn exact_lower_prefix_aliases(&self) -> usize {
        self.exact_lower_prefix_aliases
    }
}
