//! Evaluation-backed OODS launch schedules.

use core::ffi::c_void;

use stwo_backend_cuda_kernels::raw as cuda_raw;

use super::{
    check_cuda, pow2, to_u32, OodsEvaluationLaunchGroup, OodsPassCollapseProgram,
    PreparedOodsError, PreparedOodsGraph, SECURE_WORDS,
};

impl PreparedOodsGraph<'_> {
    pub(super) fn launch_evaluation_group(
        &self,
        group: &OodsEvaluationLaunchGroup,
        stream: *mut c_void,
    ) -> Result<(), PreparedOodsError> {
        self.launch_evaluation_derive(group, stream)?;
        let evaluation_size = to_u32(pow2(group.requirements.log_size)?)?;
        let evaluation_point = self.group_evaluation_point(group);
        let code = unsafe {
            cuda_raw::stwo_oods_barycentric_weights_on(
                group.half_coset_initial_index,
                group.half_coset_step_size,
                evaluation_size,
                group.requirements.log_size,
                evaluation_point,
                group.si0,
                group.vanishing_rotation,
                self.barycentric_numerators
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                self.barycentric_weights
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                self.barycentric_scales
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                stream,
            )
        };
        check_cuda("prepared_oods_barycentric_weights", code)?;
        self.launch_evaluation_values(
            group,
            self.barycentric_weights
                .as_u32_ptr()
                .cast::<cuda_raw::CudaSecureField>(),
            stream,
        )
    }

    pub(super) fn launch_collapsed_evaluation_groups(
        &self,
        program: &OodsPassCollapseProgram,
        stream: *mut c_void,
    ) -> Result<(), PreparedOodsError> {
        for cohort in &program.receipt().same_log_cohorts {
            for batch in &cohort.batches {
                let group_range = batch.first_group..batch.first_group + batch.group_count;
                for group in &self.evaluation_groups[group_range.clone()] {
                    self.launch_evaluation_derive(group, stream)?;
                }

                let first_group = &self.evaluation_groups[batch.first_group];
                let evaluation_size = to_u32(pow2(batch.log_size)?)?;
                let descriptor_offsets =
                    unsafe { self.barycentric_scales.as_u32_ptr().add(batch.first_group) };
                let code = unsafe {
                    cuda_raw::stwo_oods_barycentric_weights_collapsed_cohort_on(
                        first_group.half_coset_initial_index,
                        first_group.half_coset_step_size,
                        evaluation_size,
                        batch.log_size,
                        self.evaluation_points.as_u32_ptr(),
                        descriptor_offsets,
                        to_u32(batch.group_count)?,
                        first_group.si0,
                        first_group.vanishing_rotation,
                        self.barycentric_weights
                            .as_u32_ptr()
                            .cast::<cuda_raw::CudaSecureField>(),
                        stream,
                    )
                };
                check_cuda("prepared_oods_barycentric_weights_collapsed_cohort", code)?;

                let weight_stride = pow2(batch.log_size)?;
                for (local_group, group) in self.evaluation_groups[group_range].iter().enumerate() {
                    let weights = unsafe {
                        self.barycentric_weights
                            .as_u32_ptr()
                            .cast::<cuda_raw::CudaSecureField>()
                            .add(local_group * weight_stride)
                    };
                    self.launch_evaluation_values(group, weights, stream)?;
                }
            }
        }
        Ok(())
    }

    fn launch_evaluation_derive(
        &self,
        group: &OodsEvaluationLaunchGroup,
        stream: *mut c_void,
    ) -> Result<(), PreparedOodsError> {
        let requirements = &group.requirements;
        let descriptor_offset = requirements.descriptor_offset;
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
                .add(requirements.factor_offset_words / SECURE_WORDS)
        };
        let code = unsafe {
            cuda_raw::stwo_oods_derive_points_on(
                self.parameter
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                offsets,
                fold_counts,
                output_indices,
                to_u32(requirements.sample_count)?,
                requirements.log_size,
                self.sample_points.as_u32_ptr(),
                self.group_evaluation_point(group),
                factors,
                stream,
            )
        };
        check_cuda("prepared_oods_derive_evaluation_points", code)?;
        Ok(())
    }

    fn launch_evaluation_values(
        &self,
        group: &OodsEvaluationLaunchGroup,
        weights: *const cuda_raw::CudaSecureField,
        stream: *mut c_void,
    ) -> Result<(), PreparedOodsError> {
        let requirements = &group.requirements;
        let descriptor_offset = requirements.descriptor_offset;
        let pointers = unsafe {
            self.source_pointers
                .as_u32_ptr()
                .cast::<*const u32>()
                .add(descriptor_offset)
        };
        let output_indices = unsafe { self.output_indices.as_u32_ptr().add(descriptor_offset) };
        let code = unsafe {
            cuda_raw::stwo_oods_barycentric_eval_many_on(
                pointers,
                to_u32(requirements.sample_count)?,
                weights,
                to_u32(pow2(requirements.log_size)?)?,
                self.barycentric_partials
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                to_u32(requirements.reduction_blocks)?,
                output_indices,
                self.sampled_values
                    .as_u32_ptr()
                    .cast::<cuda_raw::CudaSecureField>(),
                stream,
            )
        };
        check_cuda("prepared_oods_barycentric_eval", code)?;
        Ok(())
    }

    fn group_evaluation_point(&self, group: &OodsEvaluationLaunchGroup) -> *mut u32 {
        unsafe {
            self.evaluation_points
                .as_u32_ptr()
                .cast::<cuda_raw::CudaSecureField>()
                .add(2 * group.requirements.descriptor_offset)
                .cast::<u32>()
        }
    }
}
