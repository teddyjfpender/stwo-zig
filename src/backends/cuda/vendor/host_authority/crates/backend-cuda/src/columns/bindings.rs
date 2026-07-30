#![allow(dead_code)] // ported intact from the stwo-cuda prototype
// Wrappers mirror the C entry points one-to-one.
#![allow(clippy::too_many_arguments)]

use core::ffi::c_void;

use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo_backend_cuda_kernels::raw as sys_raw;

/// Checked CUDA default-pool setup. The native side caches only success, so a
/// failed formal admission leaves the pool retryable.
pub(crate) fn try_ensure_mem_pool_init() -> Result<(), crate::CudaRuntimeError> {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(crate::CudaRuntimeError::Unavailable);
    }
    let code = unsafe { sys_raw::cuda_mem_pool_init() };
    crate::backend::exec_context::check_cuda("default_pool_init", code)?;
    Ok(())
}

/// Legacy compatibility wrapper. Allocation call sites retain their cudaMalloc
/// fallback, while replacement backends use the checked public admission API.
pub fn ensure_mem_pool_init() {
    static READY: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if READY.get().is_some() {
        return;
    }
    if let Err(error) = try_ensure_mem_pool_init() {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            eprintln!("stwo-backend-cuda: default-pool initialization failed: {error}");
        });
    } else {
        let _ = READY.set(());
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CudaSecureField {
    a: BaseField,
    b: BaseField,
    c: BaseField,
    d: BaseField,
}

impl CudaSecureField {
    pub fn zero() -> Self {
        Self {
            a: BaseField::from(0),
            b: BaseField::from(0),
            c: BaseField::from(0),
            d: BaseField::from(0),
        }
    }

    pub(crate) fn into_raw(self) -> sys_raw::CudaSecureField {
        sys_raw::CudaSecureField {
            a: self.a.0,
            b: self.b.0,
            c: self.c.0,
            d: self.d.0,
        }
    }

    fn from_raw(value: sys_raw::CudaSecureField) -> Self {
        Self {
            a: BaseField::from_u32_unchecked(value.a),
            b: BaseField::from_u32_unchecked(value.b),
            c: BaseField::from_u32_unchecked(value.c),
            d: BaseField::from_u32_unchecked(value.d),
        }
    }
}

impl From<SecureField> for CudaSecureField {
    fn from(value: SecureField) -> Self {
        Self {
            a: value.0 .0,
            b: value.0 .1,
            c: value.1 .0,
            d: value.1 .1,
        }
    }
}

impl From<CudaSecureField> for SecureField {
    fn from(value: CudaSecureField) -> Self {
        SecureField::from_m31(value.a, value.b, value.c, value.d)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CirclePointBaseField {
    x: BaseField,
    y: BaseField,
}

impl CirclePointBaseField {
    fn into_raw(self) -> sys_raw::CirclePointBaseField {
        sys_raw::CirclePointBaseField {
            x: self.x.0,
            y: self.y.0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LayerIndexPair {
    pub layer_idx: u32,
    pub hash_idx: u32,
}

impl From<CirclePoint<BaseField>> for CirclePointBaseField {
    fn from(value: CirclePoint<BaseField>) -> Self {
        Self {
            x: value.x,
            y: value.y,
        }
    }
}

#[repr(C)]
pub(crate) struct CirclePointSecureField {
    x: CudaSecureField,
    y: CudaSecureField,
}

impl From<CirclePoint<SecureField>> for CirclePointSecureField {
    fn from(value: CirclePoint<SecureField>) -> Self {
        Self {
            x: CudaSecureField::from(value.x),
            y: CudaSecureField::from(value.y),
        }
    }
}

fn raw_blake2s_ptr(ptr: *const Blake2sHash) -> *const sys_raw::Blake2sHash {
    ptr.cast()
}

fn raw_blake2s_mut_ptr(ptr: *mut Blake2sHash) -> *mut sys_raw::Blake2sHash {
    ptr.cast()
}

pub use sys_raw::{
    accumulate, batch_inverse_base_field, bit_reverse_base_field, bit_reverse_secure_field,
    copy_device_pointer_vec_from_host_to_device, copy_uint32_t_vec_from_device_to_device,
    copy_uint32_t_vec_from_device_to_device_offset, copy_uint32_t_vec_from_device_to_host,
    copy_uint32_t_vec_from_host_to_device, copy_uint32_t_vec_from_host_to_device_into,
    copy_uint32_t_vec_from_host_to_device_into_async, cuda_alloc_pinned_host_u32,
    cuda_alloc_zeroes_uint32_t, cuda_free_memory, cuda_free_pinned_host_u32, cuda_gather_uint32_t,
    cuda_get_memory_info, cuda_get_uint32_t, cuda_increase_at, cuda_malloc_uint32_t,
    cuda_pool_highwater, cuda_pool_highwater_reset, cuda_release_uploaded_pointer_vec,
    cuda_set_uint32_t, cuda_zero_device_region, lift_accumulate_secure_columns,
    logup_fraction_chain, ntt_b2n_column, ntt_n2b_columns, stwo_legacy_stream_sync,
};

pub unsafe fn cuda_get_secure_field(device_ptr: *const c_void, index: usize) -> CudaSecureField {
    CudaSecureField::from_raw(sys_raw::cuda_get_secure_field(device_ptr, index))
}

pub unsafe fn cuda_malloc_blake_2s_hash(size: usize) -> *const Blake2sHash {
    sys_raw::cuda_malloc_blake_2s_hash(size).cast()
}

pub unsafe fn cuda_alloc_zeroes_blake_2s_hash(size: usize) -> *const Blake2sHash {
    sys_raw::cuda_alloc_zeroes_blake_2s_hash(size).cast()
}

pub unsafe fn precompute_twiddles(
    initial: CirclePointBaseField,
    step: CirclePointBaseField,
    total_size: usize,
) -> *const u32 {
    sys_raw::precompute_twiddles(initial.into_raw(), step.into_raw(), total_size)
}

pub unsafe fn eval_at_point(
    coeffs: *const u32,
    coeffs_size: u32,
    point_x: CudaSecureField,
    point_y: CudaSecureField,
) -> CudaSecureField {
    CudaSecureField::from_raw(sys_raw::eval_at_point(
        coeffs,
        coeffs_size,
        point_x.into_raw(),
        point_y.into_raw(),
    ))
}

pub unsafe fn batch_eval_at_points(
    coeffs_ptrs: *const *const u32,
    coeffs_size: i32,
    num_polys: i32,
    point_x: CudaSecureField,
    point_y: CudaSecureField,
    results: *mut CudaSecureField,
) {
    sys_raw::batch_eval_at_points(
        coeffs_ptrs,
        coeffs_size,
        num_polys,
        point_x.into_raw(),
        point_y.into_raw(),
        results.cast(),
    );
}

pub unsafe fn logup_sum_secure_coords(
    c0: *const u32,
    c1: *const u32,
    c2: *const u32,
    c3: *const u32,
    size: u32,
) -> CudaSecureField {
    CudaSecureField::from_raw(sys_raw::logup_sum_secure_coords(c0, c1, c2, c3, size))
}

pub unsafe fn logup_shift_secure_coords(
    c0: *const u32,
    c1: *const u32,
    c2: *const u32,
    c3: *const u32,
    shift: CudaSecureField,
    size: u32,
) {
    sys_raw::logup_shift_secure_coords(c0, c1, c2, c3, shift.into_raw(), size);
}

pub unsafe fn barycentric_point_vanishings(
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    size: u32,
    log_size: u32,
    point_x: CudaSecureField,
    point_y: CudaSecureField,
    result: *const u32,
) {
    sys_raw::barycentric_point_vanishings(
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        point_x.into_raw(),
        point_y.into_raw(),
        result,
    );
}

pub unsafe fn barycentric_weights_from_point_vanishings(
    point_vanishings: *const u32,
    size: u32,
    even_scale: CudaSecureField,
    odd_scale: CudaSecureField,
    result_weights: *const u32,
) {
    sys_raw::barycentric_weights_from_point_vanishings(
        point_vanishings,
        size,
        even_scale.into_raw(),
        odd_scale.into_raw(),
        result_weights,
    );
}

pub unsafe fn barycentric_eval_base_field(
    eval_values: *const u32,
    weights: *const u32,
    size: u32,
) -> CudaSecureField {
    CudaSecureField::from_raw(sys_raw::barycentric_eval_base_field(
        eval_values,
        weights,
        size,
    ))
}

pub unsafe fn barycentric_eval_base_field_many(
    columns_dev: *const *const u32,
    n_cols: u32,
    weights: *const u32,
    size: u32,
) -> Vec<CudaSecureField> {
    let mut raw = vec![sys_raw::CudaSecureField::default(); n_cols as usize];
    sys_raw::barycentric_eval_base_field_many(columns_dev, n_cols, weights, size, raw.as_mut_ptr());
    raw.into_iter().map(CudaSecureField::from_raw).collect()
}

pub unsafe fn fold_line(
    gpu_domain: *const u32,
    twiddle_offset: usize,
    n: usize,
    eval_values: *const *const u32,
    alpha: CudaSecureField,
    folded_values: *const *const u32,
) {
    sys_raw::fold_line(
        gpu_domain,
        twiddle_offset,
        n,
        eval_values,
        alpha.into_raw(),
        folded_values,
    );
}

pub unsafe fn fold_circle_into_line(
    gpu_domain: *const u32,
    twiddle_offset: usize,
    n: usize,
    eval_values: *const *const u32,
    alpha: CudaSecureField,
    folded_values: *const *const u32,
) {
    sys_raw::fold_circle_into_line(
        gpu_domain,
        twiddle_offset,
        n,
        eval_values,
        alpha.into_raw(),
        folded_values,
    );
}

pub unsafe fn commit_on_first_layer(
    size: usize,
    amount_of_columns: usize,
    columns: *const *const u32,
    result: *mut Blake2sHash,
) {
    sys_raw::commit_on_first_layer(
        size,
        amount_of_columns,
        columns,
        raw_blake2s_mut_ptr(result),
    );
}

pub unsafe fn commit_on_first_layer_lifted(
    size: usize,
    amount_of_columns: usize,
    columns: *const *const u32,
    column_log_sizes: *const u32,
    lifting_log_size: u32,
    result: *mut Blake2sHash,
) {
    sys_raw::commit_on_first_layer_lifted(
        size,
        amount_of_columns,
        columns,
        column_log_sizes,
        lifting_log_size,
        raw_blake2s_mut_ptr(result),
    );
}

/// Streaming leaf commit (VRAM diet): the lifted first layer split so the caller
/// LDEs base columns one group at a time. init -> update per group -> finalize;
/// `state` holds h[8] per leaf. Byte-identical to `commit_on_first_layer_lifted`.
pub unsafe fn stream_leaf_init(size: u32, state: *mut Blake2sHash) {
    sys_raw::stream_leaf_init(size, raw_blake2s_mut_ptr(state));
}

pub unsafe fn stream_leaf_update(
    size: u32,
    group_n_cols: u32,
    columns: *const *const u32,
    column_log_sizes: *const u32,
    lifting_log_size: u32,
    cols_done: u32,
    state: *mut Blake2sHash,
) {
    sys_raw::stream_leaf_update(
        size,
        group_n_cols,
        columns,
        column_log_sizes,
        lifting_log_size,
        cols_done,
        raw_blake2s_mut_ptr(state),
    );
}

/// ILP2 leaf-update lane (Step 3.2, opt-in `STWO_CUDA_BLAKE2S_LEAF_ILP=1`):
/// two adjacent rows per thread, interleaved compression streams, halved grid.
/// Byte-identical to [`stream_leaf_update`].
pub unsafe fn stream_leaf_update_ilp2(
    size: u32,
    group_n_cols: u32,
    columns: *const *const u32,
    column_log_sizes: *const u32,
    lifting_log_size: u32,
    cols_done: u32,
    state: *mut Blake2sHash,
) {
    sys_raw::stream_leaf_update_ilp2(
        size,
        group_n_cols,
        columns,
        column_log_sizes,
        lifting_log_size,
        cols_done,
        raw_blake2s_mut_ptr(state),
    );
}

pub unsafe fn stream_leaf_finalize(
    size: u32,
    rem_cols: u32,
    columns: *const *const u32,
    column_log_sizes: *const u32,
    lifting_log_size: u32,
    cols_done: u32,
    result: *mut Blake2sHash,
) {
    sys_raw::stream_leaf_finalize(
        size,
        rem_cols,
        columns,
        column_log_sizes,
        lifting_log_size,
        cols_done,
        raw_blake2s_mut_ptr(result),
    );
}

/// Workstream D layer-pair fusion: hash two internal (column-free) tree levels per
/// launch. `size` = grandparent hash count; `previous_layer` holds `4 * size`.
/// Byte-identical to two `commit_on_layer_with_previous` calls with zero columns.
pub unsafe fn commit_on_two_layers_with_previous(
    size: usize,
    previous_layer: *const Blake2sHash,
    result: *mut Blake2sHash,
) {
    sys_raw::commit_on_two_layers_with_previous(
        size,
        raw_blake2s_ptr(previous_layer),
        raw_blake2s_mut_ptr(result),
    );
}

pub unsafe fn commit_on_layer_with_previous(
    size: usize,
    amount_of_columns: usize,
    columns: *const *const u32,
    previous_layer: *const Blake2sHash,
    result: *mut Blake2sHash,
) {
    sys_raw::commit_on_layer_with_previous(
        size,
        amount_of_columns,
        columns,
        raw_blake2s_ptr(previous_layer),
        raw_blake2s_mut_ptr(result),
    );
}

pub unsafe fn copy_blake_2s_hash_vec_from_host_to_device(
    from: *const Blake2sHash,
    size: usize,
) -> *mut Blake2sHash {
    sys_raw::copy_blake_2s_hash_vec_from_host_to_device(raw_blake2s_ptr(from), size).cast()
}

pub unsafe fn copy_blake_2s_hash_vec_from_device_to_host(
    from: *const Blake2sHash,
    to: *mut Blake2sHash,
    size: usize,
) {
    sys_raw::copy_blake_2s_hash_vec_from_device_to_host(
        raw_blake2s_ptr(from),
        raw_blake2s_mut_ptr(to),
        size,
    );
}

pub unsafe fn copy_blake_2s_hash_vec_from_device_to_device(
    from: *const Blake2sHash,
    dst: *const Blake2sHash,
    size: usize,
) {
    sys_raw::copy_blake_2s_hash_vec_from_device_to_device(
        raw_blake2s_ptr(from),
        raw_blake2s_ptr(dst),
        size,
    );
}

pub unsafe fn cuda_get_blake_2s_hash(
    device_ptr: *const Blake2sHash,
    host_ptr: *mut Blake2sHash,
    index: usize,
) {
    sys_raw::cuda_get_blake_2s_hash(
        raw_blake2s_ptr(device_ptr),
        raw_blake2s_mut_ptr(host_ptr),
        index,
    );
}

pub unsafe fn cuda_set_blake_2s_hash(
    device_ptr: *mut Blake2sHash,
    index: usize,
    host_ptr: *const Blake2sHash,
) {
    sys_raw::cuda_set_blake_2s_hash(
        raw_blake2s_mut_ptr(device_ptr),
        index,
        raw_blake2s_ptr(host_ptr),
    );
}

pub unsafe fn cuda_batch_get_blake_2s_hash(
    device_ptr: *const Blake2sHash,
    host_ptr: *mut Blake2sHash,
    indices: *const u32,
    n_indices: u32,
) {
    sys_raw::cuda_batch_get_blake_2s_hash(
        raw_blake2s_ptr(device_ptr),
        raw_blake2s_mut_ptr(host_ptr),
        indices,
        n_indices,
    );
}

pub unsafe fn cuda_multi_layer_batch_get_blake_2s_hash(
    layer_device_ptrs: *const *const Blake2sHash,
    host_ptr: *mut Blake2sHash,
    pairs: *const LayerIndexPair,
    n_pairs: u32,
) {
    sys_raw::cuda_multi_layer_batch_get_blake_2s_hash(
        layer_device_ptrs.cast(),
        raw_blake2s_mut_ptr(host_ptr),
        pairs.cast(),
        n_pairs,
    );
}

pub unsafe fn accumulate_quotients(
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    domain_size: u32,
    columns: *const *const u32,
    number_of_columns: usize,
    random_coeff: CudaSecureField,
    sample_points: *const u32,
    sample_columns_indexes: *const u32,
    sample_columns_indexes_size: u32,
    sample_column_values: *const CudaSecureField,
    sample_column_and_values_sizes: *const u32,
    sample_size: u32,
    result_column_0: *const u32,
    result_column_1: *const u32,
    result_column_2: *const u32,
    result_column_3: *const u32,
    flattened_line_coeffs_size: u32,
) {
    sys_raw::accumulate_quotients(
        half_coset_initial_index,
        half_coset_step_size,
        domain_size,
        columns,
        number_of_columns,
        random_coeff.into_raw(),
        sample_points,
        sample_columns_indexes,
        sample_columns_indexes_size,
        sample_column_values.cast(),
        sample_column_and_values_sizes,
        sample_size,
        result_column_0,
        result_column_1,
        result_column_2,
        result_column_3,
        flattened_line_coeffs_size,
    );
}

pub unsafe fn accumulate_partial_quotient_numerators(
    domain_size: u32,
    columns: *const *const u32,
    sample_column_indexes: *const u32,
    sample_column_indexes_size: u32,
    line_coeffs_b: *const CudaSecureField,
    line_coeffs_c: *const CudaSecureField,
    result_column_0: *const u32,
    result_column_1: *const u32,
    result_column_2: *const u32,
    result_column_3: *const u32,
) {
    sys_raw::accumulate_partial_quotient_numerators(
        domain_size,
        columns,
        sample_column_indexes,
        sample_column_indexes_size,
        line_coeffs_b.cast(),
        line_coeffs_c.cast(),
        result_column_0,
        result_column_1,
        result_column_2,
        result_column_3,
    );
}

pub unsafe fn combine_quotients_from_numerators(
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    domain_size: u32,
    domain_log_size: u32,
    sample_points: *const CirclePointSecureField,
    sample_size: u32,
    first_linear_term_accs: *const CudaSecureField,
    partial_numerator_log_sizes: *const u32,
    partial_numerators_0: *const *const u32,
    partial_numerators_1: *const *const u32,
    partial_numerators_2: *const *const u32,
    partial_numerators_3: *const *const u32,
    result_column_0: *const u32,
    result_column_1: *const u32,
    result_column_2: *const u32,
    result_column_3: *const u32,
) {
    sys_raw::combine_quotients_from_numerators(
        half_coset_initial_index,
        half_coset_step_size,
        domain_size,
        domain_log_size,
        sample_points.cast(),
        sample_size,
        first_linear_term_accs.cast(),
        partial_numerator_log_sizes,
        partial_numerators_0,
        partial_numerators_1,
        partial_numerators_2,
        partial_numerators_3,
        result_column_0,
        result_column_1,
        result_column_2,
        result_column_3,
    );
}

pub unsafe fn gen_eq_evals(
    v: CudaSecureField,
    y: *const CudaSecureField,
    y_size: u32,
    evals: *const CudaSecureField,
    evals_size: u32,
) {
    sys_raw::gen_eq_evals(v.into_raw(), y.cast(), y_size, evals.cast(), evals_size);
}

pub unsafe fn gkr_next_grand_product_layer(
    input_layer: *const CudaSecureField,
    input_size: u32,
    output_layer: *const CudaSecureField,
) {
    sys_raw::gkr_next_grand_product_layer(input_layer.cast(), input_size, output_layer.cast());
}

pub unsafe fn gkr_next_logup_generic_layer(
    numerators: *const CudaSecureField,
    denominators: *const CudaSecureField,
    input_size: u32,
    next_numerators: *const CudaSecureField,
    next_denominators: *const CudaSecureField,
) {
    sys_raw::gkr_next_logup_generic_layer(
        numerators.cast(),
        denominators.cast(),
        input_size,
        next_numerators.cast(),
        next_denominators.cast(),
    );
}

pub unsafe fn gkr_next_logup_multiplicities_layer(
    numerators: *const u32,
    denominators: *const CudaSecureField,
    input_size: u32,
    next_numerators: *const CudaSecureField,
    next_denominators: *const CudaSecureField,
) {
    sys_raw::gkr_next_logup_multiplicities_layer(
        numerators,
        denominators.cast(),
        input_size,
        next_numerators.cast(),
        next_denominators.cast(),
    );
}

pub unsafe fn gkr_next_logup_singles_layer(
    denominators: *const CudaSecureField,
    input_size: u32,
    next_numerators: *const CudaSecureField,
    next_denominators: *const CudaSecureField,
) {
    sys_raw::gkr_next_logup_singles_layer(
        denominators.cast(),
        input_size,
        next_numerators.cast(),
        next_denominators.cast(),
    );
}

pub unsafe fn gkr_sum_grand_product(
    eq_evals: *const CudaSecureField,
    input_layer: *const CudaSecureField,
    n_terms: u32,
    eval_at_0: *mut CudaSecureField,
    eval_at_2: *mut CudaSecureField,
) {
    sys_raw::gkr_sum_grand_product(
        eq_evals.cast(),
        input_layer.cast(),
        n_terms,
        eval_at_0.cast(),
        eval_at_2.cast(),
    );
}

pub unsafe fn gkr_sum_logup_generic(
    eq_evals: *const CudaSecureField,
    numerators: *const CudaSecureField,
    denominators: *const CudaSecureField,
    n_terms: u32,
    lambda: CudaSecureField,
    eval_at_0: *mut CudaSecureField,
    eval_at_2: *mut CudaSecureField,
) {
    sys_raw::gkr_sum_logup_generic(
        eq_evals.cast(),
        numerators.cast(),
        denominators.cast(),
        n_terms,
        lambda.into_raw(),
        eval_at_0.cast(),
        eval_at_2.cast(),
    );
}

pub unsafe fn gkr_sum_logup_multiplicities(
    eq_evals: *const CudaSecureField,
    numerators: *const u32,
    denominators: *const CudaSecureField,
    n_terms: u32,
    lambda: CudaSecureField,
    eval_at_0: *mut CudaSecureField,
    eval_at_2: *mut CudaSecureField,
) {
    sys_raw::gkr_sum_logup_multiplicities(
        eq_evals.cast(),
        numerators,
        denominators.cast(),
        n_terms,
        lambda.into_raw(),
        eval_at_0.cast(),
        eval_at_2.cast(),
    );
}

pub unsafe fn gkr_sum_logup_singles(
    eq_evals: *const CudaSecureField,
    denominators: *const CudaSecureField,
    n_terms: u32,
    lambda: CudaSecureField,
    eval_at_0: *mut CudaSecureField,
    eval_at_2: *mut CudaSecureField,
) {
    sys_raw::gkr_sum_logup_singles(
        eq_evals.cast(),
        denominators.cast(),
        n_terms,
        lambda.into_raw(),
        eval_at_0.cast(),
        eval_at_2.cast(),
    );
}

pub unsafe fn fix_first_variable_base_field(
    evals: *const u32,
    evals_size: usize,
    assignment: CudaSecureField,
    output_evals: *const u32,
) {
    sys_raw::fix_first_variable_base_field(evals, evals_size, assignment.into_raw(), output_evals);
}

pub unsafe fn fix_first_variable_secure_field(
    evals: *const u32,
    evals_size: usize,
    assignment: CudaSecureField,
    output_evals: *const u32,
) {
    sys_raw::fix_first_variable_secure_field(
        evals,
        evals_size,
        assignment.into_raw(),
        output_evals,
    );
}

fn pointer_and_len_are_compatible<T>(ptr: *const T, len: u32) -> bool {
    len == 0 || !ptr.is_null()
}

fn mutable_pointer_is_present<T>(ptr: *mut T) -> bool {
    !ptr.is_null()
}

#[cfg(all(test, stwo_cuda_link))]
mod tests {
    use stwo::core::utils::offset_bit_reversed_circle_domain_index;
    use stwo_backend_cuda_kernels::raw::test_offset_bit_reversed_indices;

    #[test]
    fn test_cuda_offset_bit_reversed_indices_with_blowup() {
        const DOMAIN_LOG_SIZE: u32 = 10;
        const EVAL_LOG_SIZE: u32 = 11;
        const OFFSET: isize = -1;
        const N: usize = 1 << EVAL_LOG_SIZE;

        let rust_results: Vec<usize> = (0..N)
            .map(|i| {
                offset_bit_reversed_circle_domain_index(i, DOMAIN_LOG_SIZE, EVAL_LOG_SIZE, OFFSET)
            })
            .collect();

        let mut cuda_results = vec![0u32; N];
        unsafe {
            test_offset_bit_reversed_indices(
                cuda_results.as_mut_ptr(),
                DOMAIN_LOG_SIZE,
                EVAL_LOG_SIZE,
                OFFSET as i32,
                N as u32,
            );
        }

        let mut mismatch_count = 0;
        for i in 0..N {
            if rust_results[i] as u32 != cuda_results[i] {
                mismatch_count += 1;
            }
        }

        assert_eq!(
            mismatch_count, 0,
            "Found {} mismatches between Rust and CUDA offset computation",
            mismatch_count
        );
    }
}
