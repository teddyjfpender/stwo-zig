//! Panicking `no_mangle` stand-ins for every kernel entry point, used when the build
//! script did not find nvcc (`stwo_cuda_link` unset). Generated mechanically from the
//! declarations in `raw.rs`; keep the two files in sync.
#![allow(unused_variables, clippy::missing_safety_doc)]

use core::ffi::c_void;

use crate::raw::{
    Blake2sHash, CirclePointBaseField, CompactBlake2sTailDescriptor, CudaFunctionAttributes,
    CudaQuotientNativeRunManifest, CudaSecureField, LayerIndexPair, ProgressiveBlake2sState,
};

const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;

#[cold]
fn no_cuda_symbol(symbol: &str) -> ! {
    panic!(
        "CUDA kernel entry point `{symbol}` was called, but the kernels were not compiled \
         into this build (nvcc was not found). Build on a machine with the CUDA toolkit."
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_static_cuda_module_build_identity(out: *mut u8) -> i32 {
    if !out.is_null() {
        core::ptr::write_bytes(out, 0, 32);
    }
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_uint32_t_vec_from_device_to_host(
    device_ptr: *const u32,
    host_ptr: *const u32,
    size: u32,
) {
    no_cuda_symbol("copy_uint32_t_vec_from_device_to_host")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_uint32_t_vec_from_host_to_device(
    host_ptr: *const u32,
    size: u32,
) -> *const u32 {
    no_cuda_symbol("copy_uint32_t_vec_from_host_to_device")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_uint32_t_vec_from_device_to_device(
    from: *const u32,
    dst: *const u32,
    size: u32,
) -> *const u32 {
    no_cuda_symbol("copy_uint32_t_vec_from_device_to_device")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_uint32_t_vec_from_device_to_device_offset(
    from: *const u32,
    dst: *const u32,
    size: u32,
    offset: u32,
) {
    no_cuda_symbol("copy_uint32_t_vec_from_device_to_device_offset")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_zero_device_region(ptr: *const u32, offset_words: u64, n_words: u64) {
    let _ = (ptr, offset_words, n_words);
    no_cuda_symbol("cuda_zero_device_region")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_alloc_pinned_host_u32(n_words: u64) -> *mut u32 {
    let _ = n_words;
    no_cuda_symbol("cuda_alloc_pinned_host_u32")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_free_pinned_host_u32(ptr: *mut u32) {
    let _ = ptr;
    no_cuda_symbol("cuda_free_pinned_host_u32")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_uint32_t_vec_from_host_to_device_into(
    host_ptr: *const u32,
    device_ptr: *const u32,
    n_words: u64,
) {
    let _ = (host_ptr, device_ptr, n_words);
    no_cuda_symbol("copy_uint32_t_vec_from_host_to_device_into")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_uint32_t_vec_from_host_to_device_into_async(
    host_ptr: *const u32,
    device_ptr: *const u32,
    n_words: u64,
) {
    let _ = (host_ptr, device_ptr, n_words);
    no_cuda_symbol("copy_uint32_t_vec_from_host_to_device_into_async")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_legacy_stream_sync() {
    no_cuda_symbol("stwo_legacy_stream_sync")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn inclusive_prefix_sum_x4(
    c0: *const u32,
    c1: *const u32,
    c2: *const u32,
    c3: *const u32,
    len: u32,
) {
    let _ = (c0, c1, c2, c3, len);
    no_cuda_symbol("inclusive_prefix_sum_x4")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn inclusive_prefix_sum(
    device_bit_rev_circle_domain_evals: *const u32,
    len: u32,
) {
    let _ = (device_bit_rev_circle_domain_evals, len);
    no_cuda_symbol("inclusive_prefix_sum")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn logup_fraction_chain(
    num0: *const u32,
    num1: *const u32,
    num2: *const u32,
    num3: *const u32,
    denom_packed: *const u32,
    prev0: *const u32,
    prev1: *const u32,
    prev2: *const u32,
    prev3: *const u32,
    size: u32,
) {
    let _ = (
        num0,
        num1,
        num2,
        num3,
        denom_packed,
        prev0,
        prev1,
        prev2,
        prev3,
        size,
    );
    no_cuda_symbol("logup_fraction_chain")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_logup_pairs_from_flats(
    _flats: *const u32,
    _n_rows: u32,
    _n_real: u32,
    _descs_host: *const u32,
    _n_cols: u32,
    _alphas_host: *const u32,
    _n_alphas: u32,
    _z_host: *const u32,
    _num_cols_device_table: *const *mut u32,
    _den_dense_device_table: *const *mut u32,
) -> bool {
    let _ = (
        _flats,
        _n_rows,
        _descs_host,
        _n_cols,
        _alphas_host,
        _n_alphas,
        _z_host,
        _num_cols_device_table,
        _den_dense_device_table,
    );
    no_cuda_symbol("stwo_logup_pairs_from_flats")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_scan_temp_bytes(_len: u32) -> usize {
    no_cuda_symbol("stwo_relation_scan_temp_bytes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_expand_challenges_on(
    _drawn_z_alpha: *const u32,
    _alpha_powers: *mut u32,
    _n_alpha_powers: u32,
    _z: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_expand_challenges_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_pairs_on(
    _sources: *const *const u32,
    _n_sources: u32,
    _n_rows: u32,
    _n_real: u32,
    _source_offset_rows: u32,
    _descriptors: *const u32,
    _n_columns: u32,
    _alpha_powers: *const u32,
    _n_alpha_powers: u32,
    _z: *const u32,
    _outputs: *const *mut u32,
    _denominators: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_pairs_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_pairs_global_on(
    _source_tables: *const *const *const u32,
    _descriptors: *const *const u32,
    _output_tables: *const *const *mut u32,
    _denominator_slabs: *const *mut u32,
    _geometry: *const u32,
    _n_instances: u32,
    _total_pair_blocks: u32,
    _alpha_powers: *const u32,
    _n_alpha_powers: u32,
    _z: *const u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_pairs_global_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_fused_on(
    _source_tables: *const *const *const u32,
    _descriptors: *const *const u32,
    _output_tables: *const *const *mut u32,
    _geometry: *const u32,
    _n_instances: u32,
    _total_row_blocks: u32,
    _alpha_powers: *const u32,
    _n_alpha_powers: u32,
    _z: *const u32,
    _eligible_mask: *const u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_fused_on")
}

#[cfg(feature = "test-only-relation-ab")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_fused_all_one_read_test_on(
    _source_tables: *const *const *const u32,
    _descriptors: *const *const u32,
    _output_tables: *const *const *mut u32,
    _geometry: *const u32,
    _n_instances: u32,
    _total_row_blocks: u32,
    _alpha_powers: *const u32,
    _n_alpha_powers: u32,
    _z: *const u32,
    _eligible_mask: *const u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_fused_all_one_read_test_on")
}

#[cfg(feature = "test-only-relation-ab")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_fused_test_function_attributes(
    _strategy: u32,
    _out: *mut crate::raw::CudaFunctionAttributes,
) -> i32 {
    no_cuda_symbol("stwo_relation_fused_test_function_attributes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_blake_g_inputs_on(
    _sources: *const *const u32,
    _n_sources: u32,
    _n_rows: u32,
    _n_real: u32,
    _alpha_powers: *const u32,
    _n_alpha_powers: u32,
    _z: *const u32,
    _outputs: *const *mut u32,
    _n_outputs: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_blake_g_inputs_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_fraction_chain_on(
    _outputs: *const *mut u32,
    _denominators: *mut u32,
    _inverse_scratch: *mut u32,
    _n_rows: u32,
    _n_columns: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_fraction_chain_on")
}

#[no_mangle]
pub unsafe extern "C" fn stwo_relation_fraction_chain_global_on(
    _output_tables: *const *const *mut u32,
    _denominator_slabs: *const *mut u32,
    _geometry: *const u32,
    _n_instances: u32,
    _total_inverse_blocks: u32,
    _total_chain_blocks: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_fraction_chain_global_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_reduce_shift_on(
    _output_0: *mut u32,
    _output_1: *mut u32,
    _output_2: *mut u32,
    _output_3: *mut u32,
    _n_rows: u32,
    _reduction_a: *mut u32,
    _reduction_b: *mut u32,
    _reduction_capacity: u32,
    _claimed_sum: *mut u32,
    _inverse_rows: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_reduce_shift_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_prefix_scan_on(
    _output: *mut u32,
    _n_rows: u32,
    _eval_scratch: *mut u32,
    _scan_temp: *mut core::ffi::c_void,
    _scan_temp_bytes: usize,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_prefix_scan_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_tail_global_on(
    _output_tables: *const *const *mut u32,
    _claimed_sums: *const *mut u32,
    _geometry: *const u32,
    _n_instances: u32,
    _total_row_blocks: u32,
    _reduction_partials: *mut u32,
    _reduction_capacity: u32,
    _scan_block_sums: *mut u32,
    _scan_capacity: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_tail_global_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn logup_fraction_chain_dense(
    num0: *const u32,
    num1: *const u32,
    num2: *const u32,
    num3: *const u32,
    denoms_dense: *const u32,
    prev0: *const u32,
    prev1: *const u32,
    prev2: *const u32,
    prev3: *const u32,
    size: u32,
) {
    let _ = (
        num0,
        num1,
        num2,
        num3,
        denoms_dense,
        prev0,
        prev1,
        prev2,
        prev3,
        size,
    );
    no_cuda_symbol("logup_fraction_chain_dense")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn logup_sum_secure_coords(
    c0: *const u32,
    c1: *const u32,
    c2: *const u32,
    c3: *const u32,
    size: u32,
) -> CudaSecureField {
    let _ = (c0, c1, c2, c3, size);
    no_cuda_symbol("logup_sum_secure_coords")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_limb_split_big(
    values: *const u32,
    n_values: u32,
    column_length: u32,
    limb_cols: *const *const u32,
) {
    let _ = (values, n_values, column_length, limb_cols);
    no_cuda_symbol("memory_limb_split_big")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_limb_split_small(
    values: *const u32,
    n_values: u32,
    column_length: u32,
    limb_cols: *const *const u32,
) {
    let _ = (values, n_values, column_length, limb_cols);
    no_cuda_symbol("memory_limb_split_small")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_limb_split_big_into_on(
    values: *const u32,
    n_values: u32,
    column_length: u32,
    limb_cols_host: *const *mut u32,
    mults_host: *const u32,
    mults: *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (
        values,
        n_values,
        column_length,
        limb_cols_host,
        mults_host,
        mults,
        stream,
    );
    no_cuda_symbol("memory_limb_split_big_into_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_limb_split_small_into_on(
    values: *const u32,
    n_values: u32,
    column_length: u32,
    limb_cols_host: *const *mut u32,
    mults_host: *const u32,
    mults: *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (
        values,
        n_values,
        column_length,
        limb_cols_host,
        mults_host,
        mults,
        stream,
    );
    no_cuda_symbol("memory_limb_split_small_into_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_limb_split_big_columns_on(
    values: *const u32,
    n_values: u32,
    column_length: u32,
    limb_cols_host: *const *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (values, n_values, column_length, limb_cols_host, stream);
    no_cuda_symbol("memory_limb_split_big_columns_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_limb_split_small_columns_on(
    values: *const u32,
    n_values: u32,
    column_length: u32,
    limb_cols_host: *const *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (values, n_values, column_length, limb_cols_host, stream);
    no_cuda_symbol("memory_limb_split_small_columns_on")
}

#[no_mangle]
pub unsafe extern "C" fn memory_address_base_trace_on(
    _raw_addr_to_id: *const u32,
    _n_addrs: u32,
    _multiplicities: *const u32,
    _count_words: u32,
    _column_length: u32,
    _outputs_host: *const *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("memory_address_base_trace_on")
}

#[no_mangle]
pub unsafe extern "C" fn memory_value_base_trace_on(
    _sources_host: *const *const u32,
    _n_limbs: u32,
    _source_words: u32,
    _source_offset: u32,
    _multiplicities: *const u32,
    _count_words: u32,
    _column_length: u32,
    _outputs_host: *const *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("memory_value_base_trace_on")
}

#[no_mangle]
pub unsafe extern "C" fn memory_address_base_trace_sliced_on(
    _address_ids: *const u32,
    _address_id_words: u32,
    _multiplicities: *const u32,
    _multiplicity_words: u32,
    _column_length: u32,
    _outputs_host: *const *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("memory_address_base_trace_sliced_on")
}

#[no_mangle]
pub unsafe extern "C" fn memory_value_base_trace_sliced_on(
    _sources_host: *const *const u32,
    _n_limbs: u32,
    _source_slice_words: u32,
    _multiplicities: *const u32,
    _multiplicity_slice_words: u32,
    _column_length: u32,
    _outputs_host: *const *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("memory_value_base_trace_sliced_on")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ec_op_builtin_witness_on(
    _execution_tables: *const *const u32,
    _n_addresses: u32,
    _n_big: u32,
    _n_small: u32,
    _segment_start_source: *const u32,
    _row_count: u32,
    _trace_columns_host: *const *mut u32,
    _lookup_words: *mut u32,
    _partial_input_columns_host: *const *mut u32,
    _partial_row_count: u32,
    _address_counts: *mut u32,
    _address_count_words: u32,
    _big_counts: *mut u32,
    _big_count_words: u32,
    _small_counts: *mut u32,
    _small_count_words: u32,
    _range_check_8_counts: *mut u32,
    _range_check_8_count_words: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("ec_op_builtin_witness_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_rc99_count(
    limb_cols: *const *const u32,
    n_pairs: u32,
    column_length: u32,
    input_to_row_lut: *const u32,
    rc_table_size: u32,
    counts: *mut u32,
) {
    let _ = (
        limb_cols,
        n_pairs,
        column_length,
        input_to_row_lut,
        rc_table_size,
        counts,
    );
    no_cuda_symbol("memory_rc99_count")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_rc99_count_on(
    limb_cols_host: *const *const u32,
    n_pairs: u32,
    column_length: u32,
    input_to_row_lut: *const u32,
    rc_table_size: u32,
    counts: *mut u32,
    stream: *mut c_void,
) -> i32 {
    let _ = (
        limb_cols_host,
        n_pairs,
        column_length,
        input_to_row_lut,
        rc_table_size,
        counts,
        stream,
    );
    no_cuda_symbol("memory_rc99_count_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_logup_inputs(
    limb_cols: *const *const u32,
    n_limbs: u32,
    mults: *const u32,
    relation_id: u32,
    id_offset: u32,
    id_tag: u32,
    column_length: u32,
    alpha_powers: *const u32,
    z: CudaSecureField,
    denoms: *const u32,
    num0: *const u32,
    num1: *const u32,
    num2: *const u32,
    num3: *const u32,
) {
    let _ = (
        limb_cols,
        n_limbs,
        mults,
        relation_id,
        id_offset,
        id_tag,
        column_length,
    );
    let _ = (alpha_powers, z, denoms, num0, num1, num2, num3);
    no_cuda_symbol("memory_logup_inputs")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_rc_pair_logup(
    limb_a: *const u32,
    limb_b: *const u32,
    limb_c: *const u32,
    limb_d: *const u32,
    rel_id0: u32,
    rel_id1: u32,
    column_length: u32,
    alpha_powers: *const u32,
    z: CudaSecureField,
    denoms: *const u32,
    num0: *const u32,
    num1: *const u32,
    num2: *const u32,
    num3: *const u32,
) {
    let _ = (
        limb_a,
        limb_b,
        limb_c,
        limb_d,
        rel_id0,
        rel_id1,
        column_length,
    );
    let _ = (alpha_powers, z, denoms, num0, num1, num2, num3);
    no_cuda_symbol("memory_rc_pair_logup")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn exec_deduce_output(
    addr_to_id: *const u32,
    big_limbs: *const *const u32,
    small_limbs: *const *const u32,
    addresses: *const u32,
    n_queries: u32,
    out_ids: *mut u32,
    out_limbs: *const *mut u32,
) {
    let _ = (
        addr_to_id,
        big_limbs,
        small_limbs,
        addresses,
        n_queries,
        out_ids,
        out_limbs,
    );
    no_cuda_symbol("exec_deduce_output")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn logup_shift_secure_coords(
    c0: *const u32,
    c1: *const u32,
    c2: *const u32,
    c3: *const u32,
    shift: CudaSecureField,
    size: u32,
) {
    let _ = (c0, c1, c2, c3, shift, size);
    no_cuda_symbol("logup_shift_secure_coords")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_write_trace(
    inputs: *const u32,
    n_rows: u32,
    column_length: u32,
    cols: *const *const u32,
) {
    let _ = (inputs, n_rows, column_length, cols);
    no_cuda_symbol("blake_g_write_trace")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_write_trace_into_on(
    inputs: *const u32,
    producer_sub: *const u32,
    producer_rows: u32,
    producer_word_base: u32,
    producer_instances: u32,
    n_rows: u32,
    column_length: u32,
    trace_cols_host: *const *mut u32,
    lookup: *mut u32,
    sub: *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (
        inputs,
        producer_sub,
        producer_rows,
        producer_word_base,
        producer_instances,
        n_rows,
        column_length,
        trace_cols_host,
        lookup,
        sub,
        stream,
    );
    no_cuda_symbol("blake_g_write_trace_into_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_write_trace_projected_into_on(
    inputs: *const u32,
    producer_sub: *const u32,
    producer_rows: u32,
    producer_word_base: u32,
    producer_instances: u32,
    n_rows: u32,
    column_length: u32,
    trace_cols_host: *const *mut u32,
    aux: *mut u32,
    sub: *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (
        inputs,
        producer_sub,
        producer_rows,
        producer_word_base,
        producer_instances,
        n_rows,
        column_length,
        trace_cols_host,
        aux,
        sub,
        stream,
    );
    no_cuda_symbol("blake_g_write_trace_projected_into_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_write_trace_fused_into_on(
    input_cols_host: *const *const u32,
    n_rows: u32,
    column_length: u32,
    trace_cols_host: *const *mut u32,
    lookup: *mut u32,
    luts_host: *const *const u32,
    counts_host: *const *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (
        input_cols_host,
        n_rows,
        column_length,
        trace_cols_host,
        lookup,
        luts_host,
        counts_host,
        stream,
    );
    no_cuda_symbol("blake_g_write_trace_fused_into_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_write_trace_fused_projected_into_on(
    input_cols_host: *const *const u32,
    n_rows: u32,
    column_length: u32,
    trace_cols_host: *const *mut u32,
    aux: *mut u32,
    luts_host: *const *const u32,
    counts_host: *const *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (
        input_cols_host,
        n_rows,
        column_length,
        trace_cols_host,
        aux,
        luts_host,
        counts_host,
        stream,
    );
    no_cuda_symbol("blake_g_write_trace_fused_projected_into_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_write_trace_fused_direct_into_on(
    input_cols_host: *const *const u32,
    n_rows: u32,
    column_length: u32,
    trace_cols_host: *const *mut u32,
    luts_host: *const *const u32,
    counts_host: *const *mut u32,
    stream: *mut core::ffi::c_void,
) -> i32 {
    let _ = (
        input_cols_host,
        n_rows,
        column_length,
        trace_cols_host,
        luts_host,
        counts_host,
        stream,
    );
    no_cuda_symbol("blake_g_write_trace_fused_direct_into_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_xor_count(
    a_cols: *const *const u32,
    b_cols: *const *const u32,
    rel_idx: *const u32,
    n_pairs: u32,
    column_length: u32,
    shift: u32,
    lut: *const u32,
    table_size: u32,
    counts: *mut u32,
) {
    let _ = (
        a_cols,
        b_cols,
        rel_idx,
        n_pairs,
        column_length,
        shift,
        lut,
        table_size,
        counts,
    );
    no_cuda_symbol("blake_g_xor_count")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_xor12_count(
    a_cols: *const *const u32,
    b_cols: *const *const u32,
    n_pairs: u32,
    column_length: u32,
    limb_bits: u32,
    expand_bits: u32,
    table_size: u32,
    counts: *mut u32,
) {
    let _ = (
        a_cols,
        b_cols,
        n_pairs,
        column_length,
        limb_bits,
        expand_bits,
        table_size,
        counts,
    );
    no_cuda_symbol("blake_g_xor12_count")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_pair_logup(
    a0: *const u32,
    b0: *const u32,
    x0: *const u32,
    a1: *const u32,
    b1: *const u32,
    x1: *const u32,
    rel0: u32,
    rel1: u32,
    column_length: u32,
    alpha: *const u32,
    z: CudaSecureField,
    denoms: *const u32,
    num0: *const u32,
    num1: *const u32,
    num2: *const u32,
    num3: *const u32,
) {
    let _ = (a0, b0, x0, a1, b1, x1, rel0, rel1, column_length);
    let _ = (alpha, z, denoms, num0, num1, num2, num3);
    no_cuda_symbol("blake_g_pair_logup")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn blake_g_final_logup(
    val_cols: *const *const u32,
    enabler: *const u32,
    rel: u32,
    column_length: u32,
    alpha: *const u32,
    z: CudaSecureField,
    denoms: *const u32,
    num0: *const u32,
    num1: *const u32,
    num2: *const u32,
    num3: *const u32,
) {
    let _ = (val_cols, enabler, rel, column_length);
    let _ = (alpha, z, denoms, num0, num1, num2, num3);
    no_cuda_symbol("blake_g_final_logup")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn pedersen_pair_logup(
    vals0: *const *const u32,
    rel0: u32,
    vals1: *const *const u32,
    rel1: u32,
    n_vals: u32,
    m0: *const u32,
    m1: *const u32,
    sign0: i32,
    sign1: i32,
    column_length: u32,
    alpha: *const u32,
    z: CudaSecureField,
    denoms: *const u32,
    num0: *const u32,
    num1: *const u32,
    num2: *const u32,
    num3: *const u32,
) {
    let _ = (
        vals0,
        rel0,
        vals1,
        rel1,
        n_vals,
        m0,
        m1,
        sign0,
        sign1,
        column_length,
    );
    let _ = (alpha, z, denoms, num0, num1, num2, num3);
    no_cuda_symbol("pedersen_pair_logup")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn pedersen_multi_logup(
    vals: *const *const u32,
    n_vals: u32,
    rel: u32,
    mult: *const u32,
    neg_num: i32,
    column_length: u32,
    alpha: *const u32,
    z: CudaSecureField,
    denoms: *const u32,
    num0: *const u32,
    num1: *const u32,
    num2: *const u32,
    num3: *const u32,
) {
    let _ = (vals, n_vals, rel, mult, neg_num, column_length);
    let _ = (alpha, z, denoms, num0, num1, num2, num3);
    no_cuda_symbol("pedersen_multi_logup")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_gather_uint32_t(
    device_src: *const u32,
    host_indices: *const u32,
    n_indices: u32,
    host_out: *mut u32,
) {
    let _ = (device_src, host_indices, n_indices, host_out);
    no_cuda_symbol("cuda_gather_uint32_t")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_batch_gather_column_rows_launch(
    columns_device: *const *const u32,
    row_offsets_device: *const u32,
    row_indices_device: *const u32,
    n_columns: u32,
    total_rows: u32,
    output_device: *mut u32,
    stream: *mut c_void,
) -> i32 {
    let _ = (
        columns_device,
        row_offsets_device,
        row_indices_device,
        n_columns,
        total_rows,
        output_device,
        stream,
    );
    no_cuda_symbol("stwo_batch_gather_column_rows_launch")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_batch_gather_column_rows_host(
    columns_host: *const *const u32,
    column_lengths_host: *const u32,
    row_offsets_host: *const u32,
    row_indices_host: *const u32,
    n_columns: u32,
    total_rows: u32,
    output_host: *mut u32,
) -> i32 {
    let _ = (
        columns_host,
        column_lengths_host,
        row_offsets_host,
        row_indices_host,
        n_columns,
        total_rows,
        output_host,
    );
    no_cuda_symbol("stwo_batch_gather_column_rows_host")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_malloc_uint32_t(size: u32) -> *const u32 {
    no_cuda_symbol("cuda_malloc_uint32_t")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_set_uint32_t(device_ptr: *const c_void, index: usize, val: u32) {
    no_cuda_symbol("cuda_set_uint32_t")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_get_uint32_t(device_ptr: *const c_void, index: usize) -> u32 {
    no_cuda_symbol("cuda_get_uint32_t")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_increase_at(device_ptr: *const c_void, addr: u32) {
    no_cuda_symbol("cuda_increase_at")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_get_secure_field(
    device_ptr: *const c_void,
    index: usize,
) -> CudaSecureField {
    no_cuda_symbol("cuda_get_secure_field")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_malloc_blake_2s_hash(size: usize) -> *const Blake2sHash {
    no_cuda_symbol("cuda_malloc_blake_2s_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_alloc_zeroes_uint32_t(size: u32) -> *const u32 {
    no_cuda_symbol("cuda_alloc_zeroes_uint32_t")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_alloc_zeroes_blake_2s_hash(size: usize) -> *const Blake2sHash {
    no_cuda_symbol("cuda_alloc_zeroes_blake_2s_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_free_memory(device_ptr: *const c_void) {
    no_cuda_symbol("cuda_free_memory")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_pool_highwater(used_high: *mut usize, reserved_high: *mut usize) {
    no_cuda_symbol("cuda_pool_highwater")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_pool_highwater_reset() {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_get_memory_info(free_mem: *mut usize, total_mem: *mut usize) {
    no_cuda_symbol("cuda_get_memory_info")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bit_reverse_base_field(array: *const u32, size: usize) {
    no_cuda_symbol("bit_reverse_base_field")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bit_reverse_secure_field(array: *const u32, size: usize) {
    no_cuda_symbol("bit_reverse_secure_field")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn batch_inverse_base_field(from: *const u32, dst: *const u32, size: usize) {
    no_cuda_symbol("batch_inverse_base_field")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sort_values_and_permute_with_bit_reverse_order(
    from: *const u32,
    size: usize,
) -> *const u32 {
    no_cuda_symbol("sort_values_and_permute_with_bit_reverse_order")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn precompute_twiddles(
    initial: CirclePointBaseField,
    step: CirclePointBaseField,
    total_size: usize,
) -> *const u32 {
    no_cuda_symbol("precompute_twiddles")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn evaluate_columns(
    eval_domain_sizes: *const u32,
    values: *const *const u32,
    twiddles_tree: *const u32,
    twiddle_tree_size: u32,
    number_of_columns: u32,
    column_sizes: *const u32,
) {
    no_cuda_symbol("evaluate_columns")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn eval_at_point(
    coeffs: *const u32,
    coeffs_size: u32,
    point_x: CudaSecureField,
    point_y: CudaSecureField,
) -> CudaSecureField {
    no_cuda_symbol("eval_at_point")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn batch_eval_at_points(
    coeffs_ptrs: *const *const u32,
    coeffs_size: i32,
    num_polys: i32,
    point_x: CudaSecureField,
    point_y: CudaSecureField,
    results: *mut CudaSecureField,
) {
    no_cuda_symbol("batch_eval_at_points")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn barycentric_point_vanishings(
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    size: u32,
    log_size: u32,
    point_x: CudaSecureField,
    point_y: CudaSecureField,
    result: *const u32,
) {
    let _ = (
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        point_x,
        point_y,
        result,
    );
    no_cuda_symbol("barycentric_point_vanishings")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn barycentric_weights_from_point_vanishings(
    point_vanishings: *const u32,
    size: u32,
    even_scale: CudaSecureField,
    odd_scale: CudaSecureField,
    result_weights: *const u32,
) {
    no_cuda_symbol("barycentric_weights_from_point_vanishings")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn barycentric_eval_base_field(
    eval_values: *const u32,
    weights: *const u32,
    size: u32,
) -> CudaSecureField {
    no_cuda_symbol("barycentric_eval_base_field")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn barycentric_eval_base_field_many(
    columns_dev: *const *const u32,
    n_cols: u32,
    weights: *const u32,
    size: u32,
    out_host: *mut CudaSecureField,
) {
    no_cuda_symbol("barycentric_eval_base_field_many")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fold_line(
    gpu_domain: *const u32,
    twiddle_offset: usize,
    n: usize,
    eval_values: *const *const u32,
    alpha: CudaSecureField,
    folded_values: *const *const u32,
) {
    no_cuda_symbol("fold_line")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fold_circle_into_line(
    gpu_domain: *const u32,
    twiddle_offset: usize,
    n: usize,
    eval_values: *const *const u32,
    alpha: CudaSecureField,
    folded_values: *const *const u32,
) {
    no_cuda_symbol("fold_circle_into_line")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_fold_line_on(
    gpu_domain: *const u32,
    twiddle_offset: u32,
    n: u32,
    eval_values: *const *mut u32,
    alpha: *const CudaSecureField,
    alpha_squarings: u32,
    folded_values: *const *mut u32,
    stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_fold_line_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_fold_circle_into_line_on(
    gpu_domain: *const u32,
    twiddle_offset: u32,
    n: u32,
    eval_values: *const *mut u32,
    alpha: *const CudaSecureField,
    alpha_squarings: u32,
    folded_values: *const *mut u32,
    stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_fold_circle_into_line_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn accumulate(
    size: u32,
    left_columns: *const *const u32,
    right_columns: *const *const u32,
) {
    no_cuda_symbol("accumulate")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lift_accumulate_secure_columns(
    size: u32,
    log_ratio: u32,
    previous_columns: *const *const u32,
    current_columns: *const *const u32,
) {
    no_cuda_symbol("lift_accumulate_secure_columns")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn commit_on_first_layer(
    size: usize,
    amount_of_columns: usize,
    columns: *const *const u32,
    result: *mut Blake2sHash,
) {
    no_cuda_symbol("commit_on_first_layer")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn commit_on_first_layer_lifted(
    size: usize,
    amount_of_columns: usize,
    columns: *const *const u32,
    column_log_sizes: *const u32,
    lifting_log_size: u32,
    result: *mut Blake2sHash,
) {
    no_cuda_symbol("commit_on_first_layer_lifted")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn commit_on_layer_with_previous(
    size: usize,
    amount_of_columns: usize,
    columns: *const *const u32,
    previous_layer: *const Blake2sHash,
    result: *mut Blake2sHash,
) {
    no_cuda_symbol("commit_on_layer_with_previous")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn commit_on_two_layers_with_previous(
    size: usize,
    previous_layer: *const Blake2sHash,
    result: *mut Blake2sHash,
) {
    no_cuda_symbol("commit_on_two_layers_with_previous")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stream_leaf_init(_size: u32, _state: *mut Blake2sHash) {
    no_cuda_symbol("stream_leaf_init")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stream_leaf_update(
    _size: u32,
    _group_n_cols: u32,
    _columns: *const *const u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _state: *mut Blake2sHash,
) {
    no_cuda_symbol("stream_leaf_update")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stream_leaf_update_ilp2(
    _size: u32,
    _group_n_cols: u32,
    _columns: *const *const u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _state: *mut Blake2sHash,
) {
    no_cuda_symbol("stream_leaf_update_ilp2")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stream_leaf_finalize(
    _size: u32,
    _rem_cols: u32,
    _columns: *const *const u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _result: *mut Blake2sHash,
) {
    no_cuda_symbol("stream_leaf_finalize")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_leaf_init_on(
    _size: u32,
    _state: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_leaf_init_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_progressive_init_on(
    _size: u32,
    _states: *mut crate::raw::ProgressiveBlake2sState,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_progressive_init_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_progressive_absorb_on(
    _size: u32,
    _number_of_columns: u32,
    _absorbed_columns_before: u32,
    _columns: *const *mut u32,
    _states: *mut crate::raw::ProgressiveBlake2sState,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_progressive_absorb_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_progressive_absorb_quad_on(
    _size: u32,
    _number_of_columns: u32,
    _absorbed_columns_before: u32,
    _columns: *const *mut u32,
    _initializes_state: u32,
    _states: *mut crate::raw::ProgressiveBlake2sState,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_progressive_absorb_quad_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_compact_absorb_quad_on(
    _size: u32,
    _number_of_columns: u32,
    _absorbed_columns_before: u32,
    _columns: *const *mut u32,
    _initializes_state: u32,
    _tail: *const CompactBlake2sTailDescriptor,
    _states: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_compact_absorb_quad_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_compact_expand_absorb_quad_on(
    _from_log_size: u32,
    _to_log_size: u32,
    _number_of_columns: u32,
    _absorbed_columns_before: u32,
    _columns: *const *mut u32,
    _tail: *const CompactBlake2sTailDescriptor,
    _source_states: *const Blake2sHash,
    _destination_states: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_compact_expand_absorb_quad_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_compact_absorb_n2b_terminal_pair_on(
    _size: u32,
    _number_of_columns: u32,
    _absorbed_columns_before: u32,
    _prefinal_columns: *const *mut u32,
    _initializes_state: u32,
    _tail: *const CompactBlake2sTailDescriptor,
    _twiddles: *mut u32,
    _twiddle_words: u32,
    _states: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_compact_absorb_n2b_terminal_pair_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_progressive_expand_on(
    _from_log_size: u32,
    _to_log_size: u32,
    _states_in: *const crate::raw::ProgressiveBlake2sState,
    _states_out: *mut crate::raw::ProgressiveBlake2sState,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_progressive_expand_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_progressive_expand_in_place_on(
    _from_log_size: u32,
    _to_log_size: u32,
    _states: *mut crate::raw::ProgressiveBlake2sState,
    _scratch_pair: *mut crate::raw::ProgressiveBlake2sState,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_progressive_expand_in_place_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_compact_expand_in_place_on(
    _from_log_size: u32,
    _to_log_size: u32,
    _states: *mut Blake2sHash,
    _scratch_pair: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_compact_expand_in_place_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_progressive_finalize_on(
    _size: u32,
    _absorbed_columns: u32,
    _states: *const crate::raw::ProgressiveBlake2sState,
    _result: *mut crate::raw::Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_progressive_finalize_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_progressive_finalize_in_place_on(
    _size: u32,
    _absorbed_columns: u32,
    _states_and_hashes: *mut crate::raw::ProgressiveBlake2sState,
    _scratch_pair: *mut crate::raw::ProgressiveBlake2sState,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_progressive_finalize_in_place_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_compact_finalize_quad_in_place_on(
    _size: u32,
    _absorbed_columns: u32,
    _tail: *const CompactBlake2sTailDescriptor,
    _states_and_hashes: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_compact_finalize_quad_in_place_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_leaf_update_on(
    _size: u32,
    _group_n_cols: u32,
    _columns: *const *mut u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _state: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_leaf_update_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_leaf_update_ilp2_on(
    _size: u32,
    _group_n_cols: u32,
    _columns: *const *mut u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _state: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_leaf_update_ilp2_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_leaf_update_quad_on(
    _size: u32,
    _group_n_cols: u32,
    _columns: *const *mut u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _state: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_leaf_update_quad_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_leaf_finalize_on(
    _size: u32,
    _rem_cols: u32,
    _columns: *const *mut u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _result: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_leaf_finalize_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_leaf_group_from_lde_on(
    _size: u32,
    _group_n_cols: u32,
    _prefinal_columns: *const *mut u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _is_final: u32,
    _twiddles: *mut u32,
    _twiddle_words: u32,
    _state: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_leaf_group_from_lde_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_layer_on(
    _previous_layer: *const Blake2sHash,
    _output_size: u32,
    _result: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_layer_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_layer_in_place_on(
    _output_size: u32,
    _hashes: *mut crate::raw::Blake2sHash,
    _scratch_pair: *mut crate::raw::ProgressiveBlake2sState,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_layer_in_place_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_interior4_on(
    _previous_layer: *const Blake2sHash,
    _output_size: u32,
    _result: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_interior4_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_fri_leaf_on(
    _evaluation_size: u32,
    _coordinate_columns: *const *mut u32,
    _log_rows_per_leaf: u32,
    _result: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_fri_leaf_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_blake_2s_hash_vec_from_host_to_device(
    from: *const Blake2sHash,
    size: usize,
) -> *mut Blake2sHash {
    no_cuda_symbol("copy_blake_2s_hash_vec_from_host_to_device")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_blake_2s_hash_vec_from_device_to_host(
    from: *const Blake2sHash,
    to: *mut Blake2sHash,
    size: usize,
) {
    no_cuda_symbol("copy_blake_2s_hash_vec_from_device_to_host")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_blake_2s_hash_vec_from_device_to_device(
    from: *const Blake2sHash,
    dst: *const Blake2sHash,
    size: usize,
) {
    no_cuda_symbol("copy_blake_2s_hash_vec_from_device_to_device")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_get_blake_2s_hash(
    device_ptr: *const Blake2sHash,
    host_ptr: *mut Blake2sHash,
    index: usize,
) {
    no_cuda_symbol("cuda_get_blake_2s_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_set_blake_2s_hash(
    device_ptr: *mut Blake2sHash,
    index: usize,
    host_ptr: *const Blake2sHash,
) {
    no_cuda_symbol("cuda_set_blake_2s_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_batch_get_blake_2s_hash(
    device_ptr: *const Blake2sHash,
    host_ptr: *mut Blake2sHash,
    indices: *const u32,
    n_indices: u32,
) {
    no_cuda_symbol("cuda_batch_get_blake_2s_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_multi_layer_batch_get_blake_2s_hash(
    layer_device_ptrs: *const *const Blake2sHash,
    host_ptr: *mut Blake2sHash,
    pairs: *const LayerIndexPair,
    n_pairs: u32,
) {
    no_cuda_symbol("cuda_multi_layer_batch_get_blake_2s_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_device_pointer_vec_from_host_to_device(
    from: *const *const u32,
    size: usize,
) -> *const *const u32 {
    no_cuda_symbol("copy_device_pointer_vec_from_host_to_device")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_release_uploaded_pointer_vec(device_ptr: *const *const u32) {
    no_cuda_symbol("cuda_release_uploaded_pointer_vec")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn accumulate_quotients(
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
    no_cuda_symbol("accumulate_quotients")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn accumulate_partial_quotient_numerators(
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
    no_cuda_symbol("accumulate_partial_quotient_numerators")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn combine_quotients_from_numerators(
    half_coset_initial_index: u32,
    half_coset_step_size: u32,
    domain_size: u32,
    domain_log_size: u32,
    sample_points: *const CudaSecureField,
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
    no_cuda_symbol("combine_quotients_from_numerators")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_combine_quotients_from_numerators_on(
    _half_coset_initial_index: u32,
    _half_coset_step_size: u32,
    _domain_size: u32,
    _domain_log_size: u32,
    _sample_points: *const u32,
    _sample_size: u32,
    _first_linear_term_accs: *const CudaSecureField,
    _partial_numerator_log_sizes: *const u32,
    _partial_numerators_0: *const *const u32,
    _partial_numerators_1: *const *const u32,
    _partial_numerators_2: *const *const u32,
    _partial_numerators_3: *const *const u32,
    _result_column_0: *mut u32,
    _result_column_1: *mut u32,
    _result_column_2: *mut u32,
    _result_column_3: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_combine_quotients_from_numerators_on")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_combine_quotients_b2n_init7_on(
    _half_coset_initial_index: u32,
    _half_coset_step_size: u32,
    _domain_size: u32,
    _domain_log_size: u32,
    _sample_points: *const u32,
    _sample_size: u32,
    _first_linear_term_accs: *const CudaSecureField,
    _partial_numerator_log_sizes: *const u32,
    _partial_numerators_0: *const *const u32,
    _partial_numerators_1: *const *const u32,
    _partial_numerators_2: *const *const u32,
    _partial_numerators_3: *const *const u32,
    _result_column_0: *mut u32,
    _result_column_1: *mut u32,
    _result_column_2: *mut u32,
    _result_column_3: *mut u32,
    _inverse_twiddles: *const u32,
    _inverse_twiddle_words: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_combine_quotients_b2n_init7_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_combine_quotients_b2n_init7_function_attributes(
    _out: *mut CudaFunctionAttributes,
) -> i32 {
    no_cuda_symbol("stwo_combine_quotients_b2n_init7_function_attributes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_prepare_quotient_numerator_terms_on(
    _term_descriptors: *const u32,
    _term_count: u32,
    _sample_points: *const u32,
    _sample_values: *const CudaSecureField,
    _random_coefficient: *const CudaSecureField,
    _term_points: *mut u32,
    _line_coefficients: *mut CudaSecureField,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_prepare_quotient_numerator_terms_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_finalize_quotient_numerator_groups_on(
    _group_offsets: *const u32,
    _group_term_indices: *const u32,
    _group_count: u32,
    _term_points: *const u32,
    _line_coefficients: *mut CudaSecureField,
    _sample_points: *mut u32,
    _first_linear_terms: *mut CudaSecureField,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_finalize_quotient_numerator_groups_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_zero_quotient_numerator_outputs_on(
    _group_log_sizes: *const u32,
    _group_count: u32,
    _max_output_size: u32,
    _outputs_0: *const *mut u32,
    _outputs_1: *const *mut u32,
    _outputs_2: *const *mut u32,
    _outputs_3: *const *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_zero_quotient_numerator_outputs_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_accumulate_quotient_numerator_batch_on(
    _group_offsets: *const u32,
    _term_descriptors: *const u32,
    _group_count: u32,
    _max_output_size: u32,
    _source_evaluations: *const *const u32,
    _line_coefficients: *const CudaSecureField,
    _group_log_sizes: *const u32,
    _outputs_0: *const *mut u32,
    _outputs_1: *const *mut u32,
    _outputs_2: *const *mut u32,
    _outputs_3: *const *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_accumulate_quotient_numerator_batch_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_accumulate_quotient_numerator_single_write_on(
    _group_offsets: *const u32,
    _term_descriptors: *const u32,
    _group_count: u32,
    _max_output_size: u32,
    _source_evaluations: *const *const u32,
    _line_coefficients: *const CudaSecureField,
    _group_log_sizes: *const u32,
    _outputs_0: *const *mut u32,
    _outputs_1: *const *mut u32,
    _outputs_2: *const *mut u32,
    _outputs_3: *const *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_accumulate_quotient_numerator_single_write_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_accumulate_quotient_numerator_packed_single_write_on(
    _group_row_offsets: *const u64,
    _group_term_offsets: *const u32,
    _term_descriptors: *const u32,
    _group_count: u32,
    _packed_output_rows: u64,
    _source_evaluations: *const *const u32,
    _line_coefficients: *const CudaSecureField,
    _group_log_sizes: *const u32,
    _outputs_0: *const *mut u32,
    _outputs_1: *const *mut u32,
    _outputs_2: *const *mut u32,
    _outputs_3: *const *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_accumulate_quotient_numerator_packed_single_write_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_accumulate_quotient_numerator_group_direct_on(
    _term_descriptors: *const u32,
    _term_begin: u32,
    _term_end: u32,
    _group_log_size: u32,
    _source_evaluations: *const *const u32,
    _line_coefficients: *const CudaSecureField,
    _group_b: *const CudaSecureField,
    _output_0: *mut u32,
    _output_1: *mut u32,
    _output_2: *mut u32,
    _output_3: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_accumulate_quotient_numerator_group_direct_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_accumulate_quotient_numerator_group_direct_tiled_on(
    _term_descriptors: *const u32,
    _term_begin: u32,
    _term_end: u32,
    _group_log_size: u32,
    _source_evaluations: *const *const u32,
    _line_coefficients: *const CudaSecureField,
    _group_b: *const CudaSecureField,
    _output_0: *mut u32,
    _output_1: *mut u32,
    _output_2: *mut u32,
    _output_3: *mut u32,
    _tile_words: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_accumulate_quotient_numerator_group_direct_tiled_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_accumulate_quotient_numerator_group_direct_contribution_tiled_on(
    _term_descriptors: *const u32,
    _term_begin: u32,
    _term_end: u32,
    _group_log_size: u32,
    _source_evaluations: *const *const u32,
    _line_coefficients: *const CudaSecureField,
    _group_b: *const CudaSecureField,
    _output_0: *mut u32,
    _output_1: *mut u32,
    _output_2: *mut u32,
    _output_3: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_accumulate_quotient_numerator_group_direct_contribution_tiled_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_quotient_numerator_group_direct_tiled_function_attributes(
    _tile_words: u32,
    _out: *mut CudaFunctionAttributes,
) -> i32 {
    no_cuda_symbol("stwo_quotient_numerator_group_direct_tiled_function_attributes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_quotient_numerator_group_direct_contribution_tiled_function_attributes(
    _out: *mut CudaFunctionAttributes,
) -> i32 {
    no_cuda_symbol("stwo_quotient_numerator_group_direct_contribution_tiled_function_attributes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_precompute_quotient_numerator_native_run_on(
    _term_descriptors: *const u32,
    _term_begin: u32,
    _term_end: u32,
    _source_log_size: u32,
    _source_evaluations: *const *const u32,
    _line_coefficients: *const CudaSecureField,
    _scratch_0: *mut u32,
    _scratch_1: *mut u32,
    _scratch_2: *mut u32,
    _scratch_3: *mut u32,
    _scratch_offset_words: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_precompute_quotient_numerator_native_run_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_expand_quotient_numerator_native_run_sums_on(
    _manifest: *const CudaQuotientNativeRunManifest,
    _term_descriptors: *const u32,
    _source_evaluations: *const *const u32,
    _line_coefficients: *const CudaSecureField,
    _group_b: *const CudaSecureField,
    _scratch_0: *const u32,
    _scratch_1: *const u32,
    _scratch_2: *const u32,
    _scratch_3: *const u32,
    _output_0: *mut u32,
    _output_1: *mut u32,
    _output_2: *mut u32,
    _output_3: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_expand_quotient_numerator_native_run_sums_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_quotient_numerator_native_run_precompute_function_attributes(
    _out: *mut CudaFunctionAttributes,
) -> i32 {
    no_cuda_symbol("stwo_quotient_numerator_native_run_precompute_function_attributes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_quotient_numerator_native_run_sum_expand_function_attributes(
    _out: *mut CudaFunctionAttributes,
) -> i32 {
    no_cuda_symbol("stwo_quotient_numerator_native_run_sum_expand_function_attributes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_prepare_quotient_numerator_prepacked_terms_on(
    _group_term_offsets: *const u32,
    _term_descriptors: *const u32,
    _group_count: u32,
    _term_count: u32,
    _source_evaluations: *const *const u32,
    _source_count: u32,
    _line_coefficients: *const CudaSecureField,
    _prepacked_storage: *mut u32,
    _prepacked_storage_words: u64,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_prepare_quotient_numerator_prepacked_terms_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_accumulate_quotient_numerator_prepacked_single_write_on(
    _group_row_offsets: *const u64,
    _group_term_offsets: *const u32,
    _group_count: u32,
    _term_count: u32,
    _packed_output_rows: u64,
    _prepacked_storage: *mut u32,
    _prepacked_storage_words: u64,
    _group_log_sizes: *const u32,
    _outputs_0: *const *mut u32,
    _outputs_1: *const *mut u32,
    _outputs_2: *const *mut u32,
    _outputs_3: *const *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_accumulate_quotient_numerator_prepacked_single_write_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_oods_derive_points_on(
    _oods_parameter: *const CudaSecureField,
    _offset_points: *const CirclePointBaseField,
    _fold_counts: *const u32,
    _output_indices: *const u32,
    _sample_count: u32,
    _coefficient_log_size: u32,
    _sample_points: *mut u32,
    _evaluation_points: *mut u32,
    _folding_factors: *mut CudaSecureField,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_oods_derive_points_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_oods_eval_first_on(
    _coefficients: *const *const u32,
    _coefficient_size: u32,
    _sample_count: u32,
    _folding_factors: *const CudaSecureField,
    _scratch: *mut CudaSecureField,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_oods_eval_first_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_oods_eval_reduce_on(
    _input: *const CudaSecureField,
    _input_size: u32,
    _input_stride: u32,
    _factor_index: u32,
    _coefficient_log_size: u32,
    _sample_count: u32,
    _folding_factors: *const CudaSecureField,
    _output: *mut CudaSecureField,
    _output_stride: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_oods_eval_reduce_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_oods_store_results_on(
    _reduced: *const CudaSecureField,
    _reduced_stride: u32,
    _output_indices: *const u32,
    _sample_count: u32,
    _sampled_values: *mut CudaSecureField,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_oods_store_results_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_oods_barycentric_weights_on(
    _half_coset_initial_index: u32,
    _half_coset_step_size: u32,
    _size: u32,
    _log_size: u32,
    _evaluation_point: *const u32,
    _si0: CudaSecureField,
    _vanishing_rotation: CirclePointBaseField,
    _numerator_inverses: *mut CudaSecureField,
    _weights: *mut CudaSecureField,
    _scales: *mut CudaSecureField,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_oods_barycentric_weights_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_oods_barycentric_weights_collapsed_cohort_on(
    _half_coset_initial_index: u32,
    _half_coset_step_size: u32,
    _size: u32,
    _log_size: u32,
    _evaluation_points: *const u32,
    _descriptor_offsets: *const u32,
    _group_count: u32,
    _si0: CudaSecureField,
    _vanishing_rotation: CirclePointBaseField,
    _weights: *mut CudaSecureField,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_oods_barycentric_weights_collapsed_cohort_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_oods_barycentric_eval_many_on(
    _columns: *const *const u32,
    _column_count: u32,
    _weights: *const CudaSecureField,
    _size: u32,
    _partial_sums: *mut CudaSecureField,
    _reduction_blocks: u32,
    _output_indices: *const u32,
    _sampled_values: *mut CudaSecureField,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_oods_barycentric_eval_many_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gen_eq_evals(
    v: CudaSecureField,
    y: *const CudaSecureField,
    y_size: u32,
    evals: *const CudaSecureField,
    evals_size: u32,
) {
    no_cuda_symbol("gen_eq_evals")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gkr_next_grand_product_layer(
    input_layer: *const CudaSecureField,
    input_size: u32,
    output_layer: *const CudaSecureField,
) {
    no_cuda_symbol("gkr_next_grand_product_layer")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gkr_next_logup_generic_layer(
    numerators: *const CudaSecureField,
    denominators: *const CudaSecureField,
    input_size: u32,
    next_numerators: *const CudaSecureField,
    next_denominators: *const CudaSecureField,
) {
    no_cuda_symbol("gkr_next_logup_generic_layer")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gkr_next_logup_multiplicities_layer(
    numerators: *const u32,
    denominators: *const CudaSecureField,
    input_size: u32,
    next_numerators: *const CudaSecureField,
    next_denominators: *const CudaSecureField,
) {
    no_cuda_symbol("gkr_next_logup_multiplicities_layer")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gkr_next_logup_singles_layer(
    denominators: *const CudaSecureField,
    input_size: u32,
    next_numerators: *const CudaSecureField,
    next_denominators: *const CudaSecureField,
) {
    no_cuda_symbol("gkr_next_logup_singles_layer")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gkr_sum_grand_product(
    eq_evals: *const CudaSecureField,
    input_layer: *const CudaSecureField,
    n_terms: u32,
    eval_at_0: *mut CudaSecureField,
    eval_at_2: *mut CudaSecureField,
) {
    no_cuda_symbol("gkr_sum_grand_product")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gkr_sum_logup_generic(
    eq_evals: *const CudaSecureField,
    numerators: *const CudaSecureField,
    denominators: *const CudaSecureField,
    n_terms: u32,
    lambda: CudaSecureField,
    eval_at_0: *mut CudaSecureField,
    eval_at_2: *mut CudaSecureField,
) {
    no_cuda_symbol("gkr_sum_logup_generic")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gkr_sum_logup_multiplicities(
    eq_evals: *const CudaSecureField,
    numerators: *const u32,
    denominators: *const CudaSecureField,
    n_terms: u32,
    lambda: CudaSecureField,
    eval_at_0: *mut CudaSecureField,
    eval_at_2: *mut CudaSecureField,
) {
    no_cuda_symbol("gkr_sum_logup_multiplicities")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gkr_sum_logup_singles(
    eq_evals: *const CudaSecureField,
    denominators: *const CudaSecureField,
    n_terms: u32,
    lambda: CudaSecureField,
    eval_at_0: *mut CudaSecureField,
    eval_at_2: *mut CudaSecureField,
) {
    no_cuda_symbol("gkr_sum_logup_singles")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fix_first_variable_base_field(
    evals: *const u32,
    evals_size: usize,
    assignment: CudaSecureField,
    output_evals: *const u32,
) {
    no_cuda_symbol("fix_first_variable_base_field")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fix_first_variable_secure_field(
    evals: *const u32,
    evals_size: usize,
    assignment: CudaSecureField,
    output_evals: *const u32,
) {
    no_cuda_symbol("fix_first_variable_secure_field")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_n2b_native_batch(
    value: *mut *mut u32,
    log_n: u32,
    num_poly: u32,
    start_stage: u32,
    end_stage: u32,
    g_twiddles: *const u32,
    twiddles_size: u32,
    eval_domain_size: u32,
) {
    no_cuda_symbol("ntt_n2b_native_batch")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_b2n_column(
    values_columns: *mut *mut u32,
    log_n: u32,
    num_poly: u32,
    g_twiddles: *const u32,
    twiddles_size: u32,
    eval_domain_size: u32,
) {
    no_cuda_symbol("ntt_b2n_column")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_b2n_columns_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_b2n_columns_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_b2n_columns_after_first_seven_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *const u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_b2n_columns_after_first_seven_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_b2n_after_first_seven_function_attributes(
    _start_stage: u32,
    _stages: u32,
    _out: *mut CudaFunctionAttributes,
) -> i32 {
    no_cuda_symbol("stwo_ntt_b2n_after_first_seven_function_attributes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_b2n_columns_out_of_place_on(
    _inputs: *const *const u32,
    _outputs: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *const u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_b2n_columns_out_of_place_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_b2n_columns_to_retained_on(
    _inputs: *const *const u32,
    _retained_outputs: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *const u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_b2n_columns_to_retained_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_b2n_composition_to_retained_on(
    _source_values: *const *mut u32,
    _retained_outputs: *const *mut u32,
    _log_n: u32,
    _inverse_twiddles: *const u32,
    _inverse_twiddle_words: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_b2n_composition_to_retained_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_b2n_composition_fused_first_forward_on(
    _source_values: *const *mut u32,
    _retained_outputs: *const *mut u32,
    _log_n: u32,
    _inverse_twiddles: *const u32,
    _inverse_twiddle_words: u32,
    _forward_twiddles: *const u32,
    _forward_twiddle_words: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_b2n_composition_fused_first_forward_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntt_n2b_columns(
    values_columns: *mut *mut u32,
    log_n: u32,
    num_poly: u32,
    g_twiddles: *const u32,
    twiddles_size: u32,
    eval_domain_size: u32,
) {
    no_cuda_symbol("ntt_n2b_columns")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_n2b_columns_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_n2b_columns_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_n2b_columns_from_stage_two_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_n2b_columns_from_stage_two_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_n2b_columns_from_stage_two_before_circle_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_n2b_columns_from_stage_two_before_circle_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_n2b_columns_from_stage_two_before_final_interval_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_n2b_columns_from_stage_two_before_final_interval_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_n2b_columns_final_interval_before_circle_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_n2b_columns_final_interval_before_circle_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_n2b_columns_after_first_stage_two_interval_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_n2b_columns_after_first_stage_two_interval_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_lde_n2b_columns_on(
    _coefficient_values: *const *const u32,
    _coefficient_sizes: *const u32,
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_lde_n2b_columns_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_lde_n2b_columns_before_circle_on(
    _coefficient_values: *const *const u32,
    _coefficient_sizes: *const u32,
    _device_values: *const *mut u32,
    _log_n: u32,
    _num_poly: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_lde_n2b_columns_before_circle_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_lde_n2b_hash16_configure(_log_n: u32) -> i32 {
    no_cuda_symbol("stwo_lde_n2b_hash16_configure")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_lde_n2b_hash16_on(
    _coefficient_values: *const *const u32,
    _coefficient_sizes: *const u32,
    _device_values: *const *mut u32,
    _log_n: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _cols_done: u32,
    _is_final: u32,
    _states: *mut Blake2sHash,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_lde_n2b_hash16_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_malloc_poseidon252_hash(size: usize) -> *mut [u8; 32] {
    no_cuda_symbol("cuda_malloc_poseidon252_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_alloc_zeroes_poseidon252_hash(size: usize) -> *mut [u8; 32] {
    no_cuda_symbol("cuda_alloc_zeroes_poseidon252_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_poseidon252_hash_vec_from_host_to_device(
    from: *const [u8; 32],
    size: usize,
) -> *mut [u8; 32] {
    no_cuda_symbol("copy_poseidon252_hash_vec_from_host_to_device")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_poseidon252_hash_vec_from_device_to_host(
    from: *const [u8; 32],
    to: *mut [u8; 32],
    size: usize,
) {
    no_cuda_symbol("copy_poseidon252_hash_vec_from_device_to_host")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn copy_poseidon252_hash_vec_from_device_to_device(
    from: *const [u8; 32],
    dst: *mut [u8; 32],
    size: usize,
) {
    no_cuda_symbol("copy_poseidon252_hash_vec_from_device_to_device")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_get_poseidon252_hash(
    device_ptr: *const [u8; 32],
    host_ptr: *mut [u8; 32],
    index: usize,
) {
    no_cuda_symbol("cuda_get_poseidon252_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_set_poseidon252_hash(
    device_ptr: *mut [u8; 32],
    index: usize,
    value: *const [u8; 32],
) {
    no_cuda_symbol("cuda_set_poseidon252_hash")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn poseidon252_commit_on_first_layer(
    size: usize,
    amount_of_columns: usize,
    columns: *const *const u32,
    result: *mut [u8; 32],
) {
    no_cuda_symbol("poseidon252_commit_on_first_layer")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn poseidon252_commit_on_layer_with_previous(
    size: usize,
    amount_of_columns: usize,
    columns: *const *const u32,
    previous_layer: *const [u8; 32],
    result: *mut [u8; 32],
) {
    no_cuda_symbol("poseidon252_commit_on_layer_with_previous")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn test_offset_bit_reversed_indices(
    result_host: *mut u32,
    domain_log_size: u32,
    eval_log_size: u32,
    offset: i32,
    n: u32,
) {
    no_cuda_symbol("test_offset_bit_reversed_indices")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_mem_pool_init() -> i32 {
    no_cuda_symbol("cuda_mem_pool_init")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_default_pool_alloc_checked(
    _byte_count: usize,
    output: *mut *mut core::ffi::c_void,
) -> i32 {
    if let Some(output) = unsafe { output.as_mut() } {
        *output = core::ptr::null_mut();
    }
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_default_pool_copy_h2d_checked(
    _host: *const core::ffi::c_void,
    _device: *mut core::ffi::c_void,
    _byte_count: usize,
) -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_default_pool_free_checked(_device: *mut core::ffi::c_void) -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_default_pool_stream_sync_checked() -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_default_pool_current(
    _used_current: *mut usize,
    _reserved_current: *mut usize,
) -> i32 {
    no_cuda_symbol("cuda_default_pool_current")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuda_default_pool_trim(
    _min_bytes_to_keep: usize,
    _used_current: *mut usize,
    _reserved_current: *mut usize,
) -> i32 {
    no_cuda_symbol("cuda_default_pool_trim")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn grind_blake2s(_host_prefixed_digest: *const u32, _pow_bits: u32) -> u64 {
    no_cuda_symbol("grind_blake2s")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_cuda_jit_eval_fused(
    _source: *const core::ffi::c_char,
    _kernel_name: *const core::ffi::c_char,
    _semantic_hash: u64,
    _trace_values: *const u32,
    _interaction_offsets: *const u32,
    _base_params: *const u32,
    _ext_params: *const u32,
    _random_coeff_powers: *const u32,
    _denom_inv: *const u32,
    _coord_0: *mut u32,
    _coord_1: *mut u32,
    _coord_2: *mut u32,
    _coord_3: *mut u32,
    _row_count: u32,
    _log_n_rows: u32,
    _rc_base: u32,
    _relax_opt: bool,
) -> bool {
    no_cuda_symbol("stwo_cuda_jit_eval_fused")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_cuda_jit_eval_fused_on(
    _source: *const core::ffi::c_char,
    _kernel_name: *const core::ffi::c_char,
    _semantic_hash: u64,
    _trace_values: *const u32,
    _interaction_offsets: *const u32,
    _base_params: *const u32,
    _ext_params: *const u32,
    _random_coeff_powers: *const u32,
    _denom_inv: *const u32,
    _coord_0: *mut u32,
    _coord_1: *mut u32,
    _coord_2: *mut u32,
    _coord_3: *mut u32,
    _row_count: u32,
    _log_n_rows: u32,
    _rc_base: u32,
    _relax_opt: bool,
    _stream: *mut core::ffi::c_void,
) -> bool {
    no_cuda_symbol("stwo_cuda_jit_eval_fused_on")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_cuda_jit_eval_composition_wave_on(
    _source: *const core::ffi::c_char,
    _kernel_name: *const core::ffi::c_char,
    _cache_key: u64,
    _parts: *const crate::raw::CudaCompositionWavePart,
    _random_coeff_powers: *const u32,
    _coord_0: *mut u32,
    _coord_1: *mut u32,
    _coord_2: *mut u32,
    _coord_3: *mut u32,
    _full_domain_rows: u32,
    _shard_start: u32,
    _shard_rows: u32,
    _stream: *mut core::ffi::c_void,
) -> bool {
    no_cuda_symbol("stwo_cuda_jit_eval_composition_wave_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_composition_generate_descending_powers_on(
    _random_coefficient: *const CudaSecureField,
    _powers: *mut CudaSecureField,
    _count: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_composition_generate_descending_powers_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_composition_lift_accumulate_on(
    _previous_coordinates: *const u32,
    _previous_log_size: u32,
    _current_coordinates: *mut u32,
    _current_log_size: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_composition_lift_accumulate_on")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_composition_materialize_ext_params_on(
    _destinations: *const *mut CudaSecureField,
    _source_kinds: *const u32,
    _source_indices: *const u32,
    _scales: *const u32,
    _count: u32,
    _z: *const CudaSecureField,
    _alpha_powers: *const CudaSecureField,
    _alpha_power_count: u32,
    _claimed_sums: *const *const CudaSecureField,
    _claimed_sum_count: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_composition_materialize_ext_params_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_cuda_jit_precompile(
    _source: *const core::ffi::c_char,
    _kernel_name: *const core::ffi::c_char,
    _semantic_hash: u64,
    _relax_opt: bool,
) -> bool {
    no_cuda_symbol("stwo_cuda_jit_precompile")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_cuda_jit_precompile_batch(
    _sources: *const *const core::ffi::c_char,
    _kernel_names: *const *const core::ffi::c_char,
    _cache_keys: *const u64,
    _relax_opts: *const bool,
    _count: u32,
) -> bool {
    no_cuda_symbol("stwo_cuda_jit_precompile_batch")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_cuda_jit_set_require_aot(_required: bool) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_cuda_jit_get_aot_stats(out: *mut crate::raw::CudaJitAotStats) {
    if let Some(out) = unsafe { out.as_mut() } {
        *out = crate::raw::CudaJitAotStats::default();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_cuda_jit_get_pedersen_module_publication(
    _kernel_name: *const core::ffi::c_char,
    _cache_key: u64,
    out: *mut crate::raw::CudaPedersenModulePublication,
) -> bool {
    if let Some(out) = unsafe { out.as_mut() } {
        *out = crate::raw::CudaPedersenModulePublication::default();
    }
    false
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_cuda_jit_get_aot_function_publication(
    _kernel_name: *const core::ffi::c_char,
    _cache_key: u64,
    out: *mut crate::raw::CudaAotFunctionPublication,
) -> bool {
    if let Some(out) = unsafe { out.as_mut() } {
        *out = crate::raw::CudaAotFunctionPublication::default();
    }
    false
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_installed_aot_function_borrow_published_create(
    _exec_context: *mut core::ffi::c_void,
    _kernel_name: *const core::ffi::c_char,
    _cache_key: u64,
    _expected_sm: u32,
    _expected_module_token: u64,
    _expected_function_token: u64,
    _expected_context_token: u64,
    _argument_count: u32,
    _grid_x: u32,
    _grid_y: u32,
    _grid_z: u32,
    _block_x: u32,
    _block_y: u32,
    _block_z: u32,
    _dynamic_shared_bytes: u32,
    out_handle: *mut *mut core::ffi::c_void,
    out_receipt: *mut crate::raw::CudaInstalledAotFunctionReceipt,
) -> i32 {
    if let Some(out_handle) = unsafe { out_handle.as_mut() } {
        *out_handle = core::ptr::null_mut();
    }
    if let Some(out_receipt) = unsafe { out_receipt.as_mut() } {
        *out_receipt = crate::raw::CudaInstalledAotFunctionReceipt::default();
    }
    no_cuda_symbol("stwo_installed_aot_function_borrow_published_create")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_installed_aot_function_launch(
    _handle: *mut core::ffi::c_void,
    _exec_context: *mut core::ffi::c_void,
    _arguments: *mut *mut core::ffi::c_void,
    _argument_count: u32,
) -> i32 {
    no_cuda_symbol("stwo_installed_aot_function_launch")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_installed_aot_function_destroy(
    _handle: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_installed_aot_function_destroy")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_cuda_jit_reset_aot_stats() {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gen_seq_column_on_gpu(_output: *mut u32, _log_size: u32) {
    no_cuda_symbol("gen_seq_column_on_gpu")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gen_range_check_columns_on_gpu(
    _output_columns: *const *mut u32,
    _n_columns: u32,
    _bits_per_segment: *const u32,
    _n_segments: u32,
) {
    no_cuda_symbol("gen_range_check_columns_on_gpu")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gen_bitwise_xor_columns_on_gpu(
    _output_columns: *const *mut u32,
    _n_bits: u32,
) {
    no_cuda_symbol("gen_bitwise_xor_columns_on_gpu")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_preprocessed_alloc_u32_checked(
    _count: usize,
    output: *mut *mut u32,
) -> i32 {
    if let Some(output) = unsafe { output.as_mut() } {
        *output = core::ptr::null_mut();
    }
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_preprocessed_copy_h2d_checked(
    _host: *const u32,
    _device: *mut u32,
    _count: usize,
) -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_preprocessed_gen_seq_checked(
    _output: *mut u32,
    _log_size: u32,
) -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_preprocessed_gen_range_checked(
    _output_columns: *const *mut u32,
    _n_columns: u32,
    _bits_per_segment: *const u32,
    _n_segments: u32,
) -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_preprocessed_gen_xor_checked(
    _output_columns: *const *mut u32,
    _n_bits: u32,
) -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_preprocessed_stream_sync_checked() -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_cuda_jit_witness_launch(
    _source: *const core::ffi::c_char,
    _kernel_name: *const core::ffi::c_char,
    _cache_key: u64,
    _input_cols: *const *const u32,
    _table_bases: *const *const u32,
    _table_strides: *const u32,
    _out_cols: *const *mut u32,
    _mult_counts: *const *mut u32,
    _lookup_words: *mut u32,
    sub_words: *mut u32,
    _row_count: u32,
    _relax_opt: bool,
    _stream: *mut core::ffi::c_void,
) -> bool {
    no_cuda_symbol("stwo_cuda_jit_witness_launch")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_cuda_jit_witness_phase_pair_launch(
    _kernel_names: *const *const core::ffi::c_char,
    _cache_keys: *const u64,
    _input_cols: *const *const u32,
    _table_bases: *const *const u32,
    _table_strides: *const u32,
    _out_cols: *const *mut u32,
    _mult_counts: *const *mut u32,
    _lookup_words: *mut u32,
    _sub_words: *mut u32,
    _phase_scratch: *mut u32,
    _row_count: u32,
    _stream: *mut core::ffi::c_void,
) -> bool {
    no_cuda_symbol("stwo_cuda_jit_witness_phase_pair_launch")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_fanout_stream(_i: i32) -> *mut core::ffi::c_void {
    no_cuda_symbol("stwo_fanout_stream")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_fanout_fork(_stream: *mut core::ffi::c_void) {
    no_cuda_symbol("stwo_fanout_fork")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_fanout_join(_stream: *mut core::ffi::c_void) {
    no_cuda_symbol("stwo_fanout_join")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_cuda_device_snapshot(
    _out_count: *mut u32,
    _out_current: *mut u32,
    _out_sm_major: *mut u32,
    _out_sm_minor: *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_cuda_device_snapshot")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_create(_out_handle: *mut *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_exec_context_create")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_destroy(_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_exec_context_destroy")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_sync(_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_exec_context_sync")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_pool_current(
    _handle: *mut core::ffi::c_void,
    _used_current: *mut usize,
    _reserved_current: *mut usize,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_pool_current")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_stream_sync(
    _handle: *mut core::ffi::c_void,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_stream_sync")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_stream(
    _handle: *mut core::ffi::c_void,
    _out_stream: *mut *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_stream")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_device(
    _handle: *mut core::ffi::c_void,
    _out_device: *mut i32,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_device")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_timing_begin(
    _handle: *mut core::ffi::c_void,
    _out_interval_capacity: *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_timing_begin")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_timing_mark(_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_exec_context_timing_mark")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_timing_elapsed(
    _handle: *mut core::ffi::c_void,
    _out_elapsed_ms: *mut f32,
    _capacity: u32,
    _out_count: *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_timing_elapsed")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_lane_count(
    _handle: *mut core::ffi::c_void,
    _out_count: *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_lane_count")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_lane_stream(
    _handle: *mut core::ffi::c_void,
    _lane: u32,
    _out_stream: *mut *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_lane_stream")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_lane_fork(
    _handle: *mut core::ffi::c_void,
    _lane: u32,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_lane_fork")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_lane_join(
    _handle: *mut core::ffi::c_void,
    _lane: u32,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_lane_join")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_join_all_lanes(_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_exec_context_join_all_lanes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_alloc_u32(
    _handle: *mut core::ffi::c_void,
    _count: usize,
    _out_ptr: *mut *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_alloc_u32")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_free_u32(
    _handle: *mut core::ffi::c_void,
    _ptr: *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_free_u32")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_memset_async(
    _handle: *mut core::ffi::c_void,
    _dst: *mut core::ffi::c_void,
    _value: i32,
    _bytes: usize,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_memset_async")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_fill_u32_async(
    _handle: *mut core::ffi::c_void,
    _dst: *mut u32,
    _value: u32,
    _count: usize,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_fill_u32_async")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_memcpy_d2d_async(
    _handle: *mut core::ffi::c_void,
    _dst: *mut core::ffi::c_void,
    _src: *const core::ffi::c_void,
    _bytes: usize,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_memcpy_d2d_async")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_memcpy_h2d_async(
    _handle: *mut core::ffi::c_void,
    _dst: *mut core::ffi::c_void,
    _src: *const core::ffi::c_void,
    _bytes: usize,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_memcpy_h2d_async")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_exec_context_memcpy_d2h_async(
    _handle: *mut core::ffi::c_void,
    _dst: *mut core::ffi::c_void,
    _src: *const core::ffi::c_void,
    _bytes: usize,
) -> i32 {
    no_cuda_symbol("stwo_exec_context_memcpy_d2h_async")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_vmm_allocation_create(
    _context_handle: *mut core::ffi::c_void,
    _requested_bytes: usize,
    _out_handle: *mut *mut core::ffi::c_void,
    _out_ptr: *mut *mut core::ffi::c_void,
    _out_mapped_bytes: *mut usize,
    _out_granularity: *mut usize,
) -> i32 {
    no_cuda_symbol("stwo_vmm_allocation_create")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_vmm_allocation_unmap_release(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
    _expected_generation: u32,
) -> i32 {
    no_cuda_symbol("stwo_vmm_allocation_unmap_release")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_vmm_allocation_remap_next(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
    _current_generation: u32,
    _next_generation: u32,
) -> i32 {
    no_cuda_symbol("stwo_vmm_allocation_remap_next")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_vmm_allocation_destroy(_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_vmm_allocation_destroy")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_context_uuid(
    _context_handle: *mut core::ffi::c_void,
    _out_uuid: *mut u8,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_context_uuid")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_owner_create(
    _context_handle: *mut core::ffi::c_void,
    _logical_bytes: usize,
    _initial_generation: u64,
    _expected_owner_uuid: *const u8,
    _out_handle: *mut *mut core::ffi::c_void,
    _out_pointer: *mut *mut core::ffi::c_void,
    _out_allocation_bytes: *mut usize,
    _out_memory_handle: *mut u8,
    _out_ready_event_handle: *mut u8,
    _out_consumed_event_handle: *mut u8,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_owner_create")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_owner_publish(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
    _source: *const core::ffi::c_void,
    _bytes: usize,
    _generation: u64,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_owner_publish")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_owner_reclaim(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
    _generation: u64,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_owner_reclaim")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_owner_mark_peer_closed(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
    _generation: u64,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_owner_mark_peer_closed")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_owner_close(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_owner_close")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_import_open(
    _context_handle: *mut core::ffi::c_void,
    _logical_bytes: usize,
    _allocation_bytes: usize,
    _initial_generation: u64,
    _expected_peer_uuid: *const u8,
    _memory_handle: *const u8,
    _ready_event_handle: *const u8,
    _consumed_event_handle: *const u8,
    _out_handle: *mut *mut core::ffi::c_void,
    _out_remote_pointer: *mut *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_import_open")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_import_consume(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
    _destination: *mut core::ffi::c_void,
    _bytes: usize,
    _generation: u64,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_import_consume")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_import_arm_next(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
    _next_generation: u64,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_import_arm_next")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_import_close(
    _handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
    _generation: u64,
) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_import_close")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ipc_exchange_import_destroy(_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_ipc_exchange_import_destroy")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_graph_capture_begin(_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_graph_capture_begin")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_graph_capture_end(
    _handle: *mut core::ffi::c_void,
    _out_exec: *mut *mut core::ffi::c_void,
    _out_kernel_nodes: *mut u64,
) -> i32 {
    no_cuda_symbol("stwo_graph_capture_end")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_graph_capture_abort(_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_graph_capture_abort")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_graph_launch(
    _exec_handle: *mut core::ffi::c_void,
    _context_handle: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_graph_launch")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_graph_destroy(_exec_handle: *mut core::ffi::c_void) -> i32 {
    no_cuda_symbol("stwo_graph_destroy")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_transcript_init_on(
    _state: *mut u32,
    _seed: *const u32,
    _seed_snapshot: *mut u32,
    _initial_chain: u64,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_transcript_init_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_transcript_mix_words_on(
    _state: *mut u32,
    _expected_step: u32,
    _expected_chain: u64,
    _next_chain: u64,
    _source: *const u32,
    _n_words: u32,
    _validate_m31: u32,
    _input_snapshot: *mut u32,
    _boundary_snapshot: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_transcript_mix_words_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_transcript_absorb_pow_on(
    _state: *mut u32,
    _expected_step: u32,
    _expected_chain: u64,
    _next_chain: u64,
    _nonce_words: *const u32,
    _pow_bits: u32,
    _input_snapshot: *mut u32,
    _boundary_snapshot: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_transcript_absorb_pow_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_transcript_draw_u32s_on(
    _state: *mut u32,
    _expected_step: u32,
    _expected_chain: u64,
    _next_chain: u64,
    _output: *mut u32,
    _output_snapshot: *mut u32,
    _boundary_snapshot: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_transcript_draw_u32s_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_transcript_draw_secure_on(
    _state: *mut u32,
    _expected_step: u32,
    _expected_chain: u64,
    _next_chain: u64,
    _n_felts: u32,
    _max_rejection_rounds: u32,
    _output: *mut u32,
    _output_snapshot: *mut u32,
    _boundary_snapshot: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_transcript_draw_secure_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_transcript_draw_queries_on(
    _state: *mut u32,
    _expected_step: u32,
    _expected_chain: u64,
    _next_chain: u64,
    _log_domain_size: u32,
    _n_queries: u32,
    _output: *mut u32,
    _output_snapshot: *mut u32,
    _boundary_snapshot: *mut u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_transcript_draw_queries_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_wit_deduce_oracle_run(
    _kind: u32,
    _h_in: *const u32,
    _h_out: *mut u32,
    _n_items: u32,
) -> i32 {
    no_cuda_symbol("stwo_wit_deduce_oracle_run")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pedersen_table_init(_columns: *const *mut u32, _n_rows: u32) {
    no_cuda_symbol("pedersen_table_init")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_pedersen_table_init_borrowed_checked(
    _columns: *const *mut u32,
    _n_rows: u32,
) -> i32 {
    CUDA_ERROR_NOT_SUPPORTED
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_tail(
    _first_dev: *const Blake2sHash,
    _first_size: u32,
    _out_levels_dev: *const *mut Blake2sHash,
    _n_levels: u32,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_tail")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_tail_on(
    _first_dev: *const Blake2sHash,
    _first_size: u32,
    _out_levels_dev: *const *mut Blake2sHash,
    _n_levels: u32,
    _stream: *mut core::ffi::c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_tail_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake_g_inputs_from_sub(
    _producer_sub_dev: *const u32,
    _producer_rows: u32,
    _word_base: u32,
    _n_instances: u32,
    _consumer_rows: u32,
    _out_row_major_dev: *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_blake_g_inputs_from_sub")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_witness_edge_gather(
    _producer_sub_dev: *const u32,
    _producer_rows: u32,
    _word_base: u32,
    _words_per_instance: u32,
    _n_instances: u32,
    _consumer_rows: u32,
    _consumer_cols_dev: *const *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_witness_edge_gather")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_witness_input_gather_on(
    _producer_subs_dev: *const *const u32,
    _edge_descs_dev: *const u32,
    _n_edges: u32,
    _input_width: u32,
    _total_real_rows: u32,
    _consumer_rows: u32,
    _consumer_cols_dev: *const *mut u32,
    _include_enabler: u32,
    _include_iota: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_witness_input_gather_on")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_witness_input_seed_on(
    _scalars_dev: *const u32,
    _n_scalars: u32,
    _n_real_rows: u32,
    _consumer_rows: u32,
    _consumer_cols_dev: *const *mut u32,
    _include_enabler: u32,
    _include_iota: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_witness_input_seed_on")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_witness_casm_input_scatter_on(
    _rows_dev: *const u32,
    _n_real: u32,
    _consumer_rows: u32,
    _pc_dev: *mut u32,
    _ap_dev: *mut u32,
    _fp_dev: *mut u32,
    _enabler_dev: *mut u32,
    _iota_dev: *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_witness_casm_input_scatter_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_witness_input_compact_sort_temp_bytes(
    _rows: u32,
    _out_bytes: *mut usize,
) -> i32 {
    no_cuda_symbol("stwo_witness_input_compact_sort_temp_bytes")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_witness_input_compact_scan_temp_bytes(
    _rows: u32,
    _out_bytes: *mut usize,
) -> i32 {
    no_cuda_symbol("stwo_witness_input_compact_scan_temp_bytes")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_witness_input_compact_on(
    _producer_subs_dev: *const *const u32,
    _edge_descs_dev: *const u32,
    _n_edges: u32,
    _tuple_words: u32,
    _key_words: u32,
    _total_rows: u32,
    _sort_rows: u32,
    _consumer_rows: u32,
    _n_inputs: u32,
    _consumer_cols_dev: *const *mut u32,
    _enabler_slot: u32,
    _iota_slot: u32,
    _multiplicity_slot: u32,
    _tuples_dev: *mut u32,
    _keys_a_dev: *mut u32,
    _keys_b_dev: *mut u32,
    _indices_a_dev: *mut u32,
    _indices_b_dev: *mut u32,
    _heads_dev: *mut u32,
    _positions_dev: *mut u32,
    _n_unique_dev: *mut u32,
    _sort_temp_dev: *mut c_void,
    _sort_temp_bytes: usize,
    _scan_temp_dev: *mut c_void,
    _scan_temp_bytes: usize,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_witness_input_compact_on")
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stwo_fixed_table_materialize_on(
    _source_columns_dev: *const *const u32,
    _multiplicity_columns_dev: *const *const u32,
    _trace_multiplicity_columns_dev: *const u32,
    _trace_outputs_dev: *const *mut u32,
    _n_trace_outputs: u32,
    _lookup_descriptors_dev: *const u32,
    _lookup_outputs_dev: *const *mut u32,
    _n_lookup_outputs: u32,
    _row_count: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_fixed_table_materialize_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_witness_feed_counts(
    _sub_words_dev: *const u32,
    _column_length: u32,
    _descs_dev: *const u32,
    _n_descs: u32,
    _luts_dev: *const *const u32,
    _counts_dev: *const *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_witness_feed_counts")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_witness_feed_counts_on(
    _sub_words_dev: *const u32,
    _column_length: u32,
    _descs_dev: *const u32,
    _n_descs: u32,
    _luts_dev: *const *const u32,
    _counts_dev: *const *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_witness_feed_counts_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_witness_feed_counts_privatized(
    _sub_words_dev: *const u32,
    _column_length: u32,
    _descs_dev: *const u32,
    _n_descs: u32,
    _luts_dev: *const *const u32,
    _counts_dev: *const *mut u32,
) -> i32 {
    no_cuda_symbol("stwo_witness_feed_counts_privatized")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_witness_feed_counts_privatized_on(
    _sub_words_dev: *const u32,
    _column_length: u32,
    _descs_dev: *const u32,
    _n_descs: u32,
    _luts_dev: *const *const u32,
    _counts_dev: *const *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_witness_feed_counts_privatized_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_witness_feed_clear_on(
    _destinations_dev: *const *mut u32,
    _lengths_dev: *const u32,
    _n_destinations: u32,
    _max_words: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_witness_feed_clear_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_fri_last_layer_on(
    _evaluation: *const u32,
    _evaluation_stride: u32,
    _log_size: u32,
    _inverse_twiddles: *const u32,
    _inverse_twiddle_words: u32,
    _log_degree_bound: u32,
    _coefficients: *mut u32,
    _degree_error: *mut u32,
    _transcript_coefficients: *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_fri_last_layer_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_pow_persistent_on(
    _transcript_state: *const u32,
    _pow_bits: u32,
    _prefix_digest: *mut u32,
    _best_nonce: *mut u64,
    _completed_blocks: *mut u32,
    _transcript_nonce: *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_pow_persistent_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_pow_rank_tile_on(
    _transcript_state: *const u32,
    _pow_bits: u32,
    _rank_count: u32,
    _rank: u32,
    _tile_start: u64,
    _tile_end: u64,
    _grid_blocks: u32,
    _prefix_digest: *mut u32,
    _best_nonce: *mut u64,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_pow_rank_tile_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_blake2s_sparse_leaf_group_on(
    _leaf_indices: *const u32,
    _leaf_count: *const u32,
    _max_leaf_count: u32,
    _group_n_cols: u32,
    _columns: *const *mut u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _cols_done: u32,
    _is_final: u32,
    _states: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_blake2s_sparse_leaf_group_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_decommit_normalize_queries_on(
    _raw_queries: *const u32,
    _raw_query_count: u32,
    _query_log_size: u32,
    _tree_count: u32,
    _unique_queries: *mut u32,
    _unique_count: *mut u32,
    _assembly: *mut u32,
    _assembly_capacity_words: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_decommit_normalize_queries_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_decommit_prepare_trace_queries_on(
    _unique_queries: *const u32,
    _unique_count: *const u32,
    _max_queries: u32,
    _source_log_size: u32,
    _tree_log_size: u32,
    _leaf_log_size: u32,
    _unretained_bottom_layers: u32,
    _mapped_queries: *mut u32,
    _mapped_count: *mut u32,
    _walk_queries: *mut u32,
    _walk_count: *mut u32,
    _leaf_indices: *mut u32,
    _leaf_count: *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_decommit_prepare_trace_queries_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_decommit_pack_trace_group_on(
    _tree_index: u32,
    _total_column_count: u32,
    _first_column: u32,
    _group_column_count: u32,
    _columns: *const *const u32,
    _column_log_sizes: *const u32,
    _lifting_log_size: u32,
    _mapped_queries: *const u32,
    _mapped_count: *const u32,
    _max_queries: u32,
    _assembly: *mut u32,
    _assembly_capacity_words: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_decommit_pack_trace_group_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_decommit_sparse_parent_on(
    _child_indices: *const u32,
    _child_hashes: *const Blake2sHash,
    _child_count: *const u32,
    _max_child_count: u32,
    _parent_indices: *mut u32,
    _parent_hashes: *mut Blake2sHash,
    _parent_count: *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_decommit_sparse_parent_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_decommit_assemble_trace_on(
    _tree_index: u32,
    _tree_role: u32,
    _leaf_log_size: u32,
    _first_retained_log_size: u32,
    _column_count: u32,
    _mapped_count: *const u32,
    _max_queries: u32,
    _walk_queries: *mut u32,
    _walk_scratch: *mut u32,
    _walk_count: *const u32,
    _retained_layers_by_log: *const *const Blake2sHash,
    _sparse_indices: *const u32,
    _sparse_hashes: *const Blake2sHash,
    _sparse_level_offsets: *const u32,
    _sparse_level_counts: *const u32,
    _sparse_level_count: u32,
    _assembly: *mut u32,
    _assembly_capacity_words: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_decommit_assemble_trace_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_decommit_prepare_fri_queries_on(
    _unique_queries: *const u32,
    _unique_count: *const u32,
    _max_queries: u32,
    _cumulative_fold: u32,
    _fold_step: u32,
    _log_rows_per_leaf: u32,
    _tree_queries: *mut u32,
    _tree_query_count: *mut u32,
    _expanded_positions: *mut u32,
    _expanded_count: *mut u32,
    _walk_queries: *mut u32,
    _walk_count: *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_decommit_prepare_fri_queries_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_decommit_assemble_fri_on(
    _tree_index: u32,
    _leaf_log_size: u32,
    _tree_queries: *const u32,
    _tree_query_count: *const u32,
    _expanded_positions: *const u32,
    _expanded_count: *const u32,
    _coordinate_columns: *const *const u32,
    _walk_queries: *mut u32,
    _walk_scratch: *mut u32,
    _walk_count: *const u32,
    _retained_layers_by_log: *const *const Blake2sHash,
    _assembly: *mut u32,
    _assembly_capacity_words: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_decommit_assemble_fri_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_relation_scan_tail_on(
    _output_tables: *const *const *mut u32,
    _claimed_sums: *const *mut u32,
    _geometry: *const u32,
    _n_instances: u32,
    _total_row_blocks: u32,
    _partition_descriptors: *mut u32,
    _descriptor_capacity_words: u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_relation_scan_tail_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_fri_fold_fused3_on(
    _gpu_domain: *const u32,
    _twiddle_offset_0: u32,
    _twiddle_offset_1: u32,
    _twiddle_offset_2: u32,
    _n: u32,
    _first_fold_is_circle: u32,
    _eval_values: *const *mut u32,
    _alpha: *const CudaSecureField,
    _folded_values: *const *mut u32,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_fri_fold_fused3_on")
}

// --- ntt_leaf_fused ---
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_leaf_fused_configure(_log_n: u32) -> i32 {
    no_cuda_symbol("stwo_ntt_leaf_fused_configure")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_leaf_fused_on(
    _coefficient_values: *const *const u32,
    _coefficient_sizes: *const u32,
    _device_values: *const *mut u32,
    _log_n: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _cols_done: u32,
    _is_final: u32,
    _states: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_leaf_fused_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_progressive_leaf_fused_configure(_log_n: u32) -> i32 {
    no_cuda_symbol("stwo_ntt_progressive_leaf_fused_configure")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_progressive_leaf_fused_on(
    _coefficient_values: *const *const u32,
    _coefficient_sizes: *const u32,
    _device_values: *const *mut u32,
    _log_n: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _cols_done: u32,
    _retained_write_mask: u32,
    _states: *mut ProgressiveBlake2sState,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_progressive_leaf_fused_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_direct_compact_final16_configure(_log_n: u32) -> i32 {
    no_cuda_symbol("stwo_ntt_direct_compact_final16_configure")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_direct_compact_final16_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _tiles: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _cols_done: u32,
    _initial_tail: *const CompactBlake2sTailDescriptor,
    _states: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_direct_compact_final16_on")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_direct_compact_final16_col8_configure(_log_n: u32) -> i32 {
    no_cuda_symbol("stwo_ntt_direct_compact_final16_col8_configure")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stwo_ntt_direct_compact_final16_col8_on(
    _device_values: *const *mut u32,
    _log_n: u32,
    _tiles: u32,
    _g_twiddles: *mut u32,
    _twiddles_size: u32,
    _eval_domain_size: u32,
    _cols_done: u32,
    _initial_tail: *const CompactBlake2sTailDescriptor,
    _states: *mut Blake2sHash,
    _stream: *mut c_void,
) -> i32 {
    no_cuda_symbol("stwo_ntt_direct_compact_final16_col8_on")
}
