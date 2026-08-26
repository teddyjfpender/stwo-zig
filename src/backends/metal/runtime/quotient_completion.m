static bool stwo_zig_publish_quotient_work_receipt(
    StwoZigQuotientWorkReceipt *receipt,
    bool raw_views,
    bool gpu_grouped_partials,
    bool gpu_raw_upload,
    bool resident_multi_source,
    uint32_t row_count,
    uint32_t batch_count,
    uint32_t view_count,
    uint32_t partial_group_count,
    NSData *partial_group_data,
    bool build_domain_cache,
    uint32_t domain_log_size,
    uint32_t domain_initial_index,
    uint32_t domain_step_size,
    char *error_message,
    size_t error_message_len
) {
uint64_t numerator_additions = 0u;
uint64_t numerator_multiplications = 0u;
uint64_t grouped_partial_count = 0u;
uint32_t receipt_path = 0u;
if (!raw_views) {
    if (!stwo_zig_checked_mul_u64(row_count, view_count,
                                   &numerator_additions)) {
        write_error(error_message, error_message_len,
                    @"Metal quotient combined work receipt overflow");
        return false;
    }
} else if (gpu_grouped_partials) {
    receipt_path = 3u;
    grouped_partial_count = partial_group_count;
    const StwoZigResidentRawQuotientGroup *groups = partial_group_data.bytes;
    uint64_t partial_cells = 0u;
    for (uint32_t group_index = 0u;
         group_index < partial_group_count;
         ++group_index) {
        uint64_t group_cells = 0u;
        if (!stwo_zig_checked_mul_u64(groups[group_index].row_count,
                                      groups[group_index].view_count,
                                      &group_cells) ||
            !stwo_zig_checked_add_u64(partial_cells, group_cells,
                                      &partial_cells)) {
            write_error(error_message, error_message_len,
                        @"Metal quotient grouped work receipt overflow");
            return false;
        }
    }
    uint64_t lifted_group_additions = 0u;
    if (!stwo_zig_checked_mul_u64(row_count, partial_group_count,
                                   &lifted_group_additions) ||
        !stwo_zig_checked_add_u64(partial_cells,
                                   lifted_group_additions,
                                   &numerator_additions) ||
        !stwo_zig_checked_mul_u64(partial_cells, 4u,
                                   &numerator_multiplications)) {
        write_error(error_message, error_message_len,
                    @"Metal quotient grouped work receipt overflow");
        return false;
    }
} else {
    receipt_path = gpu_raw_upload && !resident_multi_source ? 2u : 1u;
    if (!stwo_zig_checked_mul_u64(row_count, view_count,
                                   &numerator_additions) ||
        !stwo_zig_checked_mul_u64(numerator_additions, 4u,
                                   &numerator_multiplications)) {
        write_error(error_message, error_message_len,
                    @"Metal quotient raw work receipt overflow");
        return false;
    }
}
uint64_t inverse_calls = 0u;
if (!stwo_zig_checked_mul_u64(row_count, batch_count, &inverse_calls)) {
    write_error(error_message, error_message_len,
                @"Metal quotient inverse work receipt overflow");
    return false;
}
uint64_t domain_circle_additions = 0u;
if (build_domain_cache &&
    !stwo_zig_quotient_domain_circle_additions(
        row_count,
        domain_log_size,
        domain_initial_index,
        domain_step_size,
        &domain_circle_additions)) {
    write_error(error_message, error_message_len,
                @"Metal quotient domain work receipt overflow");
    return false;
}
*receipt = (StwoZigQuotientWorkReceipt){
    .schema_version = 1u,
    .path = receipt_path,
    .reserved0 = 0u,
    .reserved1 = 0u,
    .row_count = row_count,
    .batch_count = batch_count,
    .view_count = view_count,
    .grouped_partial_count = grouped_partial_count,
    .numerator_additions = numerator_additions,
    .numerator_multiplications = numerator_multiplications,
    .domain_circle_additions = domain_circle_additions,
    .batch_inverse_calls = inverse_calls,
};
    return true;
}
