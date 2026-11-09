#include "quotient_tiling.m"

// Every private quotient buffer is admitted before device allocation. No-copy
// input/output aliases retain their already charged host owners instead.
static id<MTLBuffer> stwo_quotient_owned_buffer(
    id<MTLDevice> device, const void *bytes, NSUInteger length,
    MTLResourceOptions options, void *context, StwoZigExternalBudgetAdmitV1 admit
) {
    // Zero-source quotient groups still require valid bound Metal buffers.
    // Their logical counts remain zero, so shaders never read this sentinel.
    // Charge the actual allocation and never read an empty host pointer.
    if (length == 0u) { length = sizeof(uint32_t); bytes = NULL; }
    if (!admit(context, (size_t)length)) return nil;
    return bytes != NULL ? [device newBufferWithBytes:bytes length:length options:options]
                         : [device newBufferWithLength:length options:options];
}

#include "native_quotient_reduction.m"

#include "quotient_buffer_preparation.m"

bool stwo_zig_metal_compute_quotients(
    void *runtime_ptr,
    const uint32_t *flat_views, size_t flat_views_len,
    const uint32_t *const *raw_columns, const size_t *raw_column_lengths,
    uint32_t raw_column_count,
    void *const *resident_tree_handles, uint32_t resident_tree_count,
    const void *views, uint32_t view_count, bool raw_views,
    const uint32_t *sample_components, const uint32_t *linear_terms,
    uint32_t batch_count, bool cache_domain,
    uint32_t domain_log_size, uint32_t domain_initial_index, uint32_t domain_step_size, const uint32_t *domain_x,
    const uint32_t *domain_y, uint32_t row_count,
    uint32_t *output, void *resident_output_ptr,
    const uint32_t *leaf_seed, const uint32_t *node_seed,
    uint32_t domain_prefix_bytes, uint32_t hash_family, void *fri_line_output_ptr,
    void *const *fri_coordinate_ptrs, void *fri_final_destination_ptr,
    uint32_t fri_layer_count, uint32_t fri_domain_initial_index, uint32_t fri_domain_step_size,
    uint32_t *fri_channel_state, void **fri_tree_outputs, uint32_t *fri_inverse_generation_mask,
    StwoZigCommandEpochStats *fri_stats,
    void *fri_circle_inverse, void *fri_line_inverse,
    bool fri_generate_circle, bool fri_generate_line,
    StwoZigQuotientWorkReceipt *quotient_work_receipt,
    void *quotient_parity_context, StwoZigQuotientParityObserverV1 quotient_parity_observer,
    void *budget_context, StwoZigExternalBudgetAdmitV1 budget_admit,
    bool retain_domain_cache, size_t *retained_external_bytes,
    void **tree_out, double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (retained_external_bytes != NULL) *retained_external_bytes = 0u;
    bool fri_transaction = fri_line_output_ptr != NULL;
    if (runtime_ptr == NULL || views == NULL || sample_components == NULL ||
        linear_terms == NULL || (!cache_domain && (domain_x == NULL || domain_y == NULL)) ||
        output == NULL || row_count == 0u || tree_out == NULL ||
        budget_context == NULL || budget_admit == NULL || retained_external_bytes == NULL ||
        flat_views_len > SIZE_MAX / sizeof(uint32_t) ||
        (raw_views && (raw_columns == NULL || raw_column_lengths == NULL ||
                       raw_column_count == 0u)) ||
        (resident_tree_count != 0u && resident_tree_handles == NULL) ||
        ((quotient_parity_context == NULL) != (quotient_parity_observer == NULL)) ||
        (quotient_parity_observer != NULL && !raw_views) ||
        (domain_prefix_bytes != 0u && domain_prefix_bytes != 64u) ||
        (!stwo_zig_valid_commitment_hash_family_v1(hash_family) &&
         hash_family != StwoZigCommitmentHashFamilyBlake3V1) ||
        (fri_transaction &&
            (fri_coordinate_ptrs == NULL || fri_final_destination_ptr == NULL ||
             fri_layer_count == 0u || fri_layer_count >= 31u ||
             fri_channel_state == NULL || fri_tree_outputs == NULL || fri_stats == NULL ||
             resident_output_ptr == NULL || leaf_seed == NULL || node_seed == NULL ||
             row_count < 4u || (row_count >> 1u) >> fri_layer_count == 0u ||
             (hash_family != StwoZigCommitmentHashFamilyBlake2sV1 &&
              hash_family != StwoZigCommitmentHashFamilyBlake3V1))) ||
        (!fri_transaction &&
            (fri_coordinate_ptrs != NULL || fri_final_destination_ptr != NULL ||
             fri_layer_count != 0u || fri_channel_state != NULL ||
             fri_tree_outputs != NULL || fri_inverse_generation_mask != NULL ||
             fri_stats != NULL)) ||
        (cache_domain && ((row_count & (row_count - 1u)) != 0u ||
                          domain_log_size >= 31u ||
                          row_count != (1u << domain_log_size))))
        return false;
    if (hash_family == StwoZigCommitmentHashFamilyBlake3V1) {
        if (domain_prefix_bytes != 0u) return false;
        if (leaf_seed != NULL) for (uint32_t i = 0; i < 8u; ++i) if (leaf_seed[i] != 0u) return false;
        if (node_seed != NULL) for (uint32_t i = 0; i < 8u; ++i) if (node_seed[i] != 0u) return false;
        if (fri_transaction && fri_channel_state[10] != 0u) return false;
    }

    if (quotient_work_receipt != NULL)
        memset(quotient_work_receipt, 0, sizeof(*quotient_work_receipt));
    @autoreleasepool {
        bool profile_quotient = getenv("STWO_ZIG_METAL_QUOTIENT_PROFILE") != NULL;
        NSTimeInterval quotient_wall_start = [NSDate timeIntervalSinceReferenceDate];
        *tree_out = NULL;
        bool commit_tree = resident_output_ptr != NULL || leaf_seed != NULL || node_seed != NULL;
        if (commit_tree && (resident_output_ptr == NULL || leaf_seed == NULL || node_seed == NULL))
            return false;
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigQuotientPrepared prepared = {0};
        if (!stwo_zig_prepare_quotient_buffers(
            runtime, commit_tree, profile_quotient, fri_transaction,
            runtime_ptr, flat_views, flat_views_len, raw_columns,
            raw_column_lengths, raw_column_count, resident_tree_handles, resident_tree_count,
            views, view_count, raw_views, sample_components,
            linear_terms, batch_count, cache_domain, domain_log_size,
            domain_initial_index, domain_step_size, domain_x, domain_y,
            row_count, output, resident_output_ptr, leaf_seed,
            node_seed, domain_prefix_bytes, hash_family, fri_channel_state,
            quotient_parity_observer, budget_context, budget_admit, retain_domain_cache,
            error_message, error_message_len,
            &prepared)) return false;

        NSMutableArray<id<MTLBuffer>> *raw_sources = [NSMutableArray array];
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        double parity_completed_gpu_milliseconds = 0.0;
        if (prepared.gpu_flat_pack &&
            !stwo_zig_encode_quotient_flat_pack(
                runtime,
                command,
                raw_columns,
                raw_column_lengths,
                raw_column_count,
                prepared.resident_trees,
                prepared.flat_buffer,
                raw_sources
            )) {
            write_error(error_message, error_message_len,
                        @"Metal quotient flat-pack encoding failed");
            return false;
        }
        if (prepared.build_domain_cache) {
            id<MTLComputeCommandEncoder> domain_encoder = [command computeCommandEncoder];
            [domain_encoder setComputePipelineState:runtime.quotientDomainPointsResident];
            [domain_encoder setBuffer:prepared.domain_cache_candidate offset:0u atIndex:0];
            uint32_t destination_offset = 0u;
            [domain_encoder setBytes:&destination_offset length:sizeof(destination_offset) atIndex:1];
            [domain_encoder setBytes:&row_count length:sizeof(row_count) atIndex:2];
            [domain_encoder setBytes:&domain_log_size length:sizeof(domain_log_size) atIndex:3];
            [domain_encoder setBytes:&domain_initial_index length:sizeof(domain_initial_index) atIndex:4];
            [domain_encoder setBytes:&domain_step_size length:sizeof(domain_step_size) atIndex:5];
            uint32_t domain_mode = 0u;
            [domain_encoder setBytes:&domain_mode length:sizeof(domain_mode) atIndex:6];
            NSUInteger domain_width = MIN(runtime.quotientDomainPointsResident.maxTotalThreadsPerThreadgroup,
                                          runtime.quotientDomainPointsResident.threadExecutionWidth * 8u);
            [domain_encoder dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
                      threadsPerThreadgroup:MTLSizeMake(domain_width, 1u, 1u)];
            [domain_encoder endEncoding];
        }
        if (prepared.gpu_grouped_partials) {
            id<MTLComputeCommandEncoder> partials = [command computeCommandEncoder];
            partials.label = @"stwo_zig_quotient_partials_raw";
            [partials setComputePipelineState:runtime.quotientPartialsRaw];
            id<MTLBuffer> first_source = prepared.resident_multi_source
                ? prepared.resident_quotient_sources[0] : prepared.flat_buffer;
            for (NSUInteger source_slot = 0u;
                 source_slot < stwo_zig_quotient_max_resident_sources;
                 ++source_slot) {
                id<MTLBuffer> source = prepared.resident_multi_source && source_slot < prepared.resident_quotient_sources.count
                    ? prepared.resident_quotient_sources[source_slot]
                    : first_source;
                [partials setBuffer:source offset:0u atIndex:source_slot];
            }
            [partials setBuffer:prepared.raw_view_buffer offset:0u atIndex:4];
            [partials setBuffer:prepared.partial_group_buffer offset:0u atIndex:5];
            [partials setBuffer:prepared.partial_row_start_buffer offset:0u atIndex:6];
            [partials setBytes:&prepared.partial_group_count length:sizeof(prepared.partial_group_count) atIndex:7];
            [partials setBytes:&prepared.partial_total_rows length:sizeof(prepared.partial_total_rows) atIndex:8];
            [partials setBuffer:prepared.partial_buffer offset:0u atIndex:9];
            const uint32_t accumulate = 0u;
            [partials setBytes:&accumulate length:sizeof(accumulate) atIndex:10];
            NSUInteger partial_width = MIN(runtime.quotientPartialsRaw.maxTotalThreadsPerThreadgroup,
                                           runtime.quotientPartialsRaw.threadExecutionWidth * 8u);
            [partials dispatchThreads:MTLSizeMake(prepared.partial_total_rows, 1u, 1u)
                   threadsPerThreadgroup:MTLSizeMake(partial_width, 1u, 1u)];
            [partials endEncoding];

            id<MTLComputeCommandEncoder> combine = [command computeCommandEncoder];
            combine.label = @"stwo_zig_quotient_combine_partials_raw";
            [combine setComputePipelineState:runtime.quotientCombinePartialsRaw];
            [combine setBuffer:prepared.partial_buffer offset:0u atIndex:0];
            [combine setBuffer:prepared.partial_group_buffer offset:0u atIndex:1];
            [combine setBuffer:prepared.partial_batch_group_buffer offset:0u atIndex:2];
            [combine setBuffer:prepared.sample_buffer offset:0u atIndex:3];
            [combine setBuffer:prepared.linear_buffer offset:0u atIndex:4];
            [combine setBytes:&batch_count length:sizeof(batch_count) atIndex:5];
            [combine setBuffer:prepared.x_buffer offset:prepared.x_offset atIndex:6];
            [combine setBuffer:prepared.y_buffer offset:prepared.y_offset atIndex:7];
            [combine setBuffer:prepared.output_buffer offset:0u atIndex:8];
            [combine setBytes:&row_count length:sizeof(row_count) atIndex:9];
            NSUInteger combine_width = MIN(runtime.quotientCombinePartialsRaw.maxTotalThreadsPerThreadgroup,
                                           runtime.quotientCombinePartialsRaw.threadExecutionWidth * 8u);
            [combine dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
                  threadsPerThreadgroup:MTLSizeMake(combine_width, 1u, 1u)];
            [combine endEncoding];
        } else if (prepared.gpu_raw_upload && !prepared.resident_multi_source) {
            const uint32_t numerator_tile_rows = stwo_quotient_numerator_tile_rows(row_count, batch_count, quotient_parity_observer != NULL);
            const bool tiled_numerators = numerator_tile_rows < row_count;
            NSMutableData *segment_dispatches = [NSMutableData data];
            uint64_t numerator_bytes = 0u;
            if (!stwo_zig_checked_mul_u64(batch_count, numerator_tile_rows, &numerator_bytes) ||
                !stwo_zig_checked_mul_u64(numerator_bytes, 16u, &numerator_bytes) ||
                numerator_bytes > SIZE_MAX) return false;
            id<MTLBuffer> numerators = stwo_quotient_owned_buffer(runtime.device, NULL, (NSUInteger)numerator_bytes, quotient_parity_observer != NULL
                                                                       ? MTLResourceStorageModeShared
                                                                       : MTLResourceStorageModePrivate, budget_context, budget_admit);
            if (numerators == nil) {
                write_error(error_message, error_message_len, @"Metal quotient numerator allocation failed");
                return false;
            }
            if (profile_quotient) fprintf(stderr, "Metal quotient numerator scratch: bytes=%llu tile_rows=%u domain_rows=%u tiles=%u parity_full_domain=%u\n",
                (unsigned long long)numerator_bytes, numerator_tile_rows, row_count,
                row_count / numerator_tile_rows, quotient_parity_observer != NULL);
            if (!tiled_numerators) {
                id<MTLBlitCommandEncoder> clear = [command blitCommandEncoder];
                [clear fillBuffer:numerators range:NSMakeRange(0, numerators.length) value:0u];
                [clear endEncoding];
            }
            // Diagnostic receipts retain their original per-segment execution
            // contract. Ordinary proofs use the native-height reduction.
            StwoZigNativeQuotientReduction *native_plan =
                quotient_parity_observer == NULL && quotient_work_receipt == NULL &&
                getenv("STWO_ZIG_METAL_DIRECT_SEGMENTED_QUOTIENT") == NULL
                ? stwo_native_quotient_reduction_plan(views, view_count, batch_count, row_count) : nil;
            id<MTLBuffer> native_partials = nil;
            if (native_plan != nil) {
                native_partials = stwo_quotient_owned_buffer(runtime.device, NULL,
                    (NSUInteger)native_plan.partialWords * sizeof(uint32_t),
                    MTLResourceStorageModePrivate, budget_context, budget_admit);
                if (native_partials == nil) return false;
                [raw_sources addObject:native_partials];
                id<MTLBlitCommandEncoder> clear = [command blitCommandEncoder];
                [clear fillBuffer:native_partials range:NSMakeRange(0, native_partials.length) value:0u];
                [clear endEncoding];
                if (profile_quotient) fprintf(stderr,
                    "Metal native segmented reduction: views=%u reduced_views=%u planar_groups=%lu partial_bytes=%lu\n",
                    view_count, native_plan.reducedViews,
                    (unsigned long)(native_plan.syntheticViews.length / sizeof(StwoZigRawQuotientView)),
                    (unsigned long)native_partials.length);
            }
            size_t column = 0;
            size_t flat_offset = 0;
            size_t page_size = (size_t)getpagesize();
            uint32_t parity_segment_index = 0u;
            while (column < raw_column_count) {
                StwoZigRawQuotientSourceRunV2 run;
                if (!stwo_zig_plan_raw_quotient_source_run_v2(
                        raw_columns,
                        raw_column_lengths,
                        raw_column_count,
                        prepared.resident_trees,
                        column,
                        &run)) {
                    write_error(error_message, error_message_len,
                                @"Metal quotient raw source-run remint failed");
                    return false;
                }
                const size_t run_start = run.first_column;
                const size_t run_words = run.logical_word_count;
                const bool resident_run = run.resident;
                id<MTLBuffer> resident_source = run.resident_source;
                column = run.end_column;
                size_t run_bytes = run_words * sizeof(uint32_t);
                uintptr_t address = (uintptr_t)raw_columns[run_start];
                // Cache-skewed columns intentionally begin inside a VM page.
                // Alias the complete page envelope and bind the logical byte
                // offset instead of copying every non-page-aligned column.
                uintptr_t alias_address = address - (address % page_size);
                size_t source_binding_offset = resident_run
                    ? run.resident_base_word * sizeof(uint32_t)
                    : address - alias_address;
                bool alias_shared = !resident_run && runtime.device.hasUnifiedMemory &&
                    run_bytes <= SIZE_MAX - source_binding_offset;
                size_t alias_length = 0u;
                if (alias_shared) {
                    size_t alias_span = source_binding_offset + run_bytes;
                    alias_shared = alias_span <= SIZE_MAX - (page_size - 1u);
                    if (alias_shared)
                        alias_length = (alias_span + page_size - 1u) / page_size * page_size;
                }
                id<MTLBuffer> source = resident_run ? resident_source :
                    (alias_shared
                        ? [runtime.device newBufferWithBytesNoCopy:(void *)alias_address
                                                            length:alias_length
                                                           options:MTLResourceStorageModeShared
                                                       deallocator:nil]
                        : stwo_quotient_owned_buffer(runtime.device, raw_columns[run_start], run_bytes, MTLResourceStorageModeShared, budget_context, budget_admit));
                if (source == nil || source_binding_offset > source.length) {
                    write_error(error_message, error_message_len, @"Metal quotient upload allocation failed");
                    return false;
                }
                [raw_sources addObject:source];
                NSMutableData *run_view_data = [NSMutableData data];
                const StwoZigRawQuotientSourceViewV2 *all_views =
                    (const StwoZigRawQuotientSourceViewV2 *)views;
                uint64_t min_original_offset = UINT64_MAX;
                uint64_t max_original_offset = 0u;
                uint64_t min_rebased_offset = UINT64_MAX;
                uint64_t max_rebased_offset = 0u;
                uint32_t min_batch = UINT32_MAX;
                uint32_t max_batch = 0u;
                for (uint32_t view_index = 0; view_index < view_count; ++view_index) {
                    const StwoZigRawQuotientSourceViewV2 source_view = all_views[view_index];
                    if (source_view.offset >= (uint64_t)flat_offset &&
                        source_view.offset < (uint64_t)flat_offset + (uint64_t)run_words) {
                        const uint64_t original_offset = source_view.offset;
                        uint64_t local_offset = source_view.offset - (uint64_t)flat_offset;
                        if (resident_run) {
                            bool resident_view_mapped = false;
                            size_t logical_column_start = flat_offset;
                            for (size_t source_column = run_start; source_column < column; ++source_column) {
                                size_t logical_column_end = logical_column_start + raw_column_lengths[source_column];
                                if (source_view.offset < (uint64_t)logical_column_end) {
                                    StwoZigResidentColumnBinding column_binding;
                                    size_t row_offset =
                                        (size_t)(source_view.offset - (uint64_t)logical_column_start);
                                    if (!stwo_zig_tree_resident_column(
                                            prepared.resident_trees, raw_columns[source_column],
                                            raw_column_lengths[source_column], &column_binding) ||
                                        column_binding.buffer != resident_source ||
                                        column_binding.wordOffset < run.resident_base_word ||
                                        column_binding.wordOffset - run.resident_base_word >
                                            UINT64_MAX - row_offset) {
                                        write_error(error_message, error_message_len,
                                                    @"Metal quotient resident view mapping failed");
                                        return false;
                                    }
                                    local_offset = (uint64_t)(
                                        column_binding.wordOffset - run.resident_base_word
                                    ) + (uint64_t)row_offset;
                                    resident_view_mapped = true;
                                    break;
                                }
                                logical_column_start = logical_column_end;
                            }
                            if (!resident_view_mapped) {
                                write_error(error_message, error_message_len,
                                            @"Metal quotient resident source-view is unbound");
                                return false;
                            }
                        }
                        StwoZigRawQuotientView view;
                        if (!stwo_zig_metal_local_raw_quotient_view_v2(
                                &source_view,
                                local_offset,
                                row_count,
                                batch_count,
                                &view)) {
                            write_error(error_message, error_message_len,
                                        @"Metal quotient local source-view overflow");
                            return false;
                        }
                        min_original_offset = MIN(min_original_offset, original_offset);
                        max_original_offset = MAX(max_original_offset, original_offset);
                        min_rebased_offset = MIN(min_rebased_offset, (uint64_t)view.offset);
                        max_rebased_offset = MAX(max_rebased_offset, (uint64_t)view.offset);
                        min_batch = MIN(min_batch, view.batch);
                        max_batch = MAX(max_batch, view.batch);
                        [run_view_data appendBytes:&view length:sizeof(view)];
                    }
                }
                if (native_plan != nil && !stwo_encode_native_quotient_run(runtime, command,
                        native_plan, source, resident_run || alias_shared ? source_binding_offset : 0u,
                        run_view_data, batch_count, row_count, native_partials, raw_sources,
                        budget_context, budget_admit)) {
                    write_error(error_message, error_message_len, @"Metal native quotient reduction failed");
                    return false;
                }
                // The native reduction may have removed the previous endpoint
                // batches from this run. Recompute its surviving batch range.
                if (native_plan != nil) {
                    min_batch = UINT32_MAX; max_batch = 0u;
                    const StwoZigRawQuotientView *direct = run_view_data.bytes;
                    for (size_t i = 0u; i < run_view_data.length / sizeof(*direct); ++i) {
                        min_batch = MIN(min_batch, direct[i].batch);
                        max_batch = MAX(max_batch, direct[i].batch);
                    }
                }
                uint32_t run_view_count = (uint32_t)(run_view_data.length / sizeof(StwoZigRawQuotientView));
                if (run_view_count != 0u) {
                    // A source run contributes only to its covered batch range.
                    // Rebase both the view batch IDs and the numerator binding:
                    // scanning every global batch otherwise reads and rewrites
                    // gigabytes of unchanged numerators for each source run.
                    // Keep the original views for the independent parity receipt.
                    NSMutableData *dispatch_view_data = [run_view_data mutableCopy];
                    StwoZigRawQuotientView *dispatch_views = dispatch_view_data.mutableBytes;
                    for (uint32_t i = 0u; i < run_view_count; ++i)
                        dispatch_views[i].batch -= min_batch;
                    const uint32_t run_batch_count = max_batch - min_batch + 1u;
                    id<MTLBuffer> run_views = stwo_quotient_owned_buffer(runtime.device, dispatch_view_data.bytes, dispatch_view_data.length, MTLResourceStorageModeShared, budget_context, budget_admit);
                    if (run_views == nil) return false;
                    [raw_sources addObject:run_views];
                    const StwoZigQuotientSegmentDispatch dispatch = {
                        .source = source, .views = run_views,
                        .source_offset = resident_run || alias_shared ? source_binding_offset : 0u,
                        .view_count = run_view_count, .first_batch = min_batch,
                        .batch_count = run_batch_count,
                    };
                    if (tiled_numerators) [segment_dispatches appendBytes:&dispatch length:sizeof(dispatch)];
                    else stwo_encode_quotient_numerator_tile(runtime, command, dispatch, numerators,
                                                            row_count, row_count, 0u);
                    if (quotient_parity_observer != NULL) {
                        [command commit];
                        [command waitUntilCompleted];
                        if (command.status == MTLCommandBufferStatusError) {
                            write_error(error_message, error_message_len,
                                        command.error.localizedDescription ?:
                                            @"Metal quotient numerator parity dispatch failed");
                            return false;
                        }
                        parity_completed_gpu_milliseconds +=
                            (command.GPUEndTime - command.GPUStartTime) * 1000.0;
                        StwoZigQuotientParityEventV1 event = {
                            .schema_version = 1u,
                            .phase = StwoZigQuotientParityRawSegmentV1,
                            .segment_index = parity_segment_index,
                            .segment_count = (uint32_t)prepared.raw_source_runs,
                            .first_column = (uint32_t)run_start,
                            .column_count = (uint32_t)(column - run_start),
                            .view_count = run_view_count,
                            .batch_count = batch_count,
                            .row_count = row_count,
                            .flat_offset = flat_offset,
                            .run_words = run_words,
                            .source_binding_offset = resident_run || alias_shared
                                ? source_binding_offset : 0u,
                            .flags = (resident_run
                                ? StwoZigQuotientParityResidentSourceV1 : 0u) |
                                (!resident_run && alias_shared
                                    ? StwoZigQuotientParityPageAliasSourceV1 : 0u),
                            .min_batch = min_batch,
                            .max_batch = max_batch,
                            .reserved = 0u,
                            .min_original_offset = min_original_offset,
                            .max_original_offset = max_original_offset,
                            .min_rebased_offset = min_rebased_offset,
                            .max_rebased_offset = max_rebased_offset,
                        };
                        const uint32_t *actual_domain_x =
                            (const uint32_t *)((const uint8_t *)prepared.x_buffer.contents + prepared.x_offset);
                        const uint32_t *actual_domain_y =
                            (const uint32_t *)((const uint8_t *)prepared.y_buffer.contents + prepared.y_offset);
                        if (profile_quotient) {
                            fprintf(stderr,
                                    "Metal quotient parity source: segment=%u/%u "
                                    "columns=%u+%u views=%u batches=%u rows=%llu "
                                    "resident=%u page_alias=%u flat_offset=%llu "
                                    "run_words=%llu binding_offset=%llu "
                                    "original_offsets=%llu..%llu rebased_offsets=%llu..%llu "
                                    "batch_coverage=%u..%u\n",
                                    event.segment_index, event.segment_count,
                                    event.first_column, event.column_count,
                                    event.view_count, event.batch_count,
                                    (unsigned long long)event.row_count,
                                    (event.flags & StwoZigQuotientParityResidentSourceV1) != 0u,
                                    (event.flags & StwoZigQuotientParityPageAliasSourceV1) != 0u,
                                    (unsigned long long)event.flat_offset,
                                    (unsigned long long)event.run_words,
                                    (unsigned long long)event.source_binding_offset,
                                    (unsigned long long)event.min_original_offset,
                                    (unsigned long long)event.max_original_offset,
                                    (unsigned long long)event.min_rebased_offset,
                                    (unsigned long long)event.max_rebased_offset,
                                    event.min_batch, event.max_batch);
                        }
                        if (actual_domain_x == NULL || actual_domain_y == NULL ||
                            numerators.contents == NULL ||
                            !quotient_parity_observer(
                                quotient_parity_context,
                                &event,
                                run_view_data.bytes,
                                actual_domain_x,
                                actual_domain_y,
                                numerators.contents,
                                numerators.length / sizeof(uint32_t))) {
                            write_error(error_message, error_message_len,
                                        @"Metal quotient raw-segment parity failed");
                            return false;
                        }
                        parity_segment_index += 1u;
                        command = [runtime.queue commandBuffer];
                        if (command == nil) {
                            write_error(error_message, error_message_len,
                                        @"Metal quotient parity command allocation failed");
                            return false;
                        }
                    }
                }
                flat_offset += run_words;
            }
            if (quotient_parity_observer != NULL &&
                parity_segment_index != prepared.raw_source_runs) {
                write_error(error_message, error_message_len,
                            @"Metal quotient parity source-run inventory mismatch");
                return false;
            }
            if (native_plan != nil) {
                id<MTLBuffer> basis_views = stwo_quotient_owned_buffer(runtime.device,
                    native_plan.syntheticViews.bytes, native_plan.syntheticViews.length,
                    MTLResourceStorageModeShared, budget_context, budget_admit);
                if (basis_views == nil) return false;
                [raw_sources addObject:basis_views];
                const StwoZigQuotientSegmentDispatch dispatch = {
                    .source = native_partials, .views = basis_views, .source_offset = 0u,
                    .view_count = (uint32_t)(native_plan.syntheticViews.length / sizeof(StwoZigRawQuotientView)),
                    .first_batch = 0u, .batch_count = batch_count, .planar = 1u,
                };
                if (tiled_numerators) [segment_dispatches appendBytes:&dispatch length:sizeof(dispatch)];
                else stwo_encode_quotient_numerator_tile(runtime, command, dispatch,
                    numerators, row_count, row_count, 0u);
            }
            if (tiled_numerators) {
                const StwoZigQuotientSegmentDispatch *segments = segment_dispatches.bytes;
                const size_t segment_count = segment_dispatches.length / sizeof(*segments);
                for (uint32_t row_start = 0u; row_start < row_count; row_start += numerator_tile_rows) {
                    id<MTLBlitCommandEncoder> clear = [command blitCommandEncoder];
                    [clear fillBuffer:numerators range:NSMakeRange(0, numerators.length) value:0u];
                    [clear endEncoding];
                    for (size_t segment = 0u; segment < segment_count; ++segment)
                        stwo_encode_quotient_numerator_tile(runtime, command, segments[segment], numerators,
                                                            row_count, numerator_tile_rows, row_start);
                    stwo_encode_quotient_finalize_tile(runtime, command, numerators, prepared.sample_buffer, prepared.linear_buffer,
                        batch_count, prepared.x_buffer, prepared.x_offset, prepared.y_buffer, prepared.y_offset, prepared.output_buffer,
                        row_count, numerator_tile_rows, row_start);
                }
            } else stwo_encode_quotient_finalize_tile(runtime, command, numerators, prepared.sample_buffer, prepared.linear_buffer,
                batch_count, prepared.x_buffer, prepared.x_offset, prepared.y_buffer, prepared.y_offset, prepared.output_buffer, row_count, row_count, 0u);
            if (quotient_parity_observer != NULL) {
                [command commit];
                [command waitUntilCompleted];
                if (command.status == MTLCommandBufferStatusError) {
                    write_error(error_message, error_message_len,
                                command.error.localizedDescription ?:
                                    @"Metal quotient finalize parity dispatch failed");
                    return false;
                }
                parity_completed_gpu_milliseconds +=
                    (command.GPUEndTime - command.GPUStartTime) * 1000.0;
                StwoZigQuotientParityEventV1 event = {
                    .schema_version = 1u,
                    .phase = StwoZigQuotientParityFinalizedV1,
                    .segment_index = parity_segment_index,
                    .segment_count = (uint32_t)prepared.raw_source_runs,
                    .first_column = 0u,
                    .column_count = raw_column_count,
                    .view_count = view_count,
                    .batch_count = batch_count,
                    .row_count = row_count,
                    .flat_offset = 0u,
                    .run_words = prepared.raw_len,
                    .source_binding_offset = 0u,
                    .flags = 0u,
                    .min_batch = 0u,
                    .max_batch = 0u,
                    .reserved = 0u,
                    .min_original_offset = 0u,
                    .max_original_offset = 0u,
                    .min_rebased_offset = 0u,
                    .max_rebased_offset = 0u,
                };
                const uint32_t *actual_domain_x =
                    (const uint32_t *)((const uint8_t *)prepared.x_buffer.contents + prepared.x_offset);
                const uint32_t *actual_domain_y =
                    (const uint32_t *)((const uint8_t *)prepared.y_buffer.contents + prepared.y_offset);
                if (actual_domain_x == NULL || actual_domain_y == NULL ||
                    prepared.output_buffer.contents == NULL ||
                    !quotient_parity_observer(
                        quotient_parity_context,
                        &event,
                        NULL,
                        actual_domain_x,
                        actual_domain_y,
                        prepared.output_buffer.contents,
                        prepared.output_buffer.length / sizeof(uint32_t))) {
                    write_error(error_message, error_message_len,
                                @"Metal quotient finalized parity failed");
                    return false;
                }
                command = [runtime.queue commandBuffer];
                if (command == nil) {
                    write_error(error_message, error_message_len,
                                @"Metal quotient post-parity command allocation failed");
                    return false;
                }
            }
        } else {
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            id<MTLComputePipelineState> quotient_pipeline = raw_views ? runtime.rawQuotients : runtime.quotients;
            [encoder setComputePipelineState:quotient_pipeline];
            if (raw_views) {
                id<MTLBuffer> first_source = prepared.resident_multi_source
                    ? prepared.resident_quotient_sources[0]
                    : prepared.flat_buffer;
                for (NSUInteger source_slot = 0u;
                     source_slot < stwo_zig_quotient_max_resident_sources;
                     ++source_slot) {
                    id<MTLBuffer> source = prepared.resident_multi_source &&
                        source_slot < prepared.resident_quotient_sources.count
                        ? prepared.resident_quotient_sources[source_slot]
                        : first_source;
                    [encoder setBuffer:source offset:0u atIndex:source_slot];
                }
                [encoder setBuffer:prepared.raw_view_buffer offset:0u atIndex:4];
                [encoder setBytes:&view_count length:sizeof(view_count) atIndex:5];
                [encoder setBuffer:prepared.sample_buffer offset:0u atIndex:6];
                [encoder setBuffer:prepared.linear_buffer offset:0u atIndex:7];
                [encoder setBytes:&batch_count length:sizeof(batch_count) atIndex:8];
                [encoder setBuffer:prepared.x_buffer offset:prepared.x_offset atIndex:9];
                [encoder setBuffer:prepared.y_buffer offset:prepared.y_offset atIndex:10];
                [encoder setBuffer:prepared.output_buffer offset:0u atIndex:11];
                [encoder setBytes:&row_count length:sizeof(row_count) atIndex:12];
                [encoder setBuffer:prepared.raw_batch_offset_buffer offset:0u atIndex:13];
            } else {
                [encoder setBuffer:prepared.flat_buffer offset:0 atIndex:0];
                [encoder setBuffer:prepared.view_buffer offset:0 atIndex:1];
                [encoder setBytes:&view_count length:sizeof(view_count) atIndex:2];
                [encoder setBuffer:prepared.sample_buffer offset:0 atIndex:3];
                [encoder setBuffer:prepared.linear_buffer offset:0 atIndex:4];
                [encoder setBytes:&batch_count length:sizeof(batch_count) atIndex:5];
                [encoder setBuffer:prepared.x_buffer offset:prepared.x_offset atIndex:6];
                [encoder setBuffer:prepared.y_buffer offset:prepared.y_offset atIndex:7];
                [encoder setBuffer:prepared.output_buffer offset:0 atIndex:8];
                [encoder setBytes:&row_count length:sizeof(row_count) atIndex:9];
            }
            NSUInteger width = MIN(quotient_pipeline.maxTotalThreadsPerThreadgroup,
                                   quotient_pipeline.threadExecutionWidth * 8u);
            [encoder dispatchThreads:MTLSizeMake(row_count, 1, 1)
                    threadsPerThreadgroup:MTLSizeMake(width, 1, 1)];
            [encoder endEncoding];
        }
        if (commit_tree) {
            uint32_t column_count = 4u;
            id<MTLComputeCommandEncoder> leaves = [command computeCommandEncoder];
            if (leaves == nil) {
                write_error(error_message, error_message_len, @"Resident quotient leaf encoder allocation failed");
                return false;
            }
            id<MTLComputePipelineState> leaves_pipeline =
                stwo_zig_commitment_leaves_pipeline(runtime, hash_family);
            if (leaves_pipeline == nil) return false;
            [leaves setComputePipelineState:leaves_pipeline];
            [leaves setBuffer:prepared.output_buffer offset:0 atIndex:0];
            [leaves setBuffer:prepared.column_offsets offset:0 atIndex:1];
            [leaves setBuffer:prepared.column_logs offset:0 atIndex:2];
            [leaves setBuffer:prepared.hash_arena
                         offset:(NSUInteger)prepared.layer_word_offsets[0] * sizeof(uint32_t) atIndex:3];
            [leaves setBytes:&column_count length:sizeof(column_count) atIndex:4];
            [leaves setBytes:&prepared.lifting_log_size length:sizeof(prepared.lifting_log_size) atIndex:5];
            [leaves setBuffer:prepared.leaf_seed_buffer offset:0 atIndex:6];
            [leaves setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:7];
            NSUInteger leaf_width = MIN(leaves_pipeline.maxTotalThreadsPerThreadgroup,
                                        leaves_pipeline.threadExecutionWidth * 8u);
            [leaves dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
                  threadsPerThreadgroup:MTLSizeMake(leaf_width, 1u, 1u)];
            [leaves endEncoding];
            uint64_t parent_encoders = 0u, parent_dispatches = 0u;
            if (!encode_merkle_parent_chain_prepared(runtime, prepared.hash_arena, prepared.parent_plan, command,
                                                      &parent_encoders, &parent_dispatches)) {
                write_error(error_message, error_message_len, @"Resident quotient parent-chain encoding failed");
                return false;
            }
            if (!runtime.device.hasUnifiedMemory) {
                id<MTLBlitCommandEncoder> root_copy = [command blitCommandEncoder];
                if (root_copy == nil) {
                    write_error(error_message, error_message_len, @"Resident quotient root encoder allocation failed");
                    return false;
                }
                [root_copy copyFromBuffer:prepared.hash_arena
                             sourceOffset:(NSUInteger)prepared.layer_word_offsets[prepared.lifting_log_size] * sizeof(uint32_t)
                                 toBuffer:prepared.root_readback destinationOffset:0u size:32u];
                [root_copy endEncoding];
            }
            if (fri_transaction) {
                id<MTLBlitCommandEncoder> fri_root_copy = [command blitCommandEncoder];
                if (fri_root_copy == nil) {
                    write_error(error_message, error_message_len, @"Resident FRI root transfer encoder allocation failed");
                    return false;
                }
                [fri_root_copy copyFromBuffer:prepared.hash_arena
                                  sourceOffset:(NSUInteger)prepared.layer_word_offsets[prepared.lifting_log_size] * sizeof(uint32_t)
                                      toBuffer:prepared.fri_channel_buffer
                             destinationOffset:(NSUInteger)prepared.fri_root_word_offset * sizeof(uint32_t)
                                          size:8u * sizeof(uint32_t)];
                [fri_root_copy endEncoding];

                id<MTLComputeCommandEncoder> fri_transcript = [command computeCommandEncoder];
                if (fri_transcript == nil) {
                    write_error(error_message, error_message_len, @"Resident FRI transcript encoder allocation failed");
                    return false;
                }
                uint32_t source_words = 8u;
                const bool blake3 = hash_family == StwoZigCommitmentHashFamilyBlake3V1;
                uint32_t operation = 4u;
                [fri_transcript setComputePipelineState:blake3 ? runtime.blake3Transcript : runtime.transcriptMixResident];
                if (blake3) [fri_transcript setBytes:&operation length:sizeof(operation) atIndex:4];
                [fri_transcript setBuffer:prepared.fri_channel_buffer offset:0u atIndex:0];
                [fri_transcript setBytes:&prepared.fri_state_word_offset
                                  length:sizeof(prepared.fri_state_word_offset) atIndex:1];
                [fri_transcript setBytes:&prepared.fri_root_word_offset
                                  length:sizeof(prepared.fri_root_word_offset) atIndex:2];
                [fri_transcript setBytes:&source_words length:sizeof(source_words) atIndex:3];
                [fri_transcript dispatchThreads:MTLSizeMake(1u, 1u, 1u)
                         threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
                [fri_transcript memoryBarrierWithScope:MTLBarrierScopeBuffers];

                uint32_t felt_count = 1u;
                operation = 5u;
                [fri_transcript setComputePipelineState:blake3 ? runtime.blake3Transcript : runtime.transcriptDrawSecureResident];
                if (blake3) [fri_transcript setBytes:&operation length:sizeof(operation) atIndex:4];
                [fri_transcript setBuffer:prepared.fri_channel_buffer offset:0u atIndex:0];
                [fri_transcript setBytes:&prepared.fri_state_word_offset
                                  length:sizeof(prepared.fri_state_word_offset) atIndex:1];
                [fri_transcript setBytes:&prepared.fri_alpha_word_offset
                                  length:sizeof(prepared.fri_alpha_word_offset) atIndex:2];
                [fri_transcript setBytes:&felt_count length:sizeof(felt_count) atIndex:3];
                [fri_transcript dispatchThreads:MTLSizeMake(1u, 1u, 1u)
                         threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
                [fri_transcript endEncoding];
            }
        }
        [command commit];
        bool fri_ok = true;
        if (fri_transaction) {
            fri_ok = stwo_zig_metal_fri_line_cascade_budgeted_v1(
                runtime_ptr,
                fri_line_output_ptr,
                row_count >> 1u,
                resident_output_ptr,
                NULL,
                (__bridge void *)prepared.fri_channel_buffer,
                prepared.fri_state_word_offset,
                prepared.fri_alpha_word_offset,
                NULL,
                (row_count >> 1u) - ((row_count >> 1u) >> fri_layer_count),
                fri_domain_initial_index,
                fri_domain_step_size,
                fri_coordinate_ptrs,
                fri_final_destination_ptr,
                fri_layer_count,
                leaf_seed,
                node_seed,
                domain_prefix_bytes,
                hash_family,
                fri_channel_state,
                fri_tree_outputs,
                fri_inverse_generation_mask,
                fri_circle_inverse,fri_line_inverse,
                fri_generate_circle,fri_generate_line,
                fri_stats,
                error_message,
                error_message_len
            );
        } else {
            [command waitUntilCompleted];
        }
        if (!fri_ok) {
            // Cascade can reject before enqueue/wait; prior work still owns
            // borrowed inputs. Join it before returning a failed transaction.
            [command waitUntilCompleted];
            return false;
        }
        if (command.status != MTLCommandBufferStatusCompleted) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?: @"Metal quotient execution failed");
            return false;
        }
        if (quotient_work_receipt != NULL &&
            !stwo_zig_publish_quotient_work_receipt(
                quotient_work_receipt, raw_views, prepared.gpu_grouped_partials,
                prepared.gpu_raw_upload, prepared.resident_multi_source, row_count, batch_count,
                view_count, prepared.partial_group_count, prepared.partial_group_data,
                prepared.build_domain_cache, domain_log_size, domain_initial_index,
                domain_step_size, error_message, error_message_len))
            return false;
        if (prepared.build_domain_cache && retain_domain_cache) {
            // Publish only completed data. Concurrent misses may duplicate
            // this bounded computation, but can never observe a partial grid.
            @synchronized(runtime) {
                runtime.quotientDomainCache = prepared.domain_cache_candidate;
                runtime.quotientDomainCacheRowCount = row_count;
                runtime.quotientDomainCacheLogSize = domain_log_size;
                runtime.quotientDomainCacheInitialIndex = domain_initial_index;
                runtime.quotientDomainCacheStepSize = domain_step_size;
            }
        }
        if (resident_output_ptr == NULL && !prepared.direct_output)
            memcpy(output, prepared.output_buffer.contents, prepared.output_bytes);
        if (gpu_milliseconds != NULL) {
            *gpu_milliseconds = parity_completed_gpu_milliseconds +
                (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        }
        if (profile_quotient) {
            NSTimeInterval quotient_wall_end = [NSDate timeIntervalSinceReferenceDate];
            fprintf(stderr,
                    "Metal quotient timing: gpu_ms=%.3f wall_ms=%.3f path=%s "
                    "source_runs=%zu resident_sources=%lu\n",
                    parity_completed_gpu_milliseconds +
                        (command.GPUEndTime - command.GPUStartTime) * 1000.0,
                    (quotient_wall_end - quotient_wall_start) * 1000.0,
                    prepared.gpu_grouped_partials ? (prepared.resident_multi_source ? "resident-partials" : "flat-partials") :
                        (prepared.resident_multi_source ? "resident-direct" :
                            (prepared.gpu_raw_upload ? "segmented" :
                                (prepared.gpu_flat_pack ? "gpu-flat" : "cpu-flat"))),
                    prepared.raw_source_runs,
                    (unsigned long)prepared.resident_quotient_sources.count);
        }
        if (commit_tree) {
            StwoZigMetalTree *tree = [StwoZigMetalTree new];
            tree.runtimeOwner = runtime;
            tree.layers = prepared.layers;
            tree.layerWordOffsets = prepared.layer_word_offsets_data;
            tree.layerWordLengths = prepared.layer_word_lengths_data;
            tree.rootReadback = prepared.root_readback;
            tree.rootReadbackWordOffset = runtime.device.hasUnifiedMemory
                ? prepared.layer_word_offsets[prepared.lifting_log_size] : 0u;
            tree.logSize = prepared.lifting_log_size;
            tree.gpuMilliseconds = gpu_milliseconds != NULL ? *gpu_milliseconds : 0.0;
            *retained_external_bytes = prepared.hash_arena.length +
                (runtime.device.hasUnifiedMemory ? 0u : prepared.root_readback.length);
            *tree_out = (__bridge_retained void *)tree;
        }
        return true;
    }
}
