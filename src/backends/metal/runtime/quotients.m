// Every segmented source run launches a full row grid and read-modify-writes
// every quotient accumulator. Keep that repeated domain traffic bounded; a
// more fragmented input is cheaper to pack once and evaluate in one kernel.
static const size_t stwo_zig_quotient_max_segmented_source_runs = 64u;

static StwoZigMetalTree *stwo_zig_quotient_resident_source(
    NSArray<StwoZigMetalTree *> *resident_trees,
    const uint32_t *column,
    size_t column_words,
    uintptr_t *resident_begin_out,
    size_t *resident_words_out
) {
    uintptr_t address = (uintptr_t)column;
    for (StwoZigMetalTree *tree in resident_trees) {
        uintptr_t begin = tree.residentColumnsHostBegin;
        size_t words = tree.residentColumnsWordCount;
        if (tree.residentColumns == nil || address < begin) continue;
        size_t offset_words = (address - begin) / sizeof(uint32_t);
        if (offset_words <= words && column_words <= words - offset_words) {
            *resident_begin_out = begin;
            *resident_words_out = words;
            return tree;
        }
    }
    return nil;
}

static size_t stwo_zig_quotient_raw_source_run_count(
    const uint32_t *const *raw_columns,
    const size_t *raw_column_lengths,
    uint32_t raw_column_count,
    NSArray<StwoZigMetalTree *> *resident_trees
) {
    size_t runs = 0u;
    size_t column = 0u;
    while (column < raw_column_count) {
        size_t run_start = column;
        size_t run_words = raw_column_lengths[column];
        uintptr_t resident_begin = 0u;
        size_t resident_words = 0u;
        StwoZigMetalTree *resident_tree = stwo_zig_quotient_resident_source(
            resident_trees,
            raw_columns[column],
            raw_column_lengths[column],
            &resident_begin,
            &resident_words
        );
        column += 1u;
        if (resident_tree != nil) {
            while (column < raw_column_count) {
                uintptr_t address = (uintptr_t)raw_columns[column];
                if (address < resident_begin) break;
                size_t offset_words = (address - resident_begin) / sizeof(uint32_t);
                if (offset_words > resident_words ||
                    raw_column_lengths[column] > resident_words - offset_words ||
                    run_words > SIZE_MAX - raw_column_lengths[column])
                    break;
                run_words += raw_column_lengths[column];
                column += 1u;
            }
        } else {
            while (column < raw_column_count &&
                   run_words <= SIZE_MAX - raw_column_lengths[column] &&
                   raw_columns[column] == raw_columns[run_start] + run_words) {
                run_words += raw_column_lengths[column];
                column += 1u;
            }
        }
        runs += 1u;
    }
    return runs;
}

bool stwo_zig_metal_compute_quotients(
    void *runtime_ptr,
    const uint32_t *flat_views, size_t flat_views_len,
    const uint32_t *const *raw_columns,
    const size_t *raw_column_lengths,
    uint32_t raw_column_count,
    void *const *resident_tree_handles,
    uint32_t resident_tree_count,
    const void *views, uint32_t view_count,
    bool raw_views,
    const uint32_t *sample_components,
    const uint32_t *linear_terms,
    uint32_t batch_count,
    bool cache_domain,
    uint32_t domain_log_size,
    uint32_t domain_initial_index,
    uint32_t domain_step_size,
    const uint32_t *domain_x,
    const uint32_t *domain_y,
    uint32_t row_count,
    uint32_t *output,
    void *resident_output_ptr,
    const uint32_t *leaf_seed,
    const uint32_t *node_seed,
    uint32_t domain_prefix_bytes,
    void *fri_line_output_ptr,
    void *const *fri_coordinate_ptrs,
    void *fri_final_destination_ptr,
    uint32_t fri_layer_count,
    uint32_t fri_domain_initial_index,
    uint32_t fri_domain_step_size,
    uint32_t *fri_channel_state,
    void **fri_tree_outputs,
    StwoZigCommandEpochStats *fri_stats,
    void **tree_out,
    double *gpu_milliseconds,
    char *error_message, size_t error_message_len
) {
    bool fri_transaction = fri_line_output_ptr != NULL;
    if (runtime_ptr == NULL || views == NULL || sample_components == NULL ||
        linear_terms == NULL || (!cache_domain && (domain_x == NULL || domain_y == NULL)) ||
        output == NULL || row_count == 0u || tree_out == NULL ||
        (resident_tree_count != 0u && resident_tree_handles == NULL) ||
        (domain_prefix_bytes != 0u && domain_prefix_bytes != 64u) ||
        (fri_transaction &&
            (fri_coordinate_ptrs == NULL || fri_final_destination_ptr == NULL ||
             fri_layer_count == 0u || fri_layer_count >= 31u ||
             fri_channel_state == NULL || fri_tree_outputs == NULL || fri_stats == NULL ||
             resident_output_ptr == NULL || leaf_seed == NULL || node_seed == NULL ||
             row_count < 4u || (row_count >> 1u) >> fri_layer_count == 0u)) ||
        (!fri_transaction &&
            (fri_coordinate_ptrs != NULL || fri_final_destination_ptr != NULL ||
             fri_layer_count != 0u || fri_channel_state != NULL ||
             fri_tree_outputs != NULL || fri_stats != NULL)) ||
        (cache_domain && ((row_count & (row_count - 1u)) != 0u ||
                          domain_log_size >= 31u ||
                          row_count != (1u << domain_log_size))))
        return false;
    @autoreleasepool {
        *tree_out = NULL;
        bool commit_tree = resident_output_ptr != NULL || leaf_seed != NULL || node_seed != NULL;
        if (commit_tree && (resident_output_ptr == NULL || leaf_seed == NULL || node_seed == NULL))
            return false;
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSMutableArray<StwoZigMetalTree *> *resident_trees =
            [NSMutableArray arrayWithCapacity:resident_tree_count];
        for (uint32_t i = 0u; i < resident_tree_count; ++i) {
            StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)resident_tree_handles[i];
            if (tree == nil || tree.runtimeOwner != runtime) {
                write_error(error_message, error_message_len,
                            @"Metal quotient residency handle belongs to another runtime");
                return false;
            }
            [resident_trees addObject:tree];
        }
        NSUInteger view_word_count = raw_views ? 9u : 5u;
        id<MTLBuffer> flat_buffer;
        size_t raw_len = 0;
        bool gpu_raw_upload = false;
        if (raw_views) {
            for (uint32_t i = 0; i < raw_column_count; ++i) raw_len += raw_column_lengths[i];
            size_t raw_bytes = raw_len * sizeof(uint32_t);
            bool resident_segment_candidate =
                resident_tree_count != 0u && raw_bytes >= (8u * 1024u * 1024u);
            size_t raw_source_runs = resident_segment_candidate
                ? stwo_zig_quotient_raw_source_run_count(
                    raw_columns,
                    raw_column_lengths,
                    raw_column_count,
                    resident_trees
                )
                : 0u;
            gpu_raw_upload =
                raw_bytes >= (64u * 1024u * 1024u) ||
                (resident_segment_candidate &&
                 raw_source_runs <= stwo_zig_quotient_max_segmented_source_runs);
            flat_buffer = gpu_raw_upload
                ? [runtime.device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared]
                : [runtime.device newBufferWithLength:raw_len * sizeof(uint32_t) options:MTLResourceStorageModeShared];
            if (!gpu_raw_upload) {
                uint32_t *destination = flat_buffer.contents;
                size_t cursor = 0;
                for (uint32_t i = 0; i < raw_column_count; ++i) {
                    memcpy(destination + cursor, raw_columns[i], raw_column_lengths[i] * sizeof(uint32_t));
                    cursor += raw_column_lengths[i];
                }
            }
        } else {
            flat_buffer = [runtime.device newBufferWithBytes:flat_views
                                                     length:flat_views_len * sizeof(uint32_t)
                                                    options:MTLResourceStorageModeShared];
        }
        id<MTLBuffer> view_buffer = [runtime.device newBufferWithBytes:views
                                                                length:(NSUInteger)view_count * view_word_count * sizeof(uint32_t)
                                                               options:MTLResourceStorageModeShared];
        id<MTLBuffer> sample_buffer = [runtime.device newBufferWithBytes:sample_components
                                                                  length:(NSUInteger)batch_count * 8u * sizeof(uint32_t)
                                                                 options:MTLResourceStorageModeShared];
        id<MTLBuffer> linear_buffer = [runtime.device newBufferWithBytes:linear_terms
                                                                  length:(NSUInteger)batch_count * 8u * sizeof(uint32_t)
                                                                 options:MTLResourceStorageModeShared];
        NSUInteger domain_bytes = (NSUInteger)row_count * sizeof(uint32_t);
        NSUInteger x_offset = 0u;
        NSUInteger y_offset = 0u;
        id<MTLBuffer> x_buffer = nil;
        id<MTLBuffer> y_buffer = nil;
        id<MTLBuffer> domain_cache_candidate = nil;
        bool build_domain_cache = false;
        if (cache_domain) {
            // A local strong reference keeps a hit alive if another proof
            // replaces the one-entry cache after this synchronized lookup.
            @synchronized(runtime) {
                if (runtime.quotientDomainCache != nil &&
                    runtime.quotientDomainCacheRowCount == row_count &&
                    runtime.quotientDomainCacheLogSize == domain_log_size &&
                    runtime.quotientDomainCacheInitialIndex == domain_initial_index &&
                    runtime.quotientDomainCacheStepSize == domain_step_size) {
                    domain_cache_candidate = runtime.quotientDomainCache;
                }
            }
            if (domain_cache_candidate == nil) {
                domain_cache_candidate = [runtime.device newBufferWithLength:2u * domain_bytes
                                                                      options:MTLResourceStorageModeShared];
                build_domain_cache = true;
            }
            x_buffer = domain_cache_candidate;
            y_buffer = domain_cache_candidate;
            y_offset = domain_bytes;
        } else {
            x_buffer = [runtime.device newBufferWithBytes:domain_x length:domain_bytes
                                                   options:MTLResourceStorageModeShared];
            y_buffer = [runtime.device newBufferWithBytes:domain_y length:domain_bytes
                                                   options:MTLResourceStorageModeShared];
        }
        size_t output_bytes = (size_t)row_count * 4u * sizeof(uint32_t);
        size_t page_size = (size_t)getpagesize();
        bool direct_output = ((uintptr_t)output % page_size) == 0u && (output_bytes % page_size) == 0u;
        id<MTLBuffer> output_buffer = resident_output_ptr != NULL
            ? (__bridge id<MTLBuffer>)resident_output_ptr
            : (direct_output
                ? [runtime.device newBufferWithBytesNoCopy:output
                                                    length:output_bytes
                                                   options:MTLResourceStorageModeShared
                                               deallocator:nil]
                : [runtime.device newBufferWithLength:output_bytes options:MTLResourceStorageModeShared]);
        if (resident_output_ptr != NULL &&
            (output_buffer.length != output_bytes || output_buffer.contents != output)) {
            write_error(error_message, error_message_len, @"Resident quotient output shape mismatch");
            return false;
        }
        if (flat_buffer == nil || view_buffer == nil || sample_buffer == nil ||
            linear_buffer == nil || x_buffer == nil || y_buffer == nil || output_buffer == nil) {
            write_error(error_message, error_message_len, @"Metal quotient allocation failed");
            return false;
        }

        NSMutableArray<id<MTLBuffer>> *layers = nil;
        id<MTLBuffer> hash_arena = nil;
        id<MTLBuffer> root_readback = nil;
        id<MTLBuffer> column_offsets = nil;
        id<MTLBuffer> column_logs = nil;
        id<MTLBuffer> leaf_seed_buffer = nil;
        StwoZigMerkleParentChain *parent_plan = nil;
        NSData *layer_word_offsets_data = nil;
        NSData *layer_word_lengths_data = nil;
        const uint32_t fri_state_word_offset = 0u;
        const uint32_t fri_root_word_offset = 16u;
        const uint32_t fri_alpha_word_offset = 24u;
        id<MTLBuffer> fri_channel_buffer = nil;
        uint32_t layer_word_offsets[31] = { 0u };
        uint32_t layer_word_lengths[31] = { 0u };
        uint32_t lifting_log_size = 0u;
        if (commit_tree) {
            if (row_count > UINT32_MAX / 4u || (row_count & (row_count - 1u)) != 0u) {
                write_error(error_message, error_message_len, @"Resident quotient row count is invalid");
                return false;
            }
            lifting_log_size = 31u - (uint32_t)__builtin_clz(row_count);
            uint32_t offsets[4] = { 0u, row_count, 2u * row_count, 3u * row_count };
            uint32_t logs[4] = { lifting_log_size, lifting_log_size, lifting_log_size, lifting_log_size };
            column_offsets = [runtime.device newBufferWithBytes:offsets length:sizeof(offsets)
                                                       options:MTLResourceStorageModeShared];
            column_logs = [runtime.device newBufferWithBytes:logs length:sizeof(logs)
                                                    options:MTLResourceStorageModeShared];
            leaf_seed_buffer = [runtime.device newBufferWithBytes:leaf_seed length:8u * sizeof(uint32_t)
                                                        options:MTLResourceStorageModeShared];
            layers = [NSMutableArray arrayWithCapacity:lifting_log_size + 1u];
            uint32_t layer_count = row_count;
            uint64_t arena_words = 0u;
            for (uint32_t level = 0u; level <= lifting_log_size; ++level) {
                arena_words = (arena_words + 63u) & ~UINT64_C(63);
                uint64_t length_words = (uint64_t)layer_count * 8u;
                if (arena_words > UINT32_MAX || length_words > UINT32_MAX ||
                    arena_words + length_words > UINT32_MAX) {
                    write_error(error_message, error_message_len, @"Resident quotient Merkle arena exceeds word offsets");
                    return false;
                }
                layer_word_offsets[level] = (uint32_t)arena_words;
                layer_word_lengths[level] = (uint32_t)length_words;
                arena_words += length_words;
                layer_count >>= 1u;
            }
            hash_arena = [runtime.device newBufferWithLength:(NSUInteger)arena_words * sizeof(uint32_t)
                                                     options:runtime.device.hasUnifiedMemory
                                                         ? MTLResourceStorageModeShared
                                                         : MTLResourceStorageModePrivate];
            root_readback = runtime.device.hasUnifiedMemory ? hash_arena
                : [runtime.device newBufferWithLength:32u options:MTLResourceStorageModeShared];
            layer_word_offsets_data = [NSData dataWithBytes:layer_word_offsets
                                                    length:(NSUInteger)(lifting_log_size + 1u) * sizeof(uint32_t)];
            layer_word_lengths_data = [NSData dataWithBytes:layer_word_lengths
                                                    length:(NSUInteger)(lifting_log_size + 1u) * sizeof(uint32_t)];
            if (column_offsets == nil || column_logs == nil || leaf_seed_buffer == nil ||
                hash_arena == nil || root_readback == nil || layer_word_offsets_data == nil ||
                layer_word_lengths_data == nil) {
                write_error(error_message, error_message_len, @"Resident quotient Merkle metadata allocation failed");
                return false;
            }
            for (uint32_t level = 0u; level <= lifting_log_size; ++level) [layers addObject:hash_arena];

            uint32_t child_offsets[30] = { 0u };
            uint32_t destination_offsets[30] = { 0u };
            uint32_t parent_counts[30] = { 0u };
            for (uint32_t level = 0u; level < lifting_log_size; ++level) {
                child_offsets[level] = layer_word_offsets[level];
                destination_offsets[level] = layer_word_offsets[level + 1u];
                parent_counts[level] = row_count >> (level + 1u);
            }
            void *parent_plan_ptr = stwo_zig_metal_merkle_parent_chain_prepare(
                runtime_ptr, child_offsets, destination_offsets, parent_counts,
                lifting_log_size, node_seed, domain_prefix_bytes, error_message, error_message_len);
            if (parent_plan_ptr != NULL)
                parent_plan = (__bridge_transfer StwoZigMerkleParentChain *)parent_plan_ptr;
            if (parent_plan == nil) {
                write_error(error_message, error_message_len, @"Resident quotient parent-chain allocation failed");
                return false;
            }
            if (fri_transaction) {
                fri_channel_buffer = [runtime.device newBufferWithLength:
                    (NSUInteger)(fri_alpha_word_offset + 4u) * sizeof(uint32_t)
                    options:MTLResourceStorageModeShared];
                if (fri_channel_buffer == nil) {
                    write_error(error_message, error_message_len, @"Resident FRI transcript allocation failed");
                    return false;
                }
                memset(fri_channel_buffer.contents, 0, fri_channel_buffer.length);
                memcpy((uint32_t *)fri_channel_buffer.contents + fri_state_word_offset,
                       fri_channel_state, 10u * sizeof(uint32_t));
            }
        }

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        if (build_domain_cache) {
            id<MTLComputeCommandEncoder> domain_encoder = [command computeCommandEncoder];
            [domain_encoder setComputePipelineState:runtime.quotientDomainPointsResident];
            [domain_encoder setBuffer:domain_cache_candidate offset:0u atIndex:0];
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
        NSMutableArray<id<MTLBuffer>> *raw_sources = [NSMutableArray array];
        if (gpu_raw_upload) {
            id<MTLBuffer> numerators = [runtime.device newBufferWithLength:(NSUInteger)batch_count * row_count * 4u * sizeof(uint32_t)
                                                                   options:MTLResourceStorageModePrivate];
            if (numerators == nil) {
                write_error(error_message, error_message_len, @"Metal quotient numerator allocation failed");
                return false;
            }
            id<MTLBlitCommandEncoder> clear = [command blitCommandEncoder];
            [clear fillBuffer:numerators range:NSMakeRange(0, numerators.length) value:0u];
            [clear endEncoding];
            size_t column = 0;
            size_t flat_offset = 0;
            size_t page_size = (size_t)getpagesize();
            while (column < raw_column_count) {
                size_t run_start = column;
                size_t run_words = raw_column_lengths[column];
                uintptr_t resident_begin = 0u;
                size_t resident_words = 0u;
                StwoZigMetalTree *resident_tree = stwo_zig_quotient_resident_source(
                    resident_trees,
                    raw_columns[column],
                    raw_column_lengths[column],
                    &resident_begin,
                    &resident_words
                );
                id<MTLBuffer> resident_source =
                    resident_tree == nil ? nil : resident_tree.residentColumns;
                bool resident_run = resident_source != nil;
                column += 1;
                if (resident_run) {
                    while (column < raw_column_count) {
                        uintptr_t address = (uintptr_t)raw_columns[column];
                        if (address < resident_begin) break;
                        size_t offset_words = (address - resident_begin) / sizeof(uint32_t);
                        if (offset_words > resident_words ||
                            raw_column_lengths[column] > resident_words - offset_words) break;
                        run_words += raw_column_lengths[column];
                        column += 1;
                    }
                } else {
                    while (column < raw_column_count &&
                           raw_columns[column] == raw_columns[run_start] + run_words) {
                        run_words += raw_column_lengths[column];
                        column += 1;
                    }
                }
                size_t run_bytes = run_words * sizeof(uint32_t);
                uintptr_t address = (uintptr_t)raw_columns[run_start];
                // Cache-skewed columns intentionally begin inside a VM page.
                // Alias the complete page envelope and bind the logical byte
                // offset instead of copying every non-page-aligned column.
                uintptr_t alias_address = address - (address % page_size);
                size_t source_binding_offset = address - alias_address;
                bool alias_shared = runtime.device.hasUnifiedMemory &&
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
                        : [runtime.device newBufferWithBytes:raw_columns[run_start]
                                                      length:run_bytes
                                                     options:MTLResourceStorageModeShared]);
                if (source == nil) {
                    write_error(error_message, error_message_len, @"Metal quotient upload allocation failed");
                    return false;
                }
                [raw_sources addObject:source];
                NSMutableData *run_view_data = [NSMutableData data];
                const StwoZigRawQuotientView *all_views = (const StwoZigRawQuotientView *)views;
                for (uint32_t view_index = 0; view_index < view_count; ++view_index) {
                    StwoZigRawQuotientView view = all_views[view_index];
                    if ((size_t)view.offset >= flat_offset && (size_t)view.offset < flat_offset + run_words) {
                        if (resident_run) {
                            size_t logical_column_start = flat_offset;
                            for (size_t source_column = run_start; source_column < column; ++source_column) {
                                size_t logical_column_end = logical_column_start + raw_column_lengths[source_column];
                                if ((size_t)view.offset < logical_column_end) {
                                    size_t resident_column_offset =
                                        ((uintptr_t)raw_columns[source_column] - resident_begin) /
                                        sizeof(uint32_t);
                                    view.offset = (uint32_t)(resident_column_offset +
                                        (size_t)view.offset - logical_column_start);
                                    break;
                                }
                                logical_column_start = logical_column_end;
                            }
                        } else {
                            view.offset -= (uint32_t)flat_offset;
                        }
                        [run_view_data appendBytes:&view length:sizeof(view)];
                    }
                }
                uint32_t run_view_count = (uint32_t)(run_view_data.length / sizeof(StwoZigRawQuotientView));
                if (run_view_count != 0u) {
                    id<MTLBuffer> run_views = [runtime.device newBufferWithBytes:run_view_data.bytes
                                                                         length:run_view_data.length
                                                                        options:MTLResourceStorageModeShared];
                    [raw_sources addObject:run_views];
                    id<MTLComputeCommandEncoder> numerator_encoder = [command computeCommandEncoder];
                    [numerator_encoder setComputePipelineState:runtime.quotientNumerator];
                    [numerator_encoder setBuffer:source
                                           offset:resident_run ? 0u :
                                               (alias_shared ? source_binding_offset : 0u)
                                          atIndex:0];
                    [numerator_encoder setBuffer:run_views offset:0 atIndex:1];
                    [numerator_encoder setBytes:&run_view_count length:sizeof(run_view_count) atIndex:2];
                    [numerator_encoder setBuffer:numerators offset:0 atIndex:3];
                    [numerator_encoder setBytes:&batch_count length:sizeof(batch_count) atIndex:4];
                    [numerator_encoder setBytes:&row_count length:sizeof(row_count) atIndex:5];
                    NSUInteger numerator_width = MIN(runtime.quotientNumerator.maxTotalThreadsPerThreadgroup,
                                                     runtime.quotientNumerator.threadExecutionWidth * 8u);
                    [numerator_encoder dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
                                 threadsPerThreadgroup:MTLSizeMake(numerator_width, 1u, 1u)];
                    [numerator_encoder endEncoding];
                }
                flat_offset += run_words;
            }
            id<MTLComputeCommandEncoder> finalize = [command computeCommandEncoder];
            [finalize setComputePipelineState:runtime.quotientFinalize];
            [finalize setBuffer:numerators offset:0 atIndex:0];
            [finalize setBuffer:sample_buffer offset:0 atIndex:1];
            [finalize setBuffer:linear_buffer offset:0 atIndex:2];
            [finalize setBytes:&batch_count length:sizeof(batch_count) atIndex:3];
            [finalize setBuffer:x_buffer offset:x_offset atIndex:4];
            [finalize setBuffer:y_buffer offset:y_offset atIndex:5];
            [finalize setBuffer:output_buffer offset:0 atIndex:6];
            [finalize setBytes:&row_count length:sizeof(row_count) atIndex:7];
            NSUInteger finalize_width = MIN(runtime.quotientFinalize.maxTotalThreadsPerThreadgroup,
                                            runtime.quotientFinalize.threadExecutionWidth * 8u);
            [finalize dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
                   threadsPerThreadgroup:MTLSizeMake(finalize_width, 1u, 1u)];
            [finalize endEncoding];
        } else {
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            id<MTLComputePipelineState> quotient_pipeline = raw_views ? runtime.rawQuotients : runtime.quotients;
            [encoder setComputePipelineState:quotient_pipeline];
            [encoder setBuffer:flat_buffer offset:0 atIndex:0];
            [encoder setBuffer:view_buffer offset:0 atIndex:1];
            [encoder setBytes:&view_count length:sizeof(view_count) atIndex:2];
            [encoder setBuffer:sample_buffer offset:0 atIndex:3];
            [encoder setBuffer:linear_buffer offset:0 atIndex:4];
            [encoder setBytes:&batch_count length:sizeof(batch_count) atIndex:5];
            [encoder setBuffer:x_buffer offset:x_offset atIndex:6];
            [encoder setBuffer:y_buffer offset:y_offset atIndex:7];
            [encoder setBuffer:output_buffer offset:0 atIndex:8];
            [encoder setBytes:&row_count length:sizeof(row_count) atIndex:9];
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
            [leaves setComputePipelineState:runtime.leaves];
            [leaves setBuffer:output_buffer offset:0 atIndex:0];
            [leaves setBuffer:column_offsets offset:0 atIndex:1];
            [leaves setBuffer:column_logs offset:0 atIndex:2];
            [leaves setBuffer:hash_arena
                         offset:(NSUInteger)layer_word_offsets[0] * sizeof(uint32_t) atIndex:3];
            [leaves setBytes:&column_count length:sizeof(column_count) atIndex:4];
            [leaves setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:5];
            [leaves setBuffer:leaf_seed_buffer offset:0 atIndex:6];
            [leaves setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:7];
            NSUInteger leaf_width = MIN(runtime.leaves.maxTotalThreadsPerThreadgroup,
                                        runtime.leaves.threadExecutionWidth * 8u);
            [leaves dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
                  threadsPerThreadgroup:MTLSizeMake(leaf_width, 1u, 1u)];
            [leaves endEncoding];
            uint64_t parent_encoders = 0u, parent_dispatches = 0u;
            if (!encode_merkle_parent_chain_prepared(runtime, hash_arena, parent_plan, command,
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
                [root_copy copyFromBuffer:hash_arena
                             sourceOffset:(NSUInteger)layer_word_offsets[lifting_log_size] * sizeof(uint32_t)
                                 toBuffer:root_readback destinationOffset:0u size:32u];
                [root_copy endEncoding];
            }
            if (fri_transaction) {
                id<MTLBlitCommandEncoder> fri_root_copy = [command blitCommandEncoder];
                if (fri_root_copy == nil) {
                    write_error(error_message, error_message_len, @"Resident FRI root transfer encoder allocation failed");
                    return false;
                }
                [fri_root_copy copyFromBuffer:hash_arena
                                  sourceOffset:(NSUInteger)layer_word_offsets[lifting_log_size] * sizeof(uint32_t)
                                      toBuffer:fri_channel_buffer
                             destinationOffset:(NSUInteger)fri_root_word_offset * sizeof(uint32_t)
                                          size:8u * sizeof(uint32_t)];
                [fri_root_copy endEncoding];

                id<MTLComputeCommandEncoder> fri_transcript = [command computeCommandEncoder];
                if (fri_transcript == nil) {
                    write_error(error_message, error_message_len, @"Resident FRI transcript encoder allocation failed");
                    return false;
                }
                uint32_t source_words = 8u;
                [fri_transcript setComputePipelineState:runtime.transcriptMixResident];
                [fri_transcript setBuffer:fri_channel_buffer offset:0u atIndex:0];
                [fri_transcript setBytes:&fri_state_word_offset
                                  length:sizeof(fri_state_word_offset) atIndex:1];
                [fri_transcript setBytes:&fri_root_word_offset
                                  length:sizeof(fri_root_word_offset) atIndex:2];
                [fri_transcript setBytes:&source_words length:sizeof(source_words) atIndex:3];
                [fri_transcript dispatchThreads:MTLSizeMake(1u, 1u, 1u)
                         threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
                [fri_transcript memoryBarrierWithScope:MTLBarrierScopeBuffers];

                uint32_t felt_count = 1u;
                [fri_transcript setComputePipelineState:runtime.transcriptDrawSecureResident];
                [fri_transcript setBuffer:fri_channel_buffer offset:0u atIndex:0];
                [fri_transcript setBytes:&fri_state_word_offset
                                  length:sizeof(fri_state_word_offset) atIndex:1];
                [fri_transcript setBytes:&fri_alpha_word_offset
                                  length:sizeof(fri_alpha_word_offset) atIndex:2];
                [fri_transcript setBytes:&felt_count length:sizeof(felt_count) atIndex:3];
                [fri_transcript dispatchThreads:MTLSizeMake(1u, 1u, 1u)
                         threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
                [fri_transcript endEncoding];
            }
        }
        [command commit];
        bool fri_ok = true;
        if (fri_transaction) {
            fri_ok = stwo_zig_metal_fri_line_cascade(
                runtime_ptr,
                fri_line_output_ptr,
                row_count >> 1u,
                resident_output_ptr,
                NULL,
                (__bridge void *)fri_channel_buffer,
                fri_state_word_offset,
                fri_alpha_word_offset,
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
                fri_channel_state,
                fri_tree_outputs,
                fri_stats,
                error_message,
                error_message_len
            );
        } else {
            [command waitUntilCompleted];
        }
        if (!fri_ok) return false;
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?: @"Metal quotient execution failed");
            return false;
        }
        if (build_domain_cache) {
            // Publish only completed data. Concurrent misses may duplicate
            // this bounded computation, but can never observe a partial grid.
            @synchronized(runtime) {
                runtime.quotientDomainCache = domain_cache_candidate;
                runtime.quotientDomainCacheRowCount = row_count;
                runtime.quotientDomainCacheLogSize = domain_log_size;
                runtime.quotientDomainCacheInitialIndex = domain_initial_index;
                runtime.quotientDomainCacheStepSize = domain_step_size;
            }
        }
        if (resident_output_ptr == NULL && !direct_output)
            memcpy(output, output_buffer.contents, output_bytes);
        if (gpu_milliseconds != NULL) {
            *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        }
        if (commit_tree) {
            StwoZigMetalTree *tree = [StwoZigMetalTree new];
            tree.runtimeOwner = runtime;
            tree.layers = layers;
            tree.layerWordOffsets = layer_word_offsets_data;
            tree.layerWordLengths = layer_word_lengths_data;
            tree.rootReadback = root_readback;
            tree.rootReadbackWordOffset = runtime.device.hasUnifiedMemory
                ? layer_word_offsets[lifting_log_size] : 0u;
            tree.logSize = lifting_log_size;
            tree.gpuMilliseconds = gpu_milliseconds != NULL ? *gpu_milliseconds : 0.0;
            *tree_out = (__bridge_retained void *)tree;
        }
        return true;
    }
}
