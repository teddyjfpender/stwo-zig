// Large uniform column commitment: circle IFFT, sparse LDE, Merkle leaves and
// every parent layer share one command buffer and one completion boundary.

void *stwo_zig_metal_circle_lde_merkle_commit(
    void *runtime_ptr,
    const uint32_t *const *source_columns,
    uint32_t *const *base_columns,
    uint32_t *extended_words,
    size_t extended_word_count,
    uint32_t extended_start,
    uint32_t extended_stride,
    uint32_t column_count,
    uint32_t base_log_size,
    uint32_t extended_log_size,
    const uint32_t *inverse_twiddles,
    const uint32_t *forward_twiddles,
    uint32_t scale_factor,
    uint32_t coefficients_ready,
    const uint32_t *trace_recipe,
    const uint32_t *leaf_seed,
    const uint32_t *node_seed,
    uint32_t domain_prefix_bytes,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || source_columns == NULL || base_columns == NULL ||
        extended_words == NULL || inverse_twiddles == NULL || forward_twiddles == NULL ||
        leaf_seed == NULL || node_seed == NULL ||
        !(column_count == 8u || (column_count >= 64u && column_count <= 256u)) ||
        coefficients_ready > 1u ||
        base_log_size < 16u || extended_log_size != base_log_size + 1u ||
        extended_log_size >= 31u ||
        (domain_prefix_bytes != 0u && domain_prefix_bytes != 64u)) {
        write_error(error_message, error_message_len, @"Combined Metal commitment shape is unsupported");
        return NULL;
    }
    if (trace_recipe != NULL) {
        if (coefficients_ready != 0u) {
            write_error(error_message, error_message_len,
                @"Deferred trace cannot also be coefficient-form input");
            return NULL;
        }
        for (uint32_t word = 0u; word < 7u; ++word) {
            if (trace_recipe[word] >= 0x7fffffffu) {
                write_error(error_message, error_message_len,
                    @"Combined Metal trace recipe is non-canonical");
                return NULL;
            }
        }
    }

    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        if (!runtime.device.hasUnifiedMemory) {
            write_error(error_message, error_message_len, @"Combined Metal commitment requires unified memory");
            return NULL;
        }
        uint32_t base_len = 1u << base_log_size;
        uint32_t extended_len = 1u << extended_log_size;
        uint32_t base_pairs = base_len >> 1u;
        uint32_t extended_pairs = extended_len >> 1u;
        size_t flat_base_count = (size_t)column_count * base_len;
        size_t required_words = (size_t)extended_start +
            (size_t)(column_count - 1u) * extended_stride + extended_len;
        if (extended_stride < extended_len || required_words > extended_word_count ||
            required_words > UINT32_MAX || flat_base_count > UINT32_MAX ||
            extended_word_count > SIZE_MAX / sizeof(uint32_t)) {
            write_error(error_message, error_message_len, @"Combined Metal commitment arena is invalid");
            return NULL;
        }

        size_t page_size = (size_t)getpagesize();
        size_t base_bytes = flat_base_count * sizeof(uint32_t);
        size_t extended_bytes = extended_word_count * sizeof(uint32_t);
        bool contiguous_base = true;
        for (uint32_t column = 1u; column < column_count; ++column)
            contiguous_base &= base_columns[column] == base_columns[0] + (size_t)column * base_len;
        bool direct_base = contiguous_base && ((uintptr_t)base_columns[0] % page_size) == 0u &&
            (base_bytes % page_size) == 0u;
        bool direct_extended = ((uintptr_t)extended_words % page_size) == 0u &&
            (extended_bytes % page_size) == 0u;
        if (!direct_base || !direct_extended) {
            write_error(error_message, error_message_len, @"Combined Metal commitment requires page-aligned backing");
            return NULL;
        }

        id<MTLBuffer> coefficients = [runtime.device newBufferWithBytesNoCopy:base_columns[0]
            length:base_bytes options:MTLResourceStorageModeShared deallocator:nil];
        id<MTLBuffer> extended = [runtime.device newBufferWithBytesNoCopy:extended_words
            length:extended_bytes options:MTLResourceStorageModeShared deallocator:nil];
        size_t inverse_bytes = (size_t)base_pairs * sizeof(uint32_t);
        size_t forward_bytes = (size_t)extended_pairs * sizeof(uint32_t);
        bool direct_inverse = ((uintptr_t)inverse_twiddles % page_size) == 0u &&
            (inverse_bytes % page_size) == 0u;
        bool direct_forward = ((uintptr_t)forward_twiddles % page_size) == 0u &&
            (forward_bytes % page_size) == 0u;
        id<MTLBuffer> inverse_buffer = direct_inverse
            ? [runtime.device newBufferWithBytesNoCopy:(void *)inverse_twiddles
                length:inverse_bytes options:MTLResourceStorageModeShared deallocator:nil]
            : [runtime.device newBufferWithBytes:inverse_twiddles
                length:inverse_bytes options:MTLResourceStorageModeShared];
        id<MTLBuffer> forward_buffer = direct_forward
            ? [runtime.device newBufferWithBytesNoCopy:(void *)forward_twiddles
                length:forward_bytes options:MTLResourceStorageModeShared deallocator:nil]
            : [runtime.device newBufferWithBytes:forward_twiddles
                length:forward_bytes options:MTLResourceStorageModeShared];
        id<MTLBuffer> base_offsets = [runtime.device newBufferWithLength:
            (NSUInteger)column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> extended_offsets = [runtime.device newBufferWithLength:
            (NSUInteger)column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> column_logs = [runtime.device newBufferWithLength:
            (NSUInteger)column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> leaf_seed_buffer = [runtime.device newBufferWithBytes:leaf_seed
            length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        if (coefficients == nil || extended == nil || inverse_buffer == nil ||
            forward_buffer == nil || base_offsets == nil || extended_offsets == nil ||
            column_logs == nil || leaf_seed_buffer == nil) {
            write_error(error_message, error_message_len, @"Combined Metal commitment allocation failed");
            return NULL;
        }
        uint32_t *base_offset_words = base_offsets.contents;
        uint32_t *extended_offset_words = extended_offsets.contents;
        uint32_t *log_words = column_logs.contents;
        for (uint32_t column = 0u; column < column_count; ++column) {
            base_offset_words[column] = column * base_len;
            extended_offset_words[column] = extended_start + column * extended_stride;
            log_words[column] = extended_log_size;
        }

        uint32_t leaf_count = extended_len;
        NSMutableArray<id<MTLBuffer>> *layers =
            [NSMutableArray arrayWithCapacity:extended_log_size + 1u];
        uint32_t layer_word_offsets[31] = { 0u };
        uint32_t layer_word_lengths[31] = { 0u };
        uint32_t layer_count = leaf_count;
        uint64_t hash_words = 0u;
        for (uint32_t level = 0u; level <= extended_log_size; ++level) {
            hash_words = (hash_words + 63u) & ~UINT64_C(63);
            uint64_t length_words = (uint64_t)layer_count * 8u;
            if (hash_words > UINT32_MAX || length_words > UINT32_MAX ||
                hash_words + length_words > UINT32_MAX) {
                write_error(error_message, error_message_len, @"Combined Metal hash arena exceeds u32 offsets");
                return NULL;
            }
            layer_word_offsets[level] = (uint32_t)hash_words;
            layer_word_lengths[level] = (uint32_t)length_words;
            hash_words += length_words;
            layer_count >>= 1u;
        }
        id<MTLBuffer> hash_arena = [runtime.device newBufferWithLength:
            (NSUInteger)hash_words * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        NSData *layer_offsets_data = [NSData dataWithBytes:layer_word_offsets
            length:(NSUInteger)(extended_log_size + 1u) * sizeof(uint32_t)];
        NSData *layer_lengths_data = [NSData dataWithBytes:layer_word_lengths
            length:(NSUInteger)(extended_log_size + 1u) * sizeof(uint32_t)];
        if (hash_arena == nil || layer_offsets_data == nil || layer_lengths_data == nil) {
            write_error(error_message, error_message_len, @"Combined Metal hash allocation failed");
            return NULL;
        }
        for (uint32_t level = 0u; level <= extended_log_size; ++level)
            [layers addObject:hash_arena];

        uint32_t child_offsets[30] = { 0u };
        uint32_t destination_offsets[30] = { 0u };
        uint32_t parent_counts[30] = { 0u };
        for (uint32_t level = 0u; level < extended_log_size; ++level) {
            child_offsets[level] = layer_word_offsets[level];
            destination_offsets[level] = layer_word_offsets[level + 1u];
            parent_counts[level] = leaf_count >> (level + 1u);
        }
        void *parent_plan_ptr = stwo_zig_metal_merkle_parent_chain_prepare(
            runtime_ptr, child_offsets, destination_offsets, parent_counts,
            extended_log_size, node_seed, domain_prefix_bytes,
            error_message, error_message_len);
        if (parent_plan_ptr == NULL) return NULL;
        StwoZigMerkleParentChain *parent_plan =
            (__bridge_transfer StwoZigMerkleParentChain *)parent_plan_ptr;

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        NSMutableArray<id<MTLBuffer>> *input_sources = [NSMutableArray array];

        bool source_is_base = source_columns[0] == base_columns[0];
        for (uint32_t column = 1u; column < column_count; ++column) {
            source_is_base &= source_columns[column] ==
                base_columns[0] + (size_t)column * base_len;
        }

        if (coefficients_ready != 0u && !source_is_base) {
            id<MTLBlitCommandEncoder> coefficient_upload = [command blitCommandEncoder];
            size_t column_bytes = (size_t)base_len * sizeof(uint32_t);
            for (uint32_t column = 0u; column < column_count; ++column) {
                uintptr_t address = (uintptr_t)source_columns[column];
                bool no_copy = (address % page_size) == 0u &&
                    (column_bytes % page_size) == 0u;
                id<MTLBuffer> source = no_copy
                    ? [runtime.device newBufferWithBytesNoCopy:(void *)source_columns[column]
                        length:column_bytes options:MTLResourceStorageModeShared deallocator:nil]
                    : [runtime.device newBufferWithBytes:source_columns[column]
                        length:column_bytes options:MTLResourceStorageModeShared];
                if (source == nil) {
                    [coefficient_upload endEncoding];
                    write_error(error_message, error_message_len,
                        @"Coefficient-form Metal source allocation failed");
                    return NULL;
                }
                [input_sources addObject:source];
                [coefficient_upload copyFromBuffer:source sourceOffset:0u
                    toBuffer:coefficients destinationOffset:(NSUInteger)column * column_bytes
                    size:column_bytes];
            }
            [coefficient_upload endEncoding];
        }

        if (coefficients_ready == 0u) {
            id<MTLComputeCommandEncoder> upload = [command computeCommandEncoder];
            if (trace_recipe != NULL) {
            if (!source_is_base) {
                write_error(error_message, error_message_len,
                    @"Deferred Metal trace requires the contiguous coefficient arena");
                return NULL;
            }
            [upload setComputePipelineState:runtime.quadraticRecurrenceIfftWide];
            [upload setBuffer:coefficients offset:0u atIndex:0];
            [upload setBuffer:inverse_buffer offset:0u atIndex:1];
            [upload setBytes:&base_log_size length:sizeof(base_log_size) atIndex:2];
            [upload setBytes:&column_count length:sizeof(column_count) atIndex:3];
            [upload setBytes:trace_recipe length:7u * sizeof(uint32_t) atIndex:4];
            [upload setBytes:&scale_factor length:sizeof(scale_factor) atIndex:5];
            [upload dispatchThreadgroups:MTLSizeMake(base_len >> 12u, 1u, 1u)
                threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
            } else {
                // A transferable contiguous trace already is the coefficient
                // arena. Transform it in place; other callers retain fused upload.
                [upload setComputePipelineState:runtime.circleIfftFusedWide];
                uint32_t source_mode = source_is_base ? 0u : 1u;
                [upload setBytes:&source_mode length:sizeof(source_mode) atIndex:5];
                if (source_is_base) {
                    [upload setBuffer:coefficients offset:0u atIndex:0];
                    [upload setBuffer:coefficients offset:0u atIndex:1];
                    [upload setBuffer:inverse_buffer offset:0u atIndex:2];
                    [upload setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
                    [upload setBytes:&column_count length:sizeof(column_count) atIndex:4];
                    [upload dispatchThreadgroups:MTLSizeMake(base_len >> 12u, column_count, 1u)
                        threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
                } else {
                    size_t source_column = 0u;
                    size_t destination_words = 0u;
                    while (source_column < column_count) {
                        size_t run_start = source_column;
                        size_t run_words = base_len;
                        source_column += 1u;
                        while (source_column < column_count &&
                               source_columns[source_column] == source_columns[run_start] + run_words) {
                            run_words += base_len;
                            source_column += 1u;
                        }
                        size_t run_bytes = run_words * sizeof(uint32_t);
                        uintptr_t address = (uintptr_t)source_columns[run_start];
                        bool no_copy = (address % page_size) == 0u && (run_bytes % page_size) == 0u;
                        id<MTLBuffer> source = no_copy
                            ? [runtime.device newBufferWithBytesNoCopy:(void *)source_columns[run_start]
                                length:run_bytes options:MTLResourceStorageModeShared deallocator:nil]
                            : [runtime.device newBufferWithBytes:source_columns[run_start]
                                length:run_bytes options:MTLResourceStorageModeShared];
                        if (source == nil) {
                            [upload endEncoding];
                            write_error(error_message, error_message_len,
                                @"Combined Metal source allocation failed");
                            return NULL;
                        }
                        [input_sources addObject:source];
                        uint32_t destination_column = (uint32_t)(destination_words / base_len);
                        [upload setBuffer:source offset:0u atIndex:0];
                        [upload setBuffer:coefficients offset:0u atIndex:1];
                        [upload setBuffer:inverse_buffer offset:0u atIndex:2];
                        [upload setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
                        [upload setBytes:&destination_column length:sizeof(destination_column) atIndex:4];
                        [upload dispatchThreadgroups:MTLSizeMake(base_len >> 12u, run_words / base_len, 1u)
                            threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
                        destination_words += run_words;
                    }
                }
            }
            [upload endEncoding];

            MTLSize base_grid = MTLSizeMake(base_pairs, column_count, 1u);
            uint32_t inverse_layer = 12u;
            uint32_t inverse_layer_count = base_log_size - inverse_layer;
            if (column_count >= 64u && inverse_layer_count >= 5u) {
                uint32_t inverse_mode = 1u;
                // Inverse stages expose their cheapest register radix at the
                // top. Keep at least sixteen independent tuples per group;
                // larger cooperative tuples lose occupancy to the 2/3/4-stage
                // register kernel used for the remainder.
                uint32_t fused_count = inverse_layer_count > 8u ? 8u : inverse_layer_count;
                uint32_t lanes_per_group = 4096u >> fused_count;
                uint32_t lane_batches = (1u << inverse_layer) / lanes_per_group;
                uint32_t outer_groups = 1u <<
                    (base_log_size - inverse_layer - fused_count);
                uint32_t group_count = lane_batches * outer_groups;
                uint32_t column_config = 0x80000000u | column_count |
                    (inverse_mode << 9u) | (fused_count << 10u) |
                    (inverse_layer << 14u);
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftLastSparse];
                [encoder setThreadgroupMemoryLength:4096u * sizeof(uint32_t) atIndex:0];
                [encoder setBuffer:coefficients offset:0u atIndex:0];
                [encoder setBuffer:base_offsets offset:0u atIndex:1];
                [encoder setBuffer:inverse_buffer offset:0u atIndex:2];
                [encoder setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
                [encoder setBytes:&column_config length:sizeof(column_config) atIndex:4];
                [encoder dispatchThreadgroups:MTLSizeMake(group_count, column_count, 1u)
                    threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
                [encoder endEncoding];
                inverse_layer += fused_count;
            }
            while (inverse_layer < base_log_size) {
            if (inverse_layer + 3u < base_log_size) {
                uint32_t layer_mode = inverse_layer | 0xa0000000u;
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [encoder setBuffer:coefficients offset:0u atIndex:0];
                [encoder setBuffer:base_offsets offset:0u atIndex:1];
                [encoder setBuffer:inverse_buffer offset:0u atIndex:2];
                [encoder setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
                [encoder setBytes:&layer_mode length:sizeof(layer_mode) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                NSUInteger width = MIN((NSUInteger)256u,
                    runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [encoder dispatchThreads:MTLSizeMake(base_len >> 4u, column_count, 1u)
                    threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                inverse_layer += 4u;
            } else if (inverse_layer + 2u < base_log_size) {
                uint32_t layer_mode = inverse_layer | 0xc0000000u;
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [encoder setBuffer:coefficients offset:0u atIndex:0];
                [encoder setBuffer:base_offsets offset:0u atIndex:1];
                [encoder setBuffer:inverse_buffer offset:0u atIndex:2];
                [encoder setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
                [encoder setBytes:&layer_mode length:sizeof(layer_mode) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                NSUInteger width = MIN((NSUInteger)256u,
                    runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [encoder dispatchThreads:MTLSizeMake(base_len >> 3u, column_count, 1u)
                    threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                inverse_layer += 3u;
            } else if (inverse_layer + 1u < base_log_size) {
                uint32_t layer_mode = inverse_layer | 0x80000000u;
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [encoder setBuffer:coefficients offset:0u atIndex:0];
                [encoder setBuffer:base_offsets offset:0u atIndex:1];
                [encoder setBuffer:inverse_buffer offset:0u atIndex:2];
                [encoder setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
                [encoder setBytes:&layer_mode length:sizeof(layer_mode) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                NSUInteger width = MIN((NSUInteger)256u,
                    runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [encoder dispatchThreads:MTLSizeMake(base_len >> 2u, column_count, 1u)
                    threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                inverse_layer += 2u;
            } else {
                uint32_t inverse_offset = base_pairs - (1u << (base_log_size - inverse_layer));
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleIfftLayer];
                [encoder setBuffer:coefficients offset:0u atIndex:0];
                [encoder setBuffer:inverse_buffer offset:0u atIndex:1];
                [encoder setBytes:&base_log_size length:sizeof(base_log_size) atIndex:2];
                [encoder setBytes:&inverse_layer length:sizeof(inverse_layer) atIndex:3];
                [encoder setBytes:&inverse_offset length:sizeof(inverse_offset) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                [encoder dispatchThreads:base_grid threadsPerThreadgroup:MTLSizeMake(
                    MIN((NSUInteger)256u, runtime.circleIfftLayer.maxTotalThreadsPerThreadgroup), 1u, 1u)];
                [encoder endEncoding];
                inverse_layer += 1u;
            }
            }
        }

        MTLSize extended_grid = MTLSizeMake(extended_pairs, column_count, 1u);
        bool use_wide_tile = column_count >= 64u;
        uint32_t fused_layer = use_wide_tile ? 11u : 10u;
        uint32_t layer = extended_log_size - 3u;
        uint32_t high_layer_count = layer - fused_layer;
        uint32_t fused_count = 0u, lowest_stage = 0u;
        uint32_t lane_batches = 0u, outer_groups = 0u;
        if (use_wide_tile && high_layer_count >= 5u) {
            fused_count = high_layer_count > 12u ? 12u : high_layer_count;
            lowest_stage = layer - fused_count + 1u;
            uint32_t lanes_per_group = 4096u >> fused_count;
            lane_batches = (1u << lowest_stage) / lanes_per_group;
            outer_groups = 1u <<
                (extended_log_size - lowest_stage - fused_count);
        }
        uint32_t expand_scale_factor =
            (trace_recipe != NULL || coefficients_ready != 0u) ? 1u : scale_factor;
        bool combine_expand_high = fused_count != 0u && expand_scale_factor == 1u;
        NSUInteger expand_static_memory =
            runtime.circleExpand.staticThreadgroupMemoryLength;
        NSUInteger expand_dynamic_capacity =
            runtime.device.maxThreadgroupMemoryLength > expand_static_memory
                ? runtime.device.maxThreadgroupMemoryLength - expand_static_memory
                : 0u;
        bool pair_expand_high = combine_expand_high && outer_groups == 4u &&
            runtime.circleExpand.maxTotalThreadsPerThreadgroup >= 512u &&
            expand_dynamic_capacity >= 8192u * sizeof(uint32_t);
        uint32_t fuse_top_two = pair_expand_high ? 3u :
            (combine_expand_high ? 2u : 1u);
        id<MTLComputeCommandEncoder> expand = [command computeCommandEncoder];
        [expand setComputePipelineState:runtime.circleExpand];
        if (combine_expand_high)
            [expand setThreadgroupMemoryLength:
                (pair_expand_high ? 8192u : 4096u) * sizeof(uint32_t) atIndex:0];
        [expand setBuffer:coefficients offset:0u atIndex:0];
        [expand setBuffer:extended offset:0u atIndex:1];
        [expand setBuffer:forward_buffer offset:0u atIndex:2];
        [expand setBuffer:base_offsets offset:0u atIndex:3];
        [expand setBuffer:extended_offsets offset:0u atIndex:4];
        [expand setBytes:&base_log_size length:sizeof(base_log_size) atIndex:5];
        [expand setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:6];
        [expand setBytes:&column_count length:sizeof(column_count) atIndex:7];
        [expand setBytes:&expand_scale_factor length:sizeof(expand_scale_factor) atIndex:8];
        [expand setBytes:&fuse_top_two length:sizeof(fuse_top_two) atIndex:9];
        if (combine_expand_high) {
            uint32_t dispatched_outer_groups =
                pair_expand_high ? outer_groups >> 1u : outer_groups;
            [expand dispatchThreadgroups:MTLSizeMake(
                    lane_batches * dispatched_outer_groups, column_count, 1u)
                threadsPerThreadgroup:MTLSizeMake(
                    pair_expand_high ? 512u : 256u, 1u, 1u)];
        } else {
            [expand dispatchThreads:MTLSizeMake(base_len >> 1u, column_count, 1u)
                threadsPerThreadgroup:MTLSizeMake(
                    MIN((NSUInteger)256u, runtime.circleExpand.maxTotalThreadsPerThreadgroup), 1u, 1u)];
        }
        [expand endEncoding];

        if (combine_expand_high) {
            layer -= fused_count;
        } else if (use_wide_tile && high_layer_count >= 5u) {
            uint32_t inverse_mode = 0u;
            uint32_t column_config = 0x80000000u | column_count |
                (inverse_mode << 9u) | (fused_count << 10u) |
                (lowest_stage << 14u);
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            [encoder setComputePipelineState:runtime.circleRfftLastSparse];
            [encoder setThreadgroupMemoryLength:4096u * sizeof(uint32_t) atIndex:0];
            [encoder setBuffer:extended offset:0u atIndex:0];
            [encoder setBuffer:extended_offsets offset:0u atIndex:1];
            [encoder setBuffer:forward_buffer offset:0u atIndex:2];
            [encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
            [encoder setBytes:&column_config length:sizeof(column_config) atIndex:4];
            [encoder dispatchThreadgroups:MTLSizeMake(lane_batches * outer_groups, column_count, 1u)
                threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
            [encoder endEncoding];
            layer -= fused_count;
        }
        while (layer > fused_layer) {
            if (layer >= fused_layer + 4u) {
                uint32_t layer_mode = layer | 0x20000000u;
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [encoder setBuffer:extended offset:0u atIndex:0];
                [encoder setBuffer:extended_offsets offset:0u atIndex:1];
                [encoder setBuffer:forward_buffer offset:0u atIndex:2];
                [encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
                [encoder setBytes:&layer_mode length:sizeof(layer_mode) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                NSUInteger width = MIN((NSUInteger)256u,
                    runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [encoder dispatchThreads:MTLSizeMake(extended_len >> 4u, column_count, 1u)
                    threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                layer -= 4u;
            } else if (layer >= fused_layer + 3u) {
                uint32_t layer_mode = layer | 0x40000000u;
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [encoder setBuffer:extended offset:0u atIndex:0];
                [encoder setBuffer:extended_offsets offset:0u atIndex:1];
                [encoder setBuffer:forward_buffer offset:0u atIndex:2];
                [encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
                [encoder setBytes:&layer_mode length:sizeof(layer_mode) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                NSUInteger width = MIN((NSUInteger)256u,
                    runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [encoder dispatchThreads:MTLSizeMake(extended_len >> 3u, column_count, 1u)
                    threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                layer -= 3u;
            } else if (layer >= fused_layer + 2u) {
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [encoder setBuffer:extended offset:0u atIndex:0];
                [encoder setBuffer:extended_offsets offset:0u atIndex:1];
                [encoder setBuffer:forward_buffer offset:0u atIndex:2];
                [encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
                [encoder setBytes:&layer length:sizeof(layer) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                NSUInteger width = MIN((NSUInteger)256u,
                    runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [encoder dispatchThreads:MTLSizeMake(extended_len >> 2u, column_count, 1u)
                    threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                layer -= 2u;
            } else {
                uint32_t forward_offset = extended_pairs - (1u << (extended_log_size - layer));
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftLayerSparse];
                [encoder setBuffer:extended offset:0u atIndex:0];
                [encoder setBuffer:extended_offsets offset:0u atIndex:1];
                [encoder setBuffer:forward_buffer offset:0u atIndex:2];
                [encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
                [encoder setBytes:&layer length:sizeof(layer) atIndex:4];
                [encoder setBytes:&forward_offset length:sizeof(forward_offset) atIndex:5];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:6];
                [encoder dispatchThreads:extended_grid threadsPerThreadgroup:MTLSizeMake(
                    MIN((NSUInteger)256u, runtime.circleRfftLayerSparse.maxTotalThreadsPerThreadgroup), 1u, 1u)];
                [encoder endEncoding];
                layer -= 1u;
            }
        }
        id<MTLComputeCommandEncoder> fused = [command computeCommandEncoder];
        [fused setComputePipelineState:use_wide_tile
            ? runtime.circleRfftFusedSparseWide
            : runtime.circleRfftFusedSparse];
        [fused setBuffer:extended offset:0u atIndex:0];
        [fused setBuffer:extended_offsets offset:0u atIndex:1];
        [fused setBuffer:forward_buffer offset:0u atIndex:2];
        [fused setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
        [fused setBytes:&column_count length:sizeof(column_count) atIndex:4];
        [fused dispatchThreadgroups:MTLSizeMake(
                extended_len >> (use_wide_tile ? 12u : 11u), column_count, 1u)
            threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
        [fused endEncoding];

        id<MTLComputeCommandEncoder> leaf_encoder = [command computeCommandEncoder];
        [leaf_encoder setComputePipelineState:runtime.leaves];
        [leaf_encoder setBuffer:extended offset:0u atIndex:0];
        [leaf_encoder setBuffer:extended_offsets offset:0u atIndex:1];
        [leaf_encoder setBuffer:column_logs offset:0u atIndex:2];
        [leaf_encoder setBuffer:hash_arena
            offset:(NSUInteger)layer_word_offsets[0] * sizeof(uint32_t) atIndex:3];
        [leaf_encoder setBytes:&column_count length:sizeof(column_count) atIndex:4];
        [leaf_encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:5];
        [leaf_encoder setBuffer:leaf_seed_buffer offset:0u atIndex:6];
        [leaf_encoder setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:7];
        NSUInteger leaf_width = MIN(runtime.leaves.maxTotalThreadsPerThreadgroup,
            runtime.leaves.threadExecutionWidth * 8u);
        [leaf_encoder dispatchThreads:MTLSizeMake(leaf_count, 1u, 1u)
            threadsPerThreadgroup:MTLSizeMake(leaf_width, 1u, 1u)];
        [leaf_encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        uint64_t parent_dispatches = 0u;
        if (!encode_merkle_parent_chain_on_encoder(
                runtime, hash_arena, parent_plan, leaf_encoder, &parent_dispatches)) {
            [leaf_encoder endEncoding];
            write_error(error_message, error_message_len, @"Combined Metal parent encoding failed");
            return NULL;
        }
        [leaf_encoder endEncoding];

        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                command.error.localizedDescription ?: @"Combined Metal commitment failed");
            return NULL;
        }

        double elapsed = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        if (gpu_milliseconds != NULL) *gpu_milliseconds = elapsed;
        StwoZigMetalTree *tree = [StwoZigMetalTree new];
        tree.runtimeOwner = runtime;
        tree.layers = layers;
        tree.layerWordOffsets = layer_offsets_data;
        tree.layerWordLengths = layer_lengths_data;
        tree.rootReadback = hash_arena;
        tree.rootReadbackWordOffset = layer_word_offsets[extended_log_size];
        tree.logSize = extended_log_size;
        tree.gpuMilliseconds = elapsed;
        tree.residentColumns = extended;
        tree.residentColumnsHostBegin = (uintptr_t)extended_words;
        tree.residentColumnsWordCount = extended_word_count;
        uintptr_t resident_begin = (uintptr_t)extended_words;
        size_t resident_words = extended_word_count;
        uint32_t resident_offset = 0u;
        tree.residentColumnBuffers = @[ extended ];
        tree.residentColumnHostBegins =
            [NSData dataWithBytes:&resident_begin length:sizeof(resident_begin)];
        tree.residentColumnWordCounts =
            [NSData dataWithBytes:&resident_words length:sizeof(resident_words)];
        tree.residentColumnWordOffsets =
            [NSData dataWithBytes:&resident_offset length:sizeof(resident_offset)];
        return (__bridge_retained void *)tree;
    }
}
