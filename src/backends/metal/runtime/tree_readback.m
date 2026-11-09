bool stwo_zig_metal_tree_copy_hashes(
    void *runtime_ptr,
    void *tree_ptr,
    uint32_t layer_log_size,
    const uint32_t *indices,
    uint32_t index_count,
    uint8_t *destination,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || tree_ptr == NULL || indices == NULL || destination == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)tree_ptr;
        if (layer_log_size > tree.logSize - tree.prunedBottomLayers) {
            write_error(error_message, error_message_len, @"Invalid Metal layer log size");
            return false;
        }
        uint32_t layer_count = 1u << layer_log_size;
        for (uint32_t i = 0; i < index_count; ++i) {
            if (indices[i] >= layer_count) {
                write_error(error_message, error_message_len, @"Invalid Metal layer hash index");
                return false;
            }
        }

        NSUInteger layer_index = (NSUInteger)(tree.logSize - layer_log_size);
        id<MTLBuffer> source = tree.layers[layer_index];
        NSUInteger layer_offset = (NSUInteger)tree_layer_word_offset(tree, layer_index) * sizeof(uint32_t);
        if (source.storageMode == MTLStorageModeShared) {
            const uint8_t *source_bytes = source.contents;
            if (source_bytes == NULL) {
                write_error(error_message, error_message_len, @"Metal shared hash layer is not CPU-visible");
                return false;
            }
            source_bytes += layer_offset;
            for (uint32_t i = 0; i < index_count; ++i) {
                memcpy(destination + (NSUInteger)i * 32u,
                       source_bytes + (NSUInteger)indices[i] * 32u, 32u);
            }
            return true;
        }
        id<MTLBuffer> readback = [runtime.device newBufferWithLength:(NSUInteger)index_count * 32u
                                                            options:MTLResourceStorageModeShared];
        if (readback == nil) {
            write_error(error_message, error_message_len, @"Metal selective readback allocation failed");
            return false;
        }
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
        for (uint32_t i = 0; i < index_count; ++i) {
            [blit copyFromBuffer:source sourceOffset:layer_offset + (NSUInteger)indices[i] * 32u
                       toBuffer:readback destinationOffset:(NSUInteger)i * 32u size:32u];
        }
        [blit endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?: @"Metal selective hash readback failed");
            return false;
        }
        memcpy(destination, readback.contents, (NSUInteger)index_count * 32u);
        return true;
    }
}

bool stwo_zig_metal_tree_copy_hashes_batch(
    void *runtime_ptr,
    void *tree_ptr,
    const uint32_t *layer_log_sizes,
    const uint32_t *const *indices,
    const uint32_t *index_counts,
    uint8_t *const *destinations,
    uint32_t request_count,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || tree_ptr == NULL || layer_log_sizes == NULL ||
        indices == NULL || index_counts == NULL || destinations == NULL || request_count == 0u)
        return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)tree_ptr;
        size_t total_hashes = 0u;
        for (uint32_t request = 0u; request < request_count; ++request) {
            uint32_t layer_log_size = layer_log_sizes[request];
            uint32_t index_count = index_counts[request];
            if (layer_log_size >= 31u || layer_log_size > tree.logSize - tree.prunedBottomLayers ||
                (index_count != 0u && (indices[request] == NULL || destinations[request] == NULL))) {
                write_error(error_message, error_message_len, @"Invalid Metal hash-read batch");
                return false;
            }
            uint32_t layer_count = 1u << layer_log_size;
            for (uint32_t index = 0u; index < index_count; ++index) {
                if (indices[request][index] >= layer_count) {
                    write_error(error_message, error_message_len, @"Invalid Metal batched hash index");
                    return false;
                }
            }
            if ((size_t)index_count > SIZE_MAX - total_hashes) {
                write_error(error_message, error_message_len, @"Metal hash-read batch exceeds address space");
                return false;
            }
            total_hashes += (size_t)index_count;
        }
        if (total_hashes == 0u) return true;
        if (total_hashes > SIZE_MAX / 32u) {
            write_error(error_message, error_message_len, @"Metal hash-read batch exceeds address space");
            return false;
        }

        // Tree-producing entry points wait for successful command completion
        // before publishing the immutable tree.  Shared layers are therefore
        // coherent for direct CPU point queries here; no additional GPU epoch
        // or synchronization boundary is required.
        bool all_layers_shared = true;
        for (uint32_t request = 0u; request < request_count; ++request) {
            NSUInteger layer_index = (NSUInteger)(tree.logSize - layer_log_sizes[request]);
            id<MTLBuffer> source = tree.layers[layer_index];
            if (source.storageMode != MTLStorageModeShared || source.contents == NULL) {
                all_layers_shared = false;
                break;
            }
        }
        if (all_layers_shared) {
            for (uint32_t request = 0u; request < request_count; ++request) {
                NSUInteger layer_index = (NSUInteger)(tree.logSize - layer_log_sizes[request]);
                id<MTLBuffer> source = tree.layers[layer_index];
                const uint8_t *source_bytes = (const uint8_t *)source.contents +
                    (NSUInteger)tree_layer_word_offset(tree, layer_index) * sizeof(uint32_t);
                for (uint32_t index = 0u; index < index_counts[request]; ++index) {
                    memcpy(destinations[request] + (NSUInteger)index * 32u,
                           source_bytes + (NSUInteger)indices[request][index] * 32u, 32u);
                }
            }
            return true;
        }

        id<MTLBuffer> readback = [runtime.device newBufferWithLength:(NSUInteger)total_hashes * 32u
                                                             options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
        if (readback == nil || command == nil || blit == nil) {
            write_error(error_message, error_message_len, @"Metal batched hash-read allocation failed");
            return false;
        }

        size_t destination_hash = 0u;
        for (uint32_t request = 0u; request < request_count; ++request) {
            NSUInteger layer_index = (NSUInteger)(tree.logSize - layer_log_sizes[request]);
            id<MTLBuffer> source = tree.layers[layer_index];
            NSUInteger layer_offset = (NSUInteger)tree_layer_word_offset(tree, layer_index) * sizeof(uint32_t);
            for (uint32_t index = 0u; index < index_counts[request]; ++index) {
                [blit copyFromBuffer:source sourceOffset:layer_offset + (NSUInteger)indices[request][index] * 32u
                           toBuffer:readback destinationOffset:(NSUInteger)destination_hash * 32u size:32u];
                destination_hash += 1u;
            }
        }
        [blit endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?: @"Metal batched hash readback failed");
            return false;
        }

        const uint8_t *source_bytes = readback.contents;
        size_t source_hash = 0u;
        for (uint32_t request = 0u; request < request_count; ++request) {
            size_t byte_count = (size_t)index_counts[request] * 32u;
            if (byte_count != 0u) memcpy(destinations[request], source_bytes + source_hash * 32u, byte_count);
            source_hash += (size_t)index_counts[request];
        }
        return true;
    }
}

// Return values: 1 = gathered, 2 = this tree has no resident-column map and
// the caller may use its host fallback, 0 = an advertised map or execution was
// invalid. This distinction prevents a mismatched proof column list from
// silently falling back after resident admission.
int32_t stwo_zig_metal_tree_copy_queried_values(
    void *runtime_ptr,
    void *tree_ptr,
    const uint32_t *const *columns,
    const size_t *column_lengths,
    uint32_t column_count,
    const uint32_t *queries,
    uint32_t query_count,
    uint32_t *destination,
    size_t destination_words,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || tree_ptr == NULL || columns == NULL ||
        column_lengths == NULL || column_count == 0u || queries == NULL ||
        query_count == 0u || destination == NULL) return 0;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)tree_ptr;
        if (tree.residentColumnBuffers == nil || tree.residentColumnBuffers.count == 0u ||
            tree.residentColumnHostBegins == nil || tree.residentColumnWordCounts == nil ||
            tree.residentColumnWordOffsets == nil) return 2;
        uint32_t offset_word_bytes = tree.residentColumnOffsetWordBytes;
        if (tree.residentColumnBuffers.count != 1u || tree.logSize >= 31u ||
            (offset_word_bytes != sizeof(uint32_t) &&
             offset_word_bytes != sizeof(uint64_t)) ||
            tree.residentColumnHostBegins.length != (NSUInteger)column_count * sizeof(uintptr_t) ||
            tree.residentColumnWordCounts.length != (NSUInteger)column_count * sizeof(size_t) ||
            tree.residentColumnWordOffsets.length !=
                (NSUInteger)column_count * offset_word_bytes) {
            write_error(error_message, error_message_len,
                        @"Metal resident queried-value map shape mismatch");
            return 0;
        }
        if ((size_t)column_count > SIZE_MAX / (size_t)query_count ||
            destination_words < (size_t)column_count * (size_t)query_count) {
            write_error(error_message, error_message_len,
                        @"Metal queried-value output exceeds address space");
            return 0;
        }

        const uintptr_t *resident_begins = tree.residentColumnHostBegins.bytes;
        const size_t *resident_counts = tree.residentColumnWordCounts.bytes;
        const uint32_t *resident_narrow_offsets = offset_word_bytes == sizeof(uint32_t)
            ? tree.residentColumnWordOffsets.bytes : NULL;
        const uint64_t *resident_wide_offsets = offset_word_bytes == sizeof(uint64_t)
            ? tree.residentColumnWordOffsets.bytes : NULL;
        id<MTLBuffer> source = tree.residentColumnBuffers[0];
        size_t source_words = source.length / sizeof(uint32_t);
        NSMutableData *log_data =
            [NSMutableData dataWithLength:(NSUInteger)column_count * sizeof(uint32_t)];
        NSMutableData *offset_data =
            [NSMutableData dataWithLength:(NSUInteger)column_count * offset_word_bytes];
        NSMutableData *matched_data =
            [NSMutableData dataWithLength:(NSUInteger)column_count * sizeof(uint8_t)];
        if (log_data == nil || offset_data == nil || matched_data == nil) {
            write_error(error_message, error_message_len,
                        @"Metal queried-value metadata allocation failed");
            return 0;
        }
        uint32_t *logs = log_data.mutableBytes;
        uint32_t *narrow_offsets = offset_word_bytes == sizeof(uint32_t)
            ? offset_data.mutableBytes : NULL;
        uint64_t *wide_offsets = offset_word_bytes == sizeof(uint64_t)
            ? offset_data.mutableBytes : NULL;
        uint8_t *matched = matched_data.mutableBytes;
        NSArray<StwoZigMetalTree *> *single_tree = @[ tree ];
        for (uint32_t column = 0u; column < column_count; ++column) {
            size_t words = column_lengths[column];
            uint32_t resident = column_count;
            for (uint32_t candidate = 0u; candidate < column_count; ++candidate) {
                if (matched[candidate] == 0u &&
                    (uintptr_t)columns[column] == resident_begins[candidate] &&
                    words == resident_counts[candidate]) {
                    resident = candidate;
                    break;
                }
            }
            uint64_t resident_offset = resident == column_count ? 0u :
                (offset_word_bytes == sizeof(uint64_t)
                    ? resident_wide_offsets[resident]
                    : (uint64_t)resident_narrow_offsets[resident]);
            if (resident == column_count || words < 2u ||
                (words & (words - 1u)) != 0u ||
                resident_offset > (uint64_t)source_words ||
                (uint64_t)words > (uint64_t)source_words - resident_offset) {
                write_error(error_message, error_message_len,
                            @"Metal queried-value columns do not match the committed tree");
                return 0;
            }
            StwoZigResidentColumnBinding binding = {0};
            if (!stwo_zig_tree_resident_column(
                    single_tree, columns[column], words, &binding) ||
                binding.buffer != source ||
                binding.wordOffset != (size_t)resident_offset ||
                binding.availableWords != words) {
                write_error(error_message, error_message_len,
                            @"Metal queried-value residency resolver disagrees with the committed tree");
                return 0;
            }
            matched[resident] = 1u;
            if (offset_word_bytes == sizeof(uint64_t))
                wide_offsets[column] = resident_offset;
            else
                narrow_offsets[column] = (uint32_t)resident_offset;
            uint32_t log_size = (uint32_t)__builtin_ctzll((unsigned long long)words);
            if (log_size > tree.logSize) {
                write_error(error_message, error_message_len,
                            @"Metal queried-value column log exceeds the tree");
                return 0;
            }
            logs[column] = log_size;
        }
        uint32_t query_limit = 1u << tree.logSize;
        for (uint32_t query = 0u; query < query_count; ++query) {
            if (queries[query] >= query_limit) {
                write_error(error_message, error_message_len,
                            @"Metal queried-value position exceeds the tree");
                return 0;
            }
        }

        id<MTLBuffer> offsets_buffer = [runtime.device
            newBufferWithBytes:offset_data.bytes
            length:(NSUInteger)column_count * offset_word_bytes
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> logs_buffer = [runtime.device
            newBufferWithBytes:logs
            length:(NSUInteger)column_count * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> queries_buffer = [runtime.device
            newBufferWithBytes:queries
            length:(NSUInteger)query_count * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> output = [runtime.device
            newBufferWithLength:(NSUInteger)column_count * (NSUInteger)query_count * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (offsets_buffer == nil || logs_buffer == nil || queries_buffer == nil ||
            output == nil || command == nil || encoder == nil) {
            write_error(error_message, error_message_len,
                        @"Metal queried-value command allocation failed");
            return 0;
        }
        [encoder setComputePipelineState:offset_word_bytes == sizeof(uint64_t)
            ? runtime.decommitGatherTreeValuesResidentWide
            : runtime.decommitGatherTreeValuesResident];
        [encoder setBuffer:source offset:0u atIndex:0];
        [encoder setBuffer:offsets_buffer offset:0u atIndex:1];
        [encoder setBuffer:logs_buffer offset:0u atIndex:2];
        [encoder setBytes:&column_count length:sizeof(column_count) atIndex:3];
        uint32_t lifting_log = tree.logSize;
        [encoder setBytes:&lifting_log length:sizeof(lifting_log) atIndex:4];
        [encoder setBuffer:queries_buffer offset:0u atIndex:5];
        [encoder setBytes:&query_count length:sizeof(query_count) atIndex:6];
        [encoder setBuffer:output offset:0u atIndex:7];
        NSUInteger width = MIN((NSUInteger)query_count, 32u);
        NSUInteger height = MIN((NSUInteger)column_count, 8u);
        [encoder dispatchThreads:MTLSizeMake(query_count, column_count, 1u)
            threadsPerThreadgroup:MTLSizeMake(width, height, 1u)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?: @"Metal queried-value gather failed");
            return 0;
        }
        memcpy(destination, output.contents,
               (size_t)column_count * (size_t)query_count * sizeof(uint32_t));
        return 1;
    }
}
