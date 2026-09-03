// FRI fold-to-next-tree transaction. Included after the runtime and tree
// Objective-C owners are declared in the parent translation unit.

void *stwo_zig_metal_fri_fold_line_and_commit(
    void *runtime_ptr, void *source_ptr, uint32_t source_count,
    const uint32_t *inverse_x, uint32_t inverse_x_count,
    const uint32_t *alphas, uint32_t fold_count, void *destination_ptr,
    void *coordinates_ptr,
    const uint32_t *leaf_seed, const uint32_t *node_seed,
    uint32_t domain_prefix_bytes, uint32_t hash_family, StwoZigCommandEpochStats *stats,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || source_ptr == NULL || destination_ptr == NULL || coordinates_ptr == NULL ||
        inverse_x == NULL || alphas == NULL || leaf_seed == NULL || node_seed == NULL ||
        stats == NULL || source_count < 2u || (source_count & (source_count - 1u)) != 0u ||
        fold_count == 0u || fold_count >= 31u ||
        (domain_prefix_bytes != 0u && domain_prefix_bytes != 64u) ||
        !stwo_zig_valid_commitment_hash_family_v1(hash_family)) {
        write_error(error_message, error_message_len, @"Invalid Metal FRI fold + commitment arguments");
        return NULL;
    }
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> source = (__bridge id<MTLBuffer>)source_ptr;
        id<MTLBuffer> destination = (__bridge id<MTLBuffer>)destination_ptr;
        id<MTLBuffer> coordinates = (__bridge id<MTLBuffer>)coordinates_ptr;
        uint32_t final_count = source_count >> fold_count;
        if (final_count == 0u || source.length < (NSUInteger)source_count * 16u ||
            destination.length < (NSUInteger)final_count * 16u ||
            coordinates.length < (NSUInteger)final_count * 16u) {
            write_error(error_message, error_message_len, @"Metal FRI resident buffers have invalid lengths");
            return NULL;
        }

        uint64_t expected_inverse_count = 0u;
        uint32_t stage_count = source_count;
        for (uint32_t step = 0u; step < fold_count; ++step) {
            stage_count >>= 1u;
            expected_inverse_count += stage_count;
        }
        if (expected_inverse_count != inverse_x_count) {
            write_error(error_message, error_message_len, @"Metal FRI inverse-coordinate shape mismatch");
            return NULL;
        }

        id<MTLBuffer> inverse_buffer = [runtime.device newBufferWithBytes:inverse_x
            length:(NSUInteger)inverse_x_count * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> alpha_buffer = [runtime.device newBufferWithBytes:alphas
            length:(NSUInteger)fold_count * 4u * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> leaf_seed_buffer = [runtime.device newBufferWithBytes:leaf_seed
            length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> node_seed_buffer = [runtime.device newBufferWithBytes:node_seed
            length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        if (inverse_buffer == nil || alpha_buffer == nil ||
            leaf_seed_buffer == nil || node_seed_buffer == nil) {
            write_error(error_message, error_message_len, @"Metal FRI fold + commitment allocation failed");
            return NULL;
        }

        uint32_t tree_log_size = 0u;
        for (uint32_t count = final_count; count > 1u; count >>= 1u) tree_log_size += 1u;
        NSMutableArray<id<MTLBuffer>> *layers = [NSMutableArray arrayWithCapacity:tree_log_size + 1u];
        uint32_t layer_count = final_count;
        for (uint32_t level = 0u; level <= tree_log_size; ++level) {
            MTLResourceOptions storage = level == tree_log_size || runtime.device.hasUnifiedMemory
                ? MTLResourceStorageModeShared
                : MTLResourceStorageModePrivate;
            id<MTLBuffer> layer = [runtime.device newBufferWithLength:(NSUInteger)layer_count * 32u
                options:storage];
            if (layer == nil) {
                write_error(error_message, error_message_len, @"Metal FRI tree layer allocation failed");
                return NULL;
            }
            [layers addObject:layer];
            layer_count >>= 1u;
        }

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        if (command == nil) {
            write_error(error_message, error_message_len, @"Metal FRI command allocation failed");
            return NULL;
        }
        NSMutableArray<id<MTLBuffer>> *intermediates = [NSMutableArray arrayWithCapacity:fold_count - 1u];
        id<MTLBuffer> fold_source = source;
        uint32_t input_count = source_count;
        NSUInteger inverse_byte_offset = 0u;
        uint64_t compute_encoders = 0u, dispatches = 0u;
        for (uint32_t step = 0u; step < fold_count; ++step) {
            uint32_t output_count = input_count >> 1u;
            id<MTLBuffer> fold_destination = destination;
            if (step + 1u != fold_count) {
                fold_destination = [runtime.device newBufferWithLength:(NSUInteger)output_count * 16u
                    options:MTLResourceStorageModePrivate];
                if (fold_destination == nil) {
                    write_error(error_message, error_message_len, @"Metal FRI intermediate allocation failed");
                    return NULL;
                }
                [intermediates addObject:fold_destination];
            }
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            if (encoder == nil) {
                write_error(error_message, error_message_len, @"Metal FRI fold encoder allocation failed");
                return NULL;
            }
            [encoder setComputePipelineState:runtime.friFoldLine];
            bind_fri_line_kernel(
                encoder, fold_source, inverse_byte_offset, inverse_buffer,
                alpha_buffer, (NSUInteger)step * 16u, fold_destination, output_count,
                fold_destination, fold_destination, inverse_buffer, 0u, 0u
            );
            NSUInteger width = MIN(runtime.friFoldLine.maxTotalThreadsPerThreadgroup,
                                   runtime.friFoldLine.threadExecutionWidth * 8u);
            [encoder dispatchThreads:MTLSizeMake(output_count, 1u, 1u)
                threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            [encoder endEncoding];
            compute_encoders += 1u;
            dispatches += 1u;
            inverse_byte_offset += (NSUInteger)output_count * sizeof(uint32_t);
            fold_source = fold_destination;
            input_count = output_count;
        }

        id<MTLComputeCommandEncoder> conversion = [command computeCommandEncoder];
        if (conversion == nil) {
            write_error(error_message, error_message_len, @"Metal FRI coordinate encoder allocation failed");
            return NULL;
        }
        [conversion setComputePipelineState:runtime.qm31ToCoordinates];
        bind_qm31_coordinate_kernel(
            conversion, destination, coordinates, final_count,
            coordinates, destination, 0u, 0u
        );
        NSUInteger conversion_width = MIN(runtime.qm31ToCoordinates.maxTotalThreadsPerThreadgroup,
                                          runtime.qm31ToCoordinates.threadExecutionWidth * 8u);
        [conversion dispatchThreads:MTLSizeMake(final_count, 1u, 1u)
             threadsPerThreadgroup:MTLSizeMake(conversion_width, 1u, 1u)];
        [conversion endEncoding];
        compute_encoders += 1u;
        dispatches += 1u;

        uint32_t column_offsets[4] = { 0u, final_count, 2u * final_count, 3u * final_count };
        uint32_t column_logs[4] = { tree_log_size, tree_log_size, tree_log_size, tree_log_size };
        uint32_t column_count = 4u;
        id<MTLComputeCommandEncoder> leaves = [command computeCommandEncoder];
        if (leaves == nil) {
            write_error(error_message, error_message_len, @"Metal FRI leaf encoder allocation failed");
            return NULL;
        }
        id<MTLComputePipelineState> leaves_pipeline =
            stwo_zig_commitment_leaves_pipeline(runtime, hash_family);
        id<MTLComputePipelineState> parents_pipeline =
            stwo_zig_commitment_parents_pipeline(runtime, hash_family);
        if (leaves_pipeline == nil || parents_pipeline == nil) return NULL;
        [leaves setComputePipelineState:leaves_pipeline];
        [leaves setBuffer:coordinates offset:0u atIndex:0];
        [leaves setBytes:column_offsets length:sizeof(column_offsets) atIndex:1];
        [leaves setBytes:column_logs length:sizeof(column_logs) atIndex:2];
        [leaves setBuffer:layers[0] offset:0u atIndex:3];
        [leaves setBytes:&column_count length:sizeof(column_count) atIndex:4];
        [leaves setBytes:&tree_log_size length:sizeof(tree_log_size) atIndex:5];
        [leaves setBuffer:leaf_seed_buffer offset:0u atIndex:6];
        [leaves setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:7];
        NSUInteger leaf_width = MIN(leaves_pipeline.maxTotalThreadsPerThreadgroup,
                                    leaves_pipeline.threadExecutionWidth * 8u);
        [leaves dispatchThreads:MTLSizeMake(final_count, 1u, 1u)
             threadsPerThreadgroup:MTLSizeMake(leaf_width, 1u, 1u)];
        [leaves endEncoding];
        compute_encoders += 1u;
        dispatches += 1u;

        uint32_t parent_count = final_count >> 1u;
        for (uint32_t level = 1u; level <= tree_log_size; ++level) {
            id<MTLComputeCommandEncoder> parent = [command computeCommandEncoder];
            if (parent == nil) {
                write_error(error_message, error_message_len, @"Metal FRI parent encoder allocation failed");
                return NULL;
            }
            [parent setComputePipelineState:parents_pipeline];
            [parent setBuffer:layers[level - 1u] offset:0u atIndex:0];
            [parent setBuffer:layers[level] offset:0u atIndex:1];
            [parent setBytes:&parent_count length:sizeof(parent_count) atIndex:2];
            [parent setBuffer:node_seed_buffer offset:0u atIndex:3];
            [parent setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:4];
            NSUInteger width = MIN(parents_pipeline.maxTotalThreadsPerThreadgroup,
                                   parents_pipeline.threadExecutionWidth * 8u);
            [parent dispatchThreads:MTLSizeMake(parent_count, 1u, 1u)
                 threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            [parent endEncoding];
            compute_encoders += 1u;
            dispatches += 1u;
            parent_count >>= 1u;
        }

        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?: @"Metal FRI fold + commitment failed");
            return NULL;
        }
        double gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        *stats = (StwoZigCommandEpochStats){
            .command_buffers = 1u,
            .wait_count = 1u,
            .intermediate_wait_count = 0u,
            .compute_encoders = compute_encoders,
            .blit_encoders = 0u,
            .dispatches = dispatches,
            .gpu_milliseconds = gpu_milliseconds,
        };
        StwoZigMetalTree *tree = [StwoZigMetalTree new];
        tree.runtimeOwner = runtime;
        tree.layers = layers;
        tree.rootReadback = layers.lastObject;
        tree.logSize = tree_log_size;
        tree.gpuMilliseconds = gpu_milliseconds;
        return (__bridge_retained void *)tree;
    }
}

bool stwo_zig_metal_fri_line_cascade(
    void *runtime_ptr, void *source_ptr, uint32_t source_count,
    void *circle_source_ptr, const uint32_t *circle_alpha,
    void *prior_channel_buffer_ptr, uint32_t prior_state_word_offset,
    uint32_t prior_alpha_word_offset,
    const uint32_t *inverse_x, uint32_t inverse_x_count,
    uint32_t domain_initial_index, uint32_t domain_step_size,
    void *const *coordinate_ptrs, void *final_destination_ptr,
    uint32_t fri_layer_count,
    const uint32_t *leaf_seed, const uint32_t *node_seed,
    uint32_t domain_prefix_bytes, uint32_t *channel_state,
    void **tree_outputs, uint32_t *inverse_generation_mask,
    StwoZigCommandEpochStats *stats,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || source_ptr == NULL ||
        (circle_source_ptr == NULL &&
            (circle_alpha != NULL || prior_channel_buffer_ptr != NULL)) ||
        (circle_source_ptr != NULL &&
            ((circle_alpha == NULL) == (prior_channel_buffer_ptr == NULL))) ||
        coordinate_ptrs == NULL || final_destination_ptr == NULL ||
        leaf_seed == NULL || node_seed == NULL || channel_state == NULL ||
        tree_outputs == NULL || stats == NULL ||
        source_count < 2u ||
        (source_count & (source_count - 1u)) != 0u || fri_layer_count == 0u ||
        fri_layer_count >= 31u || source_count >> fri_layer_count == 0u ||
        (domain_prefix_bytes != 0u && domain_prefix_bytes != 64u)) {
        write_error(error_message, error_message_len, @"Invalid Metal FRI cascade arguments");
        return false;
    }

    uint64_t expected_inverse_count = 0u;
    uint32_t count = source_count;
    for (uint32_t stage = 0u; stage < fri_layer_count; ++stage) {
        count >>= 1u;
        expected_inverse_count += count;
    }
    if (expected_inverse_count != inverse_x_count) {
        write_error(error_message, error_message_len, @"Metal FRI cascade inverse-coordinate shape mismatch");
        return false;
    }

    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> initial_source = (__bridge id<MTLBuffer>)source_ptr;
        id<MTLBuffer> circle_source = circle_source_ptr == NULL
            ? nil
            : (__bridge id<MTLBuffer>)circle_source_ptr;
        id<MTLBuffer> prior_channel_buffer = prior_channel_buffer_ptr == NULL
            ? nil
            : (__bridge id<MTLBuffer>)prior_channel_buffer_ptr;
        id<MTLBuffer> final_destination = (__bridge id<MTLBuffer>)final_destination_ptr;
        uint32_t final_count = source_count >> fri_layer_count;
        if (initial_source.length < (NSUInteger)source_count * 16u ||
            (circle_source != nil && circle_source.length < (NSUInteger)source_count * 32u) ||
            (prior_channel_buffer != nil &&
                (prior_state_word_offset > UINT32_MAX - 10u ||
                 prior_alpha_word_offset > UINT32_MAX - 4u ||
                 prior_channel_buffer.length <
                    (NSUInteger)(MAX(prior_state_word_offset + 10u,
                                    prior_alpha_word_offset + 4u)) * sizeof(uint32_t))) ||
            final_destination.length < (NSUInteger)final_count * 16u) {
            write_error(error_message, error_message_len, @"Metal FRI cascade evaluation buffer is too small");
            return false;
        }

        id<MTLBuffer> circle_inverse_buffer = nil;
        bool build_circle_inverse_cache = false;
        if (circle_source != nil) {
            @synchronized(runtime) {
                if (runtime.friCircleInverseCache != nil &&
                    runtime.friCircleInverseCacheCount == source_count &&
                    runtime.friCircleInverseCacheInitialIndex == domain_initial_index &&
                    runtime.friCircleInverseCacheStepSize == domain_step_size) {
                    circle_inverse_buffer = runtime.friCircleInverseCache;
                }
            }
            if (circle_inverse_buffer == nil) {
                circle_inverse_buffer = [runtime.device newBufferWithLength:
                    (NSUInteger)source_count * sizeof(uint32_t)
                    options:MTLResourceStorageModePrivate];
                build_circle_inverse_cache = true;
            }
            if (circle_inverse_buffer == nil) {
                write_error(error_message, error_message_len, @"Metal FRI circle inverse allocation failed");
                return false;
            }
        }

        id<MTLBuffer> inverse_buffer = nil;
        bool build_inverse_cache = false;
        if (inverse_x == NULL) {
            @synchronized(runtime) {
                if (runtime.friLineInverseCache != nil &&
                    runtime.friLineInverseCacheSourceCount == source_count &&
                    runtime.friLineInverseCacheLayerCount == fri_layer_count &&
                    runtime.friLineInverseCacheInitialIndex == domain_initial_index &&
                    runtime.friLineInverseCacheStepSize == domain_step_size) {
                    inverse_buffer = runtime.friLineInverseCache;
                }
            }
            if (inverse_buffer == nil) {
                inverse_buffer = [runtime.device newBufferWithLength:
                    (NSUInteger)inverse_x_count * sizeof(uint32_t)
                    options:MTLResourceStorageModePrivate];
                build_inverse_cache = true;
            }
        } else {
            inverse_buffer = [runtime.device newBufferWithBytes:inverse_x
                length:(NSUInteger)inverse_x_count * sizeof(uint32_t)
                options:MTLResourceStorageModeShared];
        }
        const uint32_t transcript_state_base = 0u;
        const uint32_t transcript_root_base = 16u;
        const uint32_t transcript_alpha_base = transcript_root_base + fri_layer_count * 8u;
        const uint32_t transcript_words = transcript_alpha_base + fri_layer_count * 4u;
        // A single offset-addressed arena makes every tree tail eligible for
        // the threadgroup-local parent reduction and avoids one buffer object
        // per logical Merkle level. Keep every level 256-byte aligned.
        uint64_t arena_words = ((uint64_t)transcript_words + 63u) & ~63u;
        count = source_count;
        for (uint32_t stage = 0u; stage < fri_layer_count; ++stage) {
            uint32_t layer_nodes = count;
            while (layer_nodes > 1u) {
                arena_words = (arena_words + 63u) & ~63u;
                arena_words += (uint64_t)layer_nodes * 8u;
                layer_nodes >>= 1u;
            }
            count >>= 1u;
        }
        if (arena_words > UINT32_MAX || arena_words > SIZE_MAX / sizeof(uint32_t)) {
            write_error(error_message, error_message_len, @"Metal FRI cascade arena is too large");
            return false;
        }
        id<MTLBuffer> transcript_arena = [runtime.device newBufferWithLength:
            (NSUInteger)arena_words * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> leaf_seed_buffer = [runtime.device newBufferWithBytes:leaf_seed
            length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> node_seed_buffer = [runtime.device newBufferWithBytes:node_seed
            length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        if (inverse_buffer == nil || transcript_arena == nil ||
            leaf_seed_buffer == nil || node_seed_buffer == nil) {
            write_error(error_message, error_message_len, @"Metal FRI cascade parameter allocation failed");
            return false;
        }
        memset(transcript_arena.contents, 0, (NSUInteger)transcript_words * sizeof(uint32_t));
        if (prior_channel_buffer == nil)
            memcpy(transcript_arena.contents, channel_state, 10u * sizeof(uint32_t));

        NSMutableArray<StwoZigMetalTree *> *trees =
            [NSMutableArray arrayWithCapacity:fri_layer_count];
        NSMutableArray<id<MTLBuffer>> *destinations =
            [NSMutableArray arrayWithCapacity:fri_layer_count];
        uint32_t arena_cursor = (transcript_words + 63u) & ~63u;
        count = source_count;
        for (uint32_t stage = 0u; stage < fri_layer_count; ++stage) {
            id<MTLBuffer> coordinates = (__bridge id<MTLBuffer>)coordinate_ptrs[stage];
            if (coordinates == nil || coordinates.length < (NSUInteger)count * 16u) {
                write_error(error_message, error_message_len, @"Metal FRI cascade coordinate buffer is too small");
                return false;
            }

            uint32_t tree_log_size = 0u;
            for (uint32_t nodes = count; nodes > 1u; nodes >>= 1u) tree_log_size += 1u;
            NSMutableArray<id<MTLBuffer>> *layers =
                [NSMutableArray arrayWithCapacity:tree_log_size + 1u];
            NSMutableData *layer_word_offsets_data =
                [NSMutableData dataWithLength:(tree_log_size + 1u) * sizeof(uint32_t)];
            NSMutableData *layer_word_lengths_data =
                [NSMutableData dataWithLength:(tree_log_size + 1u) * sizeof(uint32_t)];
            uint32_t *layer_word_offsets = layer_word_offsets_data.mutableBytes;
            uint32_t *layer_word_lengths = layer_word_lengths_data.mutableBytes;
            const uint32_t root_word_offset = transcript_root_base + stage * 8u;
            uint32_t layer_nodes = count;
            for (uint32_t level = 0u; level <= tree_log_size; ++level) {
                [layers addObject:transcript_arena];
                if (level == tree_log_size) {
                    layer_word_offsets[level] = root_word_offset;
                } else {
                    arena_cursor = (arena_cursor + 63u) & ~63u;
                    layer_word_offsets[level] = arena_cursor;
                    arena_cursor += layer_nodes * 8u;
                }
                layer_word_lengths[level] = layer_nodes * 8u;
                layer_nodes >>= 1u;
            }
            StwoZigMetalTree *tree = [StwoZigMetalTree new];
            tree.runtimeOwner = runtime;
            tree.layers = layers;
            tree.layerWordOffsets = layer_word_offsets_data;
            tree.layerWordLengths = layer_word_lengths_data;
            tree.rootReadback = transcript_arena;
            tree.rootReadbackWordOffset = root_word_offset;
            tree.logSize = tree_log_size;
            [trees addObject:tree];

            uint32_t destination_count = count >> 1u;
            id<MTLBuffer> destination = final_destination;
            if (stage + 1u != fri_layer_count) {
                destination = [runtime.device newBufferWithLength:(NSUInteger)destination_count * 16u
                    options:MTLResourceStorageModePrivate];
                if (destination == nil) {
                    write_error(error_message, error_message_len, @"Metal FRI cascade intermediate allocation failed");
                    return false;
                }
            }
            [destinations addObject:destination];
            count = destination_count;
        }
        if (arena_cursor != (uint32_t)arena_words) {
            write_error(error_message, error_message_len, @"Metal FRI cascade arena layout mismatch");
            return false;
        }

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        if (command == nil) {
            write_error(error_message, error_message_len, @"Metal FRI cascade command allocation failed");
            return false;
        }
        uint64_t compute_encoders = 1u, blit_encoders = 0u, dispatches = 0u;
        if (prior_channel_buffer != nil) {
            id<MTLBlitCommandEncoder> state_copy = [command blitCommandEncoder];
            if (state_copy == nil) {
                write_error(error_message, error_message_len, @"Metal FRI transcript transfer encoder failed");
                return false;
            }
            [state_copy copyFromBuffer:prior_channel_buffer
                          sourceOffset:(NSUInteger)prior_state_word_offset * sizeof(uint32_t)
                              toBuffer:transcript_arena
                     destinationOffset:0u
                                  size:10u * sizeof(uint32_t)];
            [state_copy endEncoding];
            blit_encoders += 1u;
        }
        if (circle_source != nil) {
            id<MTLComputeCommandEncoder> circle_encoder = [command computeCommandEncoder];
            if (circle_encoder == nil) {
                write_error(error_message, error_message_len, @"Metal FRI circle cascade encoder failed");
                return false;
            }
            if (build_circle_inverse_cache) {
                encode_fri_inverse_domain(
                    runtime, circle_encoder, circle_inverse_buffer, 0u, source_count,
                    domain_initial_index, domain_step_size, 2u
                );
                [circle_encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
                dispatches += 1u;
            }
            [circle_encoder setComputePipelineState:runtime.friFoldCircle];
            [circle_encoder setBuffer:circle_source offset:0u atIndex:0];
            [circle_encoder setBuffer:circle_inverse_buffer offset:0u atIndex:1];
            if (prior_channel_buffer != nil) {
                [circle_encoder setBuffer:prior_channel_buffer
                                   offset:(NSUInteger)prior_alpha_word_offset * sizeof(uint32_t)
                                 atIndex:2];
            } else {
                [circle_encoder setBytes:circle_alpha length:4u * sizeof(uint32_t) atIndex:2];
            }
            [circle_encoder setBuffer:initial_source offset:0u atIndex:3];
            [circle_encoder setBytes:&source_count length:sizeof(source_count) atIndex:4];
            NSUInteger circle_width = MIN(
                runtime.friFoldCircle.maxTotalThreadsPerThreadgroup,
                runtime.friFoldCircle.threadExecutionWidth * 8u
            );
            [circle_encoder dispatchThreads:MTLSizeMake(source_count, 1u, 1u)
                   threadsPerThreadgroup:MTLSizeMake(circle_width, 1u, 1u)];
            [circle_encoder endEncoding];
            compute_encoders += 1u;
            dispatches += 1u;
        }
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (encoder == nil) {
            write_error(error_message, error_message_len, @"Metal FRI cascade compute encoder failed");
            return false;
        }
        const uint32_t disabled_transcript_config[3] = {0u, 0u, 0u};

        if (build_inverse_cache) {
            uint32_t domain_count = source_count;
            uint32_t current_initial = domain_initial_index;
            uint32_t current_step = domain_step_size;
            NSUInteger domain_offset = 0u;
            for (uint32_t stage = 0u; stage < fri_layer_count; ++stage) {
                uint32_t value_count = domain_count >> 1u;
                encode_fri_inverse_domain(
                    runtime, encoder, inverse_buffer, domain_offset, value_count,
                    current_initial, current_step, 1u
                );
                dispatches += 1u;
                domain_offset += (NSUInteger)value_count * sizeof(uint32_t);
                domain_count = value_count;
                current_initial = (current_initial << 1u) & 0x7fffffffu;
                current_step = (current_step << 1u) & 0x7fffffffu;
            }
            [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        }

        id<MTLBuffer> initial_coordinates = (__bridge id<MTLBuffer>)coordinate_ptrs[0];
        StwoZigMetalTree *initial_tree = trees[0];
        [encoder setComputePipelineState:runtime.qm31ToCoordinates];
        [encoder setBuffer:initial_source offset:0u atIndex:0];
        [encoder setBuffer:initial_coordinates offset:0u atIndex:1];
        [encoder setBytes:&source_count length:sizeof(source_count) atIndex:2];
        [encoder setBuffer:transcript_arena
            offset:(NSUInteger)tree_layer_word_offset(initial_tree, 0u) * sizeof(uint32_t)
            atIndex:3];
        [encoder setBuffer:leaf_seed_buffer offset:0u atIndex:4];
        [encoder setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:5];
        uint32_t write_initial_leaf = 1u;
        [encoder setBytes:&write_initial_leaf length:sizeof(write_initial_leaf) atIndex:6];
        NSUInteger initial_width = MIN(runtime.qm31ToCoordinates.maxTotalThreadsPerThreadgroup,
                                       runtime.qm31ToCoordinates.threadExecutionWidth * 8u);
        [encoder dispatchThreads:MTLSizeMake(source_count, 1u, 1u)
             threadsPerThreadgroup:MTLSizeMake(initial_width, 1u, 1u)];
        [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        dispatches += 1u;

        id<MTLBuffer> evaluation = initial_source;
        count = source_count;
        NSUInteger inverse_offset = 0u;
        NSUInteger tail_static_bytes = runtime.parentTailSparse.staticThreadgroupMemoryLength;
        NSUInteger tail_available_bytes = runtime.device.maxThreadgroupMemoryLength > tail_static_bytes
            ? runtime.device.maxThreadgroupMemoryLength - tail_static_bytes : 0u;
        uint32_t tail_capacity = (uint32_t)MIN((NSUInteger)256u,
            MIN(runtime.parentTailSparse.maxTotalThreadsPerThreadgroup,
                tail_available_bytes / (8u * sizeof(uint32_t))));
        for (uint32_t stage = 0u; stage < fri_layer_count; ++stage) {
            StwoZigMetalTree *tree = trees[stage];
            uint32_t tree_log_size = tree.logSize;

            uint32_t child_offsets[31], destination_offsets[31], parent_counts[31];
            uint32_t parent_count = count >> 1u;
            for (uint32_t level = 1u; level <= tree_log_size; ++level) {
                child_offsets[level - 1u] = tree_layer_word_offset(tree, level - 1u);
                destination_offsets[level - 1u] = tree_layer_word_offset(tree, level);
                parent_counts[level - 1u] = parent_count;
                parent_count >>= 1u;
            }

            uint32_t first_parent_level = 1u;
            if (tail_capacity >= 2u && parent_counts[0] > tail_capacity) {
                // Reduce independent bottom subtrees concurrently with the
                // existing tail kernel. 128 parent hashes need only 4 KiB of
                // scratch and leave the 256-thread upper-tail policy intact.
                uint32_t bottom_capacity = MIN(128u, tail_capacity);
                uint32_t bottom_width = 1u;
                while ((bottom_width << 1u) <= bottom_capacity) bottom_width <<= 1u;
                uint32_t bottom_levels = 1u;
                for (uint32_t width = bottom_width; width > 1u; width >>= 1u)
                    bottom_levels += 1u;
                uint32_t bottom_counts[31];
                uint32_t local_count = bottom_width;
                for (uint32_t level = 0u; level < bottom_levels; ++level) {
                    bottom_counts[level] = local_count;
                    local_count >>= 1u;
                }

                [encoder setComputePipelineState:runtime.parentTailSparse];
                [encoder setBuffer:transcript_arena offset:0u atIndex:0];
                [encoder setBytes:child_offsets
                    length:(NSUInteger)bottom_levels * sizeof(uint32_t) atIndex:1];
                [encoder setBytes:destination_offsets
                    length:(NSUInteger)bottom_levels * sizeof(uint32_t) atIndex:2];
                [encoder setBytes:bottom_counts
                    length:(NSUInteger)bottom_levels * sizeof(uint32_t) atIndex:3];
                [encoder setBytes:&bottom_levels length:sizeof(bottom_levels) atIndex:4];
                [encoder setBuffer:node_seed_buffer offset:0u atIndex:5];
                [encoder setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:6];
                [encoder setBytes:disabled_transcript_config
                    length:sizeof(disabled_transcript_config) atIndex:7];
                [encoder setThreadgroupMemoryLength:(NSUInteger)bottom_width * 8u * sizeof(uint32_t)
                    atIndex:0];
                [encoder dispatchThreadgroups:MTLSizeMake(parent_counts[0] / bottom_width, 1u, 1u)
                     threadsPerThreadgroup:MTLSizeMake(bottom_width, 1u, 1u)];
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
                dispatches += 1u;
                first_parent_level = bottom_levels + 1u;
            }

            uint32_t root_base = transcript_root_base + stage * 8u;
            uint32_t alpha_base = transcript_alpha_base + stage * 4u;
            bool fused_transcript = false;
            uint32_t tail_level = tree_log_size + 1u;
            for (uint32_t level = first_parent_level; level < tree_log_size; ++level) {
                if (parent_counts[level - 1u] <= tail_capacity) {
                    tail_level = level;
                    break;
                }
            }
            for (uint32_t level = first_parent_level; level < tail_level; ++level) {
                uint32_t level_index = level - 1u;
                [encoder setComputePipelineState:runtime.parents];
                [encoder setBuffer:transcript_arena
                    offset:(NSUInteger)child_offsets[level_index] * sizeof(uint32_t) atIndex:0];
                [encoder setBuffer:transcript_arena
                    offset:(NSUInteger)destination_offsets[level_index] * sizeof(uint32_t) atIndex:1];
                [encoder setBytes:&parent_counts[level_index] length:sizeof(uint32_t) atIndex:2];
                [encoder setBuffer:node_seed_buffer offset:0u atIndex:3];
                [encoder setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:4];
                NSUInteger parent_width = MIN(runtime.parents.maxTotalThreadsPerThreadgroup,
                                              runtime.parents.threadExecutionWidth * 8u);
                [encoder dispatchThreads:MTLSizeMake(parent_counts[level_index], 1u, 1u)
                     threadsPerThreadgroup:MTLSizeMake(parent_width, 1u, 1u)];
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
                dispatches += 1u;
            }
            if (tail_level <= tree_log_size) {
                uint32_t tail_index = tail_level - 1u;
                uint32_t tail_levels = tree_log_size - tail_index;
                uint32_t tail_width = parent_counts[tail_index];
                uint32_t last_tail_index = tail_index + tail_levels - 1u;
                fused_transcript = parent_counts[last_tail_index] == 1u &&
                    destination_offsets[last_tail_index] == root_base;
                uint32_t transcript_config[3] = {
                    transcript_state_base, alpha_base, fused_transcript ? 1u : 0u,
                };
                [encoder setComputePipelineState:runtime.parentTailSparse];
                [encoder setBuffer:transcript_arena offset:0u atIndex:0];
                [encoder setBytes:child_offsets + tail_index
                    length:(NSUInteger)tail_levels * sizeof(uint32_t) atIndex:1];
                [encoder setBytes:destination_offsets + tail_index
                    length:(NSUInteger)tail_levels * sizeof(uint32_t) atIndex:2];
                [encoder setBytes:parent_counts + tail_index
                    length:(NSUInteger)tail_levels * sizeof(uint32_t) atIndex:3];
                [encoder setBytes:&tail_levels length:sizeof(tail_levels) atIndex:4];
                [encoder setBuffer:node_seed_buffer offset:0u atIndex:5];
                [encoder setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:6];
                [encoder setBytes:transcript_config length:sizeof(transcript_config) atIndex:7];
                NSUInteger tail_scratch_width = MAX((NSUInteger)tail_width, (NSUInteger)16u);
                [encoder setThreadgroupMemoryLength:tail_scratch_width * 8u * sizeof(uint32_t)
                    atIndex:0];
                [encoder dispatchThreadgroups:MTLSizeMake(1u, 1u, 1u)
                     threadsPerThreadgroup:MTLSizeMake(
                         MAX((NSUInteger)tail_width, runtime.parentTailSparse.threadExecutionWidth),
                         1u, 1u)];
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
                dispatches += 1u;
            }

            if (!fused_transcript) {
                uint32_t source_words = 8u;
                [encoder setComputePipelineState:runtime.transcriptMixResident];
                [encoder setBuffer:transcript_arena offset:0u atIndex:0];
                [encoder setBytes:&transcript_state_base length:sizeof(transcript_state_base) atIndex:1];
                [encoder setBytes:&root_base length:sizeof(root_base) atIndex:2];
                [encoder setBytes:&source_words length:sizeof(source_words) atIndex:3];
                [encoder dispatchThreads:MTLSizeMake(1u, 1u, 1u)
                     threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
                dispatches += 1u;

                uint32_t felt_count = 1u;
                [encoder setComputePipelineState:runtime.transcriptDrawSecureResident];
                [encoder setBuffer:transcript_arena offset:0u atIndex:0];
                [encoder setBytes:&transcript_state_base length:sizeof(transcript_state_base) atIndex:1];
                [encoder setBytes:&alpha_base length:sizeof(alpha_base) atIndex:2];
                [encoder setBytes:&felt_count length:sizeof(felt_count) atIndex:3];
                [encoder dispatchThreads:MTLSizeMake(1u, 1u, 1u)
                     threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
                dispatches += 1u;
            }

            uint32_t destination_count = count >> 1u;
            id<MTLBuffer> destination = destinations[stage];
            uint32_t prepare_next = stage + 1u != fri_layer_count ? 1u : 0u;
            [encoder setComputePipelineState:runtime.friFoldLine];
            [encoder setBuffer:evaluation offset:0u atIndex:0];
            [encoder setBuffer:inverse_buffer offset:inverse_offset atIndex:1];
            [encoder setBuffer:transcript_arena
                offset:(NSUInteger)alpha_base * sizeof(uint32_t) atIndex:2];
            [encoder setBuffer:destination offset:0u atIndex:3];
            [encoder setBytes:&destination_count length:sizeof(destination_count) atIndex:4];
            if (prepare_next != 0u) {
                id<MTLBuffer> next_coordinates = (__bridge id<MTLBuffer>)coordinate_ptrs[stage + 1u];
                StwoZigMetalTree *next_tree = trees[stage + 1u];
                [encoder setBuffer:next_coordinates offset:0u atIndex:5];
                [encoder setBuffer:transcript_arena
                    offset:(NSUInteger)tree_layer_word_offset(next_tree, 0u) * sizeof(uint32_t)
                    atIndex:6];
                [encoder setBuffer:leaf_seed_buffer offset:0u atIndex:7];
                [encoder setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:8];
            } else {
                [encoder setBuffer:destination offset:0u atIndex:5];
                [encoder setBuffer:destination offset:0u atIndex:6];
                [encoder setBuffer:inverse_buffer offset:inverse_offset atIndex:7];
                [encoder setBytes:&domain_prefix_bytes length:sizeof(domain_prefix_bytes) atIndex:8];
            }
            [encoder setBytes:&prepare_next length:sizeof(prepare_next) atIndex:9];
            NSUInteger fold_width = MIN(runtime.friFoldLine.maxTotalThreadsPerThreadgroup,
                                        runtime.friFoldLine.threadExecutionWidth * 8u);
            [encoder dispatchThreads:MTLSizeMake(destination_count, 1u, 1u)
                 threadsPerThreadgroup:MTLSizeMake(fold_width, 1u, 1u)];
            if (stage + 1u != fri_layer_count)
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
            dispatches += 1u;

            inverse_offset += (NSUInteger)destination_count * sizeof(uint32_t);
            evaluation = destination;
            count = destination_count;
        }
        [encoder endEncoding];

        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?: @"Metal FRI cascade failed");
            return false;
        }
        if (build_circle_inverse_cache) {
            @synchronized(runtime) {
                runtime.friCircleInverseCache = circle_inverse_buffer;
                runtime.friCircleInverseCacheCount = source_count;
                runtime.friCircleInverseCacheInitialIndex = domain_initial_index;
                runtime.friCircleInverseCacheStepSize = domain_step_size;
            }
        }
        uint32_t *completed_state = (uint32_t *)transcript_arena.contents;
        if (completed_state[9] != 0u) {
            write_error(error_message, error_message_len, @"Metal FRI cascade transcript rejection limit exceeded");
            return false;
        }
        memcpy(channel_state, completed_state, 10u * sizeof(uint32_t));
        if (build_inverse_cache) {
            @synchronized(runtime) {
                runtime.friLineInverseCache = inverse_buffer;
                runtime.friLineInverseCacheSourceCount = source_count;
                runtime.friLineInverseCacheLayerCount = fri_layer_count;
                runtime.friLineInverseCacheInitialIndex = domain_initial_index;
                runtime.friLineInverseCacheStepSize = domain_step_size;
            }
        }

        double gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        *stats = (StwoZigCommandEpochStats){
            .command_buffers = 1u,
            .wait_count = 1u,
            .intermediate_wait_count = 0u,
            .compute_encoders = compute_encoders,
            .blit_encoders = blit_encoders,
            .dispatches = dispatches,
            .gpu_milliseconds = gpu_milliseconds,
        };
        for (uint32_t stage = 0u; stage < fri_layer_count; ++stage) {
            StwoZigMetalTree *tree = trees[stage];
            tree.gpuMilliseconds = gpu_milliseconds;
            tree_outputs[stage] = (__bridge_retained void *)tree;
        }
        if (inverse_generation_mask != NULL) {
            *inverse_generation_mask =
                (build_circle_inverse_cache ? 1u : 0u) |
                (build_inverse_cache ? 2u : 0u);
        }
        return true;
    }
}
