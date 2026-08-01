void *stwo_zig_metal_merkle_leaf_prepare(
    void *runtime_ptr, const uint32_t *column_offsets, const uint32_t *column_log_sizes,
    uint32_t column_count, uint32_t lifting_log_size, uint32_t destination_offset,
    const uint32_t *leaf_seed, uint32_t prefix_bytes,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || column_offsets == NULL || column_log_sizes == NULL || column_count == 0u ||
        lifting_log_size >= 31u || (destination_offset & 63u) != 0u || leaf_seed == NULL ||
        (prefix_bytes != 0u && prefix_bytes != 64u)) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        for (uint32_t column = 0; column < column_count; ++column) if (column_log_sizes[column] > lifting_log_size) return NULL;
        StwoZigMerkleLeafPlan *plan = [StwoZigMerkleLeafPlan new];
        plan.columnOffsets = [runtime.device newBufferWithBytes:column_offsets length:column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.columnLogSizes = [runtime.device newBufferWithBytes:column_log_sizes length:column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.leafSeed = [runtime.device newBufferWithBytes:leaf_seed length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.columnCount = column_count; plan.liftingLogSize = lifting_log_size; plan.destinationOffset = destination_offset;
        plan.prefixBytes = prefix_bytes;
        if (plan.columnOffsets == nil || plan.columnLogSizes == nil || plan.leafSeed == nil) {
            write_error(error_message, error_message_len, @"Metal Merkle leaf plan allocation failed"); return NULL;
        }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_merkle_leaf_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

bool stwo_zig_metal_merkle_leaf_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigMerkleLeafPlan *plan = (__bridge StwoZigMerkleLeafPlan *)plan_ptr;
        uint32_t leaf_count = 1u << plan.liftingLogSize;
        uint32_t column_count = plan.columnCount, lifting_log_size = plan.liftingLogSize;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.leaves]; [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBuffer:plan.columnOffsets offset:0 atIndex:1]; [encoder setBuffer:plan.columnLogSizes offset:0 atIndex:2];
        [encoder setBuffer:arena offset:(NSUInteger)plan.destinationOffset * sizeof(uint32_t) atIndex:3];
        [encoder setBytes:&column_count length:sizeof(column_count) atIndex:4];
        [encoder setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:5]; [encoder setBuffer:plan.leafSeed offset:0 atIndex:6];
        uint32_t prefix_bytes = plan.prefixBytes;
        [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:7];
        NSUInteger width = MIN((NSUInteger)256u, runtime.leaves.maxTotalThreadsPerThreadgroup);
        [encoder dispatchThreads:MTLSizeMake(leaf_count, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription); return false;
        }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_resident_merkle_prepare(
    void *runtime_ptr, const uint32_t *column_offsets, const uint32_t *column_log_sizes,
    uint32_t column_count, uint32_t lifting_log_size, const uint32_t *layer_offsets,
    uint32_t layer_count, const uint32_t *leaf_seed, const uint32_t *node_seed,
    uint32_t prefix_bytes,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || column_offsets == NULL || column_log_sizes == NULL || column_count == 0u ||
        lifting_log_size >= 31u || layer_offsets == NULL || layer_count < 2u ||
        layer_count > lifting_log_size + 1u || leaf_seed == NULL || node_seed == NULL ||
        (prefix_bytes != 0u && prefix_bytes != 64u)) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        for (uint32_t column = 0; column < column_count; ++column) {
            if (column_log_sizes[column] > lifting_log_size ||
                (column != 0u && column_log_sizes[column - 1u] > column_log_sizes[column])) return NULL;
        }
        for (uint32_t layer = 0; layer < layer_count; ++layer) if ((layer_offsets[layer] & 63u) != 0u) return NULL;
        StwoZigResidentMerklePlan *plan = [StwoZigResidentMerklePlan new];
        plan.columnOffsets = [runtime.device newBufferWithBytes:column_offsets length:column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.columnLogSizes = [runtime.device newBufferWithBytes:column_log_sizes length:column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.layerOffsets = [NSData dataWithBytes:layer_offsets length:layer_count * sizeof(uint32_t)];
        plan.leafSeed = [runtime.device newBufferWithBytes:leaf_seed length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.nodeSeed = [runtime.device newBufferWithBytes:node_seed length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.columnCount = column_count; plan.liftingLogSize = lifting_log_size; plan.layerCount = layer_count;
        plan.prefixBytes = prefix_bytes;
        if (plan.columnOffsets == nil || plan.columnLogSizes == nil || plan.layerOffsets == nil ||
            plan.leafSeed == nil || plan.nodeSeed == nil) {
            write_error(error_message, error_message_len, @"Resident Merkle plan allocation failed"); return NULL;
        }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_resident_merkle_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

void *stwo_zig_metal_commit_arena_alias(
    void *runtime_ptr, void *contents, size_t byte_length,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || contents == NULL || byte_length == 0u) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        size_t page_size = (size_t)getpagesize();
        if ((uintptr_t)contents % page_size != 0u || byte_length % page_size != 0u ||
            (uint64_t)byte_length > (uint64_t)runtime.device.maxBufferLength) {
            write_error(error_message, error_message_len,
                        @"Metal commitment arena must be page-aligned and device-addressable");
            return NULL;
        }
        id<MTLBuffer> arena = [runtime.device newBufferWithBytesNoCopy:contents
                                                            length:byte_length
                                                           options:MTLResourceStorageModeShared
                                                       deallocator:nil];
        if (arena == nil) {
            write_error(error_message, error_message_len,
                        @"Metal commitment arena no-copy binding failed");
            return NULL;
        }
        return (__bridge_retained void *)arena;
    }
}

void *stwo_zig_metal_resident_merkle_tree_from_completed_arena(
    void *runtime_ptr, void *epoch_ptr, void *arena_ptr, void *plan_ptr,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || epoch_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL)
        return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigResidentMerklePlan *plan = (__bridge StwoZigResidentMerklePlan *)plan_ptr;
        @synchronized(epoch) {
            if (epoch.runtime != runtime || epoch.arena != arena ||
                epoch.state != StwoZigCommandEpochStateCompleted ||
                epoch.command.status != MTLCommandBufferStatusCompleted ||
                epoch.residentMerklePlan != plan || epoch.residentMerkleAdopted ||
                epoch.computeEncoders == 0u || epoch.dispatches == 0u) {
                write_error(error_message, error_message_len,
                            @"Completed Metal Merkle arena lacks matching epoch provenance");
                return NULL;
            }
            // Consume provenance before allocating metadata so concurrent or
            // retrying callers can never publish two owners for one receipt.
            epoch.residentMerkleAdopted = YES;
        }
        if (plan.layerCount != plan.liftingLogSize + 1u || plan.layerCount == 0u ||
            plan.columnCount == 0u || plan.layerOffsets.length !=
                (NSUInteger)plan.layerCount * sizeof(uint32_t)) {
            write_error(error_message, error_message_len,
                        @"Completed Metal Merkle arena has invalid plan geometry");
            return NULL;
        }

        const uint32_t *layer_offsets = plan.layerOffsets.bytes;
        NSMutableArray<id<MTLBuffer>> *layers =
            [NSMutableArray arrayWithCapacity:plan.layerCount];
        NSMutableData *layer_lengths =
            [NSMutableData dataWithLength:(NSUInteger)plan.layerCount * sizeof(uint32_t)];
        if (layers == nil || layer_lengths == nil) {
            write_error(error_message, error_message_len,
                        @"Completed Metal Merkle metadata allocation failed");
            return NULL;
        }
        uint32_t *length_values = layer_lengths.mutableBytes;
        uint32_t hashes = 1u << plan.liftingLogSize;
        for (uint32_t level = 0u; level < plan.layerCount; ++level) {
            uint64_t layer_words = (uint64_t)hashes * 8u;
            uint64_t layer_end = (uint64_t)layer_offsets[level] + layer_words;
            if (layer_words > UINT32_MAX || layer_end > arena.length / sizeof(uint32_t)) {
                write_error(error_message, error_message_len,
                            @"Completed Metal Merkle layer exceeds its arena");
                return NULL;
            }
            [layers addObject:arena];
            length_values[level] = (uint32_t)layer_words;
            hashes >>= 1u;
        }

        const uint32_t *column_offsets = plan.columnOffsets.contents;
        const uint32_t *column_logs = plan.columnLogSizes.contents;
        NSMutableData *resident_begins =
            [NSMutableData dataWithLength:(NSUInteger)plan.columnCount * sizeof(uintptr_t)];
        NSMutableData *resident_counts =
            [NSMutableData dataWithLength:(NSUInteger)plan.columnCount * sizeof(size_t)];
        NSMutableData *resident_offsets =
            [NSMutableData dataWithLength:(NSUInteger)plan.columnCount * sizeof(uint32_t)];
        if (column_offsets == NULL || column_logs == NULL || resident_begins == nil ||
            resident_counts == nil || resident_offsets == nil) {
            write_error(error_message, error_message_len,
                        @"Completed Metal Merkle column map allocation failed");
            return NULL;
        }
        uintptr_t *begin_values = resident_begins.mutableBytes;
        size_t *count_values = resident_counts.mutableBytes;
        uint32_t *offset_values = resident_offsets.mutableBytes;
        for (uint32_t column = 0u; column < plan.columnCount; ++column) {
            size_t words = (size_t)1u << column_logs[column];
            if ((uint64_t)column_offsets[column] + words > arena.length / sizeof(uint32_t)) {
                write_error(error_message, error_message_len,
                            @"Completed Metal Merkle column exceeds its arena");
                return NULL;
            }
            begin_values[column] = (uintptr_t)arena.contents +
                (uintptr_t)column_offsets[column] * sizeof(uint32_t);
            count_values[column] = words;
            offset_values[column] = column_offsets[column];
        }

        StwoZigMetalTree *tree = [StwoZigMetalTree new];
        if (tree == nil) {
            write_error(error_message, error_message_len,
                        @"Completed Metal Merkle tree allocation failed");
            return NULL;
        }
        tree.runtimeOwner = runtime;
        tree.layers = layers;
        tree.layerWordOffsets = plan.layerOffsets;
        tree.layerWordLengths = layer_lengths;
        tree.rootReadback = arena;
        tree.rootReadbackWordOffset = layer_offsets[plan.layerCount - 1u];
        tree.logSize = plan.liftingLogSize;
        tree.gpuMilliseconds = (epoch.command.GPUEndTime - epoch.command.GPUStartTime) * 1000.0;
        tree.residentColumnBuffers = @[ arena ];
        tree.residentColumnHostBegins = resident_begins;
        tree.residentColumnWordCounts = resident_counts;
        tree.residentColumnWordOffsets = resident_offsets;
        return (__bridge_retained void *)tree;
    }
}

static bool encode_resident_merkle_prepared(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena, StwoZigResidentMerklePlan *plan,
    id<MTLCommandBuffer> command, uint64_t *compute_encoders, uint64_t *dispatches
) {
        if (runtime == nil || arena == nil || plan == nil || command == nil) return false;
        const uint32_t *layers = plan.layerOffsets.bytes;
        uint32_t leaf_count = 1u << plan.liftingLogSize;
        uint32_t column_count = plan.columnCount, lifting_log_size = plan.liftingLogSize;
        id<MTLComputeCommandEncoder> leaves = [command computeCommandEncoder];
        if (leaves == nil) return false;
        [leaves setComputePipelineState:runtime.leaves]; [leaves setBuffer:arena offset:0 atIndex:0];
        [leaves setBuffer:plan.columnOffsets offset:0 atIndex:1]; [leaves setBuffer:plan.columnLogSizes offset:0 atIndex:2];
        [leaves setBuffer:arena offset:(NSUInteger)layers[0] * sizeof(uint32_t) atIndex:3];
        [leaves setBytes:&column_count length:sizeof(column_count) atIndex:4];
        [leaves setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:5]; [leaves setBuffer:plan.leafSeed offset:0 atIndex:6];
        uint32_t prefix_bytes = plan.prefixBytes;
        [leaves setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:7];
        NSUInteger leaf_width = MIN((NSUInteger)256u, runtime.leaves.maxTotalThreadsPerThreadgroup);
        [leaves dispatchThreads:MTLSizeMake(leaf_count, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(leaf_width, 1u, 1u)];
        [leaves endEncoding];
        *compute_encoders += 1u; *dispatches += 1u;
        for (uint32_t level = 1u; level < plan.layerCount; ++level) {
            uint32_t child = layers[level - 1u], destination = layers[level], parent_count = leaf_count >> level;
            id<MTLComputeCommandEncoder> parents = [command computeCommandEncoder];
            if (parents == nil) return false;
            [parents setComputePipelineState:runtime.parentsSparse]; [parents setBuffer:arena offset:0 atIndex:0];
            [parents setBytes:&child length:sizeof(child) atIndex:1]; [parents setBytes:&destination length:sizeof(destination) atIndex:2];
            [parents setBytes:&parent_count length:sizeof(parent_count) atIndex:3]; [parents setBuffer:plan.nodeSeed offset:0 atIndex:4];
            [parents setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:5];
            NSUInteger width = MIN((NSUInteger)256u, runtime.parentsSparse.maxTotalThreadsPerThreadgroup);
            [parents dispatchThreads:MTLSizeMake(parent_count, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            [parents endEncoding];
            *compute_encoders += 1u; *dispatches += 1u;
        }
        return true;
}

bool stwo_zig_metal_resident_merkle_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigResidentMerklePlan *plan = (__bridge StwoZigResidentMerklePlan *)plan_ptr;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        uint64_t compute_encoders = 0u, dispatches = 0u;
        if (!encode_resident_merkle_prepared(runtime, arena, plan, command, &compute_encoders, &dispatches)) {
            write_error(error_message, error_message_len, @"Metal resident Merkle encoding failed"); return false;
        }
        [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription); return false;
        }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_command_epoch_create(
    void *runtime_ptr, void *arena_ptr, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        if (command == nil) {
            write_error(error_message, error_message_len, @"Metal command epoch allocation failed");
            return NULL;
        }
        StwoZigCommandEpoch *epoch = [StwoZigCommandEpoch new];
        epoch.runtime = runtime;
        epoch.arena = arena;
        epoch.command = command;
        epoch.retainedPlans = [NSMutableArray array];
        epoch.state = StwoZigCommandEpochStateEncoding;
        return (__bridge_retained void *)epoch;
    }
}

void stwo_zig_metal_command_epoch_destroy(void *epoch_ptr) {
    if (epoch_ptr == NULL) return;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge_transfer StwoZigCommandEpoch *)epoch_ptr;
        if (epoch.state == StwoZigCommandEpochStateSubmitted) {
            [epoch.command waitUntilCompleted];
        }
    }
}

static bool command_epoch_can_encode(
    StwoZigCommandEpoch *epoch, char *error_message, size_t error_message_len
) {
    if (epoch == nil || epoch.state != StwoZigCommandEpochStateEncoding) {
        write_error(error_message, error_message_len, @"Metal command epoch is not encoding");
        return false;
    }
    return true;
}

bool stwo_zig_metal_command_epoch_encode_circle_ifft(
    void *epoch_ptr, void *plan_ptr, char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (!command_epoch_can_encode(epoch, error_message, error_message_len)) return false;
        StwoZigCircleIfftPlan *plan = (__bridge StwoZigCircleIfftPlan *)plan_ptr;
        uint64_t compute_encoders = epoch.computeEncoders, dispatches = epoch.dispatches;
        if (!encode_circle_ifft_prepared(epoch.runtime, epoch.arena, plan, epoch.command,
                                         &compute_encoders, &dispatches)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len, @"Metal command epoch IFFT encoding failed");
            return false;
        }
        epoch.computeEncoders = compute_encoders; epoch.dispatches = dispatches;
        [epoch.retainedPlans addObject:plan];
        return true;
    }
}

bool stwo_zig_metal_command_epoch_encode_circle_lde(
    void *epoch_ptr, void *plan_ptr, char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (!command_epoch_can_encode(epoch, error_message, error_message_len)) return false;
        StwoZigCircleLdePlan *plan = (__bridge StwoZigCircleLdePlan *)plan_ptr;
        uint64_t compute_encoders = epoch.computeEncoders, dispatches = epoch.dispatches;
        if (!encode_circle_lde_prepared(epoch.runtime, epoch.arena, plan, epoch.command,
                                        &compute_encoders, &dispatches)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len, @"Metal command epoch LDE encoding failed");
            return false;
        }
        epoch.computeEncoders = compute_encoders; epoch.dispatches = dispatches;
        [epoch.retainedPlans addObject:plan];
        return true;
    }
}

bool stwo_zig_metal_command_epoch_encode_resident_merkle(
    void *epoch_ptr, void *plan_ptr, char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (!command_epoch_can_encode(epoch, error_message, error_message_len)) return false;
        if (epoch.residentMerklePlan != nil) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len,
                        @"Metal command epoch already has a resident Merkle plan");
            return false;
        }
        StwoZigResidentMerklePlan *plan = (__bridge StwoZigResidentMerklePlan *)plan_ptr;
        uint64_t compute_encoders = epoch.computeEncoders, dispatches = epoch.dispatches;
        if (!encode_resident_merkle_prepared(epoch.runtime, epoch.arena, plan, epoch.command,
                                              &compute_encoders, &dispatches)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len, @"Metal command epoch Merkle encoding failed");
            return false;
        }
        epoch.computeEncoders = compute_encoders; epoch.dispatches = dispatches;
        epoch.residentMerklePlan = plan;
        [epoch.retainedPlans addObject:plan];
        return true;
    }
}

bool stwo_zig_metal_command_epoch_encode_composition_lde(
    void *epoch_ptr, void *plan_ptr, char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (!command_epoch_can_encode(epoch, error_message, error_message_len)) return false;
        StwoZigCompositionLdePlan *plan = (__bridge StwoZigCompositionLdePlan *)plan_ptr;
        uint64_t compute_encoders = epoch.computeEncoders, dispatches = epoch.dispatches;
        if (!encode_composition_lde_counted(epoch.runtime, epoch.arena, plan, epoch.command,
                                             &compute_encoders, &dispatches)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len, @"Metal command epoch composition LDE encoding failed");
            return false;
        }
        epoch.computeEncoders = compute_encoders; epoch.dispatches = dispatches;
        [epoch.retainedPlans addObject:plan];
        return true;
    }
}

bool stwo_zig_metal_command_epoch_encode_arena_copy(
    void *epoch_ptr, void *plan_ptr, char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (!command_epoch_can_encode(epoch, error_message, error_message_len)) return false;
        StwoZigArenaCopyPlan *plan = (__bridge StwoZigArenaCopyPlan *)plan_ptr;
        uint64_t blit_encoders = epoch.blitEncoders;
        if (!encode_arena_copy_prepared(epoch.arena, plan, epoch.command, &blit_encoders,
                                        error_message, error_message_len)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            return false;
        }
        epoch.blitEncoders = blit_encoders;
        [epoch.retainedPlans addObject:plan];
        return true;
    }
}

bool stwo_zig_metal_command_epoch_encode_compact_leaf(
    void *epoch_ptr, const uint32_t *column_offsets, const uint32_t *column_logs, uint32_t column_count,
    uint32_t source_state_offset, uint32_t source_state_log, uint32_t destination_state_offset, uint32_t destination_log,
    uint32_t first_column, uint32_t is_final, uint32_t prefix_bytes, const uint32_t *leaf_seed,
    char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (!command_epoch_can_encode(epoch, error_message, error_message_len)) return false;
        uint64_t compute_encoders = epoch.computeEncoders, dispatches = epoch.dispatches;
        if (!encode_leaf_absorb_compact(
                epoch.runtime, epoch.arena, column_offsets, column_logs, column_count,
                source_state_offset, source_state_log, destination_state_offset, destination_log,
                first_column, is_final, prefix_bytes, leaf_seed, epoch.command,
                &compute_encoders, &dispatches)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len, @"Metal command epoch compact leaf encoding failed");
            return false;
        }
        epoch.computeEncoders = compute_encoders; epoch.dispatches = dispatches;
        return true;
    }
}

bool stwo_zig_metal_command_epoch_encode_merkle_parent_chain(
    void *epoch_ptr, void *plan_ptr, char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (!command_epoch_can_encode(epoch, error_message, error_message_len)) return false;
        StwoZigMerkleParentChain *plan = (__bridge StwoZigMerkleParentChain *)plan_ptr;
        uint64_t compute_encoders = epoch.computeEncoders, dispatches = epoch.dispatches;
        if (!encode_merkle_parent_chain_prepared(epoch.runtime, epoch.arena, plan, epoch.command,
                                                  &compute_encoders, &dispatches)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len, @"Metal command epoch parent-chain encoding failed");
            return false;
        }
        epoch.computeEncoders = compute_encoders; epoch.dispatches = dispatches;
        [epoch.retainedPlans addObject:plan];
        return true;
    }
}

bool stwo_zig_metal_command_epoch_submit(
    void *epoch_ptr, char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (epoch.state != StwoZigCommandEpochStateEncoding ||
            (epoch.computeEncoders == 0u && epoch.blitEncoders == 0u)) {
            write_error(error_message, error_message_len, @"Metal command epoch cannot be submitted");
            return false;
        }
        [epoch.command commit];
        epoch.state = StwoZigCommandEpochStateSubmitted;
        return true;
    }
}

bool stwo_zig_metal_command_epoch_wait(
    void *epoch_ptr, StwoZigCommandEpochStats *stats,
    char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL || stats == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (epoch.state != StwoZigCommandEpochStateSubmitted) {
            write_error(error_message, error_message_len, @"Metal command epoch is not submitted");
            return false;
        }
        [epoch.command waitUntilCompleted];
        if (epoch.command.status == MTLCommandBufferStatusError) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len,
                        epoch.command.error.localizedDescription ?: @"Metal command epoch failed");
            return false;
        }
        epoch.state = StwoZigCommandEpochStateCompleted;
        *stats = (StwoZigCommandEpochStats){
            .command_buffers = 1u,
            .wait_count = 1u,
            .intermediate_wait_count = 0u,
            .compute_encoders = epoch.computeEncoders,
            .blit_encoders = epoch.blitEncoders,
            .dispatches = epoch.dispatches,
            .gpu_milliseconds = (epoch.command.GPUEndTime - epoch.command.GPUStartTime) * 1000.0,
        };
        return true;
    }
}

static bool merkle_ranges_overlap(uint64_t lhs_start, uint64_t lhs_words,
                                  uint64_t rhs_start, uint64_t rhs_words) {
    return lhs_start < rhs_start + rhs_words && rhs_start < lhs_start + lhs_words;
}

static uint32_t merkle_parent_tail_start(
    const uint32_t *children, const uint32_t *destinations, const uint32_t *counts,
    uint32_t level_count, uint32_t capacity
) {
    if (capacity == 0u || level_count < 2u) return level_count;
    for (uint32_t candidate = 0u; candidate + 1u < level_count; ++candidate) {
        uint32_t first_count = counts[candidate];
        if (first_count > capacity || (first_count & (first_count - 1u)) != 0u) continue;
        bool eligible = true;
        for (uint32_t level = candidate + 1u; level < level_count; ++level) {
            if (children[level] != destinations[level - 1u] ||
                (uint64_t)counts[level] * 2u != counts[level - 1u]) {
                eligible = false;
                break;
            }
        }
        for (uint32_t lhs = candidate; eligible && lhs < level_count; ++lhs) {
            uint64_t lhs_words = (uint64_t)counts[lhs] * 8u;
            for (uint32_t rhs = lhs + 1u; rhs < level_count; ++rhs) {
                if (merkle_ranges_overlap(destinations[lhs], lhs_words,
                                          destinations[rhs], (uint64_t)counts[rhs] * 8u)) {
                    eligible = false;
                    break;
                }
            }
        }
        if (eligible) return candidate;
    }
    return level_count;
}

static uint32_t merkle_floor_power_of_two(uint32_t value) {
    if (value == 0u) return 0u;
    return 1u << (31u - (uint32_t)__builtin_clz(value));
}

static uint32_t merkle_parent_bottom_level_count(
    const uint32_t *children, const uint32_t *destinations, const uint32_t *counts,
    uint32_t level_count, uint32_t width, uint32_t tail_capacity
) {
    if (width < 2u || counts[0] <= tail_capacity || counts[0] % width != 0u) return 0u;
    uint32_t bottom_levels = 1u;
    for (uint32_t count = width; count > 1u; count >>= 1u) bottom_levels += 1u;
    if (level_count < bottom_levels) return 0u;

    uint64_t initial_child_start = children[0];
    uint64_t initial_child_words = (uint64_t)counts[0] * 16u;
    for (uint32_t level = 0u; level < bottom_levels; ++level) {
        uint32_t expected_count = counts[0] >> level;
        if (counts[level] != expected_count ||
            (level > 0u && children[level] != destinations[level - 1u])) return 0u;
        uint64_t destination_words = (uint64_t)counts[level] * 8u;
        if (merkle_ranges_overlap(destinations[level], destination_words,
                                  initial_child_start, initial_child_words)) return 0u;
        for (uint32_t prior = 0u; prior < level; ++prior) {
            if (merkle_ranges_overlap(destinations[level], destination_words,
                                      destinations[prior], (uint64_t)counts[prior] * 8u)) return 0u;
        }
    }
    return bottom_levels;
}

void *stwo_zig_metal_merkle_parent_chain_prepare(
    void *runtime_ptr, const uint32_t *child_offsets, const uint32_t *destination_offsets,
    const uint32_t *parent_counts, uint32_t level_count, const uint32_t *node_seed,
    uint32_t prefix_bytes,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || child_offsets == NULL || destination_offsets == NULL ||
        parent_counts == NULL || level_count == 0u || node_seed == NULL ||
        (prefix_bytes != 0u && prefix_bytes != 64u)) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        for (uint32_t level = 0; level < level_count; ++level) if (parent_counts[level] == 0u) return NULL;
        StwoZigMerkleParentChain *plan = [StwoZigMerkleParentChain new];
        plan.childOffsets = [NSData dataWithBytes:child_offsets length:(NSUInteger)level_count * sizeof(uint32_t)];
        plan.destinationOffsets = [NSData dataWithBytes:destination_offsets length:(NSUInteger)level_count * sizeof(uint32_t)];
        plan.parentCounts = [NSData dataWithBytes:parent_counts length:(NSUInteger)level_count * sizeof(uint32_t)];
        plan.nodeSeed = [runtime.device newBufferWithBytes:node_seed length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.levelCount = level_count;
        plan.prefixBytes = prefix_bytes;
        if (plan.nodeSeed == nil) { write_error(error_message, error_message_len, @"Metal Merkle parent-chain allocation failed"); return NULL; }
        NSUInteger static_bytes = runtime.parentTailSparse.staticThreadgroupMemoryLength;
        NSUInteger available_bytes = runtime.device.maxThreadgroupMemoryLength > static_bytes ?
            runtime.device.maxThreadgroupMemoryLength - static_bytes : 0u;
        NSUInteger capacity = MIN((NSUInteger)256u,
            MIN(runtime.parentTailSparse.maxTotalThreadsPerThreadgroup,
                available_bytes / (8u * sizeof(uint32_t))));
        uint32_t bottom_width = merkle_floor_power_of_two((uint32_t)MIN((NSUInteger)128u, capacity));
        plan.bottomLevelCount = merkle_parent_bottom_level_count(
            child_offsets, destination_offsets, parent_counts, level_count,
            bottom_width, (uint32_t)capacity);
        if (plan.bottomLevelCount > 0u) {
            plan.bottomThreadgroupWidth = bottom_width;
            plan.bottomThreadgroupCount = parent_counts[0] / bottom_width;
            plan.bottomScratchBytes = (NSUInteger)bottom_width * 8u * sizeof(uint32_t);
        }
        uint32_t tail_start = merkle_parent_tail_start(child_offsets, destination_offsets,
                                                       parent_counts, level_count, (uint32_t)capacity);
        plan.tailStart = MAX(tail_start, plan.bottomLevelCount);
        if (plan.tailStart < level_count) {
            uint32_t logical_width = parent_counts[plan.tailStart];
            plan.tailThreadgroupWidth = (uint32_t)MAX(
                (NSUInteger)logical_width, runtime.parentTailSparse.threadExecutionWidth);
            plan.tailScratchBytes = MAX((NSUInteger)logical_width, (NSUInteger)16u) *
                8u * sizeof(uint32_t);
        }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_merkle_parent_chain_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

static bool encode_merkle_parent_chain_on_encoder(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena, StwoZigMerkleParentChain *plan,
    id<MTLComputeCommandEncoder> encoder, uint64_t *dispatches
) {
    if (runtime == nil || arena == nil || plan == nil || encoder == nil) return false;
    const uint32_t *children = plan.childOffsets.bytes, *destinations = plan.destinationOffsets.bytes, *counts = plan.parentCounts.bytes;
    uint64_t arena_words = arena.length / sizeof(uint32_t);
    for (uint32_t level = 0u; level < plan.levelCount; ++level) {
        uint64_t child_end = (uint64_t)children[level] + (uint64_t)counts[level] * 16u;
        uint64_t destination_end = (uint64_t)destinations[level] + (uint64_t)counts[level] * 8u;
        if (child_end > arena_words || destination_end > arena_words) return false;
    }
    NSUInteger width = MIN((NSUInteger)256u, runtime.parentsSparse.maxTotalThreadsPerThreadgroup);
    uint32_t prefix_bytes = plan.prefixBytes;
    const uint32_t disabled_transcript_config[3] = {0u, 0u, 0u};
    if (plan.bottomLevelCount > 32u) return false;
    uint64_t encoded_dispatches = 0u;
    if (plan.bottomLevelCount > 0u) {
        uint32_t local_counts[32];
        for (uint32_t level = 0u; level < plan.bottomLevelCount; ++level)
            local_counts[level] = plan.bottomThreadgroupWidth >> level;
        uint32_t bottom_levels = plan.bottomLevelCount;
        [encoder setComputePipelineState:runtime.parentTailSparse];
        [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBytes:children length:(NSUInteger)bottom_levels * sizeof(uint32_t) atIndex:1];
        [encoder setBytes:destinations length:(NSUInteger)bottom_levels * sizeof(uint32_t) atIndex:2];
        [encoder setBytes:local_counts length:(NSUInteger)bottom_levels * sizeof(uint32_t) atIndex:3];
        [encoder setBytes:&bottom_levels length:sizeof(bottom_levels) atIndex:4];
        [encoder setBuffer:plan.nodeSeed offset:0 atIndex:5];
        [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:6];
        [encoder setBytes:disabled_transcript_config
            length:sizeof(disabled_transcript_config) atIndex:7];
        [encoder setThreadgroupMemoryLength:plan.bottomScratchBytes atIndex:0];
        [encoder dispatchThreadgroups:MTLSizeMake(plan.bottomThreadgroupCount, 1u, 1u)
                 threadsPerThreadgroup:MTLSizeMake(plan.bottomThreadgroupWidth, 1u, 1u)];
        encoded_dispatches += 1u;
        if (plan.bottomLevelCount < plan.levelCount)
            [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
    }
    for (uint32_t level = plan.bottomLevelCount; level < plan.tailStart; ++level) {
        uint32_t child = children[level], destination = destinations[level], count = counts[level];
        [encoder setComputePipelineState:runtime.parentsSparse]; [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBytes:&child length:sizeof(child) atIndex:1]; [encoder setBytes:&destination length:sizeof(destination) atIndex:2];
        [encoder setBytes:&count length:sizeof(count) atIndex:3]; [encoder setBuffer:plan.nodeSeed offset:0 atIndex:4];
        [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:5];
        [encoder dispatchThreads:MTLSizeMake(count, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        encoded_dispatches += 1u;
        if (level + 1u < plan.tailStart || plan.tailStart < plan.levelCount)
            [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
    }
    if (plan.tailStart < plan.levelCount) {
        uint32_t tail_levels = plan.levelCount - plan.tailStart;
        [encoder setComputePipelineState:runtime.parentTailSparse];
        [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBytes:children + plan.tailStart length:(NSUInteger)tail_levels * sizeof(uint32_t) atIndex:1];
        [encoder setBytes:destinations + plan.tailStart length:(NSUInteger)tail_levels * sizeof(uint32_t) atIndex:2];
        [encoder setBytes:counts + plan.tailStart length:(NSUInteger)tail_levels * sizeof(uint32_t) atIndex:3];
        [encoder setBytes:&tail_levels length:sizeof(tail_levels) atIndex:4];
        [encoder setBuffer:plan.nodeSeed offset:0 atIndex:5];
        [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:6];
        [encoder setBytes:disabled_transcript_config
            length:sizeof(disabled_transcript_config) atIndex:7];
        [encoder setThreadgroupMemoryLength:plan.tailScratchBytes atIndex:0];
        [encoder dispatchThreadgroups:MTLSizeMake(1u, 1u, 1u)
                 threadsPerThreadgroup:MTLSizeMake(plan.tailThreadgroupWidth, 1u, 1u)];
        encoded_dispatches += 1u;
    }
    *dispatches += encoded_dispatches;
    return true;
}

static bool encode_merkle_parent_chain_prepared(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena, StwoZigMerkleParentChain *plan,
    id<MTLCommandBuffer> command, uint64_t *compute_encoders, uint64_t *dispatches
) {
    if (command == nil) return false;
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (encoder == nil) return false;
    bool encoded = encode_merkle_parent_chain_on_encoder(runtime, arena, plan, encoder, dispatches);
    [encoder endEncoding];
    if (!encoded) return false;
    *compute_encoders += 1u;
    return true;
}

bool stwo_zig_metal_merkle_parent_chain_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigMerkleParentChain *plan = (__bridge StwoZigMerkleParentChain *)plan_ptr;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        uint64_t compute_encoders = 0u, dispatches = 0u;
        if (!encode_merkle_parent_chain_prepared(runtime, arena, plan, command, &compute_encoders, &dispatches)) {
            write_error(error_message, error_message_len, @"Metal Merkle parent-chain encoding failed"); return false;
        }
        [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) { write_error(error_message, error_message_len, command.error.localizedDescription); return false; }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}
