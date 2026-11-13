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

bool stwo_zig_metal_command_epoch_encode_compact_leaf_v2(
    void *epoch_ptr, const uint32_t *column_offsets, const uint32_t *column_logs, uint32_t column_count,
    uint32_t source_state_offset, uint32_t source_state_log, uint32_t destination_state_offset, uint32_t destination_log,
    uint32_t first_column, uint32_t is_final, uint32_t prefix_bytes, const uint32_t *leaf_seed,
    uint32_t hash_family,
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
                first_column, is_final, prefix_bytes, leaf_seed,
                hash_family, epoch.command,
                &compute_encoders, &dispatches)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len, @"Metal command epoch compact leaf encoding failed");
            return false;
        }
        epoch.computeEncoders = compute_encoders; epoch.dispatches = dispatches;
        return true;
    }
}

bool stwo_zig_metal_command_epoch_encode_compact_leaf(
    void *epoch_ptr, const uint32_t *column_offsets, const uint32_t *column_logs, uint32_t column_count,
    uint32_t source_state_offset, uint32_t source_state_log, uint32_t destination_state_offset, uint32_t destination_log,
    uint32_t first_column, uint32_t is_final, uint32_t prefix_bytes, const uint32_t *leaf_seed,
    char *error_message, size_t error_message_len
) {
    return stwo_zig_metal_command_epoch_encode_compact_leaf_v2(
        epoch_ptr, column_offsets, column_logs, column_count,
        source_state_offset, source_state_log, destination_state_offset, destination_log,
        first_column, is_final, prefix_bytes, leaf_seed,
        StwoZigCommitmentHashFamilyBlake2sV1, error_message, error_message_len);
}

bool stwo_zig_metal_command_epoch_encode_poseidon2_leaf_state_digest_v1(
    void *epoch_ptr, uint32_t state_offset, uint32_t destination_offset, uint32_t lifting_log,
    char *error_message, size_t error_message_len
) {
    if (epoch_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCommandEpoch *epoch = (__bridge StwoZigCommandEpoch *)epoch_ptr;
        if (!command_epoch_can_encode(epoch, error_message, error_message_len)) return false;
        uint64_t compute_encoders = epoch.computeEncoders, dispatches = epoch.dispatches;
        if (!encode_poseidon2_leaf_state_digest_resident_v1(
                epoch.runtime, epoch.arena, state_offset, destination_offset, lifting_log,
                epoch.command, &compute_encoders, &dispatches)) {
            epoch.state = StwoZigCommandEpochStateFailed;
            write_error(error_message, error_message_len,
                        @"Metal command epoch Poseidon leaf-state digest encoding failed");
            return false;
        }
        epoch.computeEncoders = compute_encoders;
        epoch.dispatches = dispatches;
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
