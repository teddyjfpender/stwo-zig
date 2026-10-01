bool stwo_zig_metal_blake2s_pow_search(
    void *runtime_ptr, bool m31_output, const uint32_t prefix_words[8],
    const uint32_t round_zero_columns[16], uint32_t pow_bits,
    uint64_t *nonce, double *gpu_milliseconds, uint32_t *dispatch_count,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || prefix_words == NULL || round_zero_columns == NULL || nonce == NULL ||
        gpu_milliseconds == NULL || dispatch_count == NULL ||
        pow_bits == 0u || pow_bits > 32u) {
        write_error(error_message, error_message_len, @"Invalid Metal proof-of-work arguments");
        return false;
    }

    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        // `Blake2sM31Channel` reduces the output words mod P before counting
        // zeros; the plain channel does not. Same index order for both.
        id<MTLComputePipelineState> pipeline = m31_output ? runtime.proofOfWorkM31 : runtime.proofOfWork;
        if (pipeline == nil) {
            write_error(error_message, error_message_len, @"Metal BLAKE2s proof-of-work pipeline is missing");
            return false;
        }
        id<MTLBuffer> result = [runtime.device newBufferWithLength:sizeof(uint32_t)
                                                       options:MTLResourceStorageModeShared];
        if (result == nil) {
            write_error(error_message, error_message_len, @"Metal proof-of-work allocation failed");
            return false;
        }

        // Walk the canonical Stwo search index space (hi < 2^31 - 1, lo < 2^20;
        // the kernel maps index -> (hi << 32) | lo) in ordered windows.
        // Keep each command comfortably below watchdog-scale work while
        // amortizing command-buffer submission and synchronous wait overhead.
        // On the target Apple GPU a 2^22 slice spends more time crossing the
        // host/device boundary than hashing; 2^24 remains a short dispatch.
        const uint64_t index_limit = (uint64_t)0x7fffffffu << 20u;
        const uint32_t interval_capacity = UINT32_C(1) << 24u;
        uint64_t interval_base = 0u;
        *gpu_milliseconds = 0.0;
        *dispatch_count = 0u;

        while (interval_base < index_limit) {
            uint64_t remaining = index_limit - interval_base;
            uint32_t interval_count = remaining < (uint64_t)interval_capacity
                ? (uint32_t)remaining : interval_capacity;
            *(uint32_t *)result.contents = UINT32_MAX;

            id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            if (command == nil || encoder == nil) {
                write_error(error_message, error_message_len, @"Metal proof-of-work command allocation failed");
                return false;
            }
            [encoder setComputePipelineState:pipeline];
            [encoder setBytes:prefix_words length:8u * sizeof(uint32_t) atIndex:0];
            [encoder setBytes:round_zero_columns length:16u * sizeof(uint32_t) atIndex:1];
            [encoder setBytes:&interval_base length:sizeof(interval_base) atIndex:2];
            [encoder setBytes:&interval_count length:sizeof(interval_count) atIndex:3];
            [encoder setBytes:&pow_bits length:sizeof(pow_bits) atIndex:4];
            [encoder setBuffer:result offset:0u atIndex:5];
            NSUInteger width = MIN((NSUInteger)256u,
                pipeline.maxTotalThreadsPerThreadgroup);
            [encoder dispatchThreads:MTLSizeMake(interval_count, 1u, 1u)
                 threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            [encoder endEncoding];
            [command commit];
            [command waitUntilCompleted];
            if (command.status == MTLCommandBufferStatusError) {
                write_error(error_message, error_message_len,
                            command.error.localizedDescription ?: @"Metal proof-of-work dispatch failed");
                return false;
            }
            *gpu_milliseconds += (command.GPUEndTime - command.GPUStartTime) * 1000.0;
            *dispatch_count += 1u;

            uint32_t local_match = *(const uint32_t *)result.contents;
            if (local_match != UINT32_MAX) {
                uint64_t index = interval_base + local_match;
                *nonce = ((index >> 20u) << 32u) | (index & UINT64_C(0xfffff));
                return true;
            }
            interval_base += interval_count;
        }
        write_error(error_message, error_message_len, @"Metal proof-of-work nonce space exhausted");
        return false;
    }
}

static bool channel_pow_search(
    bool blake3, void *runtime_ptr, const uint32_t prefix_state[16], uint32_t pow_bits,
    uint64_t *nonce, double *gpu_milliseconds, uint32_t *dispatch_count,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || prefix_state == NULL || nonce == NULL ||
        gpu_milliseconds == NULL || dispatch_count == NULL ||
        pow_bits == 0u || pow_bits > 32u) {
        write_error(error_message, error_message_len, @"Invalid Metal channel proof-of-work arguments");
        return false;
    }
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLComputePipelineState> pipeline = blake3 ? runtime.blake3ProofOfWork : runtime.poseidon2ChannelPowSearch;
        if (pipeline == nil) {
            write_error(error_message, error_message_len, @"Metal channel proof-of-work pipeline is missing");
            return false;
        }
        id<MTLBuffer> result = [runtime.device newBufferWithLength:sizeof(uint32_t)
                                                       options:MTLResourceStorageModeShared];
        if (result == nil) {
            write_error(error_message, error_message_len, @"Metal proof-of-work allocation failed");
            return false;
        }
        // Bound each channel search dispatch to 2^20 candidates. Harder
        // profiles advance through ordered intervals without changing
        // the lowest-nonce result or growing device allocations.
        const uint32_t interval_capacity = UINT32_C(1) << 20u;
        uint64_t interval_base = 0u;
        *gpu_milliseconds = 0.0;
        *dispatch_count = 0u;
        while (true) {
            uint64_t remaining = UINT64_MAX - interval_base;
            uint32_t interval_count = remaining < (uint64_t)interval_capacity - 1u
                ? (uint32_t)(remaining + 1u) : interval_capacity;
            *(uint32_t *)result.contents = UINT32_MAX;
            id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            if (command == nil || encoder == nil) {
                write_error(error_message, error_message_len, @"Metal proof-of-work command allocation failed");
                return false;
            }
            [encoder setComputePipelineState:pipeline];
            [encoder setBytes:prefix_state length:16u * sizeof(uint32_t) atIndex:0];
            [encoder setBytes:&interval_base length:sizeof(interval_base) atIndex:1];
            [encoder setBytes:&interval_count length:sizeof(interval_count) atIndex:2];
            [encoder setBytes:&pow_bits length:sizeof(pow_bits) atIndex:3];
            [encoder setBuffer:result offset:0u atIndex:4];
            NSUInteger width = MIN((NSUInteger)256u,
                pipeline.maxTotalThreadsPerThreadgroup);
            [encoder dispatchThreads:MTLSizeMake(interval_count, 1u, 1u)
                 threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            [encoder endEncoding];
            [command commit];
            [command waitUntilCompleted];
            if (command.status == MTLCommandBufferStatusError) {
                write_error(error_message, error_message_len,
                            command.error.localizedDescription ?: @"Metal proof-of-work dispatch failed");
                return false;
            }
            *gpu_milliseconds += (command.GPUEndTime - command.GPUStartTime) * 1000.0;
            *dispatch_count += 1u;
            uint32_t local_match = *(const uint32_t *)result.contents;
            if (local_match != UINT32_MAX) {
                *nonce = interval_base + local_match;
                return true;
            }
            if (interval_count != interval_capacity ||
                UINT64_MAX - interval_base < interval_count) {
                write_error(error_message, error_message_len, @"Metal proof-of-work nonce space exhausted");
                return false;
            }
            interval_base += interval_count;
        }
    }
}

bool stwo_zig_metal_poseidon2_channel_pow_search(
    void *runtime_ptr, const uint32_t prefix_state[16], uint32_t pow_bits,
    uint64_t *nonce, double *gpu_milliseconds, uint32_t *dispatch_count,
    char *error_message, size_t error_message_len
) {
    return channel_pow_search(false, runtime_ptr, prefix_state, pow_bits, nonce,
        gpu_milliseconds, dispatch_count, error_message, error_message_len);
}

bool stwo_zig_metal_blake3_pow_search(
    void *runtime_ptr, const uint32_t prefix_state[16], uint32_t pow_bits,
    uint64_t *nonce, double *gpu_milliseconds, uint32_t *dispatch_count,
    char *error_message, size_t error_message_len
) {
    return channel_pow_search(true, runtime_ptr, prefix_state, pow_bits, nonce,
        gpu_milliseconds, dispatch_count, error_message, error_message_len);
}
