void *stwo_zig_metal_fri_fold_prepare(
    void *runtime_ptr, uint32_t source_offset_words, uint32_t inverse_offset_words,
    uint32_t alpha_offset_words, uint32_t destination_offset_words,
    uint32_t source_count, bool circle,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || source_count < 2u || (source_count & 1u) != 0u) return NULL;
    @autoreleasepool {
        StwoZigFriFoldPlan *plan = [StwoZigFriFoldPlan new];
        plan.sourceByteOffset = (NSUInteger)source_offset_words * sizeof(uint32_t);
        plan.inverseByteOffset = (NSUInteger)inverse_offset_words * sizeof(uint32_t);
        plan.alphaByteOffset = (NSUInteger)alpha_offset_words * sizeof(uint32_t);
        plan.destinationByteOffset = (NSUInteger)destination_offset_words * sizeof(uint32_t);
        plan.sourceCount = source_count;
        plan.circle = circle;
        if (plan == nil) {
            write_error(error_message, error_message_len, @"Metal FRI fold plan allocation failed");
            return NULL;
        }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_fri_fold_plan_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

bool stwo_zig_metal_fri_fold_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigFriFoldPlan *plan = (__bridge StwoZigFriFoldPlan *)plan_ptr;
        uint32_t destination_count = plan.sourceCount >> 1u;
        if (plan.sourceByteOffset + (NSUInteger)plan.sourceCount * 4u * sizeof(uint32_t) > arena.length ||
            plan.inverseByteOffset + (NSUInteger)destination_count * sizeof(uint32_t) > arena.length ||
            plan.alphaByteOffset + 4u * sizeof(uint32_t) > arena.length ||
            plan.destinationByteOffset + (NSUInteger)destination_count * 4u * sizeof(uint32_t) > arena.length) {
            write_error(error_message, error_message_len, @"Metal FRI fold plan exceeds arena");
            return false;
        }
        id<MTLComputePipelineState> pipeline = plan.circle ? runtime.friFoldCircle : runtime.friFoldLine;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:arena offset:plan.sourceByteOffset atIndex:0];
        [encoder setBuffer:arena offset:plan.inverseByteOffset atIndex:1];
        [encoder setBuffer:arena offset:plan.alphaByteOffset atIndex:2];
        [encoder setBuffer:arena offset:plan.destinationByteOffset atIndex:3];
        [encoder setBytes:&destination_count length:sizeof(destination_count) atIndex:4];
        if (!plan.circle) {
            uint32_t disabled = 0u;
            [encoder setBuffer:arena offset:plan.destinationByteOffset atIndex:5];
            [encoder setBuffer:arena offset:plan.destinationByteOffset atIndex:6];
            [encoder setBuffer:arena offset:plan.inverseByteOffset atIndex:7];
            [encoder setBytes:&disabled length:sizeof(disabled) atIndex:8];
            [encoder setBytes:&disabled length:sizeof(disabled) atIndex:9];
        }
        NSUInteger width = MIN(pipeline.maxTotalThreadsPerThreadgroup, pipeline.threadExecutionWidth * 8u);
        [encoder dispatchThreads:MTLSizeMake(destination_count, 1u, 1u)
             threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription);
            return false;
        }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_quotient_combine_prepare(
    void *runtime_ptr, const uint32_t *partial_offsets, const uint32_t *partial_logs,
    uint32_t sample_count, uint32_t sample_offset, uint32_t linear_offset,
    uint32_t scratch_offset, uint32_t output_offset, uint32_t row_count,
    uint32_t log_size, uint32_t initial_index, uint32_t step_size,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || partial_offsets == NULL || partial_logs == NULL || sample_count == 0u ||
        row_count < 4u || (row_count & (row_count - 1u)) != 0u || log_size >= 31u) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigQuotientCombinePlan *plan = [StwoZigQuotientCombinePlan new];
        plan.partialOffsets = [runtime.device newBufferWithBytes:partial_offsets length:(NSUInteger)sample_count * 4u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.partialLogs = [runtime.device newBufferWithBytes:partial_logs length:(NSUInteger)sample_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.sampleCount = sample_count; plan.sampleOffset = sample_offset; plan.linearOffset = linear_offset;
        plan.scratchOffset = scratch_offset; plan.outputOffset = output_offset; plan.rowCount = row_count;
        plan.logSize = log_size; plan.initialIndex = initial_index; plan.stepSize = step_size;
        if (plan.partialOffsets == nil || plan.partialLogs == nil) {
            write_error(error_message, error_message_len, @"Metal quotient-combine plan allocation failed");
            return NULL;
        }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_quotient_combine_plan_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

bool stwo_zig_metal_quotient_coefficients_resident(
    void *runtime_ptr, void *arena_ptr,
    const StwoZigQuotientCoefficientTerm *term_descriptors, uint32_t term_count,
    const uint32_t *task_words, uint32_t task_count,
    const uint32_t *row_starts, uint32_t total_rows,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || term_descriptors == NULL || task_words == NULL ||
        row_starts == NULL || term_count == 0u || task_count == 0u || total_rows == 0u ||
        row_starts[0] != 0u || row_starts[task_count] != total_rows) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger arena_words = arena.length / sizeof(uint32_t);
        for (uint32_t term = 0u; term < term_count; ++term) {
            const StwoZigQuotientCoefficientTerm *descriptor = &term_descriptors[term];
            if ((NSUInteger)descriptor->source_word_offset + descriptor->source_word_count > arena_words) {
                write_error(error_message, error_message_len, @"Metal quotient coefficient source exceeds arena");
                return false;
            }
        }
        for (uint32_t task = 0u; task < task_count; ++task) {
            const uint32_t *words = task_words + (NSUInteger)task * 11u;
            uint32_t row_count = words[6];
            if (words[0] + words[1] > term_count || row_starts[task] > row_starts[task + 1u] ||
                row_starts[task + 1u] - row_starts[task] != row_count) {
                write_error(error_message, error_message_len, @"Metal quotient coefficient task is malformed");
                return false;
            }
            for (uint32_t coordinate = 0u; coordinate < 4u; ++coordinate) {
                if ((NSUInteger)words[2u + coordinate] + row_count > arena_words) {
                    write_error(error_message, error_message_len, @"Metal quotient coefficient destination exceeds arena");
                    return false;
                }
            }
        }
        id<MTLBuffer> terms = [runtime.device newBufferWithBytes:term_descriptors
            length:(NSUInteger)term_count * sizeof(StwoZigQuotientCoefficientTerm) options:MTLResourceStorageModeShared];
        id<MTLBuffer> tasks = [runtime.device newBufferWithBytes:task_words
            length:(NSUInteger)task_count * 11u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> starts = [runtime.device newBufferWithBytes:row_starts
            length:(NSUInteger)(task_count + 1u) * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        if (terms == nil || tasks == nil || starts == nil) {
            write_error(error_message, error_message_len, @"Metal quotient coefficient descriptor allocation failed");
            return false;
        }
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.quotientCoefficientsResident];
        [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBuffer:terms offset:0 atIndex:1];
        [encoder setBuffer:tasks offset:0 atIndex:2];
        [encoder setBuffer:starts offset:0 atIndex:3];
        [encoder setBytes:&task_count length:sizeof(task_count) atIndex:4];
        [encoder setBytes:&total_rows length:sizeof(total_rows) atIndex:5];
        NSUInteger width = MIN(runtime.quotientCoefficientsResident.maxTotalThreadsPerThreadgroup,
                               runtime.quotientCoefficientsResident.threadExecutionWidth * 8u);
        [encoder dispatchThreads:MTLSizeMake(total_rows, 1u, 1u)
             threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?: @"Metal quotient coefficient accumulation failed");
            return false;
        }
        if (gpu_milliseconds != NULL) {
            *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        }
        return true;
    }
}

bool stwo_zig_metal_quotient_combine_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigQuotientCombinePlan *plan = (__bridge StwoZigQuotientCombinePlan *)plan_ptr;
        uint32_t rows = plan.rowCount, log_size = plan.logSize, samples = plan.sampleCount;
        NSUInteger output_end = ((NSUInteger)plan.outputOffset + (NSUInteger)rows * 4u) * sizeof(uint32_t);
        NSUInteger scratch_end = ((NSUInteger)plan.scratchOffset + (NSUInteger)rows * samples * 2u) * sizeof(uint32_t);
        NSUInteger sample_end = ((NSUInteger)plan.sampleOffset + (NSUInteger)samples * 8u) * sizeof(uint32_t);
        NSUInteger linear_end = ((NSUInteger)plan.linearOffset + (NSUInteger)samples * 4u) * sizeof(uint32_t);
        if (output_end > arena.length || scratch_end > arena.length || sample_end > arena.length || linear_end > arena.length) {
            write_error(error_message, error_message_len, @"Metal quotient-combine plan exceeds arena");
            return false;
        }
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> domain = [command computeCommandEncoder];
        [domain setComputePipelineState:runtime.quotientDomainPointsResident]; [domain setBuffer:arena offset:0 atIndex:0];
        uint32_t output = plan.outputOffset, initial = plan.initialIndex, step = plan.stepSize;
        [domain setBytes:&output length:sizeof(output) atIndex:1]; [domain setBytes:&rows length:sizeof(rows) atIndex:2];
        [domain setBytes:&log_size length:sizeof(log_size) atIndex:3]; [domain setBytes:&initial length:sizeof(initial) atIndex:4];
        [domain setBytes:&step length:sizeof(step) atIndex:5];
        uint32_t domain_mode = 0u; [domain setBytes:&domain_mode length:sizeof(domain_mode) atIndex:6];
        NSUInteger domain_width = MIN(runtime.quotientDomainPointsResident.maxTotalThreadsPerThreadgroup, runtime.quotientDomainPointsResident.threadExecutionWidth * 8u);
        [domain dispatchThreads:MTLSizeMake(rows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(domain_width, 1u, 1u)];
        [domain endEncoding];

        id<MTLComputeCommandEncoder> denominators = [command computeCommandEncoder];
        [denominators setComputePipelineState:runtime.quotientDenominatorsResident]; [denominators setBuffer:arena offset:0 atIndex:0];
        uint32_t sample = plan.sampleOffset, scratch = plan.scratchOffset;
        [denominators setBytes:&output length:sizeof(output) atIndex:1]; [denominators setBytes:&sample length:sizeof(sample) atIndex:2];
        [denominators setBytes:&scratch length:sizeof(scratch) atIndex:3]; [denominators setBytes:&rows length:sizeof(rows) atIndex:4];
        [denominators setBytes:&samples length:sizeof(samples) atIndex:5];
        NSUInteger denominator_width = MIN(runtime.quotientDenominatorsResident.maxTotalThreadsPerThreadgroup, runtime.quotientDenominatorsResident.threadExecutionWidth * 8u);
        [denominators dispatchThreads:MTLSizeMake((NSUInteger)rows * samples, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(denominator_width, 1u, 1u)];
        [denominators endEncoding];

        id<MTLComputeCommandEncoder> combine = [command computeCommandEncoder];
        [combine setComputePipelineState:runtime.quotientCombineResident]; [combine setBuffer:arena offset:0 atIndex:0];
        [combine setBuffer:plan.partialOffsets offset:0 atIndex:1]; [combine setBuffer:plan.partialLogs offset:0 atIndex:2];
        uint32_t linear = plan.linearOffset;
        [combine setBytes:&sample length:sizeof(sample) atIndex:3]; [combine setBytes:&linear length:sizeof(linear) atIndex:4];
        [combine setBytes:&scratch length:sizeof(scratch) atIndex:5]; [combine setBytes:&output length:sizeof(output) atIndex:6];
        [combine setBytes:&rows length:sizeof(rows) atIndex:7]; [combine setBytes:&log_size length:sizeof(log_size) atIndex:8];
        [combine setBytes:&samples length:sizeof(samples) atIndex:9];
        NSUInteger combine_width = MIN(runtime.quotientCombineResident.maxTotalThreadsPerThreadgroup, runtime.quotientCombineResident.threadExecutionWidth * 8u);
        [combine dispatchThreads:MTLSizeMake(rows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(combine_width, 1u, 1u)];
        [combine endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription); return false;
        }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_fri_round_prepare(
    void *runtime_ptr, uint32_t twiddle_base, uint32_t twiddle_words,
    uint32_t input_base, uint32_t input_stride, uint32_t alpha_base,
    uint32_t output_base, uint32_t output_stride, uint32_t n,
    uint32_t fold_count, bool first_circle,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || n < 4u || (n & (n - 1u)) != 0u ||
        (fold_count != 2u && fold_count != 3u) || (first_circle && fold_count != 3u)) return NULL;
    uint32_t consumed0 = first_circle ? (n >> 1u) : n;
    if (twiddle_words < consumed0 || twiddle_words < (n >> 1u) ||
        (fold_count == 3u && twiddle_words < (n >> 2u))) return NULL;
    @autoreleasepool {
        StwoZigFriRoundPlan *plan = [StwoZigFriRoundPlan new];
        plan.twiddleBase = twiddle_base; plan.twiddleOffset0 = twiddle_words - consumed0;
        plan.twiddleOffset1 = twiddle_words - (n >> 1u);
        plan.twiddleOffset2 = fold_count == 3u ? twiddle_words - (n >> 2u) : 0u;
        plan.inputBase = input_base; plan.inputStride = input_stride; plan.alphaBase = alpha_base;
        plan.outputBase = output_base; plan.outputStride = output_stride; plan.n = n;
        plan.foldCount = fold_count; plan.firstCircle = first_circle ? 1u : 0u;
        if (plan == nil) { write_error(error_message, error_message_len, @"Metal FRI round plan allocation failed"); return NULL; }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_fri_round_plan_destroy(void *plan_ptr) { if (plan_ptr != NULL) CFRelease(plan_ptr); }

bool stwo_zig_metal_fri_round_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigFriRoundPlan *plan = (__bridge StwoZigFriRoundPlan *)plan_ptr;
        uint32_t output_count = plan.n >> plan.foldCount;
        NSUInteger input_end = ((NSUInteger)plan.inputBase + (NSUInteger)plan.inputStride * 3u + plan.n) * sizeof(uint32_t);
        NSUInteger output_end = ((NSUInteger)plan.outputBase + (NSUInteger)plan.outputStride * 3u + output_count) * sizeof(uint32_t);
        NSUInteger alpha_end = ((NSUInteger)plan.alphaBase + 4u) * sizeof(uint32_t);
        if (input_end > arena.length || output_end > arena.length || alpha_end > arena.length) {
            write_error(error_message, error_message_len, @"Metal FRI round exceeds arena"); return false;
        }
        id<MTLComputePipelineState> pipeline = plan.foldCount == 3u ? runtime.friFold3Resident : runtime.friFold2Resident;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:pipeline]; [encoder setBuffer:arena offset:0 atIndex:0];
        uint32_t values[] = { plan.twiddleBase, plan.twiddleOffset0, plan.twiddleOffset1, plan.twiddleOffset2,
            plan.inputBase, plan.inputStride, plan.alphaBase, plan.outputBase, plan.outputStride, plan.n, plan.firstCircle };
        if (plan.foldCount == 3u) {
            for (NSUInteger i = 0; i < 11u; ++i) [encoder setBytes:&values[i] length:sizeof(uint32_t) atIndex:i + 1u];
        } else {
            uint32_t compact[] = { plan.twiddleBase, plan.twiddleOffset0, plan.twiddleOffset1,
                plan.inputBase, plan.inputStride, plan.alphaBase, plan.outputBase, plan.outputStride, plan.n };
            for (NSUInteger i = 0; i < 9u; ++i) [encoder setBytes:&compact[i] length:sizeof(uint32_t) atIndex:i + 1u];
        }
        NSUInteger width = MIN(pipeline.maxTotalThreadsPerThreadgroup, pipeline.threadExecutionWidth * 8u);
        [encoder dispatchThreads:MTLSizeMake(output_count, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) { write_error(error_message, error_message_len, command.error.localizedDescription); return false; }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_fri_tree_prepare_v2(
    void *runtime_ptr, uint32_t evaluation_base, uint32_t coordinate_stride,
    uint32_t evaluation_size, uint32_t log_rows_per_leaf,
    const uint32_t *layer_offsets, uint32_t layer_count,
    const uint32_t *leaf_seed, const uint32_t *node_seed,
    uint32_t prefix_bytes, uint32_t hash_family,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || evaluation_size == 0u || (evaluation_size & (evaluation_size - 1u)) != 0u ||
        log_rows_per_leaf > 2u || layer_offsets == NULL || layer_count < 2u || leaf_seed == NULL || node_seed == NULL ||
        (prefix_bytes != 0u && prefix_bytes != 64u)) return NULL;
    if ((!stwo_zig_valid_commitment_hash_family_v1(hash_family) &&
         hash_family != StwoZigCommitmentHashFamilyBlake3V1) || coordinate_stride < evaluation_size) return NULL;
    if (hash_family == StwoZigCommitmentHashFamilyBlake3V1) {
        if (prefix_bytes != 0u) return NULL;
        for (uint32_t i=0;i<8u;++i) if (leaf_seed[i] != 0u || node_seed[i] != 0u) return NULL;
    }
    uint32_t count=evaluation_size >> log_rows_per_leaf;
    if (count < 2u || layer_count > 32u) return NULL;
    uint64_t evaluation_end=(uint64_t)evaluation_base+(uint64_t)coordinate_stride*3u+evaluation_size;
    if (evaluation_end > (1ull << 32u)) return NULL;
    for (uint32_t level=0;level<layer_count;++level) {
        uint64_t begin=layer_offsets[level], end=begin+(uint64_t)count*8u;
        if (end > (1ull << 32u) || count == 0u || (begin < evaluation_end && end > evaluation_base)) return NULL;
        for (uint32_t prior=0;prior<level;++prior) {
            uint64_t prior_end=(uint64_t)layer_offsets[prior]+(uint64_t)(evaluation_size >> log_rows_per_leaf >> prior)*8u;
            if (begin < prior_end && end > layer_offsets[prior]) return NULL;
        }
        count >>= 1u;
    }
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigFriTreePlan *plan = [StwoZigFriTreePlan new];
        plan.evaluationBase = evaluation_base; plan.coordinateStride = coordinate_stride;
        plan.evaluationSize = evaluation_size; plan.logRowsPerLeaf = log_rows_per_leaf; plan.layerCount = layer_count;
        plan.prefixBytes = prefix_bytes; plan.hashFamily = hash_family;
        plan.layerOffsets = [NSData dataWithBytes:layer_offsets length:(NSUInteger)layer_count * sizeof(uint32_t)];
        plan.leafSeed = [runtime.device newBufferWithBytes:leaf_seed length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.nodeSeed = [runtime.device newBufferWithBytes:node_seed length:8u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        if (plan.layerOffsets == nil || plan.leafSeed == nil || plan.nodeSeed == nil) {
            write_error(error_message, error_message_len, @"Metal FRI tree plan allocation failed"); return NULL;
        }
        return (__bridge_retained void *)plan;
    }
}

void *stwo_zig_metal_fri_tree_prepare(
    void *runtime_ptr, uint32_t evaluation_base, uint32_t coordinate_stride,
    uint32_t evaluation_size, uint32_t log_rows_per_leaf,
    const uint32_t *layer_offsets, uint32_t layer_count,
    const uint32_t *leaf_seed, const uint32_t *node_seed,
    uint32_t prefix_bytes,
    char *error_message, size_t error_message_len
) {
    return stwo_zig_metal_fri_tree_prepare_v2(runtime_ptr, evaluation_base,
        coordinate_stride, evaluation_size, log_rows_per_leaf, layer_offsets,
        layer_count, leaf_seed, node_seed, prefix_bytes,
        StwoZigCommitmentHashFamilyBlake2sV1, error_message, error_message_len);
}

void stwo_zig_metal_fri_tree_plan_destroy(void *plan_ptr) { if (plan_ptr != NULL) CFRelease(plan_ptr); }

bool stwo_zig_metal_fri_tree_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigFriTreePlan *plan = (__bridge StwoZigFriTreePlan *)plan_ptr;
        const uint32_t *layers = plan.layerOffsets.bytes;
        uint32_t leaves = plan.evaluationSize >> plan.logRowsPerLeaf;
        NSUInteger evaluation_end = ((NSUInteger)plan.evaluationBase + (NSUInteger)plan.coordinateStride * 3u + plan.evaluationSize) * sizeof(uint32_t);
        NSUInteger leaf_end = ((NSUInteger)layers[0] + (NSUInteger)leaves * 8u) * sizeof(uint32_t);
        if (evaluation_end > arena.length || leaf_end > arena.length) { write_error(error_message, error_message_len, @"Metal FRI tree exceeds arena"); return false; }
        for (uint32_t level=0;level<plan.layerCount;++level) {
            if (((uint64_t)layers[level]+(uint64_t)(leaves >> level)*8u)*sizeof(uint32_t) > arena.length) {
                write_error(error_message,error_message_len,@"Metal FRI parent layer exceeds arena"); return false;
            }
        }
        id<MTLComputePipelineState> leaf_pipeline=stwo_zig_commitment_fri_leaves_pipeline(runtime,plan.hashFamily);
        id<MTLComputePipelineState> parent_pipeline=stwo_zig_commitment_parents_sparse_pipeline(runtime,plan.hashFamily);
        if (leaf_pipeline==nil || parent_pipeline==nil) return false;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> leaf = [command computeCommandEncoder];
        [leaf setComputePipelineState:leaf_pipeline]; [leaf setBuffer:arena offset:0 atIndex:0];
        uint32_t base = plan.evaluationBase, stride = plan.coordinateStride, size = plan.evaluationSize;
        uint32_t packed = plan.logRowsPerLeaf, destination = layers[0];
        [leaf setBytes:&base length:sizeof(base) atIndex:1]; [leaf setBytes:&stride length:sizeof(stride) atIndex:2];
        [leaf setBytes:&size length:sizeof(size) atIndex:3]; [leaf setBytes:&packed length:sizeof(packed) atIndex:4];
        [leaf setBytes:&destination length:sizeof(destination) atIndex:5]; [leaf setBuffer:plan.leafSeed offset:0 atIndex:6];
        uint32_t prefix_bytes = plan.prefixBytes;
        [leaf setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:7];
        NSUInteger leaf_width = MIN(leaf_pipeline.maxTotalThreadsPerThreadgroup, leaf_pipeline.threadExecutionWidth * 8u);
        [leaf dispatchThreads:MTLSizeMake(leaves, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(leaf_width, 1u, 1u)];
        [leaf endEncoding];
        uint32_t parents = leaves >> 1u;
        for (uint32_t level = 1u; level < plan.layerCount; ++level) {
            id<MTLComputeCommandEncoder> parent = [command computeCommandEncoder];
            [parent setComputePipelineState:parent_pipeline]; [parent setBuffer:arena offset:0 atIndex:0];
            uint32_t child = layers[level - 1u], output = layers[level];
            [parent setBytes:&child length:sizeof(child) atIndex:1]; [parent setBytes:&output length:sizeof(output) atIndex:2];
            [parent setBytes:&parents length:sizeof(parents) atIndex:3]; [parent setBuffer:plan.nodeSeed offset:0 atIndex:4];
            [parent setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:5];
            NSUInteger width = MIN(parent_pipeline.maxTotalThreadsPerThreadgroup, parent_pipeline.threadExecutionWidth * 8u);
            [parent dispatchThreads:MTLSizeMake(parents, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            [parent endEncoding]; parents >>= 1u;
        }
        [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) { write_error(error_message, error_message_len, command.error.localizedDescription); return false; }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_fri_final_prepare(
    void *runtime_ptr, uint32_t evaluation_base, uint32_t coordinate_stride,
    uint32_t inverse_x, uint32_t coefficient_base, uint32_t degree_error,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || coordinate_stride < 2u || inverse_x == 0u) return NULL;
    @autoreleasepool {
        StwoZigFriFinalPlan *plan = [StwoZigFriFinalPlan new];
        plan.evaluationBase = evaluation_base; plan.coordinateStride = coordinate_stride;
        plan.inverseX = inverse_x; plan.coefficientBase = coefficient_base; plan.degreeError = degree_error;
        if (plan == nil) { write_error(error_message, error_message_len, @"Metal FRI final plan allocation failed"); return NULL; }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_fri_final_plan_destroy(void *plan_ptr) { if (plan_ptr != NULL) CFRelease(plan_ptr); }

bool stwo_zig_metal_fri_final_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigFriFinalPlan *plan = (__bridge StwoZigFriFinalPlan *)plan_ptr;
        NSUInteger evaluation_end = ((NSUInteger)plan.evaluationBase + (NSUInteger)plan.coordinateStride * 3u + 2u) * sizeof(uint32_t);
        NSUInteger coefficient_end = ((NSUInteger)plan.coefficientBase + 8u) * sizeof(uint32_t);
        NSUInteger error_end = ((NSUInteger)plan.degreeError + 1u) * sizeof(uint32_t);
        if (evaluation_end > arena.length || coefficient_end > arena.length || error_end > arena.length) {
            write_error(error_message, error_message_len, @"Metal FRI final exceeds arena"); return false;
        }
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.friFinalLineResident]; [encoder setBuffer:arena offset:0 atIndex:0];
        uint32_t values[] = { plan.evaluationBase, plan.coordinateStride, plan.inverseX, plan.coefficientBase, plan.degreeError };
        for (NSUInteger i = 0; i < 5u; ++i) [encoder setBytes:&values[i] length:sizeof(uint32_t) atIndex:i + 1u];
        [encoder dispatchThreads:MTLSizeMake(1u, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) { write_error(error_message, error_message_len, command.error.localizedDescription); return false; }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}
