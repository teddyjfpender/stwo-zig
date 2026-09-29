bool stwo_zig_metal_eval_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigEvalPlan *plan = (__bridge StwoZigEvalPlan *)plan_ptr;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:plan.pipeline];
        [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBuffer:plan.arguments offset:0 atIndex:1];
        [encoder dispatchThreads:MTLSizeMake(plan.rowCount, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(plan.dispatchWidth, 1u, 1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription); return false;
        }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

bool stwo_zig_metal_compact_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigCompactPlan *plan = (__bridge StwoZigCompactPlan *)plan_ptr;
        NSUInteger width = MIN((NSUInteger)256u, MIN((NSUInteger)plan.sortRows, runtime.compactGather.maxTotalThreadsPerThreadgroup));
        uint32_t block_count = (uint32_t)(plan.sortRows / width);
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> gather = [command computeCommandEncoder];
        [gather setComputePipelineState:runtime.compactGather]; [gather setBuffer:arena offset:0 atIndex:0];
        [gather setBuffer:plan.sourceOffsets offset:0 atIndex:1]; [gather setBuffer:plan.descriptors offset:0 atIndex:2];
        [gather setBuffer:plan.params offset:0 atIndex:3];
        [gather dispatchThreads:MTLSizeMake(plan.sortRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [gather endEncoding];

        uint32_t current = plan.indicesA, next = plan.indicesB;
        for (uint32_t word = plan.keyWords; word-- > 0u;) {
            for (uint32_t shift = 0u; shift < 32u; shift += 4u) {
                id<MTLComputeCommandEncoder> histogram = [command computeCommandEncoder];
                [histogram setComputePipelineState:runtime.compactRadixHistogram]; [histogram setBuffer:arena offset:0 atIndex:0];
                [histogram setBuffer:plan.params offset:0 atIndex:1]; [histogram setBytes:&word length:sizeof(word) atIndex:2];
                [histogram setBytes:&shift length:sizeof(shift) atIndex:3]; [histogram setBytes:&current length:sizeof(current) atIndex:4];
                [histogram dispatchThreads:MTLSizeMake(plan.sortRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [histogram endEncoding];

                id<MTLComputeCommandEncoder> prefix = [command computeCommandEncoder];
                [prefix setComputePipelineState:runtime.compactRadixPrefix]; [prefix setBuffer:arena offset:0 atIndex:0];
                [prefix setBuffer:plan.params offset:0 atIndex:1]; [prefix setBytes:&block_count length:sizeof(block_count) atIndex:2];
                [prefix dispatchThreadgroups:MTLSizeMake(1u, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(16u, 1u, 1u)];
                [prefix endEncoding];

                id<MTLComputeCommandEncoder> scatter = [command computeCommandEncoder];
                [scatter setComputePipelineState:runtime.compactRadixScatter]; [scatter setBuffer:arena offset:0 atIndex:0];
                [scatter setBuffer:plan.params offset:0 atIndex:1]; [scatter setBytes:&word length:sizeof(word) atIndex:2];
                [scatter setBytes:&shift length:sizeof(shift) atIndex:3]; [scatter setBytes:&current length:sizeof(current) atIndex:4];
                [scatter setBytes:&next length:sizeof(next) atIndex:5];
                [scatter dispatchThreads:MTLSizeMake(plan.sortRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [scatter endEncoding];
                uint32_t swap = current; current = next; next = swap;
            }
        }
        if (current != plan.indicesA) {
            write_error(error_message, error_message_len, @"Metal compact radix parity invariant failed"); return false;
        }

        id<MTLComputeCommandEncoder> heads = [command computeCommandEncoder];
        [heads setComputePipelineState:runtime.compactHeads]; [heads setBuffer:arena offset:0 atIndex:0];
        [heads setBuffer:plan.params offset:0 atIndex:1];
        [heads dispatchThreads:MTLSizeMake(plan.sortRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [heads endEncoding];
        id<MTLComputeCommandEncoder> scan = [command computeCommandEncoder];
        [scan setComputePipelineState:runtime.compactScanLocal]; [scan setBuffer:arena offset:0 atIndex:0];
        [scan setBuffer:plan.params offset:0 atIndex:1];
        [scan dispatchThreads:MTLSizeMake(plan.sortRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [scan endEncoding];
        id<MTLComputeCommandEncoder> scan_blocks = [command computeCommandEncoder];
        [scan_blocks setComputePipelineState:runtime.compactScanBlocks]; [scan_blocks setBuffer:arena offset:0 atIndex:0];
        [scan_blocks setBuffer:plan.params offset:0 atIndex:1]; [scan_blocks setBytes:&block_count length:sizeof(block_count) atIndex:2];
        [scan_blocks dispatchThreads:MTLSizeMake(1u, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
        [scan_blocks endEncoding];
        id<MTLComputeCommandEncoder> scan_add = [command computeCommandEncoder];
        [scan_add setComputePipelineState:runtime.compactScanAdd]; [scan_add setBuffer:arena offset:0 atIndex:0];
        [scan_add setBuffer:plan.params offset:0 atIndex:1];
        [scan_add dispatchThreads:MTLSizeMake(plan.sortRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [scan_add endEncoding];
        NSUInteger consumer_width = MIN((NSUInteger)256u, MIN((NSUInteger)plan.consumerRows, runtime.compactClearOutputs.maxTotalThreadsPerThreadgroup));
        id<MTLComputeCommandEncoder> clear = [command computeCommandEncoder];
        [clear setComputePipelineState:runtime.compactClearOutputs]; [clear setBuffer:arena offset:0 atIndex:0];
        [clear setBuffer:plan.outputOffsets offset:0 atIndex:1]; [clear setBuffer:plan.params offset:0 atIndex:2];
        [clear dispatchThreads:MTLSizeMake(plan.consumerRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(consumer_width, 1u, 1u)];
        [clear endEncoding];
        id<MTLComputeCommandEncoder> compact_scatter = [command computeCommandEncoder];
        [compact_scatter setComputePipelineState:runtime.compactScatter]; [compact_scatter setBuffer:arena offset:0 atIndex:0];
        [compact_scatter setBuffer:plan.outputOffsets offset:0 atIndex:1]; [compact_scatter setBuffer:plan.params offset:0 atIndex:2];
        [compact_scatter dispatchThreads:MTLSizeMake(plan.totalRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [compact_scatter endEncoding];
        id<MTLComputeCommandEncoder> finalize = [command computeCommandEncoder];
        [finalize setComputePipelineState:runtime.compactFinalize]; [finalize setBuffer:arena offset:0 atIndex:0];
        [finalize setBuffer:plan.outputOffsets offset:0 atIndex:1]; [finalize setBuffer:plan.params offset:0 atIndex:2];
        [finalize dispatchThreads:MTLSizeMake(plan.consumerRows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(consumer_width, 1u, 1u)];
        [finalize endEncoding];
        [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription); return false;
        }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

bool stwo_zig_metal_ec_op_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigEcOpPlan *plan = (__bridge StwoZigEcOpPlan *)plan_ptr;
        uint32_t rows = plan.rowCount;
        NSUInteger width = MIN(plan.threadgroupWidth, MIN((NSUInteger)rows, plan.pipeline.maxTotalThreadsPerThreadgroup));
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:plan.pipeline]; [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBuffer:plan.executionOffsets offset:0 atIndex:1]; [encoder setBuffer:plan.traceOffsets offset:0 atIndex:2];
        [encoder setBuffer:plan.partialOffsets offset:0 atIndex:3]; [encoder setBuffer:plan.multiplicityOffsets offset:0 atIndex:4];
        [encoder setBuffer:plan.params offset:0 atIndex:5];
        [encoder dispatchThreads:MTLSizeMake(rows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        if (plan.writeBase) {
            NSUInteger finalize_width = MIN((NSUInteger)256u, runtime.ecOpBaseFinalize.maxTotalThreadsPerThreadgroup);
            [encoder setComputePipelineState:runtime.ecOpBaseFinalize]; [encoder setBuffer:arena offset:0 atIndex:0];
            [encoder setBuffer:plan.partialOffsets offset:0 atIndex:1]; [encoder setBuffer:plan.params offset:0 atIndex:2];
            [encoder dispatchThreads:MTLSizeMake((NSUInteger)rows * 4u, 126u, 1u)
               threadsPerThreadgroup:MTLSizeMake(finalize_width, 1u, 1u)];
        }
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) { write_error(error_message, error_message_len, command.error.localizedDescription); return false; }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_relation_prepare(
    void *runtime_ptr, const uint32_t *geometry, uint32_t instance_count,
    const uint32_t *source_offsets, uint32_t source_count,
    const uint32_t *descriptors, uint32_t descriptor_words,
    const uint32_t *output_offsets, uint32_t output_count,
    uint32_t total_blocks, uint32_t alpha_offset_words, uint32_t z_offset_words,
    uint32_t scratch_offset_words, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || geometry == NULL || instance_count == 0u || source_offsets == NULL || source_count == 0u ||
        descriptors == NULL || descriptor_words == 0u || output_offsets == NULL || output_count == 0u || total_blocks == 0u) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigRelationPlan *plan = [StwoZigRelationPlan new];
        plan.geometry = [runtime.device newBufferWithBytes:geometry length:(NSUInteger)instance_count * 10u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.sourceOffsets = [runtime.device newBufferWithBytes:source_offsets length:(NSUInteger)source_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.descriptors = [runtime.device newBufferWithBytes:descriptors length:(NSUInteger)descriptor_words * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.outputOffsets = [runtime.device newBufferWithBytes:output_offsets length:(NSUInteger)output_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.instanceCount = instance_count; plan.totalBlocks = total_blocks;
        plan.alphaByteOffset = (NSUInteger)alpha_offset_words * sizeof(uint32_t);
        plan.zByteOffset = (NSUInteger)z_offset_words * sizeof(uint32_t);
        plan.scratchByteOffset = (NSUInteger)scratch_offset_words * sizeof(uint32_t);
        if (plan.geometry == nil || plan.sourceOffsets == nil || plan.descriptors == nil || plan.outputOffsets == nil) {
            write_error(error_message, error_message_len, @"Metal relation plan allocation failed"); return NULL;
        }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_relation_plan_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

bool stwo_zig_metal_relation_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigRelationPlan *plan = (__bridge StwoZigRelationPlan *)plan_ptr;
        uint32_t instances = plan.instanceCount, blocks = plan.totalBlocks;
        bool profile_relation = getenv("STWO_METAL_PROFILE_RELATION") != NULL;
        CFAbsoluteTime started = profile_relation ? CFAbsoluteTimeGetCurrent() : 0;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> fused = [command computeCommandEncoder];
        [fused setComputePipelineState:runtime.relationFused];
        [fused setBuffer:arena offset:0 atIndex:0]; [fused setBuffer:plan.geometry offset:0 atIndex:1];
        [fused setBuffer:plan.sourceOffsets offset:0 atIndex:2]; [fused setBuffer:plan.descriptors offset:0 atIndex:3];
        [fused setBuffer:plan.outputOffsets offset:0 atIndex:4]; [fused setBuffer:arena offset:plan.alphaByteOffset atIndex:5];
        [fused setBuffer:arena offset:plan.zByteOffset atIndex:6]; [fused setBytes:&instances length:sizeof(instances) atIndex:7];
        [fused dispatchThreads:MTLSizeMake((NSUInteger)blocks * 256u, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
        [fused endEncoding];
        id<MTLComputeCommandEncoder> local_scan = [command computeCommandEncoder];
        [local_scan setComputePipelineState:runtime.relationBlockScan];
        [local_scan setBuffer:arena offset:0 atIndex:0]; [local_scan setBuffer:plan.geometry offset:0 atIndex:1];
        [local_scan setBuffer:plan.outputOffsets offset:0 atIndex:2]; [local_scan setBuffer:arena offset:plan.scratchByteOffset atIndex:3];
        [local_scan setBytes:&instances length:sizeof(instances) atIndex:4];
        [local_scan dispatchThreadgroups:MTLSizeMake(blocks, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
        [local_scan endEncoding];
        id<MTLComputeCommandEncoder> block_scan = [command computeCommandEncoder];
        [block_scan setComputePipelineState:runtime.relationScanBlocks];
        [block_scan setBuffer:arena offset:0 atIndex:0]; [block_scan setBuffer:plan.geometry offset:0 atIndex:1];
        [block_scan setBuffer:arena offset:plan.scratchByteOffset atIndex:2]; [block_scan setBytes:&instances length:sizeof(instances) atIndex:3];
        NSUInteger scan_width = MIN((NSUInteger)256u, runtime.relationScanBlocks.maxTotalThreadsPerThreadgroup);
        [block_scan dispatchThreads:MTLSizeMake(instances, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(scan_width, 1u, 1u)];
        [block_scan endEncoding];
        id<MTLComputeCommandEncoder> finalize = [command computeCommandEncoder];
        [finalize setComputePipelineState:runtime.relationScanFinalize];
        [finalize setBuffer:arena offset:0 atIndex:0]; [finalize setBuffer:plan.geometry offset:0 atIndex:1];
        [finalize setBuffer:plan.outputOffsets offset:0 atIndex:2]; [finalize setBuffer:arena offset:plan.scratchByteOffset atIndex:3];
        [finalize setBytes:&instances length:sizeof(instances) atIndex:4];
        [finalize dispatchThreads:MTLSizeMake((NSUInteger)blocks * 256u, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
        [finalize endEncoding];
        CFAbsoluteTime encoded = profile_relation ? CFAbsoluteTimeGetCurrent() : 0;
        [command commit];
        CFAbsoluteTime committed = profile_relation ? CFAbsoluteTimeGetCurrent() : 0;
        [command waitUntilCompleted];
        if (profile_relation) {
            CFAbsoluteTime completed = CFAbsoluteTimeGetCurrent();
            fprintf(stderr, "metal_relation_wall blocks=%u encode_ms=%.3f commit_ms=%.3f wait_ms=%.3f kernel_ms=%.3f gpu_ms=%.3f\n",
                blocks, (encoded - started) * 1000.0, (committed - encoded) * 1000.0,
                (completed - committed) * 1000.0, (command.kernelEndTime - command.kernelStartTime) * 1000.0,
                (command.GPUEndTime - command.GPUStartTime) * 1000.0);
        }
        if (command.status == MTLCommandBufferStatusError) { write_error(error_message, error_message_len, command.error.localizedDescription); return false; }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

bool stwo_zig_metal_witness_feed_counts_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr, uint32_t column_length,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL || column_length == 0u) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigWitnessFeedPlan *plan = (__bridge StwoZigWitnessFeedPlan *)plan_ptr;
        uint32_t descriptor_count = plan.descriptorCount;
        uint32_t clear_range_count = plan.clearRangeCount;
        uint32_t clear_total_words = plan.clearTotalWords;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.clearArenaSpans];
        [encoder setBuffer:arena offset:0 atIndex:0]; [encoder setBuffer:plan.clearRanges offset:0 atIndex:1];
        [encoder setBytes:&clear_range_count length:sizeof(clear_range_count) atIndex:2]; [encoder setBytes:&clear_total_words length:sizeof(clear_total_words) atIndex:3];
        NSUInteger clear_width = MIN(runtime.clearArenaSpans.maxTotalThreadsPerThreadgroup, runtime.clearArenaSpans.threadExecutionWidth * 8u);
        [encoder dispatchThreads:MTLSizeMake(clear_total_words, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(clear_width, 1u, 1u)];
        [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        [encoder setComputePipelineState:runtime.witnessFeedCounts];
        [encoder setBuffer:arena offset:0 atIndex:0]; [encoder setBuffer:plan.descriptors offset:0 atIndex:1]; [encoder setBuffer:plan.luts offset:0 atIndex:2];
        [encoder setBuffer:plan.destinationOffsets offset:0 atIndex:3]; [encoder setBuffer:plan.sourceOffsets offset:0 atIndex:4];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:5]; [encoder setBytes:&descriptor_count length:sizeof(descriptor_count) atIndex:6];
        NSUInteger width = MIN(runtime.witnessFeedCounts.maxTotalThreadsPerThreadgroup, runtime.witnessFeedCounts.threadExecutionWidth * 8u);
        [encoder dispatchThreads:MTLSizeMake(column_length, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) { write_error(error_message, error_message_len, command.error.localizedDescription); return false; }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}
