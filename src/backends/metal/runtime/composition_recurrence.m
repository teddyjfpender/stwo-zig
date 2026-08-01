bool stwo_zig_metal_recurrence_composition(
    void *runtime_ptr,
    void *resident_tree_handle,
    const uint32_t *trace_first,
    uint32_t row_count,
    uint32_t column_count,
    uint32_t column_stride,
    const uint32_t *power_words,
    uint32_t power_word_count,
    const uint32_t *denominator_inverses,
    uint32_t *output_words,
    size_t output_word_count,
    const uint32_t *inverse_twiddles,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || trace_first == NULL || power_words == NULL ||
        denominator_inverses == NULL || output_words == NULL || inverse_twiddles == NULL ||
        row_count == 0u || row_count > UINT32_MAX / 4u ||
        column_count < 3u || column_stride < row_count ||
        power_word_count != (column_count - 2u) * 4u ||
        output_word_count != (size_t)row_count * 4u) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        uint32_t log_size = 0u;
        uint32_t remaining_rows = row_count;
        while (remaining_rows > 1u) {
            if ((remaining_rows & 1u) != 0u) return false;
            remaining_rows >>= 1u;
            log_size += 1u;
        }
        if (log_size < 11u || log_size >= 31u) return false;
        uint32_t pair_count = row_count >> 1u;
        const uint32_t coordinate_count = 4u;
        size_t trace_word_count = (size_t)(column_count - 1u) * column_stride + row_count;
        if (trace_word_count > SIZE_MAX / sizeof(uint32_t) ||
            output_word_count > SIZE_MAX / sizeof(uint32_t)) return false;
        uintptr_t trace_address = (uintptr_t)trace_first;
        size_t trace_bytes = trace_word_count * sizeof(uint32_t);
        if (trace_address > UINTPTR_MAX - trace_bytes) return false;

        size_t page_size = (size_t)getpagesize();
        id<MTLBuffer> trace_buffer = nil;
        NSUInteger trace_offset = 0u;
        StwoZigMetalTree *resident_tree = resident_tree_handle == NULL
            ? nil
            : (__bridge StwoZigMetalTree *)resident_tree_handle;
        if (resident_tree != nil) {
            if (resident_tree.runtimeOwner != runtime) {
                write_error(error_message, error_message_len,
                            @"Metal composition residency handle mismatch");
                return false;
            }
            StwoZigResidentColumnBinding resident_binding;
            if (stwo_zig_tree_resident_column(
                    @[ resident_tree ], trace_first, trace_word_count, &resident_binding)) {
                trace_buffer = resident_binding.buffer;
                trace_offset = (NSUInteger)resident_binding.wordOffset * sizeof(uint32_t);
            }
        }
        if (trace_buffer == nil) {
            // Nonresident structurally admitted traces retain a call-local
            // alias. No runtime-wide "last trace" state participates.
            uintptr_t alias_address = trace_address - (trace_address % page_size);
            size_t trace_offset_bytes = (size_t)(trace_address - alias_address);
            if (trace_bytes > SIZE_MAX - trace_offset_bytes) return false;
            size_t alias_span = trace_offset_bytes + trace_bytes;
            if (alias_span > SIZE_MAX - (page_size - 1u)) return false;
            size_t alias_length = (alias_span + page_size - 1u) / page_size * page_size;
            trace_offset = runtime.device.hasUnifiedMemory ? trace_offset_bytes : 0u;
            trace_buffer = runtime.device.hasUnifiedMemory
                ? [runtime.device newBufferWithBytesNoCopy:(void *)alias_address
                                                    length:alias_length
                                                   options:MTLResourceStorageModeShared
                                               deallocator:nil]
                : [runtime.device newBufferWithBytes:(const void *)trace_address
                                              length:trace_bytes
                                             options:MTLResourceStorageModeShared];
        }
        if (trace_buffer == nil) {
            write_error(error_message, error_message_len, @"Metal composition trace binding failed");
            return false;
        }

        size_t output_bytes = output_word_count * sizeof(uint32_t);
        bool direct_output = ((uintptr_t)output_words % page_size) == 0u &&
            (output_bytes % page_size) == 0u;
        id<MTLBuffer> output = direct_output
            ? [runtime.device newBufferWithBytesNoCopy:output_words
                                                length:output_bytes
                                               options:MTLResourceStorageModeShared
                                           deallocator:nil]
            : [runtime.device newBufferWithLength:output_bytes options:MTLResourceStorageModeShared];
        id<MTLBuffer> powers = [runtime.device newBufferWithBytes:power_words
                                                         length:(NSUInteger)power_word_count * sizeof(uint32_t)
                                                        options:MTLResourceStorageModeShared];
        id<MTLBuffer> inverse_buffer = [runtime.device newBufferWithBytes:inverse_twiddles
            length:(NSUInteger)pair_count * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> coordinate_offsets = [runtime.device newBufferWithLength:
            coordinate_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        if (output == nil || powers == nil || inverse_buffer == nil || coordinate_offsets == nil) {
            write_error(error_message, error_message_len, @"Metal composition allocation failed");
            return false;
        }
        uint32_t *offset_words = coordinate_offsets.contents;
        for (uint32_t coordinate = 0u; coordinate < coordinate_count; ++coordinate)
            offset_words[coordinate] = coordinate * row_count;

        id<MTLCommandBuffer> recurrence_command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [recurrence_command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.compositionExtParams];
        [encoder setBuffer:trace_buffer offset:trace_offset atIndex:0];
        [encoder setBuffer:powers offset:0 atIndex:1];
        [encoder setBuffer:output offset:0 atIndex:2];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:3];
        [encoder setBytes:&column_count length:sizeof(column_count) atIndex:4];
        [encoder setBytes:&column_stride length:sizeof(column_stride) atIndex:5];
        [encoder setBytes:denominator_inverses length:2u * sizeof(uint32_t) atIndex:6];
        uint32_t mode = 1u;
        [encoder setBytes:&mode length:sizeof(mode) atIndex:7];
        NSUInteger width = MIN((NSUInteger)256u, runtime.compositionExtParams.maxTotalThreadsPerThreadgroup);
        [encoder dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
             threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding];

        id<MTLComputeCommandEncoder> fused = [recurrence_command computeCommandEncoder];
        [fused setComputePipelineState:runtime.circleIfftFused];
        [fused setBuffer:output offset:0u atIndex:0];
        [fused setBuffer:output offset:0u atIndex:1];
        [fused setBuffer:inverse_buffer offset:0u atIndex:2];
        [fused setBytes:&log_size length:sizeof(log_size) atIndex:3];
        [fused setBytes:&coordinate_count length:sizeof(coordinate_count) atIndex:4];
        uint32_t source_mode = 0u;
        [fused setBytes:&source_mode length:sizeof(source_mode) atIndex:5];
        [fused dispatchThreadgroups:MTLSizeMake(row_count >> 11u, coordinate_count, 1u)
            threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
        [fused endEncoding];

        MTLSize inverse_grid = MTLSizeMake(pair_count, coordinate_count, 1u);
        uint32_t inverse_layer = 11u;
        while (inverse_layer < log_size) {
            if (inverse_layer + 1u < log_size) {
                uint32_t layer_mode = inverse_layer | 0x80000000u;
                id<MTLComputeCommandEncoder> inverse = [recurrence_command computeCommandEncoder];
                [inverse setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [inverse setBuffer:output offset:0u atIndex:0];
                [inverse setBuffer:coordinate_offsets offset:0u atIndex:1];
                [inverse setBuffer:inverse_buffer offset:0u atIndex:2];
                [inverse setBytes:&log_size length:sizeof(log_size) atIndex:3];
                [inverse setBytes:&layer_mode length:sizeof(layer_mode) atIndex:4];
                [inverse setBytes:&coordinate_count length:sizeof(coordinate_count) atIndex:5];
                NSUInteger inverse_width = MIN((NSUInteger)256u,
                    runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [inverse dispatchThreads:MTLSizeMake(row_count >> 2u, coordinate_count, 1u)
                    threadsPerThreadgroup:MTLSizeMake(inverse_width, 1u, 1u)];
                [inverse endEncoding];
                inverse_layer += 2u;
                continue;
            }
            uint32_t inverse_offset = pair_count - (1u << (log_size - inverse_layer));
            id<MTLComputeCommandEncoder> inverse = [recurrence_command computeCommandEncoder];
            [inverse setComputePipelineState:runtime.circleIfftLayer];
            [inverse setBuffer:output offset:0u atIndex:0];
            [inverse setBuffer:inverse_buffer offset:0u atIndex:1];
            [inverse setBytes:&log_size length:sizeof(log_size) atIndex:2];
            [inverse setBytes:&inverse_layer length:sizeof(inverse_layer) atIndex:3];
            [inverse setBytes:&inverse_offset length:sizeof(inverse_offset) atIndex:4];
            [inverse setBytes:&coordinate_count length:sizeof(coordinate_count) atIndex:5];
            [inverse dispatchThreads:inverse_grid threadsPerThreadgroup:MTLSizeMake(
                MIN((NSUInteger)256u, runtime.circleIfftLayer.maxTotalThreadsPerThreadgroup),
                1u, 1u)];
            [inverse endEncoding];
            inverse_layer += 1u;
        }

        uint32_t scale_factor = 1u << (31u - log_size);
        uint32_t total_values = row_count * coordinate_count;
        id<MTLComputeCommandEncoder> scale = [recurrence_command computeCommandEncoder];
        [scale setComputePipelineState:runtime.circleRescale];
        [scale setBuffer:output offset:0u atIndex:0];
        [scale setBytes:&total_values length:sizeof(total_values) atIndex:1];
        [scale setBytes:&scale_factor length:sizeof(scale_factor) atIndex:2];
        [scale dispatchThreads:MTLSizeMake(total_values, 1u, 1u)
            threadsPerThreadgroup:MTLSizeMake(
                MIN((NSUInteger)256u, runtime.circleRescale.maxTotalThreadsPerThreadgroup),
                1u, 1u)];
        [scale endEncoding];
        [recurrence_command commit];
        [recurrence_command waitUntilCompleted];
        if (recurrence_command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        recurrence_command.error.localizedDescription ?: @"Metal composition evaluation failed");
            return false;
        }
        if (!direct_output) memcpy(output_words, output.contents, output_bytes);
        if (gpu_milliseconds != NULL)
            *gpu_milliseconds =
                (recurrence_command.GPUEndTime - recurrence_command.GPUStartTime) * 1000.0;
        return true;
    }
}
