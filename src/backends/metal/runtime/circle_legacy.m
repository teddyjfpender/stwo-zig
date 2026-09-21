bool stwo_zig_metal_circle_transform(
    void *runtime_ptr,
    void *source_resident_buffer,
    uint32_t *const *columns,
    uint32_t column_count,
    uint32_t log_size,
    const uint32_t *twiddles,
    bool inverse,
    uint32_t scale_factor,
    uint32_t *source_binding,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    if (source_binding != NULL) *source_binding = 0u;
    if (runtime_ptr == NULL || columns == NULL || twiddles == NULL || column_count == 0u || log_size < 3u || log_size >= 31u) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        uint32_t value_count = 1u << log_size;
        uint32_t pair_count = value_count >> 1u;
        size_t flat_count = (size_t)column_count * value_count;
        size_t values_bytes = flat_count * sizeof(uint32_t);
        size_t page_size = (size_t)getpagesize();
        bool contiguous_values = true;
        for (uint32_t column = 1u; column < column_count; ++column)
            contiguous_values &= columns[column] == columns[0] + (size_t)column * value_count;
        id<MTLBuffer> supplied_values = source_resident_buffer == NULL
            ? nil
            : (__bridge id<MTLBuffer>)source_resident_buffer;
        if (supplied_values != nil &&
            (supplied_values.contents != columns[0] ||
             supplied_values.length != values_bytes || !contiguous_values)) {
            write_error(error_message, error_message_len,
                        @"Metal circle transform resident source mismatch");
            return false;
        }
        bool exact_resident_values = supplied_values != nil;
        bool direct_values = exact_resident_values ||
            (log_size >= 19u && contiguous_values &&
             ((uintptr_t)columns[0] % page_size) == 0u &&
             (values_bytes % page_size) == 0u);
        id<MTLBuffer> values = exact_resident_values
            ? supplied_values
            : (direct_values
                ? [runtime.device newBufferWithBytesNoCopy:columns[0]
                                                    length:values_bytes
                                                   options:MTLResourceStorageModeShared
                                               deallocator:nil]
                : [runtime.device newBufferWithLength:values_bytes
                                              options:MTLResourceStorageModeShared]);
        id<MTLBuffer> twiddle_buffer = [runtime.device newBufferWithBytes:twiddles length:(NSUInteger)pair_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> column_offsets = log_size >= 19u
            ? [runtime.device newBufferWithLength:(NSUInteger)column_count * sizeof(uint32_t)
                                         options:MTLResourceStorageModeShared]
            : nil;
        if (values == nil || twiddle_buffer == nil || (log_size >= 19u && column_offsets == nil)) {
            write_error(error_message, error_message_len, @"Metal circle transform allocation failed");
            return false;
        }
        if (column_offsets != nil) {
            uint32_t *offsets = column_offsets.contents;
            for (uint32_t column = 0u; column < column_count; ++column)
                offsets[column] = column * value_count;
        }
        uint32_t *flat = values.contents;
        if (!direct_values)
            for (uint32_t column = 0; column < column_count; ++column)
                memcpy(flat + (size_t)column * value_count, columns[column], (size_t)value_count * sizeof(uint32_t));

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        MTLSize grid = MTLSizeMake(pair_count, column_count, 1u);
        if (inverse) {
            uint32_t inverse_start_layer = 1u;
            if (log_size >= 19u) {
                id<MTLComputeCommandEncoder> fused = [command computeCommandEncoder];
                [fused setComputePipelineState:runtime.circleIfftFused];
                [fused setBuffer:values offset:0 atIndex:0];
                [fused setBuffer:values offset:0 atIndex:1];
                [fused setBuffer:twiddle_buffer offset:0 atIndex:2];
                [fused setBytes:&log_size length:sizeof(log_size) atIndex:3];
                [fused setBytes:&column_count length:sizeof(column_count) atIndex:4];
                uint32_t source_mode = 0u;
                [fused setBytes:&source_mode length:sizeof(source_mode) atIndex:5];
                [fused dispatchThreadgroups:MTLSizeMake(value_count >> 11u, column_count, 1u)
                         threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
                [fused endEncoding];
                inverse_start_layer = 11u;
            } else {
                id<MTLComputeCommandEncoder> first = [command computeCommandEncoder];
                [first setComputePipelineState:runtime.circleIfftFirst];
                [first setBuffer:values offset:0 atIndex:0];
                [first setBuffer:twiddle_buffer offset:0 atIndex:1];
                [first setBytes:&log_size length:sizeof(log_size) atIndex:2];
                [first setBytes:&column_count length:sizeof(column_count) atIndex:3];
                [first dispatchThreads:grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleIfftFirst.maxTotalThreadsPerThreadgroup), 1u, 1u)];
                [first endEncoding];
            }

            uint32_t layer = inverse_start_layer;
            while (layer < log_size) {
                if (log_size >= 19u && layer + 1u < log_size) {
                    uint32_t layer_mode = layer | 0x80000000u;
                    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                    [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                    [encoder setBuffer:values offset:0 atIndex:0];
                    [encoder setBuffer:column_offsets offset:0 atIndex:1];
                    [encoder setBuffer:twiddle_buffer offset:0 atIndex:2];
                    [encoder setBytes:&log_size length:sizeof(log_size) atIndex:3];
                    [encoder setBytes:&layer_mode length:sizeof(layer_mode) atIndex:4];
                    [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                    NSUInteger width = MIN((NSUInteger)256u, runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                    [encoder dispatchThreads:MTLSizeMake(value_count >> 2u, column_count, 1u)
                         threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                    [encoder endEncoding];
                    layer += 2u;
                    continue;
                }
                uint32_t twiddle_offset = pair_count - (1u << (log_size - layer));
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleIfftLayer];
                [encoder setBuffer:values offset:0 atIndex:0];
                [encoder setBuffer:twiddle_buffer offset:0 atIndex:1];
                [encoder setBytes:&log_size length:sizeof(log_size) atIndex:2];
                [encoder setBytes:&layer length:sizeof(layer) atIndex:3];
                [encoder setBytes:&twiddle_offset length:sizeof(twiddle_offset) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                [encoder dispatchThreads:grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleIfftLayer.maxTotalThreadsPerThreadgroup), 1u, 1u)];
                [encoder endEncoding];
                ++layer;
            }
            id<MTLComputeCommandEncoder> scale = [command computeCommandEncoder];
            uint32_t total_values = (uint32_t)flat_count;
            [scale setComputePipelineState:runtime.circleRescale];
            [scale setBuffer:values offset:0 atIndex:0];
            [scale setBytes:&total_values length:sizeof(total_values) atIndex:1];
            [scale setBytes:&scale_factor length:sizeof(scale_factor) atIndex:2];
            [scale dispatchThreads:MTLSizeMake(total_values, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleRescale.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            [scale endEncoding];
        } else {
            uint32_t layer = log_size - 1u;
            uint32_t stop_layer = log_size >= 19u ? 10u : 0u;
            while (layer > stop_layer) {
                if (log_size >= 19u && layer >= 12u) {
                    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                    [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                    [encoder setBuffer:values offset:0 atIndex:0];
                    [encoder setBuffer:column_offsets offset:0 atIndex:1];
                    [encoder setBuffer:twiddle_buffer offset:0 atIndex:2];
                    [encoder setBytes:&log_size length:sizeof(log_size) atIndex:3];
                    [encoder setBytes:&layer length:sizeof(layer) atIndex:4];
                    [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                    NSUInteger width = MIN((NSUInteger)256u, runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                    [encoder dispatchThreads:MTLSizeMake(value_count >> 2u, column_count, 1u)
                         threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                    [encoder endEncoding];
                    layer -= 2u;
                    continue;
                }
                uint32_t twiddle_offset = pair_count - (1u << (log_size - layer));
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftLayer];
                [encoder setBuffer:values offset:0 atIndex:0];
                [encoder setBuffer:twiddle_buffer offset:0 atIndex:1];
                [encoder setBytes:&log_size length:sizeof(log_size) atIndex:2];
                [encoder setBytes:&layer length:sizeof(layer) atIndex:3];
                [encoder setBytes:&twiddle_offset length:sizeof(twiddle_offset) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                [encoder dispatchThreads:grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleRfftLayer.maxTotalThreadsPerThreadgroup), 1u, 1u)];
                [encoder endEncoding];
                --layer;
            }
            id<MTLComputeCommandEncoder> tail = [command computeCommandEncoder];
            if (log_size >= 19u) {
                [tail setComputePipelineState:runtime.circleRfftFused];
                [tail setBuffer:values offset:0 atIndex:0];
                [tail setBuffer:twiddle_buffer offset:0 atIndex:1];
                [tail setBytes:&log_size length:sizeof(log_size) atIndex:2];
                [tail setBytes:&column_count length:sizeof(column_count) atIndex:3];
                [tail dispatchThreadgroups:MTLSizeMake(value_count >> 11u, column_count, 1u)
                         threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
            } else {
                [tail setComputePipelineState:runtime.circleRfftLast];
                [tail setBuffer:values offset:0 atIndex:0];
                [tail setBuffer:twiddle_buffer offset:0 atIndex:1];
                [tail setBytes:&log_size length:sizeof(log_size) atIndex:2];
                [tail setBytes:&column_count length:sizeof(column_count) atIndex:3];
                [tail dispatchThreads:grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleRfftLast.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            }
            [tail endEncoding];
        }
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription ?: @"Metal circle transform failed");
            return false;
        }
        if (!direct_values)
            for (uint32_t column = 0; column < column_count; ++column)
                memcpy(columns[column], flat + (size_t)column * value_count, (size_t)value_count * sizeof(uint32_t));
        if (source_binding != NULL)
            *source_binding = exact_resident_values ? 2u : (direct_values ? 1u : 0u);
        if (gpu_milliseconds != NULL) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_circle_lde_batch_create(
    void *runtime_ptr, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigCircleLdeBatch *batch = [StwoZigCircleLdeBatch new];
        batch.runtime = runtime;
        batch.command = [runtime.queue commandBuffer];
        batch.encodedOperations = 0u;
        batch.finished = NO;
        if (batch.command == nil) {
            write_error(error_message, error_message_len, @"Metal circle LDE batch allocation failed");
            return NULL;
        }
        return (__bridge_retained void *)batch;
    }
}

void stwo_zig_metal_circle_lde_batch_destroy(void *batch_ptr) {
    if (batch_ptr == NULL) return;
    @autoreleasepool {
        StwoZigCircleLdeBatch *batch = (__bridge_transfer StwoZigCircleLdeBatch *)batch_ptr;
        // An unfinished batch has never been committed; releasing the command
        // buffer cancels the encoded work before borrowed host arenas unwind.
        batch.command = nil;
    }
}

bool stwo_zig_metal_circle_lde_batch_finish(
    void *batch_ptr, uint64_t *encoded_operations, double *gpu_milliseconds,
    char *error_message, size_t error_message_len
) {
    if (encoded_operations != NULL) *encoded_operations = 0u;
    if (gpu_milliseconds != NULL) *gpu_milliseconds = 0.0;
    if (batch_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigCircleLdeBatch *batch = (__bridge StwoZigCircleLdeBatch *)batch_ptr;
        if (batch.finished) {
            write_error(error_message, error_message_len, @"Metal circle LDE batch already finished");
            return false;
        }
        const NSUInteger count = batch.encodedOperations;
        double total_gpu_ms = 0.0;
        if (count != 0u) {
            [batch.command commit];
            [batch.command waitUntilCompleted];
            if (batch.command.status == MTLCommandBufferStatusError) {
                write_error(error_message, error_message_len,
                            batch.command.error.localizedDescription ?: @"Metal circle LDE batch failed");
                batch.finished = YES;
                batch.command = nil;
                return false;
            }
            if (batch.command.status != MTLCommandBufferStatusCompleted) {
                write_error(error_message, error_message_len, @"Metal circle LDE batch did not complete");
                batch.finished = YES;
                batch.command = nil;
                return false;
            }
            total_gpu_ms = (batch.command.GPUEndTime - batch.command.GPUStartTime) * 1000.0;
        }
        if (encoded_operations != NULL) *encoded_operations = (uint64_t)count;
        if (gpu_milliseconds != NULL) *gpu_milliseconds = total_gpu_ms;
        batch.finished = YES;
        batch.command = nil;
        return true;
    }
}

static bool circle_lde_impl(
    void *runtime_ptr,
    void *batch_ptr,
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
    uint32_t *source_binding,
    uint32_t *normalization_batch_count,
    uint32_t *forward_skipped_layers,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    if (source_binding != NULL) *source_binding = 0u;
    if (normalization_batch_count != NULL) *normalization_batch_count = 0u;
    if (forward_skipped_layers != NULL) *forward_skipped_layers = 0u;
    if (gpu_milliseconds != NULL) *gpu_milliseconds = 0.0;
    if (runtime_ptr == NULL || source_columns == NULL || base_columns == NULL || extended_words == NULL ||
        inverse_twiddles == NULL || forward_twiddles == NULL || column_count == 0u ||
        base_log_size < 3u || extended_log_size <= base_log_size || extended_log_size >= 31u) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigCircleLdeBatch *batch = batch_ptr == NULL
            ? nil
            : (__bridge StwoZigCircleLdeBatch *)batch_ptr;
        if (batch != nil && (batch.finished || batch.runtime != runtime)) {
            write_error(error_message, error_message_len, @"Metal circle LDE batch authority mismatch");
            return false;
        }
        uint32_t base_len = 1u << base_log_size;
        uint32_t extended_len = 1u << extended_log_size;
        uint32_t base_pairs = base_len >> 1u;
        uint32_t extended_pairs = extended_len >> 1u;
        size_t flat_base_count = (size_t)column_count * base_len;
        size_t required_words = (size_t)extended_start +
            (size_t)(column_count - 1u) * extended_stride + extended_len;
        if (extended_stride < extended_len || required_words > extended_word_count ||
            required_words > UINT32_MAX || extended_word_count > SIZE_MAX / sizeof(uint32_t)) {
            write_error(error_message, error_message_len, @"Metal circle LDE arena layout is invalid");
            return false;
        }
        size_t page_size = (size_t)getpagesize();
        size_t base_bytes = flat_base_count * sizeof(uint32_t);
        bool contiguous_base = true;
        bool source_is_base = true;
        for (uint32_t column = 1u; column < column_count; ++column)
            contiguous_base &= base_columns[column] == base_columns[0] + (size_t)column * base_len;
        for (uint32_t column = 0u; column < column_count; ++column)
            source_is_base &= source_columns[column] == base_columns[column];
        bool direct_base = contiguous_base && ((uintptr_t)base_columns[0] % page_size) == 0u &&
            (base_bytes % page_size) == 0u;
        // Attribution, reported from the branch that decides it: 1 = the source
        // columns already are the page-aligned base arena, so `coefficients` is
        // a no-copy alias of host memory and nothing is copied; 2 = the source
        // is the base arena but the alias preconditions failed, so the commit
        // pays exactly one memcpy per column below; 0 = the source is not the
        // base arena at all and the fused-upload/blit encoder runs.
        if (source_binding != NULL)
            *source_binding = source_is_base ? (direct_base ? 1u : 2u) : 0u;
        id<MTLBuffer> coefficients = direct_base
            ? [runtime.device newBufferWithBytesNoCopy:base_columns[0]
                                                length:base_bytes
                                               options:MTLResourceStorageModeShared
                                           deallocator:nil]
            : [runtime.device newBufferWithLength:base_bytes options:MTLResourceStorageModeShared];
        size_t extended_bytes = extended_word_count * sizeof(uint32_t);
        bool direct_extended = ((uintptr_t)extended_words % page_size) == 0u &&
            (extended_bytes % page_size) == 0u;
        id<MTLBuffer> extended = direct_extended
            ? [runtime.device newBufferWithBytesNoCopy:extended_words
                                                length:extended_bytes
                                               options:MTLResourceStorageModeShared
                                           deallocator:nil]
            : [runtime.device newBufferWithLength:extended_bytes options:MTLResourceStorageModeShared];
        id<MTLBuffer> inverse_buffer = [runtime.device newBufferWithBytes:inverse_twiddles length:(NSUInteger)base_pairs * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> forward_buffer = [runtime.device newBufferWithBytes:forward_twiddles length:(NSUInteger)extended_pairs * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> base_offsets = [runtime.device newBufferWithLength:(NSUInteger)column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> extended_offsets = [runtime.device newBufferWithLength:(NSUInteger)column_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        if (coefficients == nil || extended == nil || inverse_buffer == nil || forward_buffer == nil ||
            base_offsets == nil || extended_offsets == nil) {
            write_error(error_message, error_message_len, @"Metal circle LDE allocation failed");
            return false;
        }
        uint32_t *base_offset_words = base_offsets.contents;
        uint32_t *extended_offset_words = extended_offsets.contents;
        for (uint32_t column = 0; column < column_count; ++column) {
            base_offset_words[column] = column * base_len;
            extended_offset_words[column] = extended_start + column * extended_stride;
        }

        const bool batched_direct = batch != nil && direct_base && direct_extended;
        id<MTLCommandBuffer> command = batched_direct
            ? batch.command
            : [runtime.queue commandBuffer];
        NSMutableArray<id<MTLBuffer>> *input_sources = [NSMutableArray array];
        // The compute encoder amortizes only on large domains. Below log 16,
        // the established blit plus fused tail is faster and less variable.
        bool fused_upload = !source_is_base && base_log_size >= 16u;
        if (!source_is_base) {
            id<MTLComputeCommandEncoder> fused_upload_encoder = fused_upload
                ? [command computeCommandEncoder]
                : nil;
            id<MTLBlitCommandEncoder> upload = fused_upload
                ? nil
                : [command blitCommandEncoder];
            uint32_t source_mode = 1u;
            if (fused_upload) {
                [fused_upload_encoder setComputePipelineState:runtime.circleIfftFused];
                [fused_upload_encoder setBytes:&source_mode length:sizeof(source_mode) atIndex:5];
            }
            size_t column = 0;
            size_t destination_words = 0;
            while (column < column_count) {
                size_t run_start = column;
                size_t run_words = base_len;
                column += 1;
                while (column < column_count && source_columns[column] == source_columns[run_start] + run_words) {
                    run_words += base_len;
                    column += 1;
                }
                size_t run_bytes = run_words * sizeof(uint32_t);
                uintptr_t address = (uintptr_t)source_columns[run_start];
                bool no_copy = (address % page_size) == 0u && (run_bytes % page_size) == 0u;
                id<MTLBuffer> source = no_copy
                    ? [runtime.device newBufferWithBytesNoCopy:(void *)source_columns[run_start]
                                                        length:run_bytes
                                                       options:MTLResourceStorageModeShared
                                                   deallocator:nil]
                    : [runtime.device newBufferWithBytes:source_columns[run_start]
                                                  length:run_bytes
                                                 options:MTLResourceStorageModeShared];
                if (source == nil) {
                    write_error(error_message, error_message_len, @"Metal circle source allocation failed");
                    return false;
                }
                [input_sources addObject:source];
                if (fused_upload) {
                    uint32_t destination_column = (uint32_t)(destination_words / base_len);
                    [fused_upload_encoder setBuffer:source offset:0 atIndex:0];
                    [fused_upload_encoder setBuffer:coefficients offset:0 atIndex:1];
                    [fused_upload_encoder setBuffer:inverse_buffer offset:0 atIndex:2];
                    [fused_upload_encoder setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
                    [fused_upload_encoder setBytes:&destination_column length:sizeof(destination_column) atIndex:4];
                    [fused_upload_encoder dispatchThreadgroups:MTLSizeMake(base_len >> 11u, run_words / base_len, 1u)
                                           threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
                } else {
                    [upload copyFromBuffer:source sourceOffset:0 toBuffer:coefficients
                         destinationOffset:destination_words * sizeof(uint32_t) size:run_bytes];
                }
                destination_words += run_words;
            }
            if (fused_upload)
                [fused_upload_encoder endEncoding];
            else
                [upload endEncoding];
        } else if (!direct_base) {
            uint32_t *coefficient_words = coefficients.contents;
            for (uint32_t column = 0u; column < column_count; ++column)
                memcpy(coefficient_words + (size_t)column * base_len,
                       source_columns[column], (size_t)base_len * sizeof(uint32_t));
        }
        MTLSize base_grid = MTLSizeMake(base_pairs, column_count, 1u);
        uint32_t inverse_start_layer = 1u;
        if (fused_upload) {
            inverse_start_layer = 11u;
        } else if (base_log_size >= 11u) {
            id<MTLComputeCommandEncoder> fused = [command computeCommandEncoder];
            [fused setComputePipelineState:runtime.circleIfftFused];
            [fused setBuffer:coefficients offset:0 atIndex:0];
            [fused setBuffer:coefficients offset:0 atIndex:1];
            [fused setBuffer:inverse_buffer offset:0 atIndex:2];
            [fused setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
            [fused setBytes:&column_count length:sizeof(column_count) atIndex:4];
            uint32_t source_mode = 0u;
            [fused setBytes:&source_mode length:sizeof(source_mode) atIndex:5];
            [fused dispatchThreadgroups:MTLSizeMake(base_len >> 11u, column_count, 1u)
                     threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
            [fused endEncoding];
            inverse_start_layer = 11u;
        } else {
            id<MTLComputeCommandEncoder> first = [command computeCommandEncoder];
            [first setComputePipelineState:runtime.circleIfftFirst];
            [first setBuffer:coefficients offset:0 atIndex:0];
            [first setBuffer:inverse_buffer offset:0 atIndex:1];
            [first setBytes:&base_log_size length:sizeof(base_log_size) atIndex:2];
            [first setBytes:&column_count length:sizeof(column_count) atIndex:3];
            [first dispatchThreads:base_grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleIfftFirst.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            [first endEncoding];
        }
        uint32_t inverse_layer = inverse_start_layer;
        while (inverse_layer < base_log_size) {
            if (inverse_layer + 1u < base_log_size) {
                uint32_t layer_mode = inverse_layer | 0x80000000u;
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [encoder setBuffer:coefficients offset:0 atIndex:0];
                [encoder setBuffer:base_offsets offset:0 atIndex:1];
                [encoder setBuffer:inverse_buffer offset:0 atIndex:2];
                [encoder setBytes:&base_log_size length:sizeof(base_log_size) atIndex:3];
                [encoder setBytes:&layer_mode length:sizeof(layer_mode) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                NSUInteger width = MIN((NSUInteger)256u, runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [encoder dispatchThreads:MTLSizeMake(base_len >> 2u, column_count, 1u)
                     threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                inverse_layer += 2u;
                continue;
            }
            uint32_t inverse_offset = base_pairs - (1u << (base_log_size - inverse_layer));
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            [encoder setComputePipelineState:runtime.circleIfftLayer];
            [encoder setBuffer:coefficients offset:0 atIndex:0];
            [encoder setBuffer:inverse_buffer offset:0 atIndex:1];
            [encoder setBytes:&base_log_size length:sizeof(base_log_size) atIndex:2];
            [encoder setBytes:&inverse_layer length:sizeof(inverse_layer) atIndex:3];
            [encoder setBytes:&inverse_offset length:sizeof(inverse_offset) atIndex:4];
            [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
            [encoder dispatchThreads:base_grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleIfftLayer.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            [encoder endEncoding];
            ++inverse_layer;
        }
        uint32_t total_base_values = (uint32_t)flat_base_count;
        bool skewed_layout = extended_stride != extended_len;
        uint32_t fuse_top_two = extended_log_size == base_log_size + 1u && base_log_size >= 12u;
        if (fuse_top_two == 0u) {
            id<MTLComputeCommandEncoder> scale = [command computeCommandEncoder];
            [scale setComputePipelineState:runtime.circleRescale];
            [scale setBuffer:coefficients offset:0 atIndex:0];
            [scale setBytes:&total_base_values length:sizeof(total_base_values) atIndex:1];
            [scale setBytes:&scale_factor length:sizeof(scale_factor) atIndex:2];
            [scale dispatchThreads:MTLSizeMake(total_base_values, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleRescale.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            [scale endEncoding];
        }

        id<MTLComputeCommandEncoder> expand = [command computeCommandEncoder];
        [expand setComputePipelineState:runtime.circleExpand];
        [expand setBuffer:coefficients offset:0 atIndex:0];
        [expand setBuffer:extended offset:0 atIndex:1];
        [expand setBuffer:forward_buffer offset:0 atIndex:2];
        [expand setBuffer:base_offsets offset:0 atIndex:3];
        [expand setBuffer:extended_offsets offset:0 atIndex:4];
        [expand setBytes:&base_log_size length:sizeof(base_log_size) atIndex:5];
        [expand setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:6];
        [expand setBytes:&column_count length:sizeof(column_count) atIndex:7];
        [expand setBytes:&scale_factor length:sizeof(scale_factor) atIndex:8];
        [expand setBytes:&fuse_top_two length:sizeof(fuse_top_two) atIndex:9];
        NSUInteger expand_count = fuse_top_two != 0u ? base_len >> 1u : extended_len;
        [expand dispatchThreads:MTLSizeMake(expand_count, column_count, 1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleExpand.maxTotalThreadsPerThreadgroup), 1u, 1u)];
        [expand endEncoding];

        MTLSize extended_grid = MTLSizeMake(extended_pairs, column_count, 1u);
        uint32_t forward_stop_layer = extended_log_size >= 11u ? 10u : 0u;
        uint32_t layer = extended_log_size - 1u - (fuse_top_two != 0u ? 2u : 0u);
        while (layer > forward_stop_layer) {
            if (layer >= 12u) {
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                [encoder setComputePipelineState:runtime.circleRfftRadix4Sparse];
                [encoder setBuffer:extended offset:0 atIndex:0];
                [encoder setBuffer:extended_offsets offset:0 atIndex:1];
                [encoder setBuffer:forward_buffer offset:0 atIndex:2];
                [encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
                [encoder setBytes:&layer length:sizeof(layer) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                NSUInteger width = MIN((NSUInteger)256u, runtime.circleRfftRadix4Sparse.maxTotalThreadsPerThreadgroup);
                [encoder dispatchThreads:MTLSizeMake(extended_len >> 2u, column_count, 1u)
                     threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                layer -= 2u;
                continue;
            }
            uint32_t forward_offset = extended_pairs - (1u << (extended_log_size - layer));
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            if (skewed_layout) {
                [encoder setComputePipelineState:runtime.circleRfftLayerSparse];
                [encoder setBuffer:extended offset:0 atIndex:0];
                [encoder setBuffer:extended_offsets offset:0 atIndex:1];
                [encoder setBuffer:forward_buffer offset:0 atIndex:2];
                [encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
                [encoder setBytes:&layer length:sizeof(layer) atIndex:4];
                [encoder setBytes:&forward_offset length:sizeof(forward_offset) atIndex:5];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:6];
                [encoder dispatchThreads:extended_grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleRfftLayerSparse.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            } else {
                [encoder setComputePipelineState:runtime.circleRfftLayer];
                [encoder setBuffer:extended offset:(NSUInteger)extended_start * sizeof(uint32_t) atIndex:0];
                [encoder setBuffer:forward_buffer offset:0 atIndex:1];
                [encoder setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:2];
                [encoder setBytes:&layer length:sizeof(layer) atIndex:3];
                [encoder setBytes:&forward_offset length:sizeof(forward_offset) atIndex:4];
                [encoder setBytes:&column_count length:sizeof(column_count) atIndex:5];
                [encoder dispatchThreads:extended_grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleRfftLayer.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            }
            [encoder endEncoding];
            --layer;
        }
        if (extended_log_size >= 11u) {
            id<MTLComputeCommandEncoder> fused = [command computeCommandEncoder];
            if (skewed_layout) {
                [fused setComputePipelineState:runtime.circleRfftFusedSparse];
                [fused setBuffer:extended offset:0 atIndex:0];
                [fused setBuffer:extended_offsets offset:0 atIndex:1];
                [fused setBuffer:forward_buffer offset:0 atIndex:2];
                [fused setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
                [fused setBytes:&column_count length:sizeof(column_count) atIndex:4];
            } else {
                [fused setComputePipelineState:runtime.circleRfftFused];
                [fused setBuffer:extended offset:(NSUInteger)extended_start * sizeof(uint32_t) atIndex:0];
                [fused setBuffer:forward_buffer offset:0 atIndex:1];
                [fused setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:2];
                [fused setBytes:&column_count length:sizeof(column_count) atIndex:3];
            }
            [fused dispatchThreadgroups:MTLSizeMake(extended_len >> 11u, column_count, 1u)
                     threadsPerThreadgroup:MTLSizeMake(256u, 1u, 1u)];
            [fused endEncoding];
        } else {
            id<MTLComputeCommandEncoder> last = [command computeCommandEncoder];
            if (skewed_layout) {
                [last setComputePipelineState:runtime.circleRfftLastSparse];
                [last setBuffer:extended offset:0 atIndex:0];
                [last setBuffer:extended_offsets offset:0 atIndex:1];
                [last setBuffer:forward_buffer offset:0 atIndex:2];
                [last setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:3];
                [last setBytes:&column_count length:sizeof(column_count) atIndex:4];
                [last dispatchThreads:extended_grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleRfftLastSparse.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            } else {
                [last setComputePipelineState:runtime.circleRfftLast];
                [last setBuffer:extended offset:(NSUInteger)extended_start * sizeof(uint32_t) atIndex:0];
                [last setBuffer:forward_buffer offset:0 atIndex:1];
                [last setBytes:&extended_log_size length:sizeof(extended_log_size) atIndex:2];
                [last setBytes:&column_count length:sizeof(column_count) atIndex:3];
                [last dispatchThreads:extended_grid threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)256u, runtime.circleRfftLast.maxTotalThreadsPerThreadgroup), 1u, 1u)];
            }
            [last endEncoding];
        }

        // Direct unified-memory bindings need neither deferred copyback nor
        // private-buffer retention. Keep their tuned per-log encoders in one
        // commitment-owned command buffer and submit/fence it exactly once.
        if (batched_direct) {
            batch.encodedOperations += 1u;
            if (normalization_batch_count != NULL) *normalization_batch_count = 1u;
            if (forward_skipped_layers != NULL) *forward_skipped_layers = fuse_top_two != 0u ? 1u : 0u;
            return true;
        }
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription ?: @"Metal circle LDE failed");
            return false;
        }
        if (!direct_base || !direct_extended) {
            uint32_t *coefficient_words = coefficients.contents;
            uint32_t *extension_words = extended.contents;
            for (uint32_t column = 0; column < column_count; ++column) {
                if (!direct_base)
                    memcpy(base_columns[column], coefficient_words + (size_t)column * base_len,
                           (size_t)base_len * sizeof(uint32_t));
                if (!direct_extended)
                    memcpy(extended_words + extended_offset_words[column],
                           extension_words + extended_offset_words[column],
                           (size_t)extended_len * sizeof(uint32_t));
            }
        }
        if (normalization_batch_count != NULL) *normalization_batch_count = 1u;
        if (forward_skipped_layers != NULL) *forward_skipped_layers = fuse_top_two != 0u ? 1u : 0u;
        if (gpu_milliseconds != NULL) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

bool stwo_zig_metal_circle_lde(
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
    uint32_t *source_binding,
    uint32_t *normalization_batch_count,
    uint32_t *forward_skipped_layers,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    return circle_lde_impl(
        runtime_ptr, NULL, source_columns, base_columns, extended_words,
        extended_word_count, extended_start, extended_stride, column_count,
        base_log_size, extended_log_size, inverse_twiddles, forward_twiddles,
        scale_factor, source_binding, normalization_batch_count,
        forward_skipped_layers, gpu_milliseconds, error_message,
        error_message_len);
}

bool stwo_zig_metal_circle_lde_batch_enqueue(
    void *runtime_ptr,
    void *batch_ptr,
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
    uint32_t *source_binding,
    uint32_t *normalization_batch_count,
    uint32_t *forward_skipped_layers,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    if (batch_ptr == NULL) return false;
    return circle_lde_impl(
        runtime_ptr, batch_ptr, source_columns, base_columns, extended_words,
        extended_word_count, extended_start, extended_stride, column_count,
        base_log_size, extended_log_size, inverse_twiddles, forward_twiddles,
        scale_factor, source_binding, normalization_batch_count,
        forward_skipped_layers, gpu_milliseconds, error_message,
        error_message_len);
}
