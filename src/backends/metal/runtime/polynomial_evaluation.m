bool stwo_zig_metal_eval_polynomials(
    void *runtime_ptr,
    const uint32_t *const *coefficients,
    const size_t *coefficient_lengths,
    uint32_t coefficient_column_count,
    size_t coefficient_count,
    const uint32_t *factors, size_t factor_word_count,
    const void *basis_tasks, uint32_t basis_task_count,
    uint32_t basis_count,
    const void *tasks, const uint32_t *task_columns, uint32_t task_count,
    uint32_t output_count,
    uint32_t *output,
    uint32_t *basis_threadgroup_width,
    uint32_t *evaluation_threadgroup_width,
    double *gpu_milliseconds,
    char *error_message, size_t error_message_len
) {
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        bool gpu_coefficient_upload = coefficient_count * sizeof(uint32_t) >= (64u * 1024u * 1024u);
        id<MTLBuffer> coefficient_buffer = [runtime.device newBufferWithLength:gpu_coefficient_upload ? sizeof(uint32_t) : coefficient_count * sizeof(uint32_t)
                                                                      options:MTLResourceStorageModeShared];
        id<MTLBuffer> factor_buffer = [runtime.device newBufferWithBytes:factors
                                                                  length:factor_word_count * sizeof(uint32_t)
                                                                 options:MTLResourceStorageModeShared];
        id<MTLBuffer> task_buffer = [runtime.device newBufferWithBytes:tasks
                                                                length:(NSUInteger)task_count * 5u * sizeof(uint32_t)
                                                               options:MTLResourceStorageModeShared];
        id<MTLBuffer> basis_task_buffer = [runtime.device newBufferWithBytes:basis_tasks
                                                                      length:(NSUInteger)basis_task_count * 4u * sizeof(uint32_t)
                                                                     options:MTLResourceStorageModeShared];
        id<MTLBuffer> basis_buffer = [runtime.device newBufferWithLength:(NSUInteger)basis_count * 4u * sizeof(uint32_t)
                                                                 options:MTLResourceStorageModePrivate];
        id<MTLBuffer> output_buffer = [runtime.device newBufferWithLength:(NSUInteger)output_count * 4u * sizeof(uint32_t)
                                                                 options:MTLResourceStorageModeShared];
        if (coefficient_buffer == nil || factor_buffer == nil || task_buffer == nil ||
            basis_task_buffer == nil || basis_buffer == nil || output_buffer == nil) {
            write_error(error_message, error_message_len, @"Metal polynomial evaluation allocation failed");
            return false;
        }
        if (!gpu_coefficient_upload) {
            uint32_t *coefficient_destination = coefficient_buffer.contents;
            size_t coefficient_cursor = 0;
            for (uint32_t i = 0; i < coefficient_column_count; ++i) {
                memcpy(coefficient_destination + coefficient_cursor, coefficients[i],
                       coefficient_lengths[i] * sizeof(uint32_t));
                coefficient_cursor += coefficient_lengths[i];
            }
        }
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        double total_gpu_milliseconds = 0.0;
        bool command_has_work = true;
        NSUInteger eval_dispatches_in_command = 0u;
        NSMutableArray<id<MTLBuffer>> *coefficient_sources = [NSMutableArray array];
        id<MTLComputeCommandEncoder> active_encoder = [command computeCommandEncoder];
        [active_encoder setComputePipelineState:runtime.polynomialBasis];
        [active_encoder setBuffer:factor_buffer offset:0 atIndex:0];
        [active_encoder setBuffer:basis_task_buffer offset:0 atIndex:1];
        [active_encoder setBytes:&basis_task_count length:sizeof(basis_task_count) atIndex:2];
        [active_encoder setBuffer:basis_buffer offset:0 atIndex:3];
        NSUInteger basis_width = MIN((NSUInteger)256u, runtime.polynomialBasis.maxTotalThreadsPerThreadgroup);
        uint32_t max_basis_blocks = 0u;
        const StwoZigPolynomialBasisTask *all_basis_tasks =
            (const StwoZigPolynomialBasisTask *)basis_tasks;
        for (uint32_t task_index = 0u; task_index < basis_task_count; ++task_index) {
            uint32_t blocks = (all_basis_tasks[task_index].basis_length +
                (uint32_t)basis_width - 1u) / (uint32_t)basis_width;
            max_basis_blocks = MAX(max_basis_blocks, blocks);
        }
        [active_encoder dispatchThreadgroups:MTLSizeMake(max_basis_blocks, basis_task_count, 1)
                      threadsPerThreadgroup:MTLSizeMake(basis_width, 1, 1)];
        [active_encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        NSUInteger width = MIN((NSUInteger)256u, runtime.polynomialEval.maxTotalThreadsPerThreadgroup);
        if (gpu_coefficient_upload) {
            size_t column = 0;
            size_t flat_offset = 0;
            size_t page_size = (size_t)getpagesize();
            const StwoZigPolynomialEvalTask *all_tasks = (const StwoZigPolynomialEvalTask *)tasks;
            while (column < coefficient_column_count) {
                size_t run_start = column;
                size_t run_words = coefficient_lengths[column];
                column += 1;
                while (column < coefficient_column_count &&
                       coefficient_lengths[column] <= UINT32_MAX - run_words &&
                       coefficients[column] == coefficients[run_start] + run_words) {
                    run_words += coefficient_lengths[column];
                    column += 1;
                }
                size_t run_bytes = run_words * sizeof(uint32_t);
                uintptr_t address = (uintptr_t)coefficients[run_start];
                bool no_copy = (address % page_size) == 0u && (run_bytes % page_size) == 0u;
                id<MTLBuffer> source = no_copy
                    ? [runtime.device newBufferWithBytesNoCopy:(void *)coefficients[run_start]
                                                        length:run_bytes
                                                       options:MTLResourceStorageModeShared
                                                   deallocator:nil]
                    : [runtime.device newBufferWithBytes:coefficients[run_start]
                                                  length:run_bytes
                                                 options:MTLResourceStorageModeShared];
                NSMutableData *run_task_data = [NSMutableData data];
                for (uint32_t task_index = 0; task_index < task_count; ++task_index) {
                    StwoZigPolynomialEvalTask task = all_tasks[task_index];
                    uint32_t task_column = task_columns[task_index];
                    if (task_column >= run_start && task_column < column) {
                        task.coefficient_offset = (uint32_t)(coefficients[task_column] - coefficients[run_start]);
                        [run_task_data appendBytes:&task length:sizeof(task)];
                    }
                }
                uint32_t run_task_count = (uint32_t)(run_task_data.length / sizeof(StwoZigPolynomialEvalTask));
                if (source == nil || run_task_count == 0u) {
                    if (source == nil) {
                        write_error(error_message, error_message_len, @"Metal coefficient source allocation failed");
                        return false;
                    }
                    flat_offset += run_words;
                    continue;
                }
                id<MTLBuffer> run_tasks = [runtime.device newBufferWithBytes:run_task_data.bytes
                                                                      length:run_task_data.length
                                                                     options:MTLResourceStorageModeShared];
                [coefficient_sources addObject:source];
                [coefficient_sources addObject:run_tasks];
                if (active_encoder == nil) active_encoder = [command computeCommandEncoder];
                [active_encoder setComputePipelineState:runtime.polynomialEval];
                [active_encoder setBuffer:source offset:0 atIndex:0];
                [active_encoder setBuffer:basis_buffer offset:0 atIndex:1];
                [active_encoder setBuffer:run_tasks offset:0 atIndex:2];
                [active_encoder setBytes:&run_task_count length:sizeof(run_task_count) atIndex:3];
                [active_encoder setBuffer:output_buffer offset:0 atIndex:4];
                [active_encoder dispatchThreadgroups:MTLSizeMake(run_task_count, 1, 1)
                         threadsPerThreadgroup:MTLSizeMake(width, 1, 1)];
                command_has_work = true;
                eval_dispatches_in_command += 1u;
                if (eval_dispatches_in_command == 128u) {
                    [active_encoder endEncoding];
                    active_encoder = nil;
                    [command commit];
                    [command waitUntilCompleted];
                    if (command.status == MTLCommandBufferStatusError) {
                        write_error(error_message, error_message_len,
                                    command.error.localizedDescription ?: @"Metal polynomial evaluation failed");
                        return false;
                    }
                    total_gpu_milliseconds += (command.GPUEndTime - command.GPUStartTime) * 1000.0;
                    [coefficient_sources removeAllObjects];
                    command = [runtime.queue commandBuffer];
                    command_has_work = false;
                    eval_dispatches_in_command = 0u;
                }
                flat_offset += run_words;
            }
        } else {
            [active_encoder setComputePipelineState:runtime.polynomialEval];
            [active_encoder setBuffer:coefficient_buffer offset:0 atIndex:0];
            [active_encoder setBuffer:basis_buffer offset:0 atIndex:1];
            [active_encoder setBuffer:task_buffer offset:0 atIndex:2];
            [active_encoder setBytes:&task_count length:sizeof(task_count) atIndex:3];
            [active_encoder setBuffer:output_buffer offset:0 atIndex:4];
            [active_encoder dispatchThreadgroups:MTLSizeMake(task_count, 1, 1)
                     threadsPerThreadgroup:MTLSizeMake(width, 1, 1)];
            command_has_work = true;
        }
        if (command_has_work) {
            [active_encoder endEncoding];
            [command commit];
            [command waitUntilCompleted];
            if (command.status == MTLCommandBufferStatusError) {
                write_error(error_message, error_message_len,
                            command.error.localizedDescription ?: @"Metal polynomial evaluation failed");
                return false;
            }
            total_gpu_milliseconds += (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        }
        memcpy(output, output_buffer.contents, (NSUInteger)output_count * 4u * sizeof(uint32_t));
        if (basis_threadgroup_width != NULL) {
            *basis_threadgroup_width = (uint32_t)basis_width;
        }
        if (evaluation_threadgroup_width != NULL) {
            *evaluation_threadgroup_width = (uint32_t)width;
        }
        if (gpu_milliseconds != NULL) {
            *gpu_milliseconds = total_gpu_milliseconds;
        }
        return true;
    }
}
