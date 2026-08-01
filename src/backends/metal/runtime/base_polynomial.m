typedef struct {
    void *plan;
    const uint32_t *selector;
    uint32_t main_column_offset;
    uint32_t main_column_count;
    uint32_t row_count;
    uint32_t power_word_offset;
    uint32_t power_word_count;
    uint32_t output_index;
    uint32_t denominator_inverses[2];
} StwoZigBasePolynomialDispatch;

typedef struct {
    uint32_t *columns[4];
    uint32_t row_count;
} StwoZigBasePolynomialOutput;

void *stwo_zig_metal_base_polynomial_prepare_aot(
    void *runtime_ptr, const char *name_bytes, size_t name_len,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || name_bytes == NULL || name_len == 0u) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSString *name = [[NSString alloc] initWithBytes:name_bytes
                                                  length:name_len
                                                encoding:NSUTF8StringEncoding];
        if (name == nil) {
            write_error(error_message, error_message_len,
                        @"Invalid base-polynomial function encoding");
            return NULL;
        }
        if (![name hasPrefix:@"stwo_zig_base_poly_"]) {
            write_error(error_message, error_message_len,
                        [NSString stringWithFormat:
                            @"Metal function %@ is not a base-polynomial kernel", name]);
            return NULL;
        }
        id<MTLComputePipelineState> pipeline = runtime.riscvPolynomialPipelines[name];
        if (pipeline == nil) {
            write_error(error_message, error_message_len,
                        [NSString stringWithFormat:@"Missing Metal function %@", name]);
            return NULL;
        }
        StwoZigBasePolynomialPlan *plan = [StwoZigBasePolynomialPlan new];
        plan.pipeline = pipeline;
        return (__bridge_retained void *)plan;
    }
}

void *stwo_zig_metal_base_polynomial_prepare_library(
    void *runtime_ptr, void *library_ptr, const char *name_bytes, size_t name_len,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || library_ptr == NULL || name_bytes == NULL || name_len == 0u)
        return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigEvalLibrary *library = (__bridge StwoZigEvalLibrary *)library_ptr;
        NSString *name = [[NSString alloc] initWithBytes:name_bytes
                                                  length:name_len
                                                encoding:NSUTF8StringEncoding];
        if (name == nil) {
            write_error(error_message, error_message_len,
                        @"Invalid base-polynomial function encoding");
            return NULL;
        }
        id<MTLComputePipelineState> pipeline = resolve_eval_pipeline(
            runtime, library, name, error_message, error_message_len
        );
        if (pipeline == nil) return NULL;
        StwoZigBasePolynomialPlan *plan = [StwoZigBasePolynomialPlan new];
        plan.pipeline = pipeline;
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_base_polynomial_plan_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

bool stwo_zig_metal_base_polynomial_batch(
    void *runtime_ptr,
    void *const *tree_ptrs,
    uint32_t tree_count,
    const uint32_t *const *main_columns,
    uint32_t total_main_columns,
    const StwoZigBasePolynomialDispatch *dispatches,
    uint32_t dispatch_count,
    const uint32_t *power_words,
    uint32_t total_power_words,
    const StwoZigBasePolynomialOutput *outputs,
    uint32_t output_count,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || tree_ptrs == NULL || tree_count == 0u ||
        main_columns == NULL || total_main_columns == 0u ||
        dispatches == NULL || dispatch_count == 0u || power_words == NULL ||
        total_power_words == 0u || outputs == NULL || output_count == 0u)
        return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSMutableArray<StwoZigMetalTree *> *trees = [NSMutableArray arrayWithCapacity:tree_count];
        for (uint32_t index = 0u; index < tree_count; ++index) {
            if (tree_ptrs[index] == NULL) continue;
            StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)tree_ptrs[index];
            if (tree.runtimeOwner != runtime) {
                write_error(error_message, error_message_len,
                            @"Base-polynomial tree belongs to another runtime");
                return false;
            }
            [trees addObject:tree];
        }
        if (trees.count == 0u) {
            write_error(error_message, error_message_len,
                        @"Base-polynomial batch has no resident trees");
            return false;
        }

        id<MTLBuffer> powers = [runtime.device newBufferWithBytes:power_words
            length:(NSUInteger)total_power_words * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        if (powers == nil) {
            write_error(error_message, error_message_len,
                        @"Base-polynomial power allocation failed");
            return false;
        }

        NSMutableArray<id<MTLBuffer>> *outputBuffers =
            [NSMutableArray arrayWithCapacity:output_count];
        for (uint32_t index = 0u; index < output_count; ++index) {
            uint32_t rows = outputs[index].row_count;
            if (rows == 0u || (rows & (rows - 1u)) != 0u) {
                write_error(error_message, error_message_len,
                            @"Invalid base-polynomial output shape");
                return false;
            }
            for (uint32_t coordinate = 0u; coordinate < 4u; ++coordinate) {
                if (outputs[index].columns[coordinate] == NULL) {
                    write_error(error_message, error_message_len,
                                @"Missing base-polynomial output column");
                    return false;
                }
            }
            NSUInteger bytes = (NSUInteger)rows * 4u * sizeof(uint32_t);
            id<MTLBuffer> output = [runtime.device newBufferWithLength:bytes
                options:MTLResourceStorageModeShared];
            if (output == nil || output.contents == NULL) {
                write_error(error_message, error_message_len,
                            @"Base-polynomial output allocation failed");
                return false;
            }
            memset(output.contents, 0, bytes);
            [outputBuffers addObject:output];
        }

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (command == nil || encoder == nil) {
            write_error(error_message, error_message_len,
                        @"Base-polynomial command allocation failed");
            return false;
        }

        for (uint32_t index = 0u; index < dispatch_count; ++index) {
            const StwoZigBasePolynomialDispatch *item = &dispatches[index];
            if (item->plan == NULL || item->selector == NULL ||
                item->main_column_count == 0u ||
                item->row_count == 0u || (item->row_count & (item->row_count - 1u)) != 0u ||
                item->main_column_offset > total_main_columns ||
                item->main_column_count > total_main_columns - item->main_column_offset ||
                item->output_index >= output_count ||
                outputs[item->output_index].row_count != item->row_count ||
                item->power_word_count == 0u ||
                item->power_word_offset > total_power_words ||
                item->power_word_count > total_power_words - item->power_word_offset) {
                [encoder endEncoding];
                write_error(error_message, error_message_len,
                            @"Invalid base-polynomial dispatch");
                return false;
            }
            StwoZigResidentColumnBinding mainBinding = {0};
            StwoZigResidentColumnBinding selectorBinding = {0};
            bool mainResident = true;
            for (uint32_t column = 0u; column < item->main_column_count; ++column) {
                StwoZigResidentColumnBinding columnBinding = {0};
                if (!stwo_zig_tree_resident_column(
                        trees,
                        main_columns[item->main_column_offset + column],
                        item->row_count,
                        &columnBinding)) {
                    mainResident = false;
                    break;
                }
                if (column == 0u) {
                    mainBinding = columnBinding;
                } else if (columnBinding.buffer != mainBinding.buffer ||
                           columnBinding.wordOffset !=
                               mainBinding.wordOffset + (size_t)column * item->row_count) {
                    mainResident = false;
                    break;
                }
            }
            if (!mainResident || !stwo_zig_tree_resident_column(
                    trees, item->selector, item->row_count, &selectorBinding)) {
                [encoder endEncoding];
                write_error(error_message, error_message_len,
                            @"Base-polynomial input is not proof-resident");
                return false;
            }

            StwoZigBasePolynomialPlan *plan =
                (__bridge StwoZigBasePolynomialPlan *)item->plan;
            if (plan.pipeline == nil) {
                [encoder endEncoding];
                write_error(error_message, error_message_len,
                            @"Base-polynomial pipeline is missing");
                return false;
            }
            [encoder setComputePipelineState:plan.pipeline];
            [encoder setBuffer:mainBinding.buffer
                        offset:mainBinding.wordOffset * sizeof(uint32_t)
                       atIndex:0];
            [encoder setBuffer:selectorBinding.buffer
                        offset:selectorBinding.wordOffset * sizeof(uint32_t)
                       atIndex:1];
            [encoder setBuffer:powers
                        offset:(NSUInteger)item->power_word_offset * sizeof(uint32_t)
                       atIndex:2];
            [encoder setBuffer:outputBuffers[item->output_index] offset:0u atIndex:3];
            [encoder setBytes:&item->row_count length:sizeof(item->row_count) atIndex:4];
            [encoder setBytes:&item->denominator_inverses
                       length:sizeof(item->denominator_inverses)
                      atIndex:5];
            NSUInteger width = MIN(
                plan.pipeline.maxTotalThreadsPerThreadgroup,
                plan.pipeline.threadExecutionWidth * 8u
            );
            [encoder dispatchThreads:MTLSizeMake(item->row_count, 1u, 1u)
                threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        }
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?:
                            @"Base-polynomial command failed");
            return false;
        }

        for (uint32_t index = 0u; index < output_count; ++index) {
            uint32_t rows = outputs[index].row_count;
            const uint32_t *source = outputBuffers[index].contents;
            for (uint32_t coordinate = 0u; coordinate < 4u; ++coordinate)
                memcpy(outputs[index].columns[coordinate],
                       source + (size_t)coordinate * rows,
                       (size_t)rows * sizeof(uint32_t));
        }
        if (gpu_milliseconds != NULL)
            *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}
