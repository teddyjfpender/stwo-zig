typedef struct {
    void *plan;
    const uint32_t *selector;
    uint32_t main_column_offset;
    uint32_t main_column_count;
    uint32_t interaction_column_offset;
    uint32_t interaction_column_count;
    uint32_t row_count;
    uint32_t power_word_offset;
    uint32_t power_word_count;
    uint32_t parameter_word_offset;
    uint32_t parameter_word_count;
    uint32_t output_index;
    uint32_t denominator_count;
    uint32_t denominator_inverses[8];
} StwoZigLookupPolynomialDispatch;

void *stwo_zig_metal_lookup_polynomial_prepare_aot(
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
                        @"Invalid lookup-polynomial function encoding");
            return NULL;
        }
        if (![name hasPrefix:@"stwo_zig_lookup_poly_"]) {
            write_error(error_message, error_message_len,
                        [NSString stringWithFormat:
                            @"Metal function %@ is not a lookup-polynomial kernel", name]);
            return NULL;
        }
        id<MTLComputePipelineState> pipeline = runtime.riscvPolynomialPipelines[name];
        if (pipeline == nil) {
            write_error(error_message, error_message_len,
                        [NSString stringWithFormat:@"Missing Metal function %@", name]);
            return NULL;
        }
        StwoZigLookupPolynomialPlan *plan = [StwoZigLookupPolynomialPlan new];
        plan.pipeline = pipeline;
        return (__bridge_retained void *)plan;
    }
}

void *stwo_zig_metal_lookup_polynomial_prepare_library(
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
                        @"Invalid lookup-polynomial function encoding");
            return NULL;
        }
        id<MTLComputePipelineState> pipeline = resolve_eval_pipeline(
            runtime, library, name, error_message, error_message_len
        );
        if (pipeline == nil) return NULL;
        StwoZigLookupPolynomialPlan *plan = [StwoZigLookupPolynomialPlan new];
        plan.pipeline = pipeline;
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_lookup_polynomial_plan_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

static bool stwo_zig_lookup_resident_columns(
    NSArray<StwoZigMetalTree *> *trees,
    void *composition_domain_buffer,
    const uint32_t *composition_domain_host_begin,
    size_t composition_domain_word_count,
    const uint32_t *const *columns,
    uint32_t first,
    uint32_t count,
    uint32_t rows,
    StwoZigResidentColumnBinding *binding
) {
    for (uint32_t column = 0u; column < count; ++column) {
        StwoZigResidentColumnBinding current = {0};
        if (!stwo_zig_polynomial_input_column(
                trees, composition_domain_buffer,
                composition_domain_host_begin,
                composition_domain_word_count,
                columns[first + column], rows, &current))
            return false;
        if (column == 0u) {
            *binding = current;
        } else if (current.buffer != binding->buffer ||
                   current.wordOffset != binding->wordOffset + (size_t)column * rows) {
            return false;
        }
    }
    return true;
}

bool stwo_zig_metal_lookup_polynomial_batch(
    void *runtime_ptr,
    void *const *tree_ptrs,
    uint32_t tree_count,
    void *composition_domain_buffer,
    const uint32_t *composition_domain_host_begin,
    size_t composition_domain_word_count,
    const uint32_t *const *main_columns,
    uint32_t total_main_columns,
    const uint32_t *const *interaction_columns,
    uint32_t total_interaction_columns,
    const StwoZigLookupPolynomialDispatch *dispatches,
    uint32_t dispatch_count,
    const uint32_t *power_words,
    uint32_t total_power_words,
    const uint32_t *parameter_words,
    uint32_t total_parameter_words,
    const StwoZigBasePolynomialOutput *outputs,
    uint32_t output_count,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || tree_ptrs == NULL || tree_count == 0u ||
        main_columns == NULL || total_main_columns == 0u || interaction_columns == NULL ||
        total_interaction_columns == 0u || dispatches == NULL || dispatch_count == 0u ||
        power_words == NULL || total_power_words == 0u || parameter_words == NULL ||
        total_parameter_words == 0u || outputs == NULL || output_count == 0u)
        return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSMutableArray<StwoZigMetalTree *> *trees = [NSMutableArray arrayWithCapacity:tree_count];
        for (uint32_t index = 0u; index < tree_count; ++index) {
            if (tree_ptrs[index] == NULL) continue;
            StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)tree_ptrs[index];
            if (tree.runtimeOwner != runtime) {
                write_error(error_message, error_message_len,
                            @"Lookup-polynomial tree belongs to another runtime");
                return false;
            }
            [trees addObject:tree];
        }
        if (trees.count == 0u) {
            write_error(error_message, error_message_len,
                        @"Lookup-polynomial batch has no resident trees");
            return false;
        }

        id<MTLBuffer> powers = [runtime.device newBufferWithBytes:power_words
            length:(NSUInteger)total_power_words * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> parameters = [runtime.device newBufferWithBytes:parameter_words
            length:(NSUInteger)total_parameter_words * sizeof(uint32_t)
            options:MTLResourceStorageModeShared];
        if (powers == nil || parameters == nil) {
            write_error(error_message, error_message_len,
                        @"Lookup-polynomial parameter allocation failed");
            return false;
        }

        NSMutableArray<id<MTLBuffer>> *outputBuffers =
            [NSMutableArray arrayWithCapacity:output_count];
        for (uint32_t index = 0u; index < output_count; ++index) {
            uint32_t rows = outputs[index].row_count;
            if (rows == 0u || (rows & (rows - 1u)) != 0u) {
                write_error(error_message, error_message_len,
                            @"Invalid lookup-polynomial output shape");
                return false;
            }
            for (uint32_t coordinate = 0u; coordinate < 4u; ++coordinate) {
                if (outputs[index].columns[coordinate] == NULL) {
                    write_error(error_message, error_message_len,
                                @"Missing lookup-polynomial output column");
                    return false;
                }
            }
            NSUInteger bytes = (NSUInteger)rows * 4u * sizeof(uint32_t);
            id<MTLBuffer> output = [runtime.device newBufferWithLength:bytes
                options:MTLResourceStorageModeShared];
            if (output == nil || output.contents == NULL) {
                write_error(error_message, error_message_len,
                            @"Lookup-polynomial output allocation failed");
                return false;
            }
            memset(output.contents, 0, bytes);
            [outputBuffers addObject:output];
        }

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (command == nil || encoder == nil) {
            write_error(error_message, error_message_len,
                        @"Lookup-polynomial command allocation failed");
            return false;
        }
        for (uint32_t index = 0u; index < dispatch_count; ++index) {
            const StwoZigLookupPolynomialDispatch *item = &dispatches[index];
            bool valid = item->plan != NULL && item->selector != NULL &&
                item->main_column_count != 0u && item->interaction_column_count != 0u &&
                item->row_count != 0u && (item->row_count & (item->row_count - 1u)) == 0u &&
                item->main_column_offset <= total_main_columns &&
                item->main_column_count <= total_main_columns - item->main_column_offset &&
                item->interaction_column_offset <= total_interaction_columns &&
                item->interaction_column_count <=
                    total_interaction_columns - item->interaction_column_offset &&
                item->power_word_offset <= total_power_words &&
                item->power_word_count <= total_power_words - item->power_word_offset &&
                item->parameter_word_offset <= total_parameter_words &&
                item->parameter_word_count <= total_parameter_words - item->parameter_word_offset &&
                item->output_index < output_count &&
                outputs[item->output_index].row_count == item->row_count &&
                (item->denominator_count == 2u ||
                 item->denominator_count == 4u ||
                 item->denominator_count == 8u) &&
                item->denominator_count <= item->row_count;
            if (!valid) {
                [encoder endEncoding];
                write_error(error_message, error_message_len,
                            @"Invalid lookup-polynomial dispatch");
                return false;
            }
            StwoZigResidentColumnBinding mainBinding = {0};
            StwoZigResidentColumnBinding interactionBinding = {0};
            StwoZigResidentColumnBinding selectorBinding = {0};
            if (!stwo_zig_lookup_resident_columns(
                    trees, composition_domain_buffer,
                    composition_domain_host_begin,
                    composition_domain_word_count,
                    main_columns, item->main_column_offset,
                    item->main_column_count, item->row_count, &mainBinding) ||
                !stwo_zig_lookup_resident_columns(
                    trees, composition_domain_buffer,
                    composition_domain_host_begin,
                    composition_domain_word_count,
                    interaction_columns, item->interaction_column_offset,
                    item->interaction_column_count, item->row_count, &interactionBinding) ||
                !stwo_zig_polynomial_input_column(
                    trees, composition_domain_buffer,
                    composition_domain_host_begin,
                    composition_domain_word_count,
                    item->selector, item->row_count, &selectorBinding)) {
                [encoder endEncoding];
                write_error(error_message, error_message_len,
                            @"Lookup-polynomial input is not proof-resident");
                return false;
            }

            StwoZigLookupPolynomialPlan *plan =
                (__bridge StwoZigLookupPolynomialPlan *)item->plan;
            if (plan.pipeline == nil) {
                [encoder endEncoding];
                write_error(error_message, error_message_len,
                            @"Lookup-polynomial pipeline is missing");
                return false;
            }
            [encoder setComputePipelineState:plan.pipeline];
            [encoder setBuffer:mainBinding.buffer
                        offset:mainBinding.wordOffset * sizeof(uint32_t) atIndex:0];
            [encoder setBuffer:selectorBinding.buffer
                        offset:selectorBinding.wordOffset * sizeof(uint32_t) atIndex:1];
            [encoder setBuffer:interactionBinding.buffer
                        offset:interactionBinding.wordOffset * sizeof(uint32_t) atIndex:2];
            [encoder setBuffer:parameters
                        offset:(NSUInteger)item->parameter_word_offset * sizeof(uint32_t) atIndex:3];
            [encoder setBuffer:powers
                        offset:(NSUInteger)item->power_word_offset * sizeof(uint32_t) atIndex:4];
            [encoder setBuffer:outputBuffers[item->output_index] offset:0u atIndex:5];
            [encoder setBytes:&item->row_count length:sizeof(item->row_count) atIndex:6];
            [encoder setBytes:&item->denominator_inverses
                       length:sizeof(item->denominator_inverses) atIndex:7];
            [encoder setBytes:&item->denominator_count
                       length:sizeof(item->denominator_count) atIndex:8];
            NSUInteger width = MIN(
                plan.pipeline.maxTotalThreadsPerThreadgroup,
                plan.pipeline.threadExecutionWidth * 8u
            );
            [encoder dispatchThreads:MTLSizeMake(item->row_count, 1u, 1u)
                threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            // Multiple authenticated lookup programs accumulate into one
            // per-log buffer. Order alone is not a device memory dependency;
            // make every preceding read/add/write visible to the next job.
            if (index + 1u < dispatch_count)
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        }
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?:
                            @"Lookup-polynomial command failed");
            return false;
        }

        for (uint32_t index = 0u; index < output_count; ++index) {
            uint32_t rows = outputs[index].row_count;
            const uint32_t *source = outputBuffers[index].contents;
            for (uint32_t coordinate = 0u; coordinate < 4u; ++coordinate) {
                uint32_t *destination = outputs[index].columns[coordinate];
                const uint32_t *coordinateSource = source + (size_t)coordinate * rows;
                for (uint32_t row = 0u; row < rows; ++row) {
                    uint32_t sum = destination[row] + coordinateSource[row];
                    destination[row] = sum >= 0x7fffffffu ? sum - 0x7fffffffu : sum;
                }
            }
        }
        if (gpu_milliseconds != NULL)
            *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}
