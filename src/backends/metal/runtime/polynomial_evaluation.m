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

static bool sampled_barycentric_mul_size(
    size_t lhs, size_t rhs, size_t *result
) {
    if (result == NULL || (rhs != 0u && lhs > SIZE_MAX / rhs)) return false;
    *result = lhs * rhs;
    return true;
}

static id<MTLBuffer> sampled_barycentric_buffer(
    StwoZigMetalRuntime *runtime,
    size_t element_count,
    size_t element_size,
    MTLResourceOptions options
) {
    size_t byte_count = 0u;
    if (!sampled_barycentric_mul_size(element_count, element_size, &byte_count) ||
        byte_count == 0u ||
        (uint64_t)byte_count > (uint64_t)runtime.device.maxBufferLength)
    {
        return nil;
    }
    return [runtime.device newBufferWithLength:(NSUInteger)byte_count options:options];
}

static bool sampled_barycentric_canonical_words(
    const uint32_t *words, size_t word_count
) {
    if (words == NULL) return false;
    for (size_t index = 0u; index < word_count; ++index) {
        if (words[index] >= 0x7fffffffu) return false;
    }
    return true;
}

typedef struct {
    uint32_t first_column;
    uint32_t column_count;
} StwoZigSampledBarycentricResidentRunV1;

/// One proof-local evaluation-form sampled-value epoch. Every column must be
/// resolved through the exact borrowed commitment tree supplied by Zig. The
/// routine never uploads a host trace or promotes pointer equality into
/// residency; only the commitment owner's authenticated resident map may bind
/// a column to a device buffer.
bool stwo_zig_metal_eval_barycentric_resident_v1(
    void *runtime_ptr,
    void *const *resident_trees,
    uint32_t tree_count,
    const uint32_t *const *columns,
    const size_t *column_lengths,
    const uint32_t *output_indices,
    uint32_t column_count,
    const StwoZigSampledBarycentricPointPlanV1 *point_plans,
    uint32_t point_plan_count,
    const StwoZigSampledBarycentricColumnGroupV1 *groups,
    uint32_t group_count,
    uint32_t output_count,
    uint32_t *output,
    StwoZigSampledBarycentricReceiptV1 *receipt,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || resident_trees == NULL || tree_count == 0u ||
        columns == NULL || column_lengths == NULL || output_indices == NULL ||
        column_count == 0u || point_plans == NULL || point_plan_count == 0u ||
        groups == NULL || group_count == 0u || output_count == 0u ||
        output_count > UINT32_MAX / 4u ||
        output == NULL || receipt == NULL)
    {
        write_error(error_message, error_message_len,
                    @"Invalid Metal sampled barycentric arguments");
        return false;
    }

    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSMutableArray<StwoZigMetalTree *> *trees =
            [NSMutableArray arrayWithCapacity:tree_count];
        for (uint32_t tree_index = 0u; tree_index < tree_count; ++tree_index) {
            if (resident_trees[tree_index] == NULL) {
                write_error(error_message, error_message_len,
                            @"Metal sampled barycentric tree is null");
                return false;
            }
            StwoZigMetalTree *tree =
                (__bridge StwoZigMetalTree *)resident_trees[tree_index];
            if (tree.runtimeOwner != runtime) {
                write_error(error_message, error_message_len,
                            @"Metal sampled barycentric tree runtime mismatch");
                return false;
            }
            [trees addObject:tree];
        }

        size_t offsets_bytes = 0u;
        if (!sampled_barycentric_mul_size(column_count, sizeof(uint64_t),
                                          &offsets_bytes))
        {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric column offset overflow");
            return false;
        }
        NSMutableData *offset_data = [NSMutableData dataWithLength:offsets_bytes];
        NSMutableArray<id<MTLBuffer>> *resident_run_buffers =
            [NSMutableArray arrayWithCapacity:group_count];
        NSMutableData *resident_run_data = [NSMutableData data];
        NSMutableData *group_run_offsets_data = [NSMutableData
            dataWithLength:((size_t)group_count + 1u) * sizeof(uint32_t)];
        NSMutableData *written_data = [NSMutableData dataWithLength:output_count];
        if (offset_data == nil || resident_run_buffers == nil ||
            resident_run_data == nil || group_run_offsets_data == nil ||
            written_data == nil)
        {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric metadata allocation failed");
            return false;
        }
        uint64_t *column_offsets = offset_data.mutableBytes;
        uint32_t *group_run_offsets = group_run_offsets_data.mutableBytes;
        uint8_t *written_outputs = written_data.mutableBytes;

        uint64_t weight_values = 0u;
        uint64_t dot_product_terms = 0u;
        uint64_t resident_evaluations = 0u;
        uint64_t inverse_tree_blocks = 0u;
        uint64_t direct_inversions = 0u;
        uint64_t reduction_additions = 0u;
        uint32_t maximum_size = 0u;
        uint32_t maximum_partial_count = 0u;
        uint32_t expected_group = 0u;
        uint32_t expected_column = 0u;
        uint32_t prior_log = 0u;
        uint64_t unique_domains = 0u;
        const uint32_t evaluation_width = 256u;
        const uint32_t inverse_width = 512u;

        for (uint32_t point_index = 0u; point_index < point_plan_count;
             ++point_index)
        {
            const StwoZigSampledBarycentricPointPlanV1 *plan =
                &point_plans[point_index];
            if (plan->reserved != 0u || plan->log_size == 0u ||
                plan->log_size >= 31u || plan->group_count == 0u ||
                plan->first_group != expected_group ||
                plan->first_group > group_count ||
                plan->group_count > group_count - plan->first_group ||
                (point_index != 0u && plan->log_size < prior_log) ||
                !sampled_barycentric_canonical_words(plan->point, 8u) ||
                !sampled_barycentric_canonical_words(plan->si0, 4u) ||
                !sampled_barycentric_canonical_words(plan->vanishing_rotation, 2u))
            {
                write_error(error_message, error_message_len,
                            @"Invalid Metal sampled barycentric point plan");
                return false;
            }
            uint32_t size = 1u << plan->log_size;
            if (point_index == 0u || plan->log_size != prior_log)
                unique_domains += 1u;
            prior_log = plan->log_size;
            maximum_size = MAX(maximum_size, size);
            if (UINT64_MAX - weight_values < size) {
                write_error(error_message, error_message_len,
                            @"Metal sampled barycentric weight count overflow");
                return false;
            }
            weight_values += size;
            if (size < 1024u) direct_inversions += size;
            else inverse_tree_blocks += size / 1024u;

            for (uint32_t local_group = 0u; local_group < plan->group_count;
                 ++local_group)
            {
                const StwoZigSampledBarycentricColumnGroupV1 *group =
                    &groups[plan->first_group + local_group];
                if (group->reserved != 0u || group->tree_index >= tree_count ||
                    group->column_count == 0u ||
                    group->first_column != expected_column ||
                    group->first_column > column_count ||
                    group->column_count > column_count - group->first_column)
                {
                    write_error(error_message, error_message_len,
                                @"Invalid Metal sampled barycentric column group");
                    return false;
                }
                StwoZigMetalTree *tree = trees[group->tree_index];
                NSArray<StwoZigMetalTree *> *single_tree = @[ tree ];
                id<MTLBuffer> prior_buffer = nil;
                group_run_offsets[plan->first_group + local_group] =
                    (uint32_t)resident_run_buffers.count;
                for (uint32_t local_column = 0u;
                     local_column < group->column_count; ++local_column)
                {
                    uint32_t column_index = group->first_column + local_column;
                    if (column_lengths[column_index] != (size_t)size ||
                        output_indices[column_index] >= output_count ||
                        written_outputs[output_indices[column_index]] != 0u)
                    {
                        write_error(error_message, error_message_len,
                                    @"Metal sampled barycentric column shape mismatch");
                        return false;
                    }
                    written_outputs[output_indices[column_index]] = 1u;
                    StwoZigResidentColumnBinding binding = { 0 };
                    if (!stwo_zig_tree_resident_column(
                            single_tree, columns[column_index], size, &binding) ||
                        binding.tree != tree || binding.buffer == nil)
                    {
                        write_error(error_message, error_message_len,
                                    @"Metal sampled barycentric column is not proof-resident");
                        return false;
                    }
                    if (prior_buffer != binding.buffer) {
                        if (resident_run_buffers.count >= UINT32_MAX) {
                            write_error(error_message, error_message_len,
                                        @"Metal sampled barycentric resident-run overflow");
                            return false;
                        }
                        StwoZigSampledBarycentricResidentRunV1 run = {
                            .first_column = column_index,
                            .column_count = 1u,
                        };
                        [resident_run_buffers addObject:binding.buffer];
                        [resident_run_data appendBytes:&run length:sizeof(run)];
                        prior_buffer = binding.buffer;
                    } else {
                        StwoZigSampledBarycentricResidentRunV1 *runs =
                            resident_run_data.mutableBytes;
                        StwoZigSampledBarycentricResidentRunV1 *run =
                            &runs[resident_run_buffers.count - 1u];
                        if (run->column_count == UINT32_MAX) {
                            write_error(error_message, error_message_len,
                                        @"Metal sampled barycentric resident-run overflow");
                            return false;
                        }
                        run->column_count += 1u;
                    }
                    column_offsets[column_index] = (uint64_t)binding.wordOffset;
                }
                group_run_offsets[plan->first_group + local_group + 1u] =
                    (uint32_t)resident_run_buffers.count;

                uint32_t reduction_blocks = MIN(
                    256u,
                    1u + (size - 1u) / evaluation_width);
                uint32_t largest_run = 0u;
                const StwoZigSampledBarycentricResidentRunV1 *runs =
                    resident_run_data.bytes;
                for (uint32_t run_index =
                         group_run_offsets[plan->first_group + local_group];
                     run_index <
                         group_run_offsets[plan->first_group + local_group + 1u];
                     ++run_index)
                {
                    largest_run = MAX(largest_run, runs[run_index].column_count);
                }
                uint64_t partial_count =
                    (uint64_t)largest_run * (uint64_t)reduction_blocks;
                if (partial_count > UINT32_MAX ||
                    partial_count > maximum_partial_count)
                {
                    if (partial_count > UINT32_MAX) {
                        write_error(error_message, error_message_len,
                                    @"Metal sampled barycentric partial shape overflow");
                        return false;
                    }
                    maximum_partial_count = (uint32_t)partial_count;
                }
                uint64_t term_count =
                    (uint64_t)group->column_count * (uint64_t)size;
                uint64_t reduction_count =
                    (uint64_t)group->column_count *
                    ((uint64_t)reduction_blocks + 1u) *
                    (uint64_t)(evaluation_width - 1u);
                if (UINT64_MAX - dot_product_terms < term_count ||
                    UINT64_MAX - resident_evaluations < group->column_count ||
                    UINT64_MAX - reduction_additions < reduction_count)
                {
                    write_error(error_message, error_message_len,
                                @"Metal sampled barycentric work count overflow");
                    return false;
                }
                dot_product_terms += term_count;
                resident_evaluations += group->column_count;
                reduction_additions += reduction_count;
                expected_column += group->column_count;
                expected_group += 1u;
            }
        }
        if (expected_group != group_count || expected_column != column_count ||
            maximum_partial_count == 0u || resident_run_buffers.count == 0u ||
            resident_run_buffers.count > UINT32_MAX ||
            resident_run_data.length != resident_run_buffers.count *
                sizeof(StwoZigSampledBarycentricResidentRunV1) ||
            group_run_offsets[group_count] != resident_run_buffers.count)
        {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric roster is incomplete");
            return false;
        }
        for (uint32_t output_index = 0u; output_index < output_count;
             ++output_index)
        {
            if (written_outputs[output_index] == 0u) {
                write_error(error_message, error_message_len,
                            @"Metal sampled barycentric output is unwritten");
                return false;
            }
        }

        if (runtime.sampledBarycentricDomain.maxTotalThreadsPerThreadgroup <
                evaluation_width ||
            runtime.sampledBarycentricScale.maxTotalThreadsPerThreadgroup < 1u ||
            runtime.sampledBarycentricParts.maxTotalThreadsPerThreadgroup <
                evaluation_width ||
            runtime.sampledBarycentricInverseDirect.maxTotalThreadsPerThreadgroup <
                evaluation_width ||
            runtime.sampledBarycentricInverseTree.maxTotalThreadsPerThreadgroup <
                inverse_width ||
            runtime.sampledBarycentricFinish.maxTotalThreadsPerThreadgroup <
                evaluation_width ||
            runtime.sampledBarycentricEvaluateMany.maxTotalThreadsPerThreadgroup <
                evaluation_width ||
            runtime.sampledBarycentricReduce.maxTotalThreadsPerThreadgroup <
                evaluation_width)
        {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric pipeline width is unsupported");
            return false;
        }

        id<MTLBuffer> offset_buffer = [runtime.device
            newBufferWithBytes:column_offsets
            length:offset_data.length
            options:MTLResourceStorageModeShared];
        size_t output_index_bytes = 0u;
        if (!sampled_barycentric_mul_size(column_count, sizeof(uint32_t),
                                          &output_index_bytes))
        {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric output-index overflow");
            return false;
        }
        id<MTLBuffer> output_index_buffer = [runtime.device
            newBufferWithBytes:output_indices
            length:output_index_bytes
            options:MTLResourceStorageModeShared];
        id<MTLBuffer> domain_buffer = sampled_barycentric_buffer(
            runtime, maximum_size, 2u * sizeof(uint32_t),
            MTLResourceStorageModePrivate);
        id<MTLBuffer> numerator_buffer = sampled_barycentric_buffer(
            runtime, maximum_size, 4u * sizeof(uint32_t),
            MTLResourceStorageModePrivate);
        id<MTLBuffer> weight_buffer = sampled_barycentric_buffer(
            runtime, maximum_size, 4u * sizeof(uint32_t),
            MTLResourceStorageModePrivate);
        id<MTLBuffer> scale_buffer = sampled_barycentric_buffer(
            runtime, 2u, 4u * sizeof(uint32_t), MTLResourceStorageModePrivate);
        id<MTLBuffer> partial_buffer = sampled_barycentric_buffer(
            runtime, maximum_partial_count, 4u * sizeof(uint32_t),
            MTLResourceStorageModePrivate);
        id<MTLBuffer> invalid_buffer = sampled_barycentric_buffer(
            runtime, point_plan_count, sizeof(uint32_t),
            MTLResourceStorageModeShared);
        id<MTLBuffer> output_buffer = sampled_barycentric_buffer(
            runtime, output_count, 4u * sizeof(uint32_t),
            MTLResourceStorageModeShared);
        if (offset_buffer == nil || output_index_buffer == nil ||
            domain_buffer == nil || numerator_buffer == nil ||
            weight_buffer == nil || scale_buffer == nil ||
            partial_buffer == nil || invalid_buffer == nil ||
            output_buffer == nil)
        {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric device allocation failed");
            return false;
        }
        memset(invalid_buffer.contents, 0,
               (size_t)point_plan_count * sizeof(uint32_t));

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (command == nil || encoder == nil) {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric command allocation failed");
            return false;
        }

        prior_log = 0u;
        for (uint32_t point_index = 0u; point_index < point_plan_count;
             ++point_index)
        {
            const StwoZigSampledBarycentricPointPlanV1 *plan =
                &point_plans[point_index];
            uint32_t size = 1u << plan->log_size;
            if (point_index == 0u || plan->log_size != prior_log) {
                uint32_t half_coset_initial_index = 1u << (30u - plan->log_size);
                uint32_t half_coset_step_size = 1u << (32u - plan->log_size);
                [encoder setComputePipelineState:runtime.sampledBarycentricDomain];
                [encoder setBuffer:domain_buffer offset:0u atIndex:0];
                [encoder setBytes:&size length:sizeof(size) atIndex:1];
                [encoder setBytes:&plan->log_size length:sizeof(plan->log_size)
                           atIndex:2];
                [encoder setBytes:&half_coset_initial_index
                           length:sizeof(half_coset_initial_index) atIndex:3];
                [encoder setBytes:&half_coset_step_size
                           length:sizeof(half_coset_step_size) atIndex:4];
                [encoder dispatchThreads:MTLSizeMake(size, 1u, 1u)
                       threadsPerThreadgroup:MTLSizeMake(evaluation_width, 1u, 1u)];
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
            }
            prior_log = plan->log_size;

            [encoder setComputePipelineState:runtime.sampledBarycentricScale];
            [encoder setBytes:&plan->point[0] length:4u * sizeof(uint32_t)
                       atIndex:0];
            [encoder setBytes:&plan->point[4] length:4u * sizeof(uint32_t)
                       atIndex:1];
            [encoder setBytes:&plan->si0[0] length:4u * sizeof(uint32_t)
                       atIndex:2];
            [encoder setBytes:&plan->vanishing_rotation[0]
                       length:2u * sizeof(uint32_t) atIndex:3];
            [encoder setBytes:&plan->log_size length:sizeof(plan->log_size)
                       atIndex:4];
            [encoder setBuffer:scale_buffer offset:0u atIndex:5];
            [encoder dispatchThreads:MTLSizeMake(1u, 1u, 1u)
                   threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];

            [encoder setComputePipelineState:runtime.sampledBarycentricParts];
            [encoder setBuffer:domain_buffer offset:0u atIndex:0];
            [encoder setBytes:&plan->point[0] length:4u * sizeof(uint32_t)
                       atIndex:1];
            [encoder setBytes:&plan->point[4] length:4u * sizeof(uint32_t)
                       atIndex:2];
            [encoder setBuffer:numerator_buffer offset:0u atIndex:3];
            [encoder setBuffer:weight_buffer offset:0u atIndex:4];
            [encoder setBuffer:invalid_buffer
                         offset:(NSUInteger)point_index * sizeof(uint32_t)
                        atIndex:5];
            [encoder setBytes:&size length:sizeof(size) atIndex:6];
            [encoder dispatchThreads:MTLSizeMake(size, 1u, 1u)
                   threadsPerThreadgroup:MTLSizeMake(evaluation_width, 1u, 1u)];
            [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];

            if (size < 1024u) {
                [encoder setComputePipelineState:
                    runtime.sampledBarycentricInverseDirect];
                [encoder setBuffer:numerator_buffer offset:0u atIndex:0];
                [encoder setBytes:&size length:sizeof(size) atIndex:1];
                [encoder dispatchThreads:MTLSizeMake(size, 1u, 1u)
                       threadsPerThreadgroup:MTLSizeMake(evaluation_width, 1u, 1u)];
            } else {
                [encoder setComputePipelineState:
                    runtime.sampledBarycentricInverseTree];
                [encoder setBuffer:numerator_buffer offset:0u atIndex:0];
                [encoder dispatchThreadgroups:MTLSizeMake(size / 1024u, 1u, 1u)
                         threadsPerThreadgroup:MTLSizeMake(inverse_width, 1u, 1u)];
            }
            [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];

            [encoder setComputePipelineState:runtime.sampledBarycentricFinish];
            [encoder setBuffer:numerator_buffer offset:0u atIndex:0];
            [encoder setBuffer:weight_buffer offset:0u atIndex:1];
            [encoder setBuffer:scale_buffer offset:0u atIndex:2];
            [encoder setBytes:&size length:sizeof(size) atIndex:3];
            [encoder dispatchThreads:MTLSizeMake(size, 1u, 1u)
                   threadsPerThreadgroup:MTLSizeMake(evaluation_width, 1u, 1u)];
            [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];

            for (uint32_t local_group = 0u; local_group < plan->group_count;
                 ++local_group)
            {
                uint32_t group_index = plan->first_group + local_group;
                uint32_t reduction_blocks = MIN(
                    256u,
                    1u + (size - 1u) / evaluation_width);
                const StwoZigSampledBarycentricResidentRunV1 *runs =
                    resident_run_data.bytes;
                for (uint32_t run_index = group_run_offsets[group_index];
                     run_index < group_run_offsets[group_index + 1u];
                     ++run_index)
                {
                    const StwoZigSampledBarycentricResidentRunV1 run =
                        runs[run_index];
                    [encoder setComputePipelineState:
                        runtime.sampledBarycentricEvaluateMany];
                    [encoder setBuffer:resident_run_buffers[run_index]
                                 offset:0u atIndex:0];
                    [encoder setBuffer:offset_buffer
                                 offset:(NSUInteger)run.first_column * sizeof(uint64_t)
                                atIndex:1];
                    [encoder setBuffer:weight_buffer offset:0u atIndex:2];
                    [encoder setBytes:&size length:sizeof(size) atIndex:3];
                    [encoder setBytes:&reduction_blocks
                               length:sizeof(reduction_blocks) atIndex:4];
                    [encoder setBuffer:partial_buffer offset:0u atIndex:5];
                    [encoder dispatchThreadgroups:
                        MTLSizeMake(reduction_blocks, run.column_count, 1u)
                             threadsPerThreadgroup:
                        MTLSizeMake(evaluation_width, 1u, 1u)];
                    [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];

                    [encoder setComputePipelineState:
                        runtime.sampledBarycentricReduce];
                    [encoder setBuffer:partial_buffer offset:0u atIndex:0];
                    [encoder setBytes:&reduction_blocks
                               length:sizeof(reduction_blocks) atIndex:1];
                    [encoder setBuffer:output_index_buffer
                                 offset:(NSUInteger)run.first_column * sizeof(uint32_t)
                                atIndex:2];
                    [encoder setBuffer:output_buffer offset:0u atIndex:3];
                    [encoder setBytes:&output_count length:sizeof(output_count)
                               atIndex:4];
                    [encoder dispatchThreadgroups:
                        MTLSizeMake(run.column_count, 1u, 1u)
                             threadsPerThreadgroup:
                        MTLSizeMake(evaluation_width, 1u, 1u)];
                    [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
                }
            }
        }
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len,
                        command.error.localizedDescription ?:
                        @"Metal sampled barycentric epoch failed");
            return false;
        }
        const uint32_t *invalid = invalid_buffer.contents;
        for (uint32_t point_index = 0u; point_index < point_plan_count;
             ++point_index)
        {
            if (invalid[point_index] != 0u) {
                write_error(error_message, error_message_len,
                            @"Metal sampled barycentric point lies on domain");
                return false;
            }
        }
        memcpy(output, output_buffer.contents,
               (size_t)output_count * 4u * sizeof(uint32_t));
        for (uint32_t word = 0u; word < output_count * 4u; ++word) {
            if (output[word] >= 0x7fffffffu) {
                write_error(error_message, error_message_len,
                            @"Metal sampled barycentric output is noncanonical");
                return false;
            }
        }

        *receipt = (StwoZigSampledBarycentricReceiptV1){
            .schema_version = 1u,
            .command_buffers = 1u,
            .wait_count = 1u,
            .reserved = 0u,
            .unique_point_count = point_plan_count,
            .unique_domain_count = unique_domains,
            .resident_column_evaluations = resident_evaluations,
            .weight_values = weight_values,
            .dot_product_terms = dot_product_terms,
            .inverse_tree_blocks = inverse_tree_blocks,
            .direct_inversions = direct_inversions,
            .reduction_additions = reduction_additions,
            .evaluation_threadgroup_width = evaluation_width,
            .inverse_threadgroup_width = inverse_width,
        };
        if (gpu_milliseconds != NULL) {
            *gpu_milliseconds =
                (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        }
        return true;
    }
}
