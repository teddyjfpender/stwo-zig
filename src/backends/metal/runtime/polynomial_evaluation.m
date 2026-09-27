// Synchronous sampled scratch uses an allocator-bearing constructor ledger.
// Numeric payloads are logical extents; framework objects/rounding are separate.
typedef struct {
    size_t run_bytes, wave_bytes, dispatches;
} StwoSampledStreamPolicyV1;
static const StwoSampledStreamPolicyV1 sampled_stream_policy = {
    64u * 1024u * 1024u, 256u * 1024u * 1024u, 128u
};
typedef bool (*StwoSampledBudgetAdmitV1)(void *, size_t, uint32_t);
typedef struct {
    uint64_t device_live_bytes, native_live_bytes, alias_live_bytes;
    uint64_t device_peak_bytes, native_peak_bytes, alias_peak_bytes;
    uint64_t external_peak_bytes, owned_allocations, alias_allocations;
    uint64_t submitted, joined;
} StwoSampledBudgetReceiptV1;
_Static_assert(sizeof(StwoSampledBudgetReceiptV1) == 88u, "Sampled budget receipt ABI");
typedef struct {
    void *context;
    StwoSampledBudgetAdmitV1 admit;
    StwoSampledBudgetReceiptV1 *receipt;
} StwoSampledBudgetLedgerV1;

static bool sampled_budget_apply(StwoSampledBudgetLedgerV1 *ledger,
                                  size_t bytes, uint32_t operation) {
    if (bytes == 0u || operation > 5u) return false;
    StwoSampledBudgetReceiptV1 next = *ledger->receipt;
    uint64_t *live = (operation % 3u == 0u) ? &next.device_live_bytes
        : (operation % 3u == 1u) ? &next.native_live_bytes : &next.alias_live_bytes;
    if (operation < 3u) {
        uint64_t *count = operation == 2u ? &next.alias_allocations : &next.owned_allocations;
        if (UINT64_MAX - *live < bytes || *count == UINT64_MAX) return false;
        *live += bytes;
        *count += 1u;
    } else {
        if (*live < bytes) return false;
        *live -= bytes;
    }
    if (UINT64_MAX - next.device_live_bytes < next.native_live_bytes) return false;
    if (ledger->admit != NULL && !ledger->admit(ledger->context, bytes, operation)) return false;
    next.device_peak_bytes = MAX(next.device_peak_bytes, next.device_live_bytes);
    next.native_peak_bytes = MAX(next.native_peak_bytes, next.native_live_bytes);
    next.alias_peak_bytes = MAX(next.alias_peak_bytes, next.alias_live_bytes);
    next.external_peak_bytes = MAX(next.external_peak_bytes,
                                   next.device_live_bytes + next.native_live_bytes);
    *ledger->receipt = next;
    return true;
}
static bool sampled_budget_release_all(StwoSampledBudgetLedgerV1 *ledger) {
    bool ok = true;
    if (ledger->receipt->device_live_bytes != 0u)
        ok = sampled_budget_apply(ledger, ledger->receipt->device_live_bytes, 3u) && ok;
    if (ledger->receipt->native_live_bytes != 0u)
        ok = sampled_budget_apply(ledger, ledger->receipt->native_live_bytes, 4u) && ok;
    if (ledger->receipt->alias_live_bytes != 0u)
        ok = sampled_budget_apply(ledger, ledger->receipt->alias_live_bytes, 5u) && ok;
    return ok;
}
// Explicit retained returns avoid an outer autoreleasepool keeping completed
// commands/encoders (and their buffer references) alive across wave release.
static id<MTLCommandBuffer> sampled_owned_command(StwoZigMetalRuntime *runtime)
    __attribute__((ns_returns_retained));
static id<MTLCommandBuffer> sampled_owned_command(StwoZigMetalRuntime *runtime) {
    @autoreleasepool { return [runtime.queue commandBuffer]; }
}
static id<MTLComputeCommandEncoder> sampled_owned_encoder(id<MTLCommandBuffer> command)
    __attribute__((ns_returns_retained));
static id<MTLComputeCommandEncoder> sampled_owned_encoder(id<MTLCommandBuffer> command) {
    @autoreleasepool { return [command computeCommandEncoder]; }
}

static id<MTLBuffer> sampled_owned_buffer(StwoZigMetalRuntime *runtime,
        const void *bytes, size_t length, MTLResourceOptions options,
        StwoSampledBudgetLedgerV1 *ledger) {
    if (length == 0u || length > runtime.device.maxBufferLength ||
        !sampled_budget_apply(ledger, length, 0u)) return nil;
    return bytes != NULL ? [runtime.device newBufferWithBytes:bytes length:length options:options]
                         : [runtime.device newBufferWithLength:length options:options];
}
static NSMutableData *sampled_owned_data(size_t length, bool capacity,
                                         StwoSampledBudgetLedgerV1 *ledger) {
    if (length == 0u || !sampled_budget_apply(ledger, length, 1u)) return nil;
    return capacity ? [NSMutableData dataWithCapacity:length]
                    : [NSMutableData dataWithLength:length];
}

static bool sampled_coefficient_evaluate_v2(
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
    char *error_message, size_t error_message_len,
    StwoSampledBudgetLedgerV1 *ledger, bool allow_unowned_aliases,
    const StwoSampledStreamPolicyV1 *stream_policy
) {
    if (stream_policy == NULL || stream_policy->run_bytes < 4u ||
        stream_policy->run_bytes % 4u != 0u || stream_policy->wave_bytes == 0u ||
        stream_policy->dispatches == 0u ||
        runtime_ptr == NULL || coefficients == NULL || coefficient_lengths == NULL ||
        coefficient_column_count == 0u || coefficient_count == 0u || coefficient_count > UINT32_MAX ||
        (factor_word_count != 0u && factors == NULL) || factor_word_count > SIZE_MAX / 4u ||
        basis_tasks == NULL || basis_task_count == 0u || basis_count == 0u ||
        tasks == NULL || task_columns == NULL || task_count == 0u || output == NULL ||
        output_count == 0u || output_count > UINT32_MAX / 4u) {
        write_error(error_message, error_message_len, @"Invalid sampled coefficient arguments");
        return false;
    }
    size_t actual_words = 0u;
    for (uint32_t i = 0u; i < coefficient_column_count; ++i) {
        if (coefficients[i] == NULL || coefficient_lengths[i] == 0u ||
            coefficient_lengths[i] > UINT32_MAX - actual_words) return false;
        actual_words += coefficient_lengths[i];
    }
    if (actual_words != coefficient_count) return false;
    for (uint32_t i = 0u; i < task_count; ++i)
        if (task_columns[i] >= coefficient_column_count) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        const bool gpu_coefficient_upload = coefficient_count * sizeof(uint32_t) >= (64u * 1024u * 1024u);
        id<MTLBuffer> coefficient_buffer = sampled_owned_buffer(runtime, NULL,
            gpu_coefficient_upload ? sizeof(uint32_t) : coefficient_count * sizeof(uint32_t),
            MTLResourceStorageModeShared, ledger);
        id<MTLBuffer> factor_buffer = sampled_owned_buffer(runtime,
            factor_word_count != 0u ? factors : NULL,
            MAX((size_t)1u, factor_word_count) * sizeof(uint32_t), MTLResourceStorageModeShared, ledger);
        id<MTLBuffer> task_buffer = sampled_owned_buffer(runtime, tasks,
            (size_t)task_count * 5u * sizeof(uint32_t), MTLResourceStorageModeShared, ledger);
        id<MTLBuffer> basis_task_buffer = sampled_owned_buffer(runtime, basis_tasks,
            (size_t)basis_task_count * 4u * sizeof(uint32_t), MTLResourceStorageModeShared, ledger);
        id<MTLBuffer> basis_buffer = sampled_owned_buffer(runtime, NULL,
            (size_t)basis_count * 4u * sizeof(uint32_t), MTLResourceStorageModePrivate, ledger);
        id<MTLBuffer> output_buffer = sampled_owned_buffer(runtime, NULL,
            (size_t)output_count * 4u * sizeof(uint32_t), MTLResourceStorageModeShared, ledger);
        if (coefficient_buffer == nil || factor_buffer == nil || task_buffer == nil ||
            basis_task_buffer == nil || basis_buffer == nil || output_buffer == nil) {
            write_error(error_message, error_message_len, @"Metal polynomial evaluation allocation failed");
            return false;
        }
        if (!gpu_coefficient_upload) {
            uint32_t *destination = coefficient_buffer.contents;
            size_t cursor = 0u;
            for (uint32_t i = 0u; i < coefficient_column_count; ++i) {
                memcpy(destination + cursor, coefficients[i], coefficient_lengths[i] * sizeof(uint32_t));
                cursor += coefficient_lengths[i];
            }
        }
        id<MTLCommandBuffer> command = sampled_owned_command(runtime);
        id<MTLComputeCommandEncoder> active_encoder = sampled_owned_encoder(command);
        if (command == nil || active_encoder == nil) return false;
        double total_gpu_milliseconds = 0.0;
        bool command_has_work = true;
        NSUInteger wave_dispatches = 0u;
        size_t wave_device_bytes = 0u, wave_alias_bytes = 0u;
        NSMutableArray<id<MTLBuffer>> *coefficient_sources = [NSMutableArray array];
        if (coefficient_sources == nil) return false;
        [active_encoder setComputePipelineState:runtime.polynomialBasis];
        [active_encoder setBuffer:factor_buffer offset:0 atIndex:0];
        [active_encoder setBuffer:basis_task_buffer offset:0 atIndex:1];
        [active_encoder setBytes:&basis_task_count length:sizeof(basis_task_count) atIndex:2];
        [active_encoder setBuffer:basis_buffer offset:0 atIndex:3];
        NSUInteger basis_width = MIN((NSUInteger)256u, runtime.polynomialBasis.maxTotalThreadsPerThreadgroup);
        NSUInteger width = MIN((NSUInteger)256u, runtime.polynomialEval.maxTotalThreadsPerThreadgroup);
        if (basis_width == 0u || width == 0u) return false;
        uint32_t max_basis_blocks = 0u;
        const StwoZigPolynomialBasisTask *all_basis_tasks = basis_tasks;
        for (uint32_t i = 0u; i < basis_task_count; ++i) {
            const uint32_t blocks = all_basis_tasks[i].basis_length / (uint32_t)basis_width +
                (all_basis_tasks[i].basis_length % (uint32_t)basis_width != 0u);
            max_basis_blocks = MAX(max_basis_blocks, blocks);
        }
        [active_encoder dispatchThreadgroups:MTLSizeMake(max_basis_blocks, basis_task_count, 1)
                      threadsPerThreadgroup:MTLSizeMake(basis_width, 1, 1)];
        [active_encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        if (gpu_coefficient_upload) {
            size_t column = 0u;
            const size_t page_size = (size_t)getpagesize();
            const StwoZigPolynomialEvalTask *all_tasks = tasks;
            while (column < coefficient_column_count) {
                const size_t run_start = column;
                size_t run_words = coefficient_lengths[column++];
                // Group contiguous columns only up to the target. A single larger
                // column is indivisible and remains subject to cap admission.
                const size_t run_limit_words = stream_policy->run_bytes / sizeof(uint32_t);
                while (column < coefficient_column_count && coefficient_lengths[column] <= run_limit_words &&
                       run_words <= run_limit_words - coefficient_lengths[column] &&
                       coefficients[column] == coefficients[run_start] + run_words)
                    run_words += coefficient_lengths[column++];
                uint32_t run_task_count = 0u;
                for (uint32_t i = 0u; i < task_count; ++i)
                    if (task_columns[i] >= run_start && task_columns[i] < column) ++run_task_count;
                if (run_task_count == 0u) continue;
                const size_t metadata_bytes = (size_t)run_task_count * sizeof(StwoZigPolynomialEvalTask);
                const size_t run_bytes = run_words * sizeof(uint32_t);
                // Include the temporary numeric task payload alongside its
                // device copy. Join before admitting the next wave's buffers.
                if (metadata_bytes > (SIZE_MAX - run_bytes) / 2u) return false;
                const size_t incoming_bytes = run_bytes + metadata_bytes * 2u;
                if (wave_dispatches != 0u &&
                    (wave_dispatches >= stream_policy->dispatches ||
                     incoming_bytes > stream_policy->wave_bytes ||
                     wave_device_bytes + wave_alias_bytes > stream_policy->wave_bytes - incoming_bytes)) {
                    [active_encoder endEncoding]; active_encoder = nil;
                    ++ledger->receipt->submitted;
                    [command commit]; [command waitUntilCompleted];
                    ++ledger->receipt->joined;
                    if (command.status != MTLCommandBufferStatusCompleted) return false;
                    total_gpu_milliseconds += (command.GPUEndTime - command.GPUStartTime) * 1000.0;
                    [coefficient_sources removeAllObjects]; command = nil;
                    command_has_work = false; wave_dispatches = 0u;
                    // All submitted buffers have lost their last strong
                    // reference before the ledger shrinks; basis/output stay.
                    if (wave_device_bytes != 0u && !sampled_budget_apply(ledger, wave_device_bytes, 3u)) return false;
                    if (wave_alias_bytes != 0u && !sampled_budget_apply(ledger, wave_alias_bytes, 5u)) return false;
                    wave_device_bytes = 0u; wave_alias_bytes = 0u;
                }
                @autoreleasepool {
                    // Exact count-first numeric payload, destroyed before the
                    // native charge is decremented outside this inner pool.
                    NSMutableData *run_task_data = sampled_owned_data(metadata_bytes, false, ledger);
                    if (run_task_data == nil) return false;
                    StwoZigPolynomialEvalTask *run_task_words = run_task_data.mutableBytes;
                    uint32_t at = 0u;
                    for (uint32_t i = 0u; i < task_count; ++i) {
                        const uint32_t task_column = task_columns[i];
                        if (task_column >= run_start && task_column < column) {
                            StwoZigPolynomialEvalTask task = all_tasks[i];
                            task.coefficient_offset = (uint32_t)(coefficients[task_column] - coefficients[run_start]);
                            run_task_words[at++] = task;
                        }
                    }
                    const uintptr_t address = (uintptr_t)coefficients[run_start];
                    const bool no_copy = allow_unowned_aliases && address % page_size == 0u && run_bytes % page_size == 0u;
                    id<MTLBuffer> source = nil;
                    if (no_copy) {
                        if (run_bytes > runtime.device.maxBufferLength || !sampled_budget_apply(ledger, run_bytes, 2u)) return false;
                        source = [runtime.device newBufferWithBytesNoCopy:(void *)coefficients[run_start]
                            length:run_bytes options:MTLResourceStorageModeShared deallocator:nil];
                        wave_alias_bytes += run_bytes;
                    } else {
                        source = sampled_owned_buffer(runtime, coefficients[run_start], run_bytes,
                                                       MTLResourceStorageModeShared, ledger);
                        wave_device_bytes += run_bytes;
                    }
                    id<MTLBuffer> run_tasks = sampled_owned_buffer(runtime, run_task_words, metadata_bytes,
                                                                 MTLResourceStorageModeShared, ledger);
                    wave_device_bytes += metadata_bytes;
                    if (source == nil || run_tasks == nil) return false;
                    [coefficient_sources addObject:source];
                    [coefficient_sources addObject:run_tasks];
                    if (command == nil) command = sampled_owned_command(runtime);
                    if (active_encoder == nil) active_encoder = sampled_owned_encoder(command);
                    if (command == nil || active_encoder == nil) return false;
                    [active_encoder setComputePipelineState:runtime.polynomialEval];
                    [active_encoder setBuffer:source offset:0 atIndex:0];
                    [active_encoder setBuffer:basis_buffer offset:0 atIndex:1];
                    [active_encoder setBuffer:run_tasks offset:0 atIndex:2];
                    [active_encoder setBytes:&run_task_count length:sizeof(run_task_count) atIndex:3];
                    [active_encoder setBuffer:output_buffer offset:0 atIndex:4];
                    [active_encoder dispatchThreadgroups:MTLSizeMake(run_task_count, 1, 1)
                         threadsPerThreadgroup:MTLSizeMake(width, 1, 1)];
                    command_has_work = true;
                    ++wave_dispatches;
                }
                // CPU metadata was copied into run_tasks, so it can be
                // destroyed independently while the command borrows that copy.
                if (!sampled_budget_apply(ledger, metadata_bytes, 4u)) return false;
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
        }
        if (command_has_work) {
            [active_encoder endEncoding]; active_encoder = nil;
            ++ledger->receipt->submitted;
            [command commit]; [command waitUntilCompleted];
            ++ledger->receipt->joined;
            if (command.status != MTLCommandBufferStatusCompleted) return false;
            total_gpu_milliseconds += (command.GPUEndTime - command.GPUStartTime) * 1000.0;
            [coefficient_sources removeAllObjects]; command = nil;
        }
        memcpy(output, output_buffer.contents, (size_t)output_count * 4u * sizeof(uint32_t));
        if (basis_threadgroup_width != NULL) *basis_threadgroup_width = (uint32_t)basis_width;
        if (evaluation_threadgroup_width != NULL) *evaluation_threadgroup_width = (uint32_t)width;
        if (gpu_milliseconds != NULL) *gpu_milliseconds = total_gpu_milliseconds;
        return true;
    }
}

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
    StwoSampledBudgetReceiptV1 receipt = {0};
    StwoSampledBudgetLedgerV1 ledger = {NULL, NULL, &receipt};
    bool ok = sampled_coefficient_evaluate_v2(runtime_ptr, coefficients, coefficient_lengths, coefficient_column_count, coefficient_count, factors, factor_word_count, basis_tasks, basis_task_count, basis_count, tasks, task_columns, task_count, output_count, output, basis_threadgroup_width, evaluation_threadgroup_width, gpu_milliseconds, error_message, error_message_len, &ledger, true, &sampled_stream_policy);
    return sampled_budget_release_all(&ledger) && ok;
}

bool stwo_zig_metal_eval_polynomials_budgeted_v2(
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
    char *error_message, size_t error_message_len,
    void *budget_context, StwoSampledBudgetAdmitV1 budget_admit, StwoSampledBudgetReceiptV1 *budget_receipt, bool allow_unowned_aliases,
    const StwoSampledStreamPolicyV1 *stream_policy
) {
    if (budget_context == NULL || budget_admit == NULL || budget_receipt == NULL) return false;
    *budget_receipt = (StwoSampledBudgetReceiptV1){0};
    StwoSampledBudgetLedgerV1 ledger = {budget_context, budget_admit, budget_receipt};
    bool ok = sampled_coefficient_evaluate_v2(runtime_ptr, coefficients, coefficient_lengths, coefficient_column_count, coefficient_count, factors, factor_word_count, basis_tasks, basis_task_count, basis_count, tasks, task_columns, task_count, output_count, output, basis_threadgroup_width, evaluation_threadgroup_width, gpu_milliseconds, error_message, error_message_len, &ledger, allow_unowned_aliases, stream_policy);
    // Inner autoreleasepool has destroyed every private buffer even on error.
    return sampled_budget_release_all(&ledger) && ok;
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
    MTLResourceOptions options, StwoSampledBudgetLedgerV1 *ledger
) {
    size_t byte_count = 0u;
    if (!sampled_barycentric_mul_size(element_count, element_size, &byte_count) ||
        byte_count == 0u ||
        (uint64_t)byte_count > (uint64_t)runtime.device.maxBufferLength)
    {
        return nil;
    }
    return sampled_owned_buffer(runtime, NULL, byte_count, options, ledger);
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
_Static_assert(sizeof(StwoZigSampledBarycentricResidentRunV1) == 8u, "Sampled run ABI");

/// One proof-local evaluation-form sampled-value epoch. Every column must be
/// resolved through the exact borrowed commitment tree supplied by Zig. The
/// routine never uploads a host trace or promotes pointer equality into
/// residency; only the commitment owner's authenticated resident map may bind
/// a column to a device buffer.
static bool sampled_barycentric_evaluate_v1(
    bool host_columns,
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
    size_t error_message_len, StwoSampledBudgetLedgerV1 *ledger
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
        for (uint32_t tree_index = 0u; !host_columns && tree_index < tree_count; ++tree_index) {
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

        // A single reusable staging slab. Each run is drained before its
        // bytes are overwritten; weights and domain buffers survive all runs.
        const size_t host_stage_limit = 64u * 1024u * 1024u;
        size_t host_stage_bytes = 0u;
        if (host_columns) {
            for (uint32_t i = 0u; i < column_count; ++i) {
                if (columns[i] == NULL || column_lengths[i] == 0u ||
                    column_lengths[i] > host_stage_limit / sizeof(uint32_t)) {
                    write_error(error_message, error_message_len,
                                @"Invalid bounded host barycentric column");
                    return false;
                }
                host_stage_bytes = MIN(host_stage_limit,
                    host_stage_bytes + column_lengths[i] * sizeof(uint32_t));
            }
        }
        id<MTLBuffer> host_stage = host_columns ? sampled_owned_buffer(runtime,
            NULL, host_stage_bytes, MTLResourceStorageModeShared, ledger) : nil;
        if (host_columns && host_stage == nil) {
            write_error(error_message, error_message_len,
                        @"Host barycentric staging allocation failed");
            return false;
        }

        size_t offsets_bytes = 0u;
        if (!sampled_barycentric_mul_size(column_count, sizeof(uint64_t),
                                          &offsets_bytes))
        {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric column offset overflow");
            return false;
        }
        NSMutableData *offset_data = sampled_owned_data(offsets_bytes, false, ledger);
        NSMutableArray<id<MTLBuffer>> *resident_run_buffers =
            [NSMutableArray arrayWithCapacity:group_count];
        NSMutableData *resident_run_data = sampled_owned_data((size_t)column_count * sizeof(StwoZigSampledBarycentricResidentRunV1), true, ledger);
        NSMutableData *group_run_offsets_data = sampled_owned_data(((size_t)group_count + 1u) * sizeof(uint32_t), false, ledger);
        NSMutableData *written_data = sampled_owned_data(output_count, false, ledger);
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
                StwoZigMetalTree *tree = host_columns ? nil : trees[group->tree_index];
                NSArray<StwoZigMetalTree *> *single_tree = host_columns ? @[] : @[ tree ];
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
                    if (host_columns) {
                        const uint32_t capacity = (uint32_t)(host_stage_bytes /
                            ((size_t)size * sizeof(uint32_t)));
                        if (capacity == 0u) {
                            write_error(error_message, error_message_len,
                                        @"Host barycentric staging capacity mismatch");
                            return false;
                        }
                        const uint32_t slot = local_column % capacity;
                        if (slot == 0u) prior_buffer = nil;
                        binding.buffer = host_stage;
                        binding.wordOffset = (size_t)slot * size;
                    } else if (!stwo_zig_tree_resident_column(
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

        id<MTLBuffer> offset_buffer = sampled_owned_buffer(runtime, column_offsets, offset_data.length,
                MTLResourceStorageModeShared, ledger);
        size_t output_index_bytes = 0u;
        if (!sampled_barycentric_mul_size(column_count, sizeof(uint32_t),
                                          &output_index_bytes))
        {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric output-index overflow");
            return false;
        }
        id<MTLBuffer> output_index_buffer = sampled_owned_buffer(runtime, output_indices, output_index_bytes,
                MTLResourceStorageModeShared, ledger);
        id<MTLBuffer> domain_buffer = sampled_barycentric_buffer(
            runtime, maximum_size, 2u * sizeof(uint32_t),
            MTLResourceStorageModePrivate, ledger);
        id<MTLBuffer> numerator_buffer = sampled_barycentric_buffer(
            runtime, maximum_size, 4u * sizeof(uint32_t),
            MTLResourceStorageModePrivate, ledger);
        id<MTLBuffer> weight_buffer = sampled_barycentric_buffer(
            runtime, maximum_size, 4u * sizeof(uint32_t),
            MTLResourceStorageModePrivate, ledger);
        id<MTLBuffer> scale_buffer = sampled_barycentric_buffer(
            runtime, 2u, 4u * sizeof(uint32_t), MTLResourceStorageModePrivate, ledger);
        id<MTLBuffer> partial_buffer = sampled_barycentric_buffer(
            runtime, maximum_partial_count, 4u * sizeof(uint32_t),
            MTLResourceStorageModePrivate, ledger);
        id<MTLBuffer> invalid_buffer = sampled_barycentric_buffer(
            runtime, point_plan_count, sizeof(uint32_t),
            MTLResourceStorageModeShared, ledger);
        id<MTLBuffer> output_buffer = sampled_barycentric_buffer(
            runtime, output_count, 4u * sizeof(uint32_t),
            MTLResourceStorageModeShared, ledger);
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

        id<MTLCommandBuffer> command = sampled_owned_command(runtime);
        id<MTLComputeCommandEncoder> encoder = sampled_owned_encoder(command);
        if (command == nil || encoder == nil) {
            write_error(error_message, error_message_len,
                        @"Metal sampled barycentric command allocation failed");
            return false;
        }

        double elapsed_gpu_ms = 0.0;
        uint32_t command_count = 0u;
        prior_log = 0u;
        for (uint32_t point_index = 0u; point_index < point_plan_count;
             ++point_index)
        {
            const StwoZigSampledBarycentricPointPlanV1 *plan =
                &point_plans[point_index];
            uint32_t size = 1u << plan->log_size;
            if (encoder == nil) {
                command = sampled_owned_command(runtime);
                encoder = sampled_owned_encoder(command);
                if (command == nil || encoder == nil) {
                    write_error(error_message, error_message_len,
                                @"Host barycentric command allocation failed");
                    return false;
                }
            }
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
                    if (host_columns) {
                        if (encoder == nil) {
                            command = sampled_owned_command(runtime);
                            encoder = sampled_owned_encoder(command);
                            if (command == nil || encoder == nil) {
                                write_error(error_message, error_message_len,
                                            @"Host barycentric command allocation failed");
                                return false;
                            }
                        }
                        for (uint32_t j = 0u; j < run.column_count; ++j) {
                            const uint32_t column = run.first_column + j;
                            memcpy((uint32_t *)host_stage.contents + column_offsets[column],
                                   columns[column], (size_t)size * sizeof(uint32_t));
                        }
                    }
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
                    if (host_columns) {
                        [encoder endEncoding];
                        ++ledger->receipt->submitted;
                        [command commit];
                        [command waitUntilCompleted];
                        ++ledger->receipt->joined;
                        if (command.status != MTLCommandBufferStatusCompleted) {
                            write_error(error_message, error_message_len,
                                        command.error.localizedDescription ?:
                                        @"Host barycentric staging run failed");
                            return false;
                        }
                        elapsed_gpu_ms += (command.GPUEndTime - command.GPUStartTime) * 1000.0;
                        command_count += 1u;
                        encoder = nil;
                        command = nil;
                    }
                }
            }
        }
        if (encoder != nil) {
            [encoder endEncoding];
            ++ledger->receipt->submitted;
            [command commit];
            [command waitUntilCompleted];
            ++ledger->receipt->joined;
            if (command.status != MTLCommandBufferStatusCompleted) {
                write_error(error_message, error_message_len,
                            command.error.localizedDescription ?:
                            @"Metal sampled barycentric epoch failed");
                return false;
            }
            elapsed_gpu_ms += (command.GPUEndTime - command.GPUStartTime) * 1000.0;
            command_count += 1u;
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
            .command_buffers = command_count,
            .wait_count = command_count,
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
            *gpu_milliseconds = elapsed_gpu_ms;
        }
        if (host_columns && getenv("STWO_RISCV_EXECUTION_PROFILE") != NULL) {
            fprintf(stderr, "METAL_HOST_BARYCENTRIC staging_bytes=%zu commands=%u columns=%u points=%u gpu_ms=%.3f\n",
                    host_stage_bytes, command_count, column_count, point_plan_count, elapsed_gpu_ms);
        }
        return true;
    }
}

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
    StwoSampledBudgetReceiptV1 private_receipt = {0};
    StwoSampledBudgetLedgerV1 ledger = {NULL, NULL, &private_receipt};
    bool ok = sampled_barycentric_evaluate_v1(false, runtime_ptr, resident_trees, tree_count, columns, column_lengths, output_indices, column_count, point_plans, point_plan_count, groups, group_count, output_count, output, receipt, gpu_milliseconds, error_message, error_message_len, &ledger);
    return sampled_budget_release_all(&ledger) && ok;
}

bool stwo_zig_metal_eval_barycentric_resident_v1_budgeted_v2(
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
    size_t error_message_len,
    void *budget_context, StwoSampledBudgetAdmitV1 budget_admit, StwoSampledBudgetReceiptV1 *budget_receipt
) {
    if (budget_context == NULL || budget_admit == NULL || budget_receipt == NULL) return false;
    *budget_receipt = (StwoSampledBudgetReceiptV1){0};
    StwoSampledBudgetLedgerV1 ledger = {budget_context, budget_admit, budget_receipt};
    bool ok = sampled_barycentric_evaluate_v1(false, runtime_ptr, resident_trees, tree_count, columns, column_lengths, output_indices, column_count, point_plans, point_plan_count, groups, group_count, output_count, output, receipt, gpu_milliseconds, error_message, error_message_len, &ledger);
    return sampled_budget_release_all(&ledger) && ok;
}

bool stwo_zig_metal_eval_barycentric_host_v1(
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
    StwoSampledBudgetReceiptV1 private_receipt = {0};
    StwoSampledBudgetLedgerV1 ledger = {NULL, NULL, &private_receipt};
    bool ok = sampled_barycentric_evaluate_v1(true, runtime_ptr, resident_trees, tree_count, columns, column_lengths, output_indices, column_count, point_plans, point_plan_count, groups, group_count, output_count, output, receipt, gpu_milliseconds, error_message, error_message_len, &ledger);
    return sampled_budget_release_all(&ledger) && ok;
}

bool stwo_zig_metal_eval_barycentric_host_v1_budgeted_v2(
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
    size_t error_message_len,
    void *budget_context, StwoSampledBudgetAdmitV1 budget_admit, StwoSampledBudgetReceiptV1 *budget_receipt
) {
    if (budget_context == NULL || budget_admit == NULL || budget_receipt == NULL) return false;
    *budget_receipt = (StwoSampledBudgetReceiptV1){0};
    StwoSampledBudgetLedgerV1 ledger = {budget_context, budget_admit, budget_receipt};
    bool ok = sampled_barycentric_evaluate_v1(true, runtime_ptr, resident_trees, tree_count, columns, column_lengths, output_indices, column_count, point_plans, point_plan_count, groups, group_count, output_count, output, receipt, gpu_milliseconds, error_message, error_message_len, &ledger);
    return sampled_budget_release_all(&ledger) && ok;
}
