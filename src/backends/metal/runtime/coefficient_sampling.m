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
        coefficient_column_count == 0u || coefficient_count == 0u || coefficient_count > SIZE_MAX / sizeof(uint32_t) ||
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
            coefficient_lengths[i] > UINT32_MAX ||
            coefficient_lengths[i] > SIZE_MAX / sizeof(uint32_t) - actual_words) return false;
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
                            const uintptr_t source_begin = (uintptr_t)coefficients[run_start];
                            const uintptr_t task_begin = (uintptr_t)coefficients[task_column];
                            if (task_begin < source_begin || (task_begin - source_begin) % sizeof(uint32_t) != 0u)
                                return false;
                            const size_t local_offset = (task_begin - source_begin) / sizeof(uint32_t);
                            if (local_offset > UINT32_MAX || local_offset > run_words ||
                                task.coefficient_length > run_words - local_offset)
                                return false;
                            task.coefficient_offset = (uint32_t)local_offset;
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

