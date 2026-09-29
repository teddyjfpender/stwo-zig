// Reuse native-height quotient partials for coefficient-basis reduction. Each
// output group owns four contiguous planes. Only four source runs are bound at
// once; exact page-backed ranges can be borrowed until the synchronous join.
typedef struct {
    const uint32_t *words;
    size_t length;
    uint32_t coefficients[4];
} StwoZigCoefficientFoldSourceV1;

typedef struct {
    void *context;
    StwoZigExternalBudgetAdmitV1 admit;
    size_t bytes;
} StwoZigCoefficientFoldBudgetV1;

static bool stwo_coefficient_fold_admit(void *raw, size_t bytes) {
    StwoZigCoefficientFoldBudgetV1 *budget = raw;
    if (bytes > SIZE_MAX - budget->bytes || !budget->admit(budget->context, bytes)) return false;
    budget->bytes += bytes;
    return true;
}

static id<MTLBuffer> stwo_coefficient_fold_buffer(
    id<MTLDevice> device, const uint32_t *words, size_t bytes,
    StwoZigCoefficientFoldBudgetV1 *budget
) {
    const size_t page = (size_t)getpagesize();
    if (bytes == 0u || bytes > device.maxBufferLength) return nil;
    if (((uintptr_t)words % page) == 0u && bytes % page == 0u) {
        return [device newBufferWithBytesNoCopy:(void *)words length:bytes
            options:MTLResourceStorageModeShared deallocator:nil];
    }
    return stwo_quotient_owned_buffer(device, words, bytes, MTLResourceStorageModeShared,
        budget, stwo_coefficient_fold_admit);
}

bool stwo_zig_metal_fold_coefficients_v1(
    void *runtime_ptr, const StwoZigCoefficientFoldSourceV1 *input, size_t count,
    uint32_t *output, uint32_t rows, void *budget_context,
    StwoZigExternalBudgetAdmitV1 admit,
    bool (*release)(void *, size_t), uint64_t *dispatches
) {
    if (runtime_ptr == NULL || input == NULL || count == 0u || output == NULL ||
        rows == 0u || admit == NULL || release == NULL || dispatches == NULL ||
        (size_t)rows > SIZE_MAX / (4u * sizeof(uint32_t))) return false;
    *dispatches = 0u;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        if (runtime.quotientPartialsRaw == nil) return false;
        StwoZigCoefficientFoldBudgetV1 destinationBudget = {budget_context, admit, 0u};
        const size_t outputBytes = (size_t)rows * 4u * sizeof(uint32_t);
        if (outputBytes > runtime.device.maxBufferLength) return false;
        const size_t page = (size_t)getpagesize();
        id<MTLBuffer> destination = ((uintptr_t)output % page == 0u && outputBytes % page == 0u)
            ? [runtime.device newBufferWithBytesNoCopy:output length:outputBytes options:MTLResourceStorageModeShared deallocator:nil]
            : stwo_quotient_owned_buffer(runtime.device, NULL, outputBytes, MTLResourceStorageModeShared, &destinationBudget, stwo_coefficient_fold_admit);
        if (destination == nil) return false;
        const bool outputAlias = destination.contents == (void *)output;
        size_t first = 0u;
        bool initialized = false;
        while (first < count) {
            StwoZigCoefficientFoldBudgetV1 waveBudget = {budget_context, admit, 0u};
            bool ok = false;
            size_t next = first;
            @autoreleasepool {
                // A bounded descriptor array allows adjacent live columns to
                // share a source buffer without packing their coefficients.
                StwoZigResidentRawQuotientView views[256];
                const uint32_t *starts[4] = {NULL, NULL, NULL, NULL};
                size_t lengths[4] = {0u, 0u, 0u, 0u};
                uint32_t slots = 0u, viewCount = 0u;
                size_t sourceBytes = 0u;
                const size_t cap = 128u * 1024u * 1024u;
                while (next < count && viewCount < 256u) {
                    const StwoZigCoefficientFoldSourceV1 source = input[next];
                    if (source.words == NULL || source.length == 0u || source.length > rows ||
                        source.length > SIZE_MAX / sizeof(uint32_t)) return false;
                    const size_t bytes = source.length * sizeof(uint32_t);
                    if (bytes > runtime.device.maxBufferLength) return false;
                    if (viewCount != 0u && (bytes > cap || sourceBytes > cap - bytes)) break;
                    uint32_t slot = slots;
                    if (slots != 0u && starts[slots - 1u] + lengths[slots - 1u] == source.words &&
                        source.length <= UINT32_MAX - lengths[slots - 1u] &&
                        lengths[slots - 1u] + source.length <= runtime.device.maxBufferLength / sizeof(uint32_t))
                        slot = slots - 1u;
                    else if (slots == 4u) break;
                    if (slot == slots) { starts[slot] = source.words; ++slots; }
                    views[viewCount++] = (StwoZigResidentRawQuotientView){
                        .offset = (uint32_t)lengths[slot], .length = (uint32_t)source.length,
                        .coeff_a = source.coefficients[0], .coeff_b = source.coefficients[1],
                        .coeff_c = source.coefficients[2], .coeff_d = source.coefficients[3],
                        .source_slot = slot,
                    };
                    lengths[slot] += source.length;
                    sourceBytes += bytes;
                    ++next;
                }
                if (viewCount == 0u) return false;
                id<MTLBuffer> sources[4];
                for (uint32_t slot = 0u; slot < slots; ++slot) {
                    sources[slot] = stwo_coefficient_fold_buffer(runtime.device, starts[slot], lengths[slot] * sizeof(uint32_t), &waveBudget);
                    if (sources[slot] == nil) return false;
                }
                for (uint32_t slot = slots; slot < 4u; ++slot) sources[slot] = sources[0];
                const StwoZigResidentRawQuotientGroup group = {.view_count = viewCount, .row_count = rows};
                const uint32_t rowStart = 0u, groupCount = 1u;
                id<MTLBuffer> viewBuffer = stwo_quotient_owned_buffer(runtime.device, views, viewCount * sizeof(*views), MTLResourceStorageModeShared, &waveBudget, stwo_coefficient_fold_admit);
                id<MTLBuffer> groupBuffer = stwo_quotient_owned_buffer(runtime.device, &group, sizeof(group), MTLResourceStorageModeShared, &waveBudget, stwo_coefficient_fold_admit);
                id<MTLBuffer> startBuffer = stwo_quotient_owned_buffer(runtime.device, &rowStart, sizeof(rowStart), MTLResourceStorageModeShared, &waveBudget, stwo_coefficient_fold_admit);
                if (viewBuffer == nil || groupBuffer == nil || startBuffer == nil) return false;
                id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                if (command == nil || encoder == nil) return false;
                encoder.label = @"stwo_zig_coefficient_basis_fold";
                [encoder setComputePipelineState:runtime.quotientPartialsRaw];
                for (uint32_t slot = 0u; slot < 4u; ++slot) [encoder setBuffer:sources[slot] offset:0u atIndex:slot];
                [encoder setBuffer:viewBuffer offset:0u atIndex:4];
                [encoder setBuffer:groupBuffer offset:0u atIndex:5];
                [encoder setBuffer:startBuffer offset:0u atIndex:6];
                [encoder setBytes:&groupCount length:sizeof(groupCount) atIndex:7];
                [encoder setBytes:&rows length:sizeof(rows) atIndex:8];
                [encoder setBuffer:destination offset:0u atIndex:9];
                const uint32_t accumulate = initialized ? 1u : 0u;
                [encoder setBytes:&accumulate length:sizeof(accumulate) atIndex:10];
                const NSUInteger width = MIN(runtime.quotientPartialsRaw.maxTotalThreadsPerThreadgroup,
                    runtime.quotientPartialsRaw.threadExecutionWidth * 8u);
                [encoder dispatchThreads:MTLSizeMake(rows, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
                [command commit];
                [command waitUntilCompleted];
                ok = command.status == MTLCommandBufferStatusCompleted;
            }
            // Inner pool and joined command no longer own any wave buffers.
            if (!release(budget_context, waveBudget.bytes) || !ok) return false;
            ++*dispatches;
            initialized = true;
            first = next;
        }
        if (!outputAlias) memcpy(output, destination.contents, outputBytes);
        // Destination is destroyed by the outer pool before the Zig scope
        // releases its remaining reservation, including constructor failures.
        return true;
    }
}
