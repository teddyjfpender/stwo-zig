// Included after base_polynomial.m for its shared composition output ABI.
// This route resolves admitted AOT kernels only. No source compilation or
// trace-column repacking belongs at this runtime boundary.
@interface StwoZigFrameworkPolynomialPlan : NSObject
@property(nonatomic, strong) StwoZigMetalRuntime *runtimeOwner;
@property(nonatomic, strong) id<MTLComputePipelineState> pipeline;
@property(nonatomic, strong) NSData *columnTrees;
@property(nonatomic) uint32_t profileWordCount;
@property(nonatomic) uint32_t relationWordCount;
@property(nonatomic) uint32_t powerWordCount;
@end
@implementation StwoZigFrameworkPolynomialPlan
@end

typedef struct {
    void *plan;
    uint32_t column_offset;
    uint32_t column_count;
    uint32_t profile_word_offset;
    uint32_t profile_word_count;
    uint32_t relation_word_offset;
    uint32_t relation_word_count;
    uint32_t power_word_offset;
    uint32_t power_word_count;
    uint32_t output_index;
    uint32_t row_count;
    uint32_t trace_log_size;
    uint32_t denominator_count;
    uint32_t denominator_inverses[8];
} StwoZigFrameworkPolynomialDispatch;

// Status values are mirrored by framework_polynomial_operations.zig.
enum { StwoFrameworkInvalid = 1u, StwoFrameworkUnsupported = 2u, StwoFrameworkExecution = 3u };

static uint32_t stwo_framework_error(
    uint32_t status, char *message, size_t length, NSString *detail
) {
    write_error(message, length, detail);
    return status;
}

static bool stwo_framework_span(uint32_t offset, uint32_t count, uint32_t total) {
    return offset <= total && count <= total - offset;
}

static bool stwo_framework_canonical(const uint32_t *words, uint32_t count) {
    if (count != 0u && words == NULL) return false;
    for (uint32_t index = 0u; index < count; ++index)
        if (words[index] >= 0x7fffffffu) return false;
    return true;
}

// The caller derives metadata from the admitted shared program. Pipeline
// presence is additionally checked against the runtime's admitted AOT roster.
void *stwo_zig_metal_framework_polynomial_prepare_aot(
    void *runtime_ptr, const char *name_bytes, size_t name_len,
    const uint32_t *column_trees, uint32_t column_count,
    uint32_t profile_word_count, uint32_t relation_word_count,
    uint32_t power_word_count, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || name_bytes == NULL || name_len == 0u ||
        column_trees == NULL || column_count == 0u || relation_word_count < 4u ||
        relation_word_count % 4u != 0u || power_word_count == 0u || power_word_count % 4u != 0u)
        return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSString *name = [[NSString alloc] initWithBytes:name_bytes length:name_len encoding:NSUTF8StringEncoding];
        if (name == nil || ![name hasPrefix:@"stwo_zig_framework_poly_v1_"]) {
            write_error(error_message, error_message_len, @"Invalid framework-polynomial AOT name");
            return NULL;
        }
        for (uint32_t index = 0u; index < column_count; ++index) {
            if (column_trees[index] > 2u && column_trees[index] != UINT32_MAX) {
                write_error(error_message, error_message_len, @"Unsupported framework column tree");
                return NULL;
            }
            if (column_trees[index] == UINT32_MAX && profile_word_count == 0u) {
                write_error(error_message, error_message_len, @"Framework parameter slot has no profile words");
                return NULL;
            }
        }
        id<MTLComputePipelineState> pipeline = runtime.riscvPolynomialPipelines[name];
        if (pipeline == nil) {
            write_error(error_message, error_message_len,
                        [NSString stringWithFormat:@"Missing admitted framework AOT function %@", name]);
            return NULL;
        }
        StwoZigFrameworkPolynomialPlan *plan = [StwoZigFrameworkPolynomialPlan new];
        plan.runtimeOwner = runtime;
        plan.pipeline = pipeline;
        plan.columnTrees = [NSData dataWithBytes:column_trees length:(size_t)column_count * sizeof(uint32_t)];
        plan.profileWordCount = profile_word_count;
        plan.relationWordCount = relation_word_count;
        plan.powerWordCount = power_word_count;
        if (plan.columnTrees == nil) return NULL;
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_framework_polynomial_plan_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

uint32_t stwo_zig_metal_framework_polynomial_batch(
    void *runtime_ptr, void *const *tree_ptrs, uint32_t tree_count,
    void *composition_domain_buffer, const uint32_t *composition_domain_host_begin,
    size_t composition_domain_word_count,
    const uint32_t *const *columns, uint32_t column_count,
    const StwoZigFrameworkPolynomialDispatch *dispatches, uint32_t dispatch_count,
    const uint32_t *profile_words, uint32_t profile_word_count,
    const uint32_t *relation_words, uint32_t relation_word_count,
    const uint32_t *power_words, uint32_t power_word_count,
    const StwoZigBasePolynomialOutput *outputs, uint32_t output_count,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (gpu_milliseconds != NULL) *gpu_milliseconds = 0.0;
    if (runtime_ptr == NULL || tree_ptrs == NULL || tree_count != 3u ||
        columns == NULL || column_count == 0u || dispatches == NULL || dispatch_count == 0u ||
        outputs == NULL || output_count == 0u || relation_word_count == 0u || power_word_count == 0u ||
        !stwo_framework_canonical(profile_words, profile_word_count) ||
        !stwo_framework_canonical(relation_words, relation_word_count) ||
        !stwo_framework_canonical(power_words, power_word_count))
        return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                    @"Invalid framework batch or noncanonical parameter words");
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSArray<StwoZigMetalTree *> *logicalTrees[3];
        for (uint32_t index = 0u; index < 3u; ++index) {
            logicalTrees[index] = @[];
            if (tree_ptrs[index] == NULL) continue;
            StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)tree_ptrs[index];
            if (tree.runtimeOwner != runtime)
                return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                            @"Framework tree belongs to another runtime");
            logicalTrees[index] = @[tree];
        }
        if (composition_domain_buffer != NULL) {
            id<MTLBuffer> scratch = (__bridge id<MTLBuffer>)composition_domain_buffer;
            if (scratch.device != runtime.device || scratch.contents != composition_domain_host_begin ||
                composition_domain_word_count == 0u || scratch.length % sizeof(uint32_t) != 0u ||
                scratch.length / sizeof(uint32_t) != composition_domain_word_count)
                return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                            @"Invalid framework composition-domain owner or extent");
        } else if (composition_domain_host_begin != NULL || composition_domain_word_count != 0u) {
            return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                        @"Framework scratch metadata has no resident buffer");
        }
        // Metadata transfers only; no trace-column copy or repack occurs.
        const uint32_t zero = 0u;
        id<MTLBuffer> profile = [runtime.device newBufferWithBytes:profile_word_count == 0u ? &zero : profile_words
            length:MAX((size_t)profile_word_count, 1u) * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> relations = [runtime.device newBufferWithBytes:relation_words
            length:(size_t)relation_word_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> powers = [runtime.device newBufferWithBytes:power_words
            length:(size_t)power_word_count * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        if (profile == nil || relations == nil || powers == nil)
            return stwo_framework_error(StwoFrameworkExecution, error_message, error_message_len,
                                        @"Framework parameter buffer allocation failed");

        NSMutableArray<id<MTLBuffer>> *outputBuffers = [NSMutableArray arrayWithCapacity:output_count];
        for (uint32_t index = 0u; index < output_count; ++index) {
            const uint32_t rows = outputs[index].row_count;
            if (rows == 0u || (rows & (rows - 1u)) != 0u)
                return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                            @"Invalid framework output geometry");
            for (uint32_t coordinate = 0u; coordinate < 4u; ++coordinate)
                if (outputs[index].columns[coordinate] == NULL)
                    return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                                @"Missing framework output column");
            const size_t bytes = (size_t)rows * 4u * sizeof(uint32_t);
            if (bytes > runtime.device.maxBufferLength)
                return stwo_framework_error(StwoFrameworkUnsupported, error_message, error_message_len,
                                            @"Framework output exceeds device buffer limit");
            id<MTLBuffer> output = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
            if (output == nil || output.contents == NULL)
                return stwo_framework_error(StwoFrameworkExecution, error_message, error_message_len,
                                            @"Framework output allocation failed");
            memset(output.contents, 0, bytes);
            [outputBuffers addObject:output];
        }

        // Resolve and validate every dispatch before encoding or submitting any
        // work. Each job retains its three logical buffers and u64 offset table.
        NSMutableArray<NSArray<id<MTLBuffer>> *> *jobBuffers = [NSMutableArray arrayWithCapacity:dispatch_count];
        for (uint32_t index = 0u; index < dispatch_count; ++index) {
            const StwoZigFrameworkPolynomialDispatch *item = &dispatches[index];
            if (item->plan == NULL || item->output_index >= output_count ||
                item->row_count != outputs[item->output_index].row_count || item->row_count >= 0x80000000u ||
                item->trace_log_size == 0u || item->trace_log_size >= 31u ||
                (item->denominator_count != 2u && item->denominator_count != 4u && item->denominator_count != 8u) ||
                ((uint64_t)1u << item->trace_log_size) * item->denominator_count != item->row_count ||
                !stwo_framework_span(item->column_offset, item->column_count, column_count) ||
                !stwo_framework_span(item->profile_word_offset, item->profile_word_count, profile_word_count) ||
                !stwo_framework_span(item->relation_word_offset, item->relation_word_count, relation_word_count) ||
                !stwo_framework_span(item->power_word_offset, item->power_word_count, power_word_count))
                return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                            @"Invalid framework dispatch spans or quotient geometry");
            StwoZigFrameworkPolynomialPlan *plan = (__bridge StwoZigFrameworkPolynomialPlan *)item->plan;
            if (![plan isKindOfClass:[StwoZigFrameworkPolynomialPlan class]] || plan.runtimeOwner != runtime ||
                plan.pipeline == nil || plan.columnTrees.length / sizeof(uint32_t) != item->column_count ||
                plan.profileWordCount != item->profile_word_count || plan.relationWordCount != item->relation_word_count ||
                plan.powerWordCount != item->power_word_count)
                return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                            @"Framework plan owner or immutable invocation metadata mismatch");
            for (uint32_t denominator = 0u; denominator < item->denominator_count; ++denominator)
                if (item->denominator_inverses[denominator] == 0u || item->denominator_inverses[denominator] >= 0x7fffffffu)
                    return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                                @"Invalid framework vanishing inverse");
            id<MTLBuffer> offsets = [runtime.device newBufferWithLength:(size_t)item->column_count * sizeof(uint64_t)
                options:MTLResourceStorageModeShared];
            if (offsets == nil || offsets.contents == NULL)
                return stwo_framework_error(StwoFrameworkExecution, error_message, error_message_len,
                                            @"Framework offset allocation failed");
            uint64_t *offsetWords = offsets.contents;
            const uint32_t *slotTrees = plan.columnTrees.bytes;
            id<MTLBuffer> bindings[3] = {nil, nil, nil};
            for (uint32_t slot = 0u; slot < item->column_count; ++slot) {
                const uint32_t logical = slotTrees[slot];
                const uint32_t *column = columns[item->column_offset + slot];
                if (logical == UINT32_MAX) {
                    if (column != NULL)
                        return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                                    @"Framework profile-input slot contains a trace pointer");
                    offsetWords[slot] = 0u;
                    continue;
                }
                StwoZigResidentColumnBinding binding = {0};
                // Search only the selected logical tree. Equal host addresses
                // in another tree cannot silently substitute its commitment.
                if (logical > 2u || logicalTrees[logical].count == 0u ||
                    !stwo_zig_polynomial_input_column(logicalTrees[logical], composition_domain_buffer,
                        composition_domain_host_begin, composition_domain_word_count,
                        column, item->row_count, &binding))
                    return stwo_framework_error(StwoFrameworkUnsupported, error_message, error_message_len,
                                                @"Framework column is not resident in its selected tree or admitted scratch");
                const size_t bufferWords = binding.buffer.length / sizeof(uint32_t);
                if (binding.buffer.device != runtime.device || binding.buffer.length % sizeof(uint32_t) != 0u ||
                    binding.wordOffset > bufferWords || item->row_count > bufferWords - binding.wordOffset)
                    return stwo_framework_error(StwoFrameworkInvalid, error_message, error_message_len,
                                                @"Framework resident column owner or extent mismatch");
                if (bindings[logical] != nil && bindings[logical] != binding.buffer)
                    return stwo_framework_error(StwoFrameworkUnsupported, error_message, error_message_len,
                                                @"Framework logical tree spans multiple resident buffers");
                bindings[logical] = binding.buffer;
                offsetWords[slot] = binding.wordOffset;
            }
            [jobBuffers addObject:@[bindings[0] ?: profile, bindings[1] ?: profile, bindings[2] ?: profile, offsets]];
        }

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (command == nil || encoder == nil)
            return stwo_framework_error(StwoFrameworkExecution, error_message, error_message_len,
                                        @"Framework command allocation failed");
        for (uint32_t index = 0u; index < dispatch_count; ++index) {
            const StwoZigFrameworkPolynomialDispatch *item = &dispatches[index];
            StwoZigFrameworkPolynomialPlan *plan = (__bridge StwoZigFrameworkPolynomialPlan *)item->plan;
            NSArray<id<MTLBuffer>> *buffers = jobBuffers[index];
            [encoder setComputePipelineState:plan.pipeline];
            for (uint32_t slot = 0u; slot < 4u; ++slot) [encoder setBuffer:buffers[slot] offset:0u atIndex:slot];
            [encoder setBuffer:profile offset:item->profile_word_count == 0u ? 0u : (size_t)item->profile_word_offset * sizeof(uint32_t) atIndex:4];
            [encoder setBuffer:relations offset:(size_t)item->relation_word_offset * sizeof(uint32_t) atIndex:5];
            [encoder setBuffer:powers offset:(size_t)item->power_word_offset * sizeof(uint32_t) atIndex:6];
            [encoder setBuffer:outputBuffers[item->output_index] offset:0u atIndex:7];
            [encoder setBytes:&item->row_count length:sizeof(item->row_count) atIndex:8];
            [encoder setBytes:item->denominator_inverses length:(size_t)item->denominator_count * sizeof(uint32_t) atIndex:9];
            [encoder setBytes:&item->denominator_count length:sizeof(item->denominator_count) atIndex:10];
            const NSUInteger width = MIN(plan.pipeline.maxTotalThreadsPerThreadgroup, plan.pipeline.threadExecutionWidth * 8u);
            [encoder dispatchThreads:MTLSizeMake(item->row_count, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            if (index + 1u < dispatch_count) [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        }
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted)
            return stwo_framework_error(StwoFrameworkExecution, error_message, error_message_len,
                                        command.error.localizedDescription ?: @"Framework command failed");
        for (uint32_t index = 0u; index < output_count; ++index) {
            const size_t rows = outputs[index].row_count;
            const uint32_t *source = outputBuffers[index].contents;
            for (uint32_t coordinate = 0u; coordinate < 4u; ++coordinate)
                memcpy(outputs[index].columns[coordinate], source + coordinate * rows, rows * sizeof(uint32_t));
        }
        if (gpu_milliseconds != NULL)
            *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return 0u;
    }
}
