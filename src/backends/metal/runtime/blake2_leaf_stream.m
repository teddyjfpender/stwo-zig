// Synchronous, proof-owned BLAKE2s leaf streaming. No source column aliases
// survive push_block. A failed dispatch poisons this stream, never a host lane.
@interface StwoZigBlake2LeafStream : NSObject
@property(nonatomic, strong) StwoZigMetalRuntime *runtime;
@property(nonatomic, strong) id<MTLBuffer> states;
@property(nonatomic, strong) NSData *leafSeed;
@property(nonatomic, strong) NSData *nodeSeed;
@property(nonatomic) uint32_t prefixBytes;
@property(nonatomic) uint32_t logSize;
@property(nonatomic) uint32_t lastColumnLog;
@property(nonatomic) uint32_t columns;
@property(nonatomic) bool finalBlock;
@property(nonatomic) bool poisoned;
@end
@implementation StwoZigBlake2LeafStream
@end

typedef bool (*StwoZigStreamAdmitV1)(void *, uint64_t);
typedef bool (*StwoZigStreamReleaseV1)(void *, uint64_t);

typedef bool (*StwoZigStreamLayerV1)(void *, uint32_t, const void *, size_t);

void *stwo_zig_metal_blake2_leaf_stream_create_v1(
    void *runtime_ptr, const uint32_t *leaf_seed, const uint32_t *node_seed,
    uint32_t prefix_bytes
) {
    if (!runtime_ptr || !leaf_seed || !node_seed || (prefix_bytes != 0u && prefix_bytes != 64u)) return NULL;
    @autoreleasepool {
        StwoZigBlake2LeafStream *stream = [StwoZigBlake2LeafStream new];
        stream.runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        stream.leafSeed = [NSData dataWithBytes:leaf_seed length:32u];
        stream.nodeSeed = [NSData dataWithBytes:node_seed length:32u];
        stream.prefixBytes = prefix_bytes;
        if (!stream.leafSeed || !stream.nodeSeed) return NULL;
        return (__bridge_retained void *)stream;
    }
}

// Budget admission precedes each genuinely owned Metal allocation. Aliasing
// is permitted only inside an explicitly supplied, page-aligned backing.
static id<MTLBuffer> stwo_stream_source_buffer(
    StwoZigBlake2LeafStream *stream, const uint32_t *column, size_t words,
    const uint32_t *const *backings, const size_t *backing_words, uint32_t backing_count,
    NSUInteger *offset, bool *aliased, void *budget, StwoZigStreamAdmitV1 admit
) {
    const uintptr_t address = (uintptr_t)column;
    const size_t bytes = words * sizeof(uint32_t);
    *offset = 0u; *aliased = false;
    for (uint32_t i = 0; i < backing_count; ++i) {
        const uintptr_t base = (uintptr_t)backings[i];
        if (backing_words[i] > SIZE_MAX / sizeof(uint32_t)) return nil;
        const size_t backing_bytes = backing_words[i] * sizeof(uint32_t);
        if (base > UINTPTR_MAX - backing_bytes) return nil;
        if (address < base || address - base > backing_bytes || bytes > backing_bytes - (address - base)) continue;
        const size_t page = (size_t)getpagesize();
        if (stream.runtime.device.hasUnifiedMemory && base % page == 0u && backing_bytes % page == 0u && backing_bytes <= stream.runtime.device.maxBufferLength) {
            id<MTLBuffer> buffer = [stream.runtime.device newBufferWithBytesNoCopy:(void *)base
                length:backing_bytes options:MTLResourceStorageModeShared deallocator:nil];
            if (!buffer) return nil;
            *offset = address - base; *aliased = true;
            return buffer;
        }
        break;
    }
    if (bytes > stream.runtime.device.maxBufferLength || !admit(budget, bytes)) return nil;
    return [stream.runtime.device newBufferWithBytes:column length:bytes options:MTLResourceStorageModeShared];
}

bool stwo_zig_metal_blake2_leaf_stream_push_v1(
    void *handle, const uint32_t *const *columns, const size_t *lengths, const uint32_t *logs,
    uint32_t count, bool final_block, const uint32_t *const *backings, const size_t *backing_words,
    uint32_t backing_count, void *budget, StwoZigStreamAdmitV1 admit,
    uint64_t *retained_bytes, uint32_t *aliases, uint32_t *uploads, char *message, size_t message_len
) {
    if (!handle || !columns || !lengths || !logs || !admit || !retained_bytes ||
        !aliases || !uploads || count == 0u || count > 16u || (!final_block && count != 16u) ||
        (backing_count && (!backings || !backing_words))) return false;
    @autoreleasepool {
        StwoZigBlake2LeafStream *stream = (__bridge StwoZigBlake2LeafStream *)handle;
        *retained_bytes = stream.states.length; *aliases = 0u; *uploads = 0u;
        if (stream.poisoned || stream.finalBlock || stream.columns > (UINT32_MAX - stream.prefixBytes) / 4u - count) return false;
        for (uint32_t i = 0; i < count; ++i) {
            if (!columns[i] || logs[i] == 0u || logs[i] >= 31u || lengths[i] != ((size_t)1u << logs[i]) ||
                lengths[i] > SIZE_MAX / sizeof(uint32_t) ||
                logs[i] < (i ? logs[i - 1u] : stream.lastColumnLog)) return false;
        }
        const uint32_t destination_log = logs[count - 1u];
        if (((size_t)1u << destination_log) > SIZE_MAX / 32u) return false;
        const size_t state_bytes = ((size_t)1u << destination_log) * 32u;
        if (state_bytes > stream.runtime.device.maxBufferLength || !admit(budget, state_bytes)) return false;
        id<MTLBuffer> destination = [stream.runtime.device newBufferWithLength:state_bytes options:MTLResourceStorageModeShared];
        if (!destination) return false;
        NSMutableArray<id<MTLBuffer>> *sources = [NSMutableArray arrayWithCapacity:count];
        NSUInteger offsets[16] = {0};
        for (uint32_t i = 0; i < count; ++i) {
            bool aliased = false;
            id<MTLBuffer> source = stwo_stream_source_buffer(stream, columns[i], lengths[i], backings,
                backing_words, backing_count, &offsets[i], &aliased, budget, admit);
            if (!source) return false;
            [sources addObject:source];
            if (aliased) ++*aliases; else ++*uploads;
        }
        id<MTLCommandBuffer> command = [stream.runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (!command || !encoder) return false;
        const uint32_t settings[6] = {count, stream.logSize, destination_log, stream.columns, final_block ? 1u : 0u, stream.prefixBytes};
        [encoder setComputePipelineState:stream.runtime.leafAbsorbStreamV1];
        for (uint32_t i = 0; i < 16u; ++i)
            [encoder setBuffer:i < count ? sources[i] : destination offset:i < count ? offsets[i] : 0u atIndex:i];
        [encoder setBuffer:stream.states ?: destination offset:0u atIndex:16];
        [encoder setBuffer:destination offset:0u atIndex:17];
        [encoder setBytes:logs length:count * sizeof(uint32_t) atIndex:18];
        [encoder setBytes:settings length:sizeof(settings) atIndex:19];
        [encoder setBytes:stream.leafSeed.bytes length:32u atIndex:20];
        NSUInteger width = MIN(stream.runtime.leafAbsorbStreamV1.maxTotalThreadsPerThreadgroup,
            stream.runtime.leafAbsorbStreamV1.threadExecutionWidth * 8u);
        [encoder dispatchThreads:MTLSizeMake((NSUInteger)1u << destination_log, 1u, 1u)
            threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            stream.poisoned = true;
            write_error(message, message_len, command.error.localizedDescription ?: @"BLAKE2s stream dispatch failed");
            return false;
        }
        stream.states = destination; stream.logSize = destination_log;
        stream.lastColumnLog = destination_log; stream.columns += count; stream.finalBlock = final_block;
        *retained_bytes = state_bytes;
        return true;
    }
}

bool stwo_zig_metal_blake2_leaf_stream_finish_v1(
    void *handle, uint32_t pruned_layers, void *context, StwoZigStreamLayerV1 publish,
    void *budget, StwoZigStreamAdmitV1 admit, StwoZigStreamReleaseV1 release, char *message, size_t message_len
) {
    if (!handle || !publish || !admit || !release) return false;
    @autoreleasepool {
        StwoZigBlake2LeafStream *stream = (__bridge StwoZigBlake2LeafStream *)handle;
        if (stream.poisoned || !stream.finalBlock || !stream.states || pruned_layers > stream.logSize) return false;
        stream.poisoned = true; // finishing is terminal, including publication failure
        const uint32_t retained_log = stream.logSize - pruned_layers;
        const uint32_t prefix_bytes = stream.prefixBytes;
        id<MTLBuffer> current = stream.states;
        stream.states = nil;
        for (uint32_t log = stream.logSize;; --log) {
            const size_t bytes = ((size_t)1u << log) * 32u;
            @autoreleasepool {
                if (log <= retained_log && !publish(context, log, current.contents, bytes)) return false;
                if (log == 0u) break;
                const uint32_t parents = (uint32_t)1u << (log - 1u);
                if (!admit(budget, (size_t)parents * 32u)) return false;
                id<MTLBuffer> next = [stream.runtime.device newBufferWithLength:(size_t)parents * 32u options:MTLResourceStorageModeShared];
                if (!next) return false;
                id<MTLCommandBuffer> command = [stream.runtime.queue commandBuffer];
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                if (!command || !encoder) return false;
                [encoder setComputePipelineState:stream.runtime.parents];
                [encoder setBuffer:current offset:0u atIndex:0];
                [encoder setBuffer:next offset:0u atIndex:1];
                [encoder setBytes:&parents length:sizeof(parents) atIndex:2];
                [encoder setBytes:stream.nodeSeed.bytes length:32u atIndex:3];
                [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:4];
                NSUInteger width = MIN(stream.runtime.parents.maxTotalThreadsPerThreadgroup, stream.runtime.parents.threadExecutionWidth * 8u);
                [encoder dispatchThreads:MTLSizeMake(parents, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
                if (command.status != MTLCommandBufferStatusCompleted) {
                    write_error(message, message_len, command.error.localizedDescription ?: @"BLAKE2s stream parent dispatch failed");
                    return false;
                }
                current = next;
            }
            // Old input and completed command references have drained. Only
            // the next layer remains owned; account its real live bytes.
            if (!release(budget, bytes)) return false;
        }
        return true;
    }
}

void stwo_zig_metal_blake2_leaf_stream_destroy_v1(void *handle) {
    if (handle) { id owned = (__bridge_transfer id)handle; (void)owned; }
}
