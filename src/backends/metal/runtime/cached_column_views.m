// Bind freshly evaluated columns for device sampling while cached hashes stay
// in the authenticated host reader. This object deliberately has no hash layers.
bool stwo_zig_metal_cached_column_view_is_unified(void *runtime_ptr) {
    if (runtime_ptr == NULL) return false;
    StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
    return runtime.device.hasUnifiedMemory;
}

void *stwo_zig_metal_cached_column_view_v1(
    void *runtime_ptr, const uint32_t *const *columns, const size_t *lengths,
    uint32_t column_count, const uint32_t *const *backings,
    const size_t *backing_lengths, uint32_t backing_count, uint32_t log_size,
    char *error_message, size_t error_message_len
) {
    @autoreleasepool {
        if (runtime_ptr == NULL || columns == NULL || lengths == NULL ||
            column_count == 0u || log_size >= 31u ||
            (backing_count != 0u && (backings == NULL || backing_lengths == NULL))) {
            write_error(error_message, error_message_len, @"Invalid cached column view");
            return NULL;
        }
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSMutableArray<id<MTLBuffer>> *regions = [NSMutableArray arrayWithCapacity:backing_count];
        NSMutableArray<id<MTLBuffer>> *buffers = [NSMutableArray arrayWithCapacity:column_count];
        NSMutableData *begins = [NSMutableData dataWithLength:(NSUInteger)column_count * sizeof(uintptr_t)];
        NSMutableData *counts = [NSMutableData dataWithLength:(NSUInteger)column_count * sizeof(size_t)];
        NSMutableData *offsets = [NSMutableData dataWithLength:(NSUInteger)column_count * sizeof(uint64_t)];
        if (regions == nil || buffers == nil || begins == nil || counts == nil || offsets == nil) {
            write_error(error_message, error_message_len, @"Cached column metadata allocation failed");
            return NULL;
        }
        const size_t page = (size_t)getpagesize();
        for (uint32_t i = 0; i < backing_count; ++i) {
            if (backings[i] == NULL || (uintptr_t)backings[i] % sizeof(uint32_t) != 0u || backing_lengths[i] == 0u ||
                backing_lengths[i] > SIZE_MAX / sizeof(uint32_t)) return NULL;
            const size_t bytes = backing_lengths[i] * sizeof(uint32_t);
            const uintptr_t begin = (uintptr_t)backings[i];
            if (begin > UINTPTR_MAX - bytes || bytes > runtime.device.maxBufferLength) return NULL;
            const bool alias = runtime.device.hasUnifiedMemory && begin % page == 0u && bytes % page == 0u;
            id<MTLBuffer> region = alias
                ? [runtime.device newBufferWithBytesNoCopy:(void *)backings[i] length:bytes
                    options:MTLResourceStorageModeShared deallocator:nil]
                : [runtime.device newBufferWithBytes:backings[i] length:bytes options:MTLResourceStorageModeShared];
            if (region == nil) {
                write_error(error_message, error_message_len, @"Cached column backing allocation failed");
                return NULL;
            }
            [regions addObject:region];
        }
        uintptr_t *begin_values = begins.mutableBytes;
        size_t *count_values = counts.mutableBytes;
        uint64_t *offset_values = offsets.mutableBytes;
        uint32_t observed_log = 0u;
        for (uint32_t i = 0; i < column_count; ++i) {
            const size_t length = lengths[i];
            const uintptr_t begin = (uintptr_t)columns[i];
            if (columns[i] == NULL || begin % sizeof(uint32_t) != 0u || length == 0u || (length & (length - 1u)) != 0u ||
                length > ((size_t)1u << log_size) || length > SIZE_MAX / sizeof(uint32_t)) return NULL;
            const size_t bytes = length * sizeof(uint32_t);
            if (begin > UINTPTR_MAX - bytes || bytes > runtime.device.maxBufferLength) return NULL;
            uint32_t column_log = 0u;
            for (size_t n = length; n > 1u; n >>= 1u) column_log += 1u;
            observed_log = MAX(observed_log, column_log);
            id<MTLBuffer> buffer = nil;
            uint64_t offset = 0u;
            for (uint32_t j = 0; j < backing_count; ++j) {
                const uintptr_t backing_begin = (uintptr_t)backings[j];
                const size_t backing_bytes = backing_lengths[j] * sizeof(uint32_t);
                if (begin >= backing_begin && begin <= backing_begin + backing_bytes &&
                    bytes <= backing_begin + backing_bytes - begin) {
                    buffer = regions[j];
                    offset = (uint64_t)((begin - backing_begin) / sizeof(uint32_t));
                    break;
                }
            }
            if (buffer == nil && backing_count != 0u) {
                write_error(error_message, error_message_len, @"Cached column is outside its backing");
                return NULL;
            }
            if (buffer == nil) {
                buffer = [runtime.device newBufferWithBytes:columns[i] length:bytes options:MTLResourceStorageModeShared];
                if (buffer == nil) return NULL;
            }
            [buffers addObject:buffer];
            begin_values[i] = begin;
            count_values[i] = length;
            offset_values[i] = offset;
        }
        if (observed_log != log_size) return NULL;
        StwoZigMetalTree *view = [StwoZigMetalTree new];
        view.runtimeOwner = runtime;
        view.logSize = log_size;
        view.residentColumnBuffers = buffers;
        view.residentColumnHostBegins = begins;
        view.residentColumnWordCounts = counts;
        view.residentColumnWordOffsets = offsets;
        view.residentColumnOffsetWordBytes = sizeof(uint64_t);
        return (__bridge_retained void *)view;
    }
}
