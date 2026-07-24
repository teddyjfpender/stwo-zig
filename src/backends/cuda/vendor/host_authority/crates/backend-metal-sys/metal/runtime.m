#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <dispatch/dispatch.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

@interface StwoMetalRuntimeBox : NSObject
@property(nonatomic, strong) id<MTLDevice> device;
@property(nonatomic, strong) id<MTLCommandQueue> queue;
@property(nonatomic, strong) id<MTLLibrary> library;
@property(nonatomic, strong) NSArray<id<MTLLibrary>> *libraries;
@property(nonatomic, strong) NSMutableDictionary<NSString *, id<MTLComputePipelineState>> *pipelines;
@property(nonatomic, strong) id<MTLBinaryArchive> binaryArchive;
@end

@implementation StwoMetalRuntimeBox
@end

@interface StwoMetalBufferBox : NSObject
@property(nonatomic, strong) id<MTLBuffer> buffer;
@property(nonatomic, assign) NSUInteger len;
@property(nonatomic, assign) BOOL isPrivate;
@end

@implementation StwoMetalBufferBox
@end

static id<MTLFunction> stwo_metal_find_function(StwoMetalRuntimeBox *runtime, NSString *name) {
    if (runtime.library != nil) {
        id<MTLFunction> function = stwo_metal_find_function(runtime, name);
        if (function != nil) {
            return function;
        }
    }
    for (id<MTLLibrary> library in runtime.libraries) {
        id<MTLFunction> function = [library newFunctionWithName:name];
        if (function != nil) {
            return function;
        }
    }
    return nil;
}

// ---------------------------------------------------------------------------
// Buffer pool for temporary GPU buffers (eliminates ~50-60 newBufferWithLength
// + release cycles per proof for GKR sum scratch, FRI fold intermediates, etc.)
// ---------------------------------------------------------------------------

@interface StwoMetalBufferPool : NSObject {
    NSMutableDictionary<NSNumber *, NSMutableArray<id<MTLBuffer>> *> *_pool;
    id<MTLDevice> _device;
}
+ (instancetype)sharedPoolForDevice:(id<MTLDevice>)device;
- (id<MTLBuffer>)acquireWithByteSize:(NSUInteger)byteSize;
- (void)returnBuffer:(id<MTLBuffer>)buffer;
@end

@implementation StwoMetalBufferPool

static StwoMetalBufferPool *sSharedPool = nil;

+ (instancetype)sharedPoolForDevice:(id<MTLDevice>)device {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sSharedPool = [[StwoMetalBufferPool alloc] initWithDevice:device];
    });
    return sSharedPool;
}

- (instancetype)initWithDevice:(id<MTLDevice>)device {
    self = [super init];
    if (self) {
        _pool = [NSMutableDictionary dictionary];
        _device = device;
    }
    return self;
}

- (id<MTLBuffer>)acquireWithByteSize:(NSUInteger)byteSize {
    if (byteSize == 0) byteSize = 4;  // Metal requires non-zero length.
    @synchronized(self) {
        NSNumber *key = @(byteSize);
        NSMutableArray<id<MTLBuffer>> *list = _pool[key];
        if (list != nil && list.count > 0) {
            id<MTLBuffer> buffer = list.lastObject;
            [list removeLastObject];
            return buffer;
        }
    }
    // Cache miss — allocate a new buffer.
    return [_device newBufferWithLength:byteSize options:MTLResourceStorageModeShared];
}

- (void)returnBuffer:(id<MTLBuffer>)buffer {
    if (buffer == nil) return;
    @synchronized(self) {
        NSNumber *key = @(buffer.length);
        NSMutableArray<id<MTLBuffer>> *list = _pool[key];
        if (list == nil) {
            list = [NSMutableArray arrayWithCapacity:8];
            _pool[key] = list;
        }
        // Cap per-size pool to avoid unbounded memory growth.
        if (list.count < 16) {
            [list addObject:buffer];
        }
    }
}

@end

// Forward declaration so pool helpers can call it.
static void stwo_metal_write_error(char *dst, size_t dst_len, NSString *message);

/// Convenience: acquire four scratch buffers of equal size from the pool.
static bool stwo_metal_pool_acquire_4(
    StwoMetalBufferPool *pool,
    NSUInteger byteSize,
    id<MTLBuffer> *out0,
    id<MTLBuffer> *out1,
    id<MTLBuffer> *out2,
    id<MTLBuffer> *out3,
    char *error_message,
    size_t error_message_len
) {
    *out0 = [pool acquireWithByteSize:byteSize];
    *out1 = [pool acquireWithByteSize:byteSize];
    *out2 = [pool acquireWithByteSize:byteSize];
    *out3 = [pool acquireWithByteSize:byteSize];
    if (*out0 == nil || *out1 == nil || *out2 == nil || *out3 == nil) {
        stwo_metal_write_error(error_message, error_message_len,
            @"Failed to acquire Metal scratch buffers from pool.");
        // Return any that succeeded back to pool.
        if (*out0) [pool returnBuffer:*out0];
        if (*out1) [pool returnBuffer:*out1];
        if (*out2) [pool returnBuffer:*out2];
        if (*out3) [pool returnBuffer:*out3];
        return false;
    }
    return true;
}

/// Convenience: return four scratch buffers to the pool.
static void stwo_metal_pool_return_4(
    StwoMetalBufferPool *pool,
    id<MTLBuffer> b0,
    id<MTLBuffer> b1,
    id<MTLBuffer> b2,
    id<MTLBuffer> b3
) {
    [pool returnBuffer:b0];
    [pool returnBuffer:b1];
    [pool returnBuffer:b2];
    [pool returnBuffer:b3];
}

typedef struct {
    uint32_t initial_x;
    uint32_t initial_y;
    uint32_t step_x;
    uint32_t step_y;
    uint32_t offset;
    uint32_t level_log_size;
} StwoMetalTwiddleLevelParams;

static void stwo_metal_write_error(char *dst, size_t dst_len, NSString *message) {
    if (dst == NULL || dst_len == 0) {
        return;
    }

    const char *utf8 = message.UTF8String;
    if (utf8 == NULL) {
        utf8 = "unknown Metal runtime error";
    }

    size_t copy_len = strnlen(utf8, dst_len - 1);
    memcpy(dst, utf8, copy_len);
    dst[copy_len] = '\0';
}

static StwoMetalRuntimeBox *stwo_metal_runtime_box(void *runtime) {
    return (__bridge StwoMetalRuntimeBox *)runtime;
}

static StwoMetalBufferBox *stwo_metal_buffer_box(void *buffer) {
    return (__bridge StwoMetalBufferBox *)buffer;
}

static id<MTLComputePipelineState> stwo_metal_pipeline(
    StwoMetalRuntimeBox *runtime,
    NSString *name,
    char *error_message,
    size_t error_message_len
) {
    @synchronized(runtime) {
        id<MTLComputePipelineState> pipeline = runtime.pipelines[name];
        if (pipeline != nil) {
            return pipeline;
        }

        id<MTLFunction> function = stwo_metal_find_function(runtime, name);
        if (function == nil) {
            stwo_metal_write_error(error_message, error_message_len, [NSString stringWithFormat:@"Missing Metal kernel '%@'.", name]);
            return nil;
        }

        NSError *error = nil;
        pipeline = [runtime.device newComputePipelineStateWithFunction:function error:&error];
        if (pipeline == nil) {
            stwo_metal_write_error(error_message, error_message_len, error.localizedDescription ?: @"Failed to compile Metal pipeline state.");
            return nil;
        }

        runtime.pipelines[name] = pipeline;
        return pipeline;
    }
}

static id<MTLComputePipelineState> stwo_metal_pipeline_with_max_threads(
    StwoMetalRuntimeBox *runtime,
    NSString *kernel_name,
    NSUInteger max_threads_per_tg,
    char *error_message,
    size_t error_message_len
) {
    NSString *cache_key = [NSString stringWithFormat:@"%@@tg%lu", kernel_name, (unsigned long)max_threads_per_tg];
    @synchronized(runtime) {
        id<MTLComputePipelineState> cached = runtime.pipelines[cache_key];
        if (cached != nil) {
            return cached;
        }
    }

    id<MTLFunction> function = stwo_metal_find_function(runtime, kernel_name);
    if (function == nil) {
        stwo_metal_write_error(error_message, error_message_len, [NSString stringWithFormat:@"Missing Metal kernel '%@'.", kernel_name]);
        return nil;
    }

    MTLComputePipelineDescriptor *desc = [[MTLComputePipelineDescriptor alloc] init];
    desc.computeFunction = function;
    desc.maxTotalThreadsPerThreadgroup = max_threads_per_tg;

    NSError *error = nil;
    id<MTLComputePipelineState> pipeline = [runtime.device
        newComputePipelineStateWithDescriptor:desc options:0 reflection:nil error:&error];
    if (pipeline == nil) {
        stwo_metal_write_error(error_message, error_message_len, error.localizedDescription ?: @"Failed to compile Metal pipeline state with descriptor.");
        return nil;
    }

    @synchronized(runtime) {
        runtime.pipelines[cache_key] = pipeline;
    }
    return pipeline;
}

static NSUInteger stwo_metal_threads_per_group(id<MTLComputePipelineState> pipeline) {
    NSUInteger threadgroup_width = pipeline.threadExecutionWidth > 0 ? pipeline.threadExecutionWidth : 1;
    NSUInteger max_threads = pipeline.maxTotalThreadsPerThreadgroup > 0 ? pipeline.maxTotalThreadsPerThreadgroup : 1;
    return MIN((NSUInteger)256, MAX(threadgroup_width, max_threads));
}

// ---------------------------------------------------------------------------
// Binary archive cache for JIT-compiled shaders
// ---------------------------------------------------------------------------

static NSURL *stwo_metal_binary_archive_url(void) {
    NSString *cachePath = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dir = [cachePath stringByAppendingPathComponent:@"stwo-metal"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    return [NSURL fileURLWithPath:[dir stringByAppendingPathComponent:@"shader_archive.metallib"]];
}

static void stwo_metal_ensure_binary_archive(StwoMetalRuntimeBox *runtime) {
    if (runtime.binaryArchive != nil) return;

    MTLBinaryArchiveDescriptor *desc = [[MTLBinaryArchiveDescriptor alloc] init];
    NSURL *url = stwo_metal_binary_archive_url();

    // Try loading an existing archive from disk.
    if ([[NSFileManager defaultManager] fileExistsAtPath:url.path]) {
        desc.url = url;
        NSError *loadError = nil;
        id<MTLBinaryArchive> archive = [runtime.device newBinaryArchiveWithDescriptor:desc
                                                                                error:&loadError];
        if (archive != nil) {
            runtime.binaryArchive = archive;
            return;
        }
        // Fall through: corrupted or incompatible archive — create fresh.
    }

    // Create a new empty archive.
    desc.url = nil;
    NSError *createError = nil;
    id<MTLBinaryArchive> archive = [runtime.device newBinaryArchiveWithDescriptor:desc
                                                                            error:&createError];
    if (archive != nil) {
        runtime.binaryArchive = archive;
    }
}

/// JIT-compile a shader and cache the pipeline in both the in-memory dictionary
/// and the on-disk binary archive.  Returns nil on failure (and writes to
/// error_message).
///
/// When max_threads_per_tg > 0, a descriptor-based pipeline is created with
/// maxTotalThreadsPerThreadgroup set to the given value, and the cache key is
/// suffixed with "@tg<N>".  Pass 0 for the default behavior.
static id<MTLComputePipelineState> stwo_metal_jit_pipeline_cached(
    StwoMetalRuntimeBox *runtime,
    NSString *sourceStr,
    NSString *functionName,
    uint32_t max_threads_per_tg,
    char *error_message,
    size_t error_message_len
) {
    NSString *cacheKey = (max_threads_per_tg > 0)
        ? [NSString stringWithFormat:@"%@@tg%u", functionName, max_threads_per_tg]
        : functionName;

    // 1. Check in-memory pipeline cache.
    @synchronized(runtime) {
        id<MTLComputePipelineState> existing = runtime.pipelines[cacheKey];
        if (existing != nil) {
            return existing;
        }
    }

    // 2. Compile from source.
    MTLCompileOptions *options = [[MTLCompileOptions alloc] init];
    if (@available(macOS 15.0, *)) {
        options.mathMode = MTLMathModeFast;
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        options.fastMathEnabled = YES;
#pragma clang diagnostic pop
    }

    NSError *compileError = nil;
    id<MTLLibrary> library = [runtime.device newLibraryWithSource:sourceStr
                                                         options:options
                                                           error:&compileError];
    if (library == nil) {
        stwo_metal_write_error(error_message, error_message_len,
            compileError.localizedDescription ?: @"Failed to JIT-compile Metal shader.");
        return nil;
    }

    id<MTLFunction> function = [library newFunctionWithName:functionName];
    if (function == nil) {
        stwo_metal_write_error(error_message, error_message_len,
            [NSString stringWithFormat:@"JIT-compiled library missing kernel '%@'.", functionName]);
        return nil;
    }

    // 3. Create pipeline.
    NSError *pipelineError = nil;
    id<MTLComputePipelineState> pipeline = nil;
    if (max_threads_per_tg > 0) {
        MTLComputePipelineDescriptor *desc = [[MTLComputePipelineDescriptor alloc] init];
        desc.computeFunction = function;
        desc.maxTotalThreadsPerThreadgroup = (NSUInteger)max_threads_per_tg;
        pipeline = [runtime.device newComputePipelineStateWithDescriptor:desc
                                                                options:0
                                                             reflection:nil
                                                                  error:&pipelineError];
    } else {
        pipeline = [runtime.device newComputePipelineStateWithFunction:function error:&pipelineError];
    }
    if (pipeline == nil) {
        stwo_metal_write_error(error_message, error_message_len,
            pipelineError.localizedDescription ?: @"Failed to create pipeline from JIT-compiled shader.");
        return nil;
    }

    // 4. Store in memory cache.
    @synchronized(runtime) {
        runtime.pipelines[cacheKey] = pipeline;
    }

    // 5. Add to binary archive and persist.
    stwo_metal_ensure_binary_archive(runtime);
    if (runtime.binaryArchive != nil) {
        if (max_threads_per_tg > 0) {
            MTLComputePipelineDescriptor *archiveDesc = [[MTLComputePipelineDescriptor alloc] init];
            archiveDesc.computeFunction = function;
            archiveDesc.maxTotalThreadsPerThreadgroup = (NSUInteger)max_threads_per_tg;
            [runtime.binaryArchive addComputePipelineFunctionsWithDescriptor:archiveDesc error:nil];
        } else {
            MTLComputePipelineDescriptor *archiveDesc = [[MTLComputePipelineDescriptor alloc] init];
            archiveDesc.computeFunction = function;
            [runtime.binaryArchive addComputePipelineFunctionsWithDescriptor:archiveDesc error:nil];
        }
        [runtime.binaryArchive serializeToURL:stwo_metal_binary_archive_url() error:nil];
    }

    return pipeline;
}

static id<MTLBuffer> stwo_metal_encode_qm31_pair_reduction(
    id<MTLCommandBuffer> command_buffer,
    id<MTLComputePipelineState> pipeline,
    id<MTLBuffer> current,
    id<MTLBuffer> temp,
    uint32_t len,
    char *error_message,
    size_t error_message_len
) {
    uint32_t current_len = len;
    id<MTLBuffer> current_buffer = current;
    id<MTLBuffer> temp_buffer = temp;

    while (current_len > 1u) {
        uint32_t next_len = current_len >> 1u;
        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return nil;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:current_buffer offset:0 atIndex:0];
        [encoder setBuffer:temp_buffer offset:0 atIndex:1];
        [encoder setBytes:&next_len length:sizeof(next_len) atIndex:2];
        MTLSize grid_size = MTLSizeMake(next_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        id<MTLBuffer> swap = current_buffer;
        current_buffer = temp_buffer;
        temp_buffer = swap;
        current_len = next_len;
    }

    return current_buffer;
}

static bool stwo_metal_dispatch_unary_u32_kernel(
    StwoMetalRuntimeBox *runtime,
    NSString *kernel_name,
    StwoMetalBufferBox *buffer,
    uint32_t log_len,
    char *error_message,
    size_t error_message_len
) {
    id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, kernel_name, error_message, error_message_len);
    if (pipeline == nil) {
        return false;
    }

    id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
    if (command_buffer == nil) {
        stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
        return false;
    }

    id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
    if (encoder == nil) {
        stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
        return false;
    }

    NSUInteger len = ((NSUInteger)1) << log_len;
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:buffer.buffer offset:0 atIndex:0];
    [encoder setBytes:&log_len length:sizeof(log_len) atIndex:1];

    MTLSize grid_size = MTLSizeMake(len, 1, 1);
    MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
    [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
    [encoder endEncoding];

    [command_buffer commit];
    [command_buffer waitUntilCompleted];

    if (command_buffer.status == MTLCommandBufferStatusError) {
        stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
        return false;
    }

    return true;
}

void *stwo_metal_runtime_create(
    const uint8_t *metallib_bytes,
    size_t metallib_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"No Metal device is available.");
            return NULL;
        }

        dispatch_data_t library_data =
            dispatch_data_create(metallib_bytes, metallib_len, dispatch_get_main_queue(), ^{
            });
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithData:library_data error:&error];
        if (library == nil) {
            stwo_metal_write_error(error_message, error_message_len, error.localizedDescription ?: @"Failed to load embedded Metal library.");
            return NULL;
        }

        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (queue == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command queue.");
            return NULL;
        }

        StwoMetalRuntimeBox *runtime = [StwoMetalRuntimeBox new];
        runtime.device = device;
        runtime.queue = queue;
        runtime.library = library;
        runtime.pipelines = [NSMutableDictionary dictionary];
        return (__bridge_retained void *)runtime;
    }
}

void *stwo_metal_runtime_create_from_sources(
    const char *const *library_sources,
    size_t library_source_count,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"No Metal device is available.");
            return NULL;
        }

        MTLCompileOptions *options = [MTLCompileOptions new];
        options.mathMode = MTLMathModeSafe;
        NSMutableArray<id<MTLLibrary>> *libraries =
            [NSMutableArray arrayWithCapacity:library_source_count];
        for (size_t i = 0; i < library_source_count; i++) {
            NSString *source = [NSString stringWithUTF8String:library_sources[i]];
            if (source == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Invalid Metal library source string.");
                return NULL;
            }
            NSError *error = nil;
            id<MTLLibrary> library = [device newLibraryWithSource:source options:options error:&error];
            if (library == nil) {
                stwo_metal_write_error(error_message, error_message_len, error.localizedDescription ?: @"Failed to compile Metal library from source.");
                return NULL;
            }
            [libraries addObject:library];
        }

        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (queue == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command queue.");
            return NULL;
        }

        StwoMetalRuntimeBox *runtime = [StwoMetalRuntimeBox new];
        runtime.device = device;
        runtime.queue = queue;
        runtime.library = nil;
        runtime.libraries = libraries;
        runtime.pipelines = [NSMutableDictionary dictionary];
        return (__bridge_retained void *)runtime;
    }
}

void stwo_metal_runtime_destroy(void *runtime) {
    if (runtime == NULL) {
        return;
    }
    @autoreleasepool {
        __unused id released = (__bridge_transfer id)runtime;
    }
}

void *stwo_metal_u32_buffer_from_host(
    void *runtime_ptr,
    const uint32_t *host_ptr,
    size_t len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        NSUInteger bytes = len * sizeof(uint32_t);
        id<MTLBuffer> buffer = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
        if (buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate Metal buffer.");
            return NULL;
        }

        if (bytes > 0) {
            memcpy(buffer.contents, host_ptr, bytes);
        }

        StwoMetalBufferBox *box = [StwoMetalBufferBox new];
        box.buffer = buffer;
        box.len = len;
        return (__bridge_retained void *)box;
    }
}

void *stwo_metal_u32_buffer_alloc_zeroed(
    void *runtime_ptr,
    size_t len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        NSUInteger bytes = len * sizeof(uint32_t);
        id<MTLBuffer> buffer = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
        if (buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate Metal buffer.");
            return NULL;
        }

        if (bytes > 0) {
            memset(buffer.contents, 0, bytes);
        }

        StwoMetalBufferBox *box = [StwoMetalBufferBox new];
        box.buffer = buffer;
        box.len = len;
        return (__bridge_retained void *)box;
    }
}

void *stwo_metal_u32_buffer_alloc_uninitialized(
    void *runtime_ptr,
    size_t len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        NSUInteger bytes = len * sizeof(uint32_t);
        id<MTLBuffer> buffer = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
        if (buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate Metal buffer.");
            return NULL;
        }

        StwoMetalBufferBox *box = [StwoMetalBufferBox new];
        box.buffer = buffer;
        box.len = len;
        return (__bridge_retained void *)box;
    }
}

void *stwo_metal_u32_buffer_alloc_uninitialized_private(
    void *runtime_ptr,
    size_t len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        NSUInteger bytes = len * sizeof(uint32_t);
        id<MTLBuffer> buffer = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModePrivate];
        if (buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate private Metal buffer.");
            return NULL;
        }

        StwoMetalBufferBox *box = [StwoMetalBufferBox new];
        box.buffer = buffer;
        box.len = len;
        box.isPrivate = YES;
        return (__bridge_retained void *)box;
    }
}

void *stwo_metal_u32_buffer_from_host_private(
    void *runtime_ptr,
    const uint32_t *host_ptr,
    size_t len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        NSUInteger bytes = len * sizeof(uint32_t);

        // Allocate a shared staging buffer for the upload.
        id<MTLBuffer> staging = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
        if (staging == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate staging buffer for private upload.");
            return NULL;
        }

        if (bytes > 0) {
            memcpy(staging.contents, host_ptr, bytes);
        }

        // Allocate the private destination buffer.
        id<MTLBuffer> private_buffer = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModePrivate];
        if (private_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate private Metal buffer.");
            return NULL;
        }

        // Blit from staging to private.
        id<MTLCommandBuffer> cmd = [runtime.queue commandBuffer];
        if (cmd == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create command buffer for private upload.");
            return NULL;
        }
        id<MTLBlitCommandEncoder> blit = [cmd blitCommandEncoder];
        [blit copyFromBuffer:staging sourceOffset:0 toBuffer:private_buffer destinationOffset:0 size:bytes];
        [blit endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        StwoMetalBufferBox *box = [StwoMetalBufferBox new];
        box.buffer = private_buffer;
        box.len = len;
        box.isPrivate = YES;
        return (__bridge_retained void *)box;
    }
}

bool stwo_metal_u32_buffer_is_private(void *buffer_ptr) {
    @autoreleasepool {
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        return buffer.isPrivate;
    }
}

bool stwo_metal_u32_buffer_promote_to_private(
    void *runtime_ptr,
    void *buffer_ptr,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalBufferBox *box = stwo_metal_buffer_box(buffer_ptr);
        if (box.isPrivate) {
            return true; // Already private — no-op.
        }
        NSUInteger bytes = box.len * sizeof(uint32_t);
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        id<MTLBuffer> private_buffer = [runtime.device newBufferWithLength:bytes
                                                                  options:MTLResourceStorageModePrivate];
        if (private_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to allocate private buffer for promotion.");
            return false;
        }
        id<MTLCommandBuffer> cmd = [runtime.queue commandBuffer];
        id<MTLBlitCommandEncoder> blit = [cmd blitCommandEncoder];
        [blit copyFromBuffer:box.buffer sourceOffset:0
                    toBuffer:private_buffer destinationOffset:0
                        size:bytes];
        [blit endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];
        box.buffer = private_buffer;
        box.isPrivate = YES;
        return true;
    }
}

void stwo_metal_u32_buffer_destroy(void *buffer) {
    if (buffer == NULL) {
        return;
    }
    @autoreleasepool {
        __unused id released = (__bridge_transfer id)buffer;
    }
}

bool stwo_metal_u32_buffer_read(
    void *runtime_ptr,
    void *buffer_ptr,
    uint32_t *host_ptr,
    size_t len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        if (len > buffer.len) {
            stwo_metal_write_error(error_message, error_message_len, @"Requested read exceeds Metal buffer length.");
            return false;
        }

        if (len == 0) return true;

        if (buffer.isPrivate) {
            // Private buffer: blit to a shared staging buffer, then memcpy.
            StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
            NSUInteger bytes = len * sizeof(uint32_t);
            id<MTLBuffer> staging = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
            if (staging == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate staging buffer for private readback.");
                return false;
            }
            id<MTLCommandBuffer> cmd = [runtime.queue commandBuffer];
            id<MTLBlitCommandEncoder> blit = [cmd blitCommandEncoder];
            [blit copyFromBuffer:buffer.buffer sourceOffset:0 toBuffer:staging destinationOffset:0 size:bytes];
            [blit endEncoding];
            [cmd commit];
            [cmd waitUntilCompleted];
            memcpy(host_ptr, staging.contents, bytes);
        } else {
            memcpy(host_ptr, buffer.buffer.contents, len * sizeof(uint32_t));
        }
        return true;
    }
}

const uint32_t *stwo_metal_u32_buffer_host_ptr(void *buffer_ptr) {
    @autoreleasepool {
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        if (buffer.isPrivate) {
            return NULL;
        }
        return (const uint32_t *)buffer.buffer.contents;
    }
}

uint32_t stwo_metal_u32_buffer_get(void *buffer_ptr, size_t index) {
    @autoreleasepool {
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        NSCAssert(!buffer.isPrivate, @"Cannot get element from private Metal buffer — use GPU readback instead.");
        return ((uint32_t *)buffer.buffer.contents)[index];
    }
}

void stwo_metal_u32_buffer_set(void *buffer_ptr, size_t index, uint32_t value) {
    @autoreleasepool {
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        NSCAssert(!buffer.isPrivate, @"Cannot set element on private Metal buffer — use GPU upload instead.");
        ((uint32_t *)buffer.buffer.contents)[index] = value;
    }
}

bool stwo_metal_u32_buffer_copy(
    void *runtime_ptr,
    void *src_ptr,
    void *dst_ptr,
    size_t len,
    size_t dst_offset,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        if (len > src.len || dst_offset + len > dst.len) {
            stwo_metal_write_error(error_message, error_message_len, @"Metal buffer copy exceeds source or destination length.");
            return false;
        }

        NSUInteger bytes = len * sizeof(uint32_t);
        if (src.isPrivate || dst.isPrivate) {
            StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
            id<MTLCommandBuffer> cmd = [runtime.queue commandBuffer];
            id<MTLBlitCommandEncoder> blit = [cmd blitCommandEncoder];
            [blit copyFromBuffer:src.buffer sourceOffset:0
                        toBuffer:dst.buffer destinationOffset:dst_offset * sizeof(uint32_t)
                            size:bytes];
            [blit endEncoding];
            [cmd commit];
            // Do NOT wait — same-queue ordering guarantees subsequent GPU
            // operations (e.g. RFFT) see the completed copy. This eliminates
            // ~50μs overhead per copy × 600+ polynomials in evaluate_polynomials.
        } else {
            memmove(
                ((uint32_t *)dst.buffer.contents) + dst_offset,
                ((uint32_t *)src.buffer.contents),
                bytes
            );
        }
        return true;
    }
}

bool stwo_metal_u32_buffer_copy_range(
    void *runtime_ptr,
    void *src_ptr,
    void *dst_ptr,
    size_t src_offset,
    size_t len,
    size_t dst_offset,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        if (src_offset + len > src.len || dst_offset + len > dst.len) {
            stwo_metal_write_error(error_message, error_message_len, @"Metal buffer range copy exceeds source or destination length.");
            return false;
        }

        NSUInteger bytes = len * sizeof(uint32_t);
        if (src.isPrivate || dst.isPrivate) {
            StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
            id<MTLCommandBuffer> cmd = [runtime.queue commandBuffer];
            id<MTLBlitCommandEncoder> blit = [cmd blitCommandEncoder];
            [blit copyFromBuffer:src.buffer sourceOffset:src_offset * sizeof(uint32_t)
                        toBuffer:dst.buffer destinationOffset:dst_offset * sizeof(uint32_t)
                            size:bytes];
            [blit endEncoding];
            [cmd commit];
            // Do NOT wait — same-queue ordering guarantees correctness.
        } else {
            memmove(
                ((uint32_t *)dst.buffer.contents) + dst_offset,
                ((uint32_t *)src.buffer.contents) + src_offset,
                bytes
            );
        }
        return true;
    }
}

bool stwo_metal_u32_buffer_read_indices(
    void *runtime_ptr,
    void *buffer_ptr,
    const uint32_t *indices,
    size_t indices_len,
    uint32_t *host_ptr,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        if (indices_len > 0 && (indices == NULL || host_ptr == NULL)) {
            stwo_metal_write_error(error_message, error_message_len, @"Indexed Metal buffer read requires non-null indices and destination pointers.");
            return false;
        }

        const uint32_t *values;
        id<MTLBuffer> staging = nil;

        if (buffer.isPrivate) {
            // Blit entire buffer to shared staging, then index from there.
            StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
            NSUInteger bytes = buffer.len * sizeof(uint32_t);
            staging = [runtime.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
            if (staging == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate staging buffer for private indexed read.");
                return false;
            }
            id<MTLCommandBuffer> cmd = [runtime.queue commandBuffer];
            id<MTLBlitCommandEncoder> blit = [cmd blitCommandEncoder];
            [blit copyFromBuffer:buffer.buffer sourceOffset:0 toBuffer:staging destinationOffset:0 size:bytes];
            [blit endEncoding];
            [cmd commit];
            [cmd waitUntilCompleted];
            values = (const uint32_t *)staging.contents;
        } else {
            values = (const uint32_t *)buffer.buffer.contents;
        }

        for (size_t i = 0; i < indices_len; ++i) {
            uint32_t index = indices[i];
            if ((NSUInteger)index >= buffer.len) {
                stwo_metal_write_error(error_message, error_message_len, @"Indexed Metal buffer read exceeded source bounds.");
                return false;
            }
            host_ptr[i] = values[index];
        }
        return true;
    }
}

bool stwo_metal_bit_reverse_u32(
    void *runtime_ptr,
    void *buffer_ptr,
    uint32_t log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        NSUInteger len = ((NSUInteger)1) << log_len;
        if (buffer.len != len) {
            stwo_metal_write_error(error_message, error_message_len, @"Bit-reverse kernel expected a power-of-two buffer length matching log_len.");
            return false;
        }

        return stwo_metal_dispatch_unary_u32_kernel(
            runtime,
            @"bit_reverse_u32",
            buffer,
            log_len,
            error_message,
            error_message_len
        );
    }
}

bool stwo_metal_bit_reverse_u32x4(
    void *runtime_ptr,
    void *buffer_ptr,
    uint32_t log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        NSUInteger len = ((NSUInteger)1) << log_len;
        if (buffer.len != len * 4) {
            stwo_metal_write_error(error_message, error_message_len, @"u32x4 bit-reverse kernel expected four limbs per logical element.");
            return false;
        }

        return stwo_metal_dispatch_unary_u32_kernel(
            runtime,
            @"bit_reverse_u32x4",
            buffer,
            log_len,
            error_message,
            error_message_len
        );
    }
}

bool stwo_metal_invert_m31_values_u32(
    void *runtime_ptr,
    void *buffer_ptr,
    uint32_t len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        if (buffer.len != (NSUInteger)len) {
            stwo_metal_write_error(error_message, error_message_len, @"M31 inversion expects a destination length matching len.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"invert_m31_values_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:buffer.buffer offset:0 atIndex:0];
        [encoder setBytes:&len length:sizeof(len) atIndex:1];

        MTLSize grid_size = MTLSizeMake((NSUInteger)len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_precompute_twiddle_level_u32(
    void *runtime_ptr,
    void *dst_ptr,
    uint32_t offset,
    uint32_t initial_x,
    uint32_t initial_y,
    uint32_t step_x,
    uint32_t step_y,
    uint32_t level_log_size,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        if (level_log_size == 0) {
            stwo_metal_write_error(error_message, error_message_len, @"Twiddle precompute expects a level_log_size greater than zero.");
            return false;
        }

        NSUInteger level_len = ((NSUInteger)1) << (level_log_size - 1);
        if (((NSUInteger)offset) + level_len > dst.len) {
            stwo_metal_write_error(error_message, error_message_len, @"Twiddle precompute level exceeds the destination buffer length.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"precompute_twiddle_level_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        StwoMetalTwiddleLevelParams params = {
            .initial_x = initial_x,
            .initial_y = initial_y,
            .step_x = step_x,
            .step_y = step_y,
            .offset = offset,
            .level_log_size = level_log_size,
        };

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:dst.buffer offset:0 atIndex:0];
        [encoder setBytes:&params length:sizeof(params) atIndex:1];

        MTLSize grid_size = MTLSizeMake(level_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// --- Fused-tail RFFT constants (must match rfft.metal defines) ---
#define RFFT_FUSED_TILE_LOG_HOST  11u
#define RFFT_FUSED_TILE_SIZE_HOST (1u << RFFT_FUSED_TILE_LOG_HOST)
#define RFFT_FUSED_THREADS_HOST   256u

// Helper: encode RFFT stages into a command buffer.
// When fused_pipeline is non-nil and values_log_len >= RFFT_FUSED_TILE_LOG_HOST,
// dispatches wide stages individually then a single fused-tail kernel for the
// last 10 line_part stages + circle_part.  Otherwise falls back to per-stage dispatch.
static bool stwo_metal_rfft_encode_stages(
    id<MTLCommandBuffer> command_buffer,
    id<MTLBuffer> values_buffer,
    NSUInteger values_offset_bytes,
    id<MTLBuffer> twiddles_buffer,
    uint32_t values_log_len,
    id<MTLComputePipelineState> line_pipeline,
    id<MTLComputePipelineState> circle_pipeline,
    id<MTLComputePipelineState> fused_pipeline,
    char *error_message,
    size_t error_message_len
) {
    uint32_t values_len = 1u << values_log_len;
    uint32_t pair_count = values_len >> 1u;

    if (fused_pipeline != nil && values_log_len >= RFFT_FUSED_TILE_LOG_HOST) {
        // Wide stages: layers (values_log_len-1) down to RFFT_FUSED_TILE_LOG_HOST
        uint32_t layer_domain_size = 1u;
        uint32_t layer_domain_offset = pair_count - 2u;
        for (uint32_t layer = values_log_len - 1u; layer >= RFFT_FUSED_TILE_LOG_HOST; --layer) {
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                return false;
            }

            [encoder setComputePipelineState:line_pipeline];
            [encoder setBuffer:values_buffer offset:values_offset_bytes atIndex:0];
            [encoder setBuffer:twiddles_buffer offset:0 atIndex:1];
            [encoder setBytes:&values_log_len length:sizeof(values_log_len) atIndex:2];
            [encoder setBytes:&layer length:sizeof(layer) atIndex:3];
            [encoder setBytes:&layer_domain_offset length:sizeof(layer_domain_offset) atIndex:4];

            MTLSize grid_size = MTLSizeMake(pair_count, 1, 1);
            MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(line_pipeline), 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
            [encoder endEncoding];

            layer_domain_size <<= 1u;
            layer_domain_offset -= layer_domain_size;
        }

        // Fused tail: layers (RFFT_FUSED_TILE_LOG_HOST-1) down to 1 + circle_part
        uint32_t n_fused_layers = RFFT_FUSED_TILE_LOG_HOST - 1u;  // 10
        uint32_t n_tiles = values_len >> RFFT_FUSED_TILE_LOG_HOST;

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:fused_pipeline];
        [encoder setBuffer:values_buffer offset:values_offset_bytes atIndex:0];
        [encoder setBuffer:twiddles_buffer offset:0 atIndex:1];
        [encoder setBytes:&values_log_len length:sizeof(values_log_len) atIndex:2];
        [encoder setBytes:&n_fused_layers length:sizeof(n_fused_layers) atIndex:3];

        MTLSize grid_size = MTLSizeMake(n_tiles, 1, 1);
        MTLSize tg_size = MTLSizeMake(RFFT_FUSED_THREADS_HOST, 1, 1);
        [encoder dispatchThreadgroups:grid_size threadsPerThreadgroup:tg_size];
        [encoder endEncoding];
    } else {
        // Original per-stage dispatch for small buffers
        uint32_t layer_domain_size = 1u;
        uint32_t layer_domain_offset = pair_count - 2u;
        for (uint32_t layer = values_log_len - 1u; layer > 0u; --layer) {
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                return false;
            }

            [encoder setComputePipelineState:line_pipeline];
            [encoder setBuffer:values_buffer offset:values_offset_bytes atIndex:0];
            [encoder setBuffer:twiddles_buffer offset:0 atIndex:1];
            [encoder setBytes:&values_log_len length:sizeof(values_log_len) atIndex:2];
            [encoder setBytes:&layer length:sizeof(layer) atIndex:3];
            [encoder setBytes:&layer_domain_offset length:sizeof(layer_domain_offset) atIndex:4];

            MTLSize grid_size = MTLSizeMake(pair_count, 1, 1);
            MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(line_pipeline), 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
            [encoder endEncoding];

            layer_domain_size <<= 1u;
            layer_domain_offset -= layer_domain_size;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:circle_pipeline];
        [encoder setBuffer:values_buffer offset:values_offset_bytes atIndex:0];
        [encoder setBuffer:twiddles_buffer offset:0 atIndex:1];
        [encoder setBytes:&values_len length:sizeof(values_len) atIndex:2];

        MTLSize grid_size = MTLSizeMake(pair_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(circle_pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];
    }

    return true;
}

bool stwo_metal_rfft_evaluate_u32(
    void *runtime_ptr,
    void *values_ptr,
    void *twiddles_ptr,
    uint32_t values_log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptr);
        StwoMetalBufferBox *twiddles = stwo_metal_buffer_box(twiddles_ptr);
        uint32_t values_len = ((uint32_t)1) << values_log_len;
        uint32_t eval_domain_size = values_len >> 1;
        if (values.len != (NSUInteger)values_len || twiddles.len != (NSUInteger)eval_domain_size) {
            stwo_metal_write_error(error_message, error_message_len, @"RFFT evaluation expects a power-of-two value buffer and a twiddle slice of half that length.");
            return false;
        }

        id<MTLComputePipelineState> line_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_line_part_u32", error_message, error_message_len);
        if (line_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> circle_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_circle_part_u32", error_message, error_message_len);
        if (circle_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> fused_pipeline = (values_log_len >= RFFT_FUSED_TILE_LOG_HOST)
            ? stwo_metal_pipeline(runtime, @"rfft_tail_fused_u32", error_message, error_message_len)
            : nil;
        if (values_log_len >= RFFT_FUSED_TILE_LOG_HOST && fused_pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        if (!stwo_metal_rfft_encode_stages(command_buffer, values.buffer, 0, twiddles.buffer,
                values_log_len, line_pipeline, circle_pipeline, fused_pipeline,
                error_message, error_message_len)) {
            return false;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// --- Async command buffer API ---
// Returns a retained command buffer handle without waiting for completion.
// Caller must later call stwo_metal_command_buffer_wait to block + release,
// or stwo_metal_command_buffer_release to discard.

void *stwo_metal_rfft_evaluate_async_u32(
    void *runtime_ptr,
    void *values_ptr,
    void *twiddles_ptr,
    uint32_t values_log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptr);
        StwoMetalBufferBox *twiddles = stwo_metal_buffer_box(twiddles_ptr);
        uint32_t values_len = ((uint32_t)1) << values_log_len;
        uint32_t eval_domain_size = values_len >> 1;
        if (values.len != (NSUInteger)values_len || twiddles.len != (NSUInteger)eval_domain_size) {
            stwo_metal_write_error(error_message, error_message_len, @"RFFT async expects a power-of-two value buffer and a twiddle slice of half that length.");
            return NULL;
        }

        id<MTLComputePipelineState> line_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_line_part_u32", error_message, error_message_len);
        if (line_pipeline == nil) {
            return NULL;
        }
        id<MTLComputePipelineState> circle_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_circle_part_u32", error_message, error_message_len);
        if (circle_pipeline == nil) {
            return NULL;
        }
        id<MTLComputePipelineState> fused_pipeline = (values_log_len >= RFFT_FUSED_TILE_LOG_HOST)
            ? stwo_metal_pipeline(runtime, @"rfft_tail_fused_u32", error_message, error_message_len)
            : nil;
        if (values_log_len >= RFFT_FUSED_TILE_LOG_HOST && fused_pipeline == nil) {
            return NULL;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return NULL;
        }

        if (!stwo_metal_rfft_encode_stages(command_buffer, values.buffer, 0, twiddles.buffer,
                values_log_len, line_pipeline, circle_pipeline, fused_pipeline,
                error_message, error_message_len)) {
            return NULL;
        }

        [command_buffer commit];
        // Do NOT waitUntilCompleted — return the handle for deferred waiting.
        return (__bridge_retained void *)command_buffer;
    }
}

bool stwo_metal_command_buffer_wait(
    void *command_buffer_ptr,
    char *error_message,
    size_t error_message_len
) {
    if (command_buffer_ptr == NULL) {
        stwo_metal_write_error(error_message, error_message_len, @"NULL command buffer handle.");
        return false;
    }
    @autoreleasepool {
        id<MTLCommandBuffer> cb = (__bridge_transfer id<MTLCommandBuffer>)command_buffer_ptr;
        [cb waitUntilCompleted];
        if (cb.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, cb.error.localizedDescription ?: @"Metal async command buffer failed.");
            return false;
        }
        return true;
    }
}

// Submits an empty command buffer to the shared queue and blocks until it
// completes. Because Metal command queues execute buffers in submission
// order, this acts as a fence: every previously committed command buffer
// (including async FFT submissions whose handles were dropped) is complete
// when this returns. Host-side reads of GPU-written buffers must call this
// first unless a later command buffer has already been waited on.
bool stwo_metal_queue_drain(
    void *runtime_ptr,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL) {
        stwo_metal_write_error(error_message, error_message_len, @"NULL runtime handle.");
        return false;
    }
    @autoreleasepool {
        StwoMetalRuntimeBox *box = (__bridge StwoMetalRuntimeBox *)runtime_ptr;
        id<MTLCommandBuffer> cb = [box.queue commandBuffer];
        if (cb == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create fence command buffer.");
            return false;
        }
        [cb commit];
        [cb waitUntilCompleted];
        if (cb.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, cb.error.localizedDescription ?: @"Metal queue drain failed.");
            return false;
        }
        return true;
    }
}

void stwo_metal_command_buffer_release(void *command_buffer_ptr) {
    if (command_buffer_ptr == NULL) {
        return;
    }
    @autoreleasepool {
        __unused id released = (__bridge_transfer id)command_buffer_ptr;
    }
}

bool stwo_metal_rfft_evaluate_subbuffer_u32(
    void *runtime_ptr,
    void *values_ptr,
    size_t value_offset,
    uint32_t values_log_len,
    void *twiddles_ptr,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptr);
        StwoMetalBufferBox *twiddles = stwo_metal_buffer_box(twiddles_ptr);
        uint32_t values_len = ((uint32_t)1) << values_log_len;
        uint32_t eval_domain_size = values_len >> 1;
        if (value_offset + (size_t)values_len > values.len ||
            twiddles.len != (NSUInteger)eval_domain_size) {
            stwo_metal_write_error(error_message, error_message_len, @"RFFT subbuffer evaluation expects an in-bounds power-of-two value range and a twiddle slice of half that length.");
            return false;
        }

        id<MTLComputePipelineState> line_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_line_part_u32", error_message, error_message_len);
        if (line_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> circle_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_circle_part_u32", error_message, error_message_len);
        if (circle_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> fused_pipeline = (values_log_len >= RFFT_FUSED_TILE_LOG_HOST)
            ? stwo_metal_pipeline(runtime, @"rfft_tail_fused_u32", error_message, error_message_len)
            : nil;
        if (values_log_len >= RFFT_FUSED_TILE_LOG_HOST && fused_pipeline == nil) {
            return false;
        }

        NSUInteger value_offset_bytes = value_offset * sizeof(uint32_t);
        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        if (!stwo_metal_rfft_encode_stages(command_buffer, values.buffer, value_offset_bytes, twiddles.buffer,
                values_log_len, line_pipeline, circle_pipeline, fused_pipeline,
                error_message, error_message_len)) {
            return false;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// Async variant of subbuffer RFFT: commits without waiting.
void *stwo_metal_rfft_evaluate_subbuffer_async_u32(
    void *runtime_ptr,
    void *values_ptr,
    size_t value_offset,
    uint32_t values_log_len,
    void *twiddles_ptr,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptr);
        StwoMetalBufferBox *twiddles = stwo_metal_buffer_box(twiddles_ptr);
        uint32_t values_len = ((uint32_t)1) << values_log_len;
        uint32_t eval_domain_size = values_len >> 1;
        if (value_offset + (size_t)values_len > values.len ||
            twiddles.len != (NSUInteger)eval_domain_size) {
            stwo_metal_write_error(error_message, error_message_len, @"RFFT async subbuffer expects an in-bounds power-of-two value range and a twiddle slice of half that length.");
            return NULL;
        }

        id<MTLComputePipelineState> line_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_line_part_u32", error_message, error_message_len);
        if (line_pipeline == nil) {
            return NULL;
        }
        id<MTLComputePipelineState> circle_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_circle_part_u32", error_message, error_message_len);
        if (circle_pipeline == nil) {
            return NULL;
        }
        id<MTLComputePipelineState> fused_pipeline = (values_log_len >= RFFT_FUSED_TILE_LOG_HOST)
            ? stwo_metal_pipeline(runtime, @"rfft_tail_fused_u32", error_message, error_message_len)
            : nil;
        if (values_log_len >= RFFT_FUSED_TILE_LOG_HOST && fused_pipeline == nil) {
            return NULL;
        }

        NSUInteger value_offset_bytes = value_offset * sizeof(uint32_t);
        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return NULL;
        }

        if (!stwo_metal_rfft_encode_stages(command_buffer, values.buffer, value_offset_bytes, twiddles.buffer,
                values_log_len, line_pipeline, circle_pipeline, fused_pipeline,
                error_message, error_message_len)) {
            return NULL;
        }

        [command_buffer commit];
        // Do NOT waitUntilCompleted — return the handle for deferred waiting.
        return (__bridge_retained void *)command_buffer;
    }
}

bool stwo_metal_rfft_evaluate_multi_u32(
    void *runtime_ptr,
    void **buffer_ptrs,
    uint32_t n_buffers,
    void *twiddles_ptr,
    uint32_t values_log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        if (n_buffers == 0) {
            return true;
        }

        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *twiddles = stwo_metal_buffer_box(twiddles_ptr);
        uint32_t values_len = ((uint32_t)1) << values_log_len;
        uint32_t eval_domain_size = values_len >> 1;

        if (twiddles.len != (NSUInteger)eval_domain_size) {
            stwo_metal_write_error(error_message, error_message_len, @"Batch RFFT: twiddle length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> line_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_line_part_u32", error_message, error_message_len);
        if (line_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> circle_pipeline =
            stwo_metal_pipeline(runtime, @"rfft_circle_part_u32", error_message, error_message_len);
        if (circle_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> fused_pipeline = (values_log_len >= RFFT_FUSED_TILE_LOG_HOST)
            ? stwo_metal_pipeline(runtime, @"rfft_tail_fused_u32", error_message, error_message_len)
            : nil;
        if (values_log_len >= RFFT_FUSED_TILE_LOG_HOST && fused_pipeline == nil) {
            return false;
        }

        // Create one command buffer per polynomial and submit all concurrently.
        // Each polynomial's RFFT layers are sequential within its command buffer,
        // but Metal schedules independent command buffers in parallel on the GPU.
        NSMutableArray<id<MTLCommandBuffer>> *command_buffers =
            [NSMutableArray arrayWithCapacity:n_buffers];

        for (uint32_t buf_idx = 0; buf_idx < n_buffers; ++buf_idx) {
            StwoMetalBufferBox *values = stwo_metal_buffer_box(buffer_ptrs[buf_idx]);
            if (values.len != (NSUInteger)values_len) {
                stwo_metal_write_error(error_message, error_message_len,
                    [NSString stringWithFormat:@"Batch RFFT: buffer %u length %lu != expected %u.",
                     buf_idx, (unsigned long)values.len, values_len]);
                return false;
            }

            id<MTLCommandBuffer> cb = [runtime.queue commandBuffer];
            if (cb == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
                return false;
            }

            if (!stwo_metal_rfft_encode_stages(cb, values.buffer, 0, twiddles.buffer,
                    values_log_len, line_pipeline, circle_pipeline, fused_pipeline,
                    error_message, error_message_len)) {
                return false;
            }

            [cb commit];
            [command_buffers addObject:cb];
        }

        // Wait for all command buffers to complete.
        for (id<MTLCommandBuffer> cb in command_buffers) {
            [cb waitUntilCompleted];
            if (cb.status == MTLCommandBufferStatusError) {
                stwo_metal_write_error(error_message, error_message_len, cb.error.localizedDescription ?: @"Batch RFFT kernel execution failed.");
                return false;
            }
        }

        return true;
    }
}

bool stwo_metal_ifft_interpolate_u32(
    void *runtime_ptr,
    void *values_ptr,
    void *inverse_twiddles_ptr,
    uint32_t values_log_len,
    uint32_t scale_factor,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptr);
        StwoMetalBufferBox *inverse_twiddles = stwo_metal_buffer_box(inverse_twiddles_ptr);
        uint32_t values_len = ((uint32_t)1) << values_log_len;
        uint32_t eval_domain_size = values_len >> 1;
        if (values.len != (NSUInteger)values_len || inverse_twiddles.len != (NSUInteger)eval_domain_size) {
            stwo_metal_write_error(error_message, error_message_len, @"IFFT interpolation expects a power-of-two value buffer and an inverse-twiddle slice of half that length.");
            return false;
        }

        id<MTLComputePipelineState> circle_pipeline =
            stwo_metal_pipeline(runtime, @"ifft_circle_part_u32", error_message, error_message_len);
        if (circle_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> line_pipeline =
            stwo_metal_pipeline(runtime, @"ifft_line_part_u32", error_message, error_message_len);
        if (line_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> rescale_pipeline =
            stwo_metal_pipeline(runtime, @"rescale_m31_values_u32", error_message, error_message_len);
        if (rescale_pipeline == nil) {
            return false;
        }

        uint32_t pair_count = values_len >> 1;
        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:circle_pipeline];
        [encoder setBuffer:values.buffer offset:0 atIndex:0];
        [encoder setBuffer:inverse_twiddles.buffer offset:0 atIndex:1];
        [encoder setBytes:&values_len length:sizeof(values_len) atIndex:2];
        MTLSize grid_size = MTLSizeMake(pair_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(circle_pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        uint32_t layer_domain_offset = 0u;
        uint32_t layer_domain_size = pair_count;
        for (uint32_t layer = 1u; layer < values_log_len; ++layer) {
            id<MTLComputeCommandEncoder> line_encoder = [command_buffer computeCommandEncoder];
            if (line_encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                return false;
            }

            [line_encoder setComputePipelineState:line_pipeline];
            [line_encoder setBuffer:values.buffer offset:0 atIndex:0];
            [line_encoder setBuffer:inverse_twiddles.buffer offset:0 atIndex:1];
            [line_encoder setBytes:&values_log_len length:sizeof(values_log_len) atIndex:2];
            [line_encoder setBytes:&layer length:sizeof(layer) atIndex:3];
            [line_encoder setBytes:&layer_domain_offset length:sizeof(layer_domain_offset) atIndex:4];

            MTLSize line_grid_size = MTLSizeMake(pair_count, 1, 1);
            MTLSize line_threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(line_pipeline), 1, 1);
            [line_encoder dispatchThreads:line_grid_size threadsPerThreadgroup:line_threadgroup_size];
            [line_encoder endEncoding];

            layer_domain_size >>= 1u;
            layer_domain_offset += layer_domain_size;
        }

        id<MTLComputeCommandEncoder> rescale_encoder = [command_buffer computeCommandEncoder];
        if (rescale_encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [rescale_encoder setComputePipelineState:rescale_pipeline];
        [rescale_encoder setBuffer:values.buffer offset:0 atIndex:0];
        [rescale_encoder setBytes:&values_len length:sizeof(values_len) atIndex:1];
        [rescale_encoder setBytes:&scale_factor length:sizeof(scale_factor) atIndex:2];
        MTLSize rescale_grid_size = MTLSizeMake(values_len, 1, 1);
        MTLSize rescale_threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(rescale_pipeline), 1, 1);
        [rescale_encoder dispatchThreads:rescale_grid_size threadsPerThreadgroup:rescale_threadgroup_size];
        [rescale_encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

/// Batched IFFT: encode all columns' IFFT dispatches into ONE command buffer.
/// Eliminates per-column CB creation overhead (~200 CBs → 1 CB).
bool stwo_metal_ifft_interpolate_batch_u32(
    void *runtime_ptr,
    void **values_ptrs,
    void **inverse_twiddles_ptrs,
    const uint32_t *values_log_lens,
    const uint32_t *scale_factors,
    uint32_t n_columns,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        if (n_columns == 0) return true;

        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);

        id<MTLComputePipelineState> circle_pipeline =
            stwo_metal_pipeline(runtime, @"ifft_circle_part_u32", error_message, error_message_len);
        if (circle_pipeline == nil) return false;
        id<MTLComputePipelineState> line_pipeline =
            stwo_metal_pipeline(runtime, @"ifft_line_part_u32", error_message, error_message_len);
        if (line_pipeline == nil) return false;
        id<MTLComputePipelineState> rescale_pipeline =
            stwo_metal_pipeline(runtime, @"rescale_m31_values_u32", error_message, error_message_len);
        if (rescale_pipeline == nil) return false;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer for batched IFFT.");
            return false;
        }

        for (uint32_t col = 0; col < n_columns; ++col) {
            StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptrs[col]);
            StwoMetalBufferBox *inverse_twiddles = stwo_metal_buffer_box(inverse_twiddles_ptrs[col]);
            uint32_t values_log_len = values_log_lens[col];
            uint32_t scale_factor = scale_factors[col];
            uint32_t values_len = ((uint32_t)1) << values_log_len;
            uint32_t pair_count = values_len >> 1;

            // Circle part.
            id<MTLComputeCommandEncoder> enc = [command_buffer computeCommandEncoder];
            [enc setComputePipelineState:circle_pipeline];
            [enc setBuffer:values.buffer offset:0 atIndex:0];
            [enc setBuffer:inverse_twiddles.buffer offset:0 atIndex:1];
            [enc setBytes:&values_len length:sizeof(values_len) atIndex:2];
            [enc dispatchThreads:MTLSizeMake(pair_count, 1, 1) threadsPerThreadgroup:MTLSizeMake(stwo_metal_threads_per_group(circle_pipeline), 1, 1)];
            [enc endEncoding];

            // Line parts.
            uint32_t layer_domain_offset = 0u;
            uint32_t layer_domain_size = pair_count;
            for (uint32_t layer = 1u; layer < values_log_len; ++layer) {
                id<MTLComputeCommandEncoder> le = [command_buffer computeCommandEncoder];
                [le setComputePipelineState:line_pipeline];
                [le setBuffer:values.buffer offset:0 atIndex:0];
                [le setBuffer:inverse_twiddles.buffer offset:0 atIndex:1];
                [le setBytes:&values_log_len length:sizeof(values_log_len) atIndex:2];
                [le setBytes:&layer length:sizeof(layer) atIndex:3];
                [le setBytes:&layer_domain_offset length:sizeof(layer_domain_offset) atIndex:4];
                [le dispatchThreads:MTLSizeMake(pair_count, 1, 1) threadsPerThreadgroup:MTLSizeMake(stwo_metal_threads_per_group(line_pipeline), 1, 1)];
                [le endEncoding];
                layer_domain_size >>= 1u;
                layer_domain_offset += layer_domain_size;
            }

            // Rescale.
            id<MTLComputeCommandEncoder> re = [command_buffer computeCommandEncoder];
            [re setComputePipelineState:rescale_pipeline];
            [re setBuffer:values.buffer offset:0 atIndex:0];
            [re setBytes:&values_len length:sizeof(values_len) atIndex:1];
            [re setBytes:&scale_factor length:sizeof(scale_factor) atIndex:2];
            [re dispatchThreads:MTLSizeMake(values_len, 1, 1) threadsPerThreadgroup:MTLSizeMake(stwo_metal_threads_per_group(rescale_pipeline), 1, 1)];
            [re endEncoding];
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Batched IFFT kernel execution failed.");
            return false;
        }
        return true;
    }
}

bool stwo_metal_ifft_line_interpolate_u32(
    void *runtime_ptr,
    void *values_ptr,
    void *inverse_line_twiddles_ptr,
    uint32_t values_log_len,
    uint32_t scale_factor,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptr);
        StwoMetalBufferBox *inverse_line_twiddles = stwo_metal_buffer_box(inverse_line_twiddles_ptr);
        uint32_t values_len = ((uint32_t)1) << values_log_len;
        uint32_t expected_twiddle_len = values_len > 1 ? values_len - 1u : 0u;
        if (values.len != (NSUInteger)values_len || inverse_line_twiddles.len != (NSUInteger)expected_twiddle_len) {
            stwo_metal_write_error(error_message, error_message_len, @"Line IFFT interpolation expects a power-of-two value buffer and a stage-twiddle slice of len(values)-1.");
            return false;
        }

        if (values_len <= 1u) {
            return true;
        }

        id<MTLComputePipelineState> line_pipeline =
            stwo_metal_pipeline(runtime, @"ifft_line_stage_u32", error_message, error_message_len);
        if (line_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> rescale_pipeline =
            stwo_metal_pipeline(runtime, @"rescale_m31_values_u32", error_message, error_message_len);
        if (rescale_pipeline == nil) {
            return false;
        }

        uint32_t pair_count = values_len >> 1u;
        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        uint32_t twiddle_offset = 0u;
        for (uint32_t stage_domain_log_size = values_log_len; stage_domain_log_size > 0u; --stage_domain_log_size) {
            uint32_t stage_domain_size = ((uint32_t)1) << stage_domain_log_size;
            uint32_t half_stage_size = stage_domain_size >> 1u;

            id<MTLComputeCommandEncoder> line_encoder = [command_buffer computeCommandEncoder];
            if (line_encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                return false;
            }

            [line_encoder setComputePipelineState:line_pipeline];
            [line_encoder setBuffer:values.buffer offset:0 atIndex:0];
            [line_encoder setBuffer:inverse_line_twiddles.buffer
                                  offset:(NSUInteger)(twiddle_offset * sizeof(uint32_t))
                                 atIndex:1];
            [line_encoder setBytes:&values_log_len length:sizeof(values_log_len) atIndex:2];
            [line_encoder setBytes:&stage_domain_log_size length:sizeof(stage_domain_log_size) atIndex:3];

            MTLSize grid_size = MTLSizeMake(pair_count, 1, 1);
            MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(line_pipeline), 1, 1);
            [line_encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
            [line_encoder endEncoding];

            twiddle_offset += half_stage_size;
        }

        id<MTLComputeCommandEncoder> rescale_encoder = [command_buffer computeCommandEncoder];
        if (rescale_encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [rescale_encoder setComputePipelineState:rescale_pipeline];
        [rescale_encoder setBuffer:values.buffer offset:0 atIndex:0];
        [rescale_encoder setBytes:&values_len length:sizeof(values_len) atIndex:1];
        [rescale_encoder setBytes:&scale_factor length:sizeof(scale_factor) atIndex:2];

        MTLSize rescale_grid = MTLSizeMake(values_len, 1, 1);
        MTLSize rescale_group = MTLSizeMake(stwo_metal_threads_per_group(rescale_pipeline), 1, 1);
        [rescale_encoder dispatchThreads:rescale_grid threadsPerThreadgroup:rescale_group];
        [rescale_encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_batch_eval_at_point_base_field_u32(
    void *runtime_ptr,
    void *flat_coeffs_ptr,
    void *factors_ptr,
    void *dst_ptr,
    uint32_t coeffs_log_len,
    uint32_t n_polys,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *flat_coeffs = stwo_metal_buffer_box(flat_coeffs_ptr);
        StwoMetalBufferBox *factors = stwo_metal_buffer_box(factors_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        uint32_t coeffs_size = 1u << coeffs_log_len;
        if (flat_coeffs.len != (NSUInteger)(coeffs_size * n_polys)) {
            stwo_metal_write_error(error_message, error_message_len, @"Point evaluation expects a flattened coefficient buffer with coeffs_size * n_polys base-field values.");
            return false;
        }
        if (factors.len != (NSUInteger)(coeffs_log_len * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"Point evaluation expects one qm31 folding factor per coefficient level.");
            return false;
        }
        if (dst.len != (NSUInteger)(n_polys * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"Point evaluation expects a destination buffer with one qm31 result per polynomial.");
            return false;
        }

        id<MTLComputePipelineState> first_pass_pipeline =
            stwo_metal_pipeline(runtime, @"batch_eval_at_point_first_pass_u32", error_message, error_message_len);
        if (first_pass_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> reduce_pipeline =
            stwo_metal_pipeline(runtime, @"batch_eval_at_point_reduce_u32", error_message, error_message_len);
        if (reduce_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> finalize_pipeline =
            stwo_metal_pipeline(runtime, @"batch_eval_at_point_finalize_u32", error_message, error_message_len);
        if (finalize_pipeline == nil) {
            return false;
        }

        uint32_t blocks_per_poly = coeffs_log_len > 9u ? (coeffs_size >> 9u) : 1u;
        NSUInteger temp_len = (NSUInteger)(blocks_per_poly * n_polys * 4u);
        id<MTLBuffer> temp_a = [runtime.device newBufferWithLength:(temp_len * sizeof(uint32_t))
                                                           options:MTLResourceStorageModePrivate];
        id<MTLBuffer> temp_b = [runtime.device newBufferWithLength:(temp_len * sizeof(uint32_t))
                                                           options:MTLResourceStorageModePrivate];
        if (temp_a == nil || temp_b == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate Metal point-evaluation temporary buffers.");
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> first_encoder = [command_buffer computeCommandEncoder];
        if (first_encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [first_encoder setComputePipelineState:first_pass_pipeline];
        [first_encoder setBuffer:flat_coeffs.buffer offset:0 atIndex:0];
        [first_encoder setBuffer:factors.buffer offset:0 atIndex:1];
        [first_encoder setBuffer:temp_a offset:0 atIndex:2];
        [first_encoder setBytes:&coeffs_log_len length:sizeof(coeffs_log_len) atIndex:3];
        [first_encoder setBytes:&blocks_per_poly length:sizeof(blocks_per_poly) atIndex:4];
        [first_encoder dispatchThreadgroups:MTLSizeMake(blocks_per_poly, n_polys, 1)
                     threadsPerThreadgroup:MTLSizeMake(256, 1, 1)];
        [first_encoder endEncoding];

        uint32_t current_stride = blocks_per_poly;
        uint32_t remaining_log_len = coeffs_log_len > 9u ? coeffs_log_len - 9u : 0u;
        id<MTLBuffer> current = temp_a;
        id<MTLBuffer> next = temp_b;

        while (current_stride > 1u) {
            uint32_t output_stride = remaining_log_len > 9u ? (current_stride >> 9u) : 1u;
            uint32_t factor_offset = remaining_log_len - 1u;

            id<MTLComputeCommandEncoder> reduce_encoder = [command_buffer computeCommandEncoder];
            if (reduce_encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                return false;
            }

            [reduce_encoder setComputePipelineState:reduce_pipeline];
            [reduce_encoder setBuffer:current offset:0 atIndex:0];
            [reduce_encoder setBuffer:factors.buffer offset:0 atIndex:1];
            [reduce_encoder setBuffer:next offset:0 atIndex:2];
            [reduce_encoder setBytes:&current_stride length:sizeof(current_stride) atIndex:3];
            [reduce_encoder setBytes:&output_stride length:sizeof(output_stride) atIndex:4];
            [reduce_encoder setBytes:&factor_offset length:sizeof(factor_offset) atIndex:5];
            [reduce_encoder dispatchThreadgroups:MTLSizeMake(output_stride, n_polys, 1)
                          threadsPerThreadgroup:MTLSizeMake(256, 1, 1)];
            [reduce_encoder endEncoding];

            current_stride = output_stride;
            remaining_log_len = remaining_log_len > 9u ? remaining_log_len - 9u : 0u;
            id<MTLBuffer> swap = current;
            current = next;
            next = swap;
        }

        id<MTLComputeCommandEncoder> finalize_encoder = [command_buffer computeCommandEncoder];
        if (finalize_encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [finalize_encoder setComputePipelineState:finalize_pipeline];
        [finalize_encoder setBuffer:current offset:0 atIndex:0];
        [finalize_encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [finalize_encoder setBytes:&current_stride length:sizeof(current_stride) atIndex:2];
        [finalize_encoder setBytes:&n_polys length:sizeof(n_polys) atIndex:3];
        [finalize_encoder dispatchThreads:MTLSizeMake(n_polys, 1, 1)
                   threadsPerThreadgroup:MTLSizeMake(stwo_metal_threads_per_group(finalize_pipeline), 1, 1)];
        [finalize_encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_batch_eval_first_pass_base_field_u32(
    void *runtime_ptr,
    void *flat_coeffs_ptr,
    void *factors_ptr,
    void *dst_ptr,
    uint32_t coeffs_log_len,
    uint32_t n_polys,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *flat_coeffs = stwo_metal_buffer_box(flat_coeffs_ptr);
        StwoMetalBufferBox *factors = stwo_metal_buffer_box(factors_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        uint32_t coeffs_size = 1u << coeffs_log_len;
        uint32_t blocks_per_poly = coeffs_log_len > 9u ? (coeffs_size >> 9u) : 1u;
        if (flat_coeffs.len != (NSUInteger)(coeffs_size * n_polys)) {
            stwo_metal_write_error(error_message, error_message_len, @"Point-evaluation first pass expects a flattened coefficient buffer with coeffs_size * n_polys base-field values.");
            return false;
        }
        if (factors.len != (NSUInteger)(coeffs_log_len * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"Point-evaluation first pass expects one qm31 folding factor per coefficient level.");
            return false;
        }
        if (dst.len != (NSUInteger)(blocks_per_poly * n_polys * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"Point-evaluation first pass expects one qm31 partial result per 512-coefficient chunk.");
            return false;
        }

        id<MTLComputePipelineState> first_pass_pipeline =
            stwo_metal_pipeline(runtime, @"batch_eval_at_point_first_pass_u32", error_message, error_message_len);
        if (first_pass_pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:first_pass_pipeline];
        [encoder setBuffer:flat_coeffs.buffer offset:0 atIndex:0];
        [encoder setBuffer:factors.buffer offset:0 atIndex:1];
        [encoder setBuffer:dst.buffer offset:0 atIndex:2];
        [encoder setBytes:&coeffs_log_len length:sizeof(coeffs_log_len) atIndex:3];
        [encoder setBytes:&blocks_per_poly length:sizeof(blocks_per_poly) atIndex:4];
        [encoder dispatchThreadgroups:MTLSizeMake(blocks_per_poly, n_polys, 1)
                     threadsPerThreadgroup:MTLSizeMake(256, 1, 1)];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

/// Descriptor for one size-group in a multi-group batch point evaluation.
typedef struct {
    void *flat_coeffs_ptr;
    void *factors_ptr;
    void *dst_ptr;
    uint32_t coeffs_log_len;
    uint32_t n_polys;
} StwoMetalBatchEvalGroup;

/// Evaluate multiple groups of same-size polynomials at their respective points
/// in a single Metal command buffer.  Each group has its own flattened
/// coefficient buffer, folding factors, and destination buffer.  Encoding all
/// groups into one command buffer avoids the per-group GPU round-trip overhead.
bool stwo_metal_batch_eval_at_point_multi_group_u32(
    void *runtime_ptr,
    const StwoMetalBatchEvalGroup *groups,
    uint32_t n_groups,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        if (n_groups == 0u) {
            return true;
        }

        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);

        id<MTLComputePipelineState> first_pass_pipeline =
            stwo_metal_pipeline(runtime, @"batch_eval_at_point_first_pass_u32", error_message, error_message_len);
        if (first_pass_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> reduce_pipeline =
            stwo_metal_pipeline(runtime, @"batch_eval_at_point_reduce_u32", error_message, error_message_len);
        if (reduce_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> finalize_pipeline =
            stwo_metal_pipeline(runtime, @"batch_eval_at_point_finalize_u32", error_message, error_message_len);
        if (finalize_pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        for (uint32_t g = 0; g < n_groups; g++) {
            StwoMetalBufferBox *flat_coeffs = stwo_metal_buffer_box(groups[g].flat_coeffs_ptr);
            StwoMetalBufferBox *factors = stwo_metal_buffer_box(groups[g].factors_ptr);
            StwoMetalBufferBox *dst = stwo_metal_buffer_box(groups[g].dst_ptr);
            uint32_t coeffs_log_len = groups[g].coeffs_log_len;
            uint32_t n_polys = groups[g].n_polys;
            uint32_t coeffs_size = 1u << coeffs_log_len;
            uint32_t blocks_per_poly = coeffs_log_len > 9u ? (coeffs_size >> 9u) : 1u;

            // Allocate per-group temporaries for the reduction tree.
            NSUInteger temp_len = (NSUInteger)(blocks_per_poly * n_polys * 4u);
            id<MTLBuffer> temp_a = [runtime.device newBufferWithLength:(temp_len * sizeof(uint32_t))
                                                               options:MTLResourceStorageModePrivate];
            id<MTLBuffer> temp_b = [runtime.device newBufferWithLength:(temp_len * sizeof(uint32_t))
                                                               options:MTLResourceStorageModePrivate];
            if (temp_a == nil || temp_b == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate Metal point-evaluation temporary buffers.");
                return false;
            }

            // First pass: reduce 512-element blocks.
            {
                id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
                if (encoder == nil) {
                    stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                    return false;
                }
                [encoder setComputePipelineState:first_pass_pipeline];
                [encoder setBuffer:flat_coeffs.buffer offset:0 atIndex:0];
                [encoder setBuffer:factors.buffer offset:0 atIndex:1];
                [encoder setBuffer:temp_a offset:0 atIndex:2];
                [encoder setBytes:&coeffs_log_len length:sizeof(coeffs_log_len) atIndex:3];
                [encoder setBytes:&blocks_per_poly length:sizeof(blocks_per_poly) atIndex:4];
                [encoder dispatchThreadgroups:MTLSizeMake(blocks_per_poly, n_polys, 1)
                         threadsPerThreadgroup:MTLSizeMake(256, 1, 1)];
                [encoder endEncoding];
            }

            // Reduce passes: repeatedly halve until stride == 1.
            uint32_t current_stride = blocks_per_poly;
            uint32_t remaining_log_len = coeffs_log_len > 9u ? coeffs_log_len - 9u : 0u;
            id<MTLBuffer> current = temp_a;
            id<MTLBuffer> next = temp_b;

            while (current_stride > 1u) {
                uint32_t output_stride = remaining_log_len > 9u ? (current_stride >> 9u) : 1u;
                uint32_t factor_offset = remaining_log_len - 1u;

                id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
                if (encoder == nil) {
                    stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                    return false;
                }

                [encoder setComputePipelineState:reduce_pipeline];
                [encoder setBuffer:current offset:0 atIndex:0];
                [encoder setBuffer:factors.buffer offset:0 atIndex:1];
                [encoder setBuffer:next offset:0 atIndex:2];
                [encoder setBytes:&current_stride length:sizeof(current_stride) atIndex:3];
                [encoder setBytes:&output_stride length:sizeof(output_stride) atIndex:4];
                [encoder setBytes:&factor_offset length:sizeof(factor_offset) atIndex:5];
                [encoder dispatchThreadgroups:MTLSizeMake(output_stride, n_polys, 1)
                              threadsPerThreadgroup:MTLSizeMake(256, 1, 1)];
                [encoder endEncoding];

                current_stride = output_stride;
                remaining_log_len = remaining_log_len > 9u ? remaining_log_len - 9u : 0u;
                id<MTLBuffer> swap = current;
                current = next;
                next = swap;
            }

            // Finalize: copy the single qm31 result per polynomial to the destination buffer.
            {
                id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
                if (encoder == nil) {
                    stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                    return false;
                }
                [encoder setComputePipelineState:finalize_pipeline];
                [encoder setBuffer:current offset:0 atIndex:0];
                [encoder setBuffer:dst.buffer offset:0 atIndex:1];
                [encoder setBytes:&current_stride length:sizeof(current_stride) atIndex:2];
                [encoder setBytes:&n_polys length:sizeof(n_polys) atIndex:3];
                [encoder dispatchThreads:MTLSizeMake(n_polys, 1, 1)
                           threadsPerThreadgroup:MTLSizeMake(stwo_metal_threads_per_group(finalize_pipeline), 1, 1)];
                [encoder endEncoding];
            }
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal multi-group point evaluation failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Transposed dot-product batch evaluation: parallel dot product against
// precomputed basis evaluations.  256 threads per polynomial, one threadgroup
// per polynomial.
// ---------------------------------------------------------------------------

bool stwo_metal_batch_eval_at_point_transposed_u32(
    void *runtime_ptr,
    void *flat_coeffs_ptr,
    void *basis_evals_ptr,
    void *dst_ptr,
    uint32_t n_polys,
    uint32_t n_coeffs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *flat_coeffs = stwo_metal_buffer_box(flat_coeffs_ptr);
        StwoMetalBufferBox *basis_evals = stwo_metal_buffer_box(basis_evals_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"batch_eval_at_point_transposed_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:flat_coeffs.buffer offset:0 atIndex:0];
        [encoder setBuffer:basis_evals.buffer offset:0 atIndex:1];
        [encoder setBuffer:dst.buffer offset:0 atIndex:2];
        [encoder setBytes:&n_polys length:sizeof(n_polys) atIndex:3];
        [encoder setBytes:&n_coeffs length:sizeof(n_coeffs) atIndex:4];

        // 256 threads per polynomial, one threadgroup per polynomial
        MTLSize grid_size = MTLSizeMake((NSUInteger)n_polys * 256u, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(256, 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription ?: @"Metal transposed point evaluation failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_fix_first_variable_base_field_u32(
    void *runtime_ptr,
    void *src_ptr,
    void *dst_ptr,
    uint32_t src_log_len,
    const uint32_t *assignment_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        if (src_log_len == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"MLE fix-first-variable expects at least one variable.");
            return false;
        }

        uint32_t src_len = ((uint32_t)1) << src_log_len;
        uint32_t midpoint = src_len >> 1u;
        if (src.len != (NSUInteger)src_len || dst.len != (NSUInteger)(midpoint * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"Base-field MLE fix-first-variable expects a power-of-two source and a secure-field destination of half that logical length.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"fix_first_variable_base_field_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src.buffer offset:0 atIndex:0];
        [encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [encoder setBytes:assignment_limbs length:sizeof(uint32_t) * 4u atIndex:2];
        [encoder setBytes:&midpoint length:sizeof(midpoint) atIndex:3];

        MTLSize grid_size = MTLSizeMake(midpoint, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_fix_first_variable_secure_field_u32x4(
    void *runtime_ptr,
    void *src_ptr,
    void *dst_ptr,
    uint32_t src_log_len,
    const uint32_t *assignment_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        if (src_log_len == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"MLE fix-first-variable expects at least one variable.");
            return false;
        }

        uint32_t src_len = ((uint32_t)1) << src_log_len;
        uint32_t midpoint = src_len >> 1u;
        if (src.len != (NSUInteger)(src_len * 4u) || dst.len != (NSUInteger)(midpoint * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"Secure-field MLE fix-first-variable expects four limbs per source and destination element.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"fix_first_variable_secure_field_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src.buffer offset:0 atIndex:0];
        [encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [encoder setBytes:assignment_limbs length:sizeof(uint32_t) * 4u atIndex:2];
        [encoder setBytes:&midpoint length:sizeof(midpoint) atIndex:3];

        MTLSize grid_size = MTLSizeMake(midpoint, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_gen_eq_evals_u32x4(
    void *runtime_ptr,
    void *factors_ptr,
    void *dst_ptr,
    uint32_t y_size,
    const uint32_t *v_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *factors = stwo_metal_buffer_box(factors_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        uint32_t eval_count = 1u << y_size;
        if (factors.len != (NSUInteger)(y_size * 2u * 4u) || dst.len != (NSUInteger)(eval_count * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR eq-eval generation expects two qm31 factors per input coordinate and one qm31 output per hypercube point.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"gkr_gen_eq_evals_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:factors.buffer offset:0 atIndex:0];
        [encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [encoder setBytes:v_limbs length:sizeof(uint32_t) * 4u atIndex:2];
        [encoder setBytes:&y_size length:sizeof(y_size) atIndex:3];

        MTLSize grid_size = MTLSizeMake(eval_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_next_grand_product_layer_u32x4(
    void *runtime_ptr,
    void *src_ptr,
    void *dst_ptr,
    uint32_t input_log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        if (input_log_len == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR next layer expects at least one input variable.");
            return false;
        }

        uint32_t input_len = 1u << input_log_len;
        uint32_t next_layer_size = input_len >> 1u;
        if (src.len != (NSUInteger)(input_len * 4u) || dst.len != (NSUInteger)(next_layer_size * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR grand-product next layer expects secure-field source and destination buffers with half-size output.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"gkr_next_grand_product_layer_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src.buffer offset:0 atIndex:0];
        [encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [encoder setBytes:&next_layer_size length:sizeof(next_layer_size) atIndex:2];

        MTLSize grid_size = MTLSizeMake(next_layer_size, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_next_logup_generic_layer_u32x4(
    void *runtime_ptr,
    void *numerators_ptr,
    void *denominators_ptr,
    void *next_numerators_ptr,
    void *next_denominators_ptr,
    uint32_t input_log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *numerators = stwo_metal_buffer_box(numerators_ptr);
        StwoMetalBufferBox *denominators = stwo_metal_buffer_box(denominators_ptr);
        StwoMetalBufferBox *next_numerators = stwo_metal_buffer_box(next_numerators_ptr);
        StwoMetalBufferBox *next_denominators = stwo_metal_buffer_box(next_denominators_ptr);
        if (input_log_len == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR next layer expects at least one input variable.");
            return false;
        }

        uint32_t input_len = 1u << input_log_len;
        uint32_t next_layer_size = input_len >> 1u;
        if (numerators.len != (NSUInteger)(input_len * 4u) ||
            denominators.len != (NSUInteger)(input_len * 4u) ||
            next_numerators.len != (NSUInteger)(next_layer_size * 4u) ||
            next_denominators.len != (NSUInteger)(next_layer_size * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR generic next layer expects secure-field numerators and denominators with half-size secure-field outputs.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"gkr_next_logup_generic_layer_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:numerators.buffer offset:0 atIndex:0];
        [encoder setBuffer:denominators.buffer offset:0 atIndex:1];
        [encoder setBuffer:next_numerators.buffer offset:0 atIndex:2];
        [encoder setBuffer:next_denominators.buffer offset:0 atIndex:3];
        [encoder setBytes:&next_layer_size length:sizeof(next_layer_size) atIndex:4];

        MTLSize grid_size = MTLSizeMake(next_layer_size, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_next_logup_multiplicities_layer_u32(
    void *runtime_ptr,
    void *numerators_ptr,
    void *denominators_ptr,
    void *next_numerators_ptr,
    void *next_denominators_ptr,
    uint32_t input_log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *numerators = stwo_metal_buffer_box(numerators_ptr);
        StwoMetalBufferBox *denominators = stwo_metal_buffer_box(denominators_ptr);
        StwoMetalBufferBox *next_numerators = stwo_metal_buffer_box(next_numerators_ptr);
        StwoMetalBufferBox *next_denominators = stwo_metal_buffer_box(next_denominators_ptr);
        if (input_log_len == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR next layer expects at least one input variable.");
            return false;
        }

        uint32_t input_len = 1u << input_log_len;
        uint32_t next_layer_size = input_len >> 1u;
        if (numerators.len != (NSUInteger)input_len ||
            denominators.len != (NSUInteger)(input_len * 4u) ||
            next_numerators.len != (NSUInteger)(next_layer_size * 4u) ||
            next_denominators.len != (NSUInteger)(next_layer_size * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR multiplicities next layer expects base-field numerators, secure-field denominators, and secure-field outputs.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"gkr_next_logup_multiplicities_layer_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:numerators.buffer offset:0 atIndex:0];
        [encoder setBuffer:denominators.buffer offset:0 atIndex:1];
        [encoder setBuffer:next_numerators.buffer offset:0 atIndex:2];
        [encoder setBuffer:next_denominators.buffer offset:0 atIndex:3];
        [encoder setBytes:&next_layer_size length:sizeof(next_layer_size) atIndex:4];

        MTLSize grid_size = MTLSizeMake(next_layer_size, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_next_logup_singles_layer_u32x4(
    void *runtime_ptr,
    void *denominators_ptr,
    void *next_numerators_ptr,
    void *next_denominators_ptr,
    uint32_t input_log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *denominators = stwo_metal_buffer_box(denominators_ptr);
        StwoMetalBufferBox *next_numerators = stwo_metal_buffer_box(next_numerators_ptr);
        StwoMetalBufferBox *next_denominators = stwo_metal_buffer_box(next_denominators_ptr);
        if (input_log_len == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR next layer expects at least one input variable.");
            return false;
        }

        uint32_t input_len = 1u << input_log_len;
        uint32_t next_layer_size = input_len >> 1u;
        if (denominators.len != (NSUInteger)(input_len * 4u) ||
            next_numerators.len != (NSUInteger)(next_layer_size * 4u) ||
            next_denominators.len != (NSUInteger)(next_layer_size * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR singles next layer expects secure-field denominators and secure-field outputs.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"gkr_next_logup_singles_layer_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:denominators.buffer offset:0 atIndex:0];
        [encoder setBuffer:next_numerators.buffer offset:0 atIndex:1];
        [encoder setBuffer:next_denominators.buffer offset:0 atIndex:2];
        [encoder setBytes:&next_layer_size length:sizeof(next_layer_size) atIndex:3];

        MTLSize grid_size = MTLSizeMake(next_layer_size, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_sum_grand_product_u32x4(
    void *runtime_ptr,
    void *eq_evals_ptr,
    void *input_layer_ptr,
    uint32_t n_terms,
    uint32_t *eval_at_0_limbs,
    uint32_t *eval_at_2_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *eq_evals = stwo_metal_buffer_box(eq_evals_ptr);
        StwoMetalBufferBox *input_layer = stwo_metal_buffer_box(input_layer_ptr);
        if (eq_evals.len != (NSUInteger)(n_terms * 4u) || input_layer.len != (NSUInteger)(n_terms * 16u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR grand-product sum expects n_terms eq-evals and 4*n_terms secure-field input evaluations.");
            return false;
        }

        id<MTLComputePipelineState> terms_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_grand_product_terms_u32x4", error_message, error_message_len);
        id<MTLComputePipelineState> reduce_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_reduce_pairs_u32x4", error_message, error_message_len);
        if (terms_pipeline == nil || reduce_pipeline == nil) {
            return false;
        }

        StwoMetalBufferPool *pool = [StwoMetalBufferPool sharedPoolForDevice:runtime.device];
        NSUInteger term_bytes = (NSUInteger)(n_terms * 4u) * sizeof(uint32_t);
        id<MTLBuffer> eval0_terms, eval2_terms, temp0, temp2;
        if (!stwo_metal_pool_acquire_4(pool, term_bytes, &eval0_terms, &eval2_terms, &temp0, &temp2, error_message, error_message_len)) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }
        [encoder setComputePipelineState:terms_pipeline];
        [encoder setBuffer:eq_evals.buffer offset:0 atIndex:0];
        [encoder setBuffer:input_layer.buffer offset:0 atIndex:1];
        [encoder setBuffer:eval0_terms offset:0 atIndex:2];
        [encoder setBuffer:eval2_terms offset:0 atIndex:3];
        [encoder setBytes:&n_terms length:sizeof(n_terms) atIndex:4];
        MTLSize grid_size = MTLSizeMake(n_terms, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(terms_pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        id<MTLBuffer> final_eval0 = stwo_metal_encode_qm31_pair_reduction(
            command_buffer, reduce_pipeline, eval0_terms, temp0, n_terms, error_message, error_message_len);
        if (final_eval0 == nil) {
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }
        id<MTLBuffer> final_eval2 = stwo_metal_encode_qm31_pair_reduction(
            command_buffer, reduce_pipeline, eval2_terms, temp2, n_terms, error_message, error_message_len);
        if (final_eval2 == nil) {
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        memcpy(eval_at_0_limbs, final_eval0.contents, sizeof(uint32_t) * 4u);
        memcpy(eval_at_2_limbs, final_eval2.contents, sizeof(uint32_t) * 4u);
        stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_sum_logup_generic_u32x4(
    void *runtime_ptr,
    void *eq_evals_ptr,
    void *numerators_ptr,
    void *denominators_ptr,
    uint32_t n_terms,
    const uint32_t *lambda_limbs,
    uint32_t *eval_at_0_limbs,
    uint32_t *eval_at_2_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *eq_evals = stwo_metal_buffer_box(eq_evals_ptr);
        StwoMetalBufferBox *numerators = stwo_metal_buffer_box(numerators_ptr);
        StwoMetalBufferBox *denominators = stwo_metal_buffer_box(denominators_ptr);
        if (eq_evals.len != (NSUInteger)(n_terms * 4u) ||
            numerators.len != (NSUInteger)(n_terms * 16u) ||
            denominators.len != (NSUInteger)(n_terms * 16u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR generic sum expects n_terms eq-evals and 4*n_terms secure-field numerator and denominator evaluations.");
            return false;
        }

        id<MTLComputePipelineState> terms_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_logup_generic_terms_u32x4", error_message, error_message_len);
        id<MTLComputePipelineState> reduce_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_reduce_pairs_u32x4", error_message, error_message_len);
        if (terms_pipeline == nil || reduce_pipeline == nil) {
            return false;
        }

        StwoMetalBufferPool *pool = [StwoMetalBufferPool sharedPoolForDevice:runtime.device];
        NSUInteger term_bytes = (NSUInteger)(n_terms * 4u) * sizeof(uint32_t);
        id<MTLBuffer> eval0_terms, eval2_terms, temp0, temp2;
        if (!stwo_metal_pool_acquire_4(pool, term_bytes, &eval0_terms, &eval2_terms, &temp0, &temp2, error_message, error_message_len)) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }
        [encoder setComputePipelineState:terms_pipeline];
        [encoder setBuffer:eq_evals.buffer offset:0 atIndex:0];
        [encoder setBuffer:numerators.buffer offset:0 atIndex:1];
        [encoder setBuffer:denominators.buffer offset:0 atIndex:2];
        [encoder setBuffer:eval0_terms offset:0 atIndex:3];
        [encoder setBuffer:eval2_terms offset:0 atIndex:4];
        [encoder setBytes:lambda_limbs length:sizeof(uint32_t) * 4u atIndex:5];
        [encoder setBytes:&n_terms length:sizeof(n_terms) atIndex:6];
        MTLSize grid_size = MTLSizeMake(n_terms, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(terms_pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        id<MTLBuffer> final_eval0 = stwo_metal_encode_qm31_pair_reduction(
            command_buffer, reduce_pipeline, eval0_terms, temp0, n_terms, error_message, error_message_len);
        if (final_eval0 == nil) {
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }
        id<MTLBuffer> final_eval2 = stwo_metal_encode_qm31_pair_reduction(
            command_buffer, reduce_pipeline, eval2_terms, temp2, n_terms, error_message, error_message_len);
        if (final_eval2 == nil) {
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        memcpy(eval_at_0_limbs, final_eval0.contents, sizeof(uint32_t) * 4u);
        memcpy(eval_at_2_limbs, final_eval2.contents, sizeof(uint32_t) * 4u);
        stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_sum_logup_multiplicities_u32(
    void *runtime_ptr,
    void *eq_evals_ptr,
    void *numerators_ptr,
    void *denominators_ptr,
    uint32_t n_terms,
    const uint32_t *lambda_limbs,
    uint32_t *eval_at_0_limbs,
    uint32_t *eval_at_2_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *eq_evals = stwo_metal_buffer_box(eq_evals_ptr);
        StwoMetalBufferBox *numerators = stwo_metal_buffer_box(numerators_ptr);
        StwoMetalBufferBox *denominators = stwo_metal_buffer_box(denominators_ptr);
        if (eq_evals.len != (NSUInteger)(n_terms * 4u) ||
            numerators.len != (NSUInteger)(n_terms * 4u) ||
            denominators.len != (NSUInteger)(n_terms * 16u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR multiplicities sum expects n_terms eq-evals, 4*n_terms base-field numerators, and 4*n_terms secure-field denominators.");
            return false;
        }

        id<MTLComputePipelineState> terms_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_logup_multiplicities_terms_u32", error_message, error_message_len);
        id<MTLComputePipelineState> reduce_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_reduce_pairs_u32x4", error_message, error_message_len);
        if (terms_pipeline == nil || reduce_pipeline == nil) {
            return false;
        }

        StwoMetalBufferPool *pool = [StwoMetalBufferPool sharedPoolForDevice:runtime.device];
        NSUInteger term_bytes = (NSUInteger)(n_terms * 4u) * sizeof(uint32_t);
        id<MTLBuffer> eval0_terms, eval2_terms, temp0, temp2;
        if (!stwo_metal_pool_acquire_4(pool, term_bytes, &eval0_terms, &eval2_terms, &temp0, &temp2, error_message, error_message_len)) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }
        [encoder setComputePipelineState:terms_pipeline];
        [encoder setBuffer:eq_evals.buffer offset:0 atIndex:0];
        [encoder setBuffer:numerators.buffer offset:0 atIndex:1];
        [encoder setBuffer:denominators.buffer offset:0 atIndex:2];
        [encoder setBuffer:eval0_terms offset:0 atIndex:3];
        [encoder setBuffer:eval2_terms offset:0 atIndex:4];
        [encoder setBytes:lambda_limbs length:sizeof(uint32_t) * 4u atIndex:5];
        [encoder setBytes:&n_terms length:sizeof(n_terms) atIndex:6];
        MTLSize grid_size = MTLSizeMake(n_terms, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(terms_pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        id<MTLBuffer> final_eval0 = stwo_metal_encode_qm31_pair_reduction(
            command_buffer, reduce_pipeline, eval0_terms, temp0, n_terms, error_message, error_message_len);
        if (final_eval0 == nil) {
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }
        id<MTLBuffer> final_eval2 = stwo_metal_encode_qm31_pair_reduction(
            command_buffer, reduce_pipeline, eval2_terms, temp2, n_terms, error_message, error_message_len);
        if (final_eval2 == nil) {
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        memcpy(eval_at_0_limbs, final_eval0.contents, sizeof(uint32_t) * 4u);
        memcpy(eval_at_2_limbs, final_eval2.contents, sizeof(uint32_t) * 4u);
        stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_gkr_sum_logup_singles_u32x4(
    void *runtime_ptr,
    void *eq_evals_ptr,
    void *denominators_ptr,
    uint32_t n_terms,
    const uint32_t *lambda_limbs,
    uint32_t *eval_at_0_limbs,
    uint32_t *eval_at_2_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *eq_evals = stwo_metal_buffer_box(eq_evals_ptr);
        StwoMetalBufferBox *denominators = stwo_metal_buffer_box(denominators_ptr);
        if (eq_evals.len != (NSUInteger)(n_terms * 4u) || denominators.len != (NSUInteger)(n_terms * 16u)) {
            stwo_metal_write_error(error_message, error_message_len, @"GKR singles sum expects n_terms eq-evals and 4*n_terms secure-field denominators.");
            return false;
        }

        id<MTLComputePipelineState> terms_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_logup_singles_terms_u32x4", error_message, error_message_len);
        id<MTLComputePipelineState> reduce_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_reduce_pairs_u32x4", error_message, error_message_len);
        if (terms_pipeline == nil || reduce_pipeline == nil) {
            return false;
        }

        StwoMetalBufferPool *pool = [StwoMetalBufferPool sharedPoolForDevice:runtime.device];
        NSUInteger term_bytes = (NSUInteger)(n_terms * 4u) * sizeof(uint32_t);
        id<MTLBuffer> eval0_terms, eval2_terms, temp0, temp2;
        if (!stwo_metal_pool_acquire_4(pool, term_bytes, &eval0_terms, &eval2_terms, &temp0, &temp2, error_message, error_message_len)) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }
        [encoder setComputePipelineState:terms_pipeline];
        [encoder setBuffer:eq_evals.buffer offset:0 atIndex:0];
        [encoder setBuffer:denominators.buffer offset:0 atIndex:1];
        [encoder setBuffer:eval0_terms offset:0 atIndex:2];
        [encoder setBuffer:eval2_terms offset:0 atIndex:3];
        [encoder setBytes:lambda_limbs length:sizeof(uint32_t) * 4u atIndex:4];
        [encoder setBytes:&n_terms length:sizeof(n_terms) atIndex:5];
        MTLSize grid_size = MTLSizeMake(n_terms, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(terms_pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        id<MTLBuffer> final_eval0 = stwo_metal_encode_qm31_pair_reduction(
            command_buffer, reduce_pipeline, eval0_terms, temp0, n_terms, error_message, error_message_len);
        if (final_eval0 == nil) {
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }
        id<MTLBuffer> final_eval2 = stwo_metal_encode_qm31_pair_reduction(
            command_buffer, reduce_pipeline, eval2_terms, temp2, n_terms, error_message, error_message_len);
        if (final_eval2 == nil) {
            stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);
            return false;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        memcpy(eval_at_0_limbs, final_eval0.contents, sizeof(uint32_t) * 4u);
        memcpy(eval_at_2_limbs, final_eval2.contents, sizeof(uint32_t) * 4u);
        stwo_metal_pool_return_4(pool, eval0_terms, eval2_terms, temp0, temp2);

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_inclusive_prefix_sum_bit_rev_circle_domain_u32(
    void *runtime_ptr,
    void *buffer_ptr,
    uint32_t log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *buffer = stwo_metal_buffer_box(buffer_ptr);
        uint32_t len = ((uint32_t)1) << log_len;
        if (buffer.len != (NSUInteger)len) {
            stwo_metal_write_error(error_message, error_message_len, @"Prefix sum expects a power-of-two base-field buffer matching log_len.");
            return false;
        }

        if (!stwo_metal_dispatch_unary_u32_kernel(
                runtime,
                @"bit_reverse_u32",
                buffer,
                log_len,
                error_message,
                error_message_len)) {
            return false;
        }

        id<MTLComputePipelineState> circle_to_coset =
            stwo_metal_pipeline(runtime, @"prefix_sum_circle_domain_order_to_coset_order_u32", error_message, error_message_len);
        if (circle_to_coset == nil) {
            return false;
        }
        id<MTLComputePipelineState> coset_to_circle =
            stwo_metal_pipeline(runtime, @"prefix_sum_coset_order_to_circle_domain_order_u32", error_message, error_message_len);
        if (coset_to_circle == nil) {
            return false;
        }
        id<MTLComputePipelineState> inclusive_step =
            stwo_metal_pipeline(runtime, @"prefix_sum_inclusive_step_u32", error_message, error_message_len);
        if (inclusive_step == nil) {
            return false;
        }

        StwoMetalBufferPool *pool = [StwoMetalBufferPool sharedPoolForDevice:runtime.device];
        NSUInteger bytes = (NSUInteger)len * sizeof(uint32_t);
        id<MTLBuffer> coset_buffer = [pool acquireWithByteSize:bytes];
        id<MTLBuffer> scan_buffer = [pool acquireWithByteSize:bytes];
        if (coset_buffer == nil || scan_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate Metal prefix-sum scratch buffers.");
            if (coset_buffer) [pool returnBuffer:coset_buffer];
            if (scan_buffer) [pool returnBuffer:scan_buffer];
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        uint32_t half_len = len >> 1u;
        id<MTLComputeCommandEncoder> reorder_encoder = [command_buffer computeCommandEncoder];
        if (reorder_encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }
        [reorder_encoder setComputePipelineState:circle_to_coset];
        [reorder_encoder setBuffer:buffer.buffer offset:0 atIndex:0];
        [reorder_encoder setBuffer:coset_buffer offset:0 atIndex:1];
        [reorder_encoder setBytes:&len length:sizeof(len) atIndex:2];
        MTLSize reorder_grid = MTLSizeMake(MAX((uint32_t)1u, half_len), 1, 1);
        MTLSize reorder_threads = MTLSizeMake(stwo_metal_threads_per_group(circle_to_coset), 1, 1);
        [reorder_encoder dispatchThreads:reorder_grid threadsPerThreadgroup:reorder_threads];
        [reorder_encoder endEncoding];

        id<MTLBuffer> current = coset_buffer;
        id<MTLBuffer> temp = scan_buffer;
        for (uint32_t stride = 1u; stride < len; stride <<= 1u) {
            id<MTLComputeCommandEncoder> scan_encoder = [command_buffer computeCommandEncoder];
            if (scan_encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                return false;
            }
            [scan_encoder setComputePipelineState:inclusive_step];
            [scan_encoder setBuffer:current offset:0 atIndex:0];
            [scan_encoder setBuffer:temp offset:0 atIndex:1];
            [scan_encoder setBytes:&len length:sizeof(len) atIndex:2];
            [scan_encoder setBytes:&stride length:sizeof(stride) atIndex:3];
            MTLSize scan_grid = MTLSizeMake(len, 1, 1);
            MTLSize scan_threads = MTLSizeMake(stwo_metal_threads_per_group(inclusive_step), 1, 1);
            [scan_encoder dispatchThreads:scan_grid threadsPerThreadgroup:scan_threads];
            [scan_encoder endEncoding];

            id<MTLBuffer> swap = current;
            current = temp;
            temp = swap;
        }

        id<MTLComputeCommandEncoder> restore_encoder = [command_buffer computeCommandEncoder];
        if (restore_encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }
        [restore_encoder setComputePipelineState:coset_to_circle];
        [restore_encoder setBuffer:current offset:0 atIndex:0];
        [restore_encoder setBuffer:buffer.buffer offset:0 atIndex:1];
        [restore_encoder setBytes:&len length:sizeof(len) atIndex:2];
        MTLSize restore_grid = MTLSizeMake(len, 1, 1);
        MTLSize restore_threads = MTLSizeMake(stwo_metal_threads_per_group(coset_to_circle), 1, 1);
        [restore_encoder dispatchThreads:restore_grid threadsPerThreadgroup:restore_threads];
        [restore_encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];
        [pool returnBuffer:coset_buffer];
        [pool returnBuffer:scan_buffer];
        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return stwo_metal_dispatch_unary_u32_kernel(
            runtime,
            @"bit_reverse_u32",
            buffer,
            log_len,
            error_message,
            error_message_len
        );
    }
}

// ---------------------------------------------------------------------------
// Interaction trace prefix sum: reduce + subtract + sequential scan
// ---------------------------------------------------------------------------

/// Batched reduce + prefix-sum for 4 QM31 coordinate columns.
/// Phase 1: parallel reduction of each coordinate (4 threadgroups in 1 CB).
/// Phase 2 is done on CPU (compute cumsum_shift from the 4 sums).
/// Phase 3: subtract cumsum_shift + sequential prefix sum (4 threads in 1 CB).
bool stwo_metal_reduce_sum_m31_4col(
    void *runtime_ptr,
    void *col0_ptr, void *col1_ptr, void *col2_ptr, void *col3_ptr,
    void *output_ptr,
    uint32_t n_elements,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *cols[4] = {
            stwo_metal_buffer_box(col0_ptr),
            stwo_metal_buffer_box(col1_ptr),
            stwo_metal_buffer_box(col2_ptr),
            stwo_metal_buffer_box(col3_ptr),
        };
        StwoMetalBufferBox *output = stwo_metal_buffer_box(output_ptr);

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"reduce_sum_m31", error_message, error_message_len);
        if (pipeline == nil) return false;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        NSUInteger tg_size = MIN((NSUInteger)256, pipeline.maxTotalThreadsPerThreadgroup);
        // Encode 4 reductions into one command buffer (one encoder per column).
        for (int i = 0; i < 4; i++) {
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:pipeline];
            [encoder setBuffer:cols[i].buffer offset:0 atIndex:0];
            [encoder setBuffer:output.buffer offset:(i * sizeof(uint32_t)) atIndex:1];
            [encoder setBytes:&n_elements length:sizeof(n_elements) atIndex:2];
            MTLSize grid = MTLSizeMake(tg_size, 1, 1);
            MTLSize threads = MTLSizeMake(tg_size, 1, 1);
            [encoder dispatchThreads:grid threadsPerThreadgroup:threads];
            [encoder endEncoding];
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal reduce_sum_m31_4col failed.");
            return false;
        }
        return true;
    }
}

bool stwo_metal_prefix_sum_subtract_m31_4col(
    void *runtime_ptr,
    void *col0_ptr, void *col1_ptr, void *col2_ptr, void *col3_ptr,
    const uint32_t *cumsum_shifts,
    uint32_t n_elements,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *cols[4] = {
            stwo_metal_buffer_box(col0_ptr),
            stwo_metal_buffer_box(col1_ptr),
            stwo_metal_buffer_box(col2_ptr),
            stwo_metal_buffer_box(col3_ptr),
        };

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"prefix_sum_subtract_m31", error_message, error_message_len);
        if (pipeline == nil) return false;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        // Encode 4 prefix sums into one command buffer.
        // Each uses 1 thread; the 4 dispatches run on different columns
        // and Metal may overlap them on different execution units.
        for (int i = 0; i < 4; i++) {
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:pipeline];
            [encoder setBuffer:cols[i].buffer offset:0 atIndex:0];
            [encoder setBytes:&cumsum_shifts[i] length:sizeof(uint32_t) atIndex:1];
            [encoder setBytes:&n_elements length:sizeof(n_elements) atIndex:2];
            MTLSize grid = MTLSizeMake(1, 1, 1);
            MTLSize threads = MTLSizeMake(1, 1, 1);
            [encoder dispatchThreads:grid threadsPerThreadgroup:threads];
            [encoder endEncoding];
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal prefix_sum_subtract_m31_4col failed.");
            return false;
        }
        return true;
    }
}

bool stwo_metal_permute_coset_to_circle_domain_bit_reversed_u32(
    void *runtime_ptr,
    void *src_ptr,
    void *dst_ptr,
    uint32_t log_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger len = ((NSUInteger)1) << log_len;
        if (src.len != len || dst.len != len) {
            stwo_metal_write_error(error_message, error_message_len, @"Coset permutation expects equal power-of-two source and destination lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"permute_coset_to_circle_domain_bit_reversed_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src.buffer offset:0 atIndex:0];
        [encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [encoder setBytes:&log_len length:sizeof(log_len) atIndex:2];

        MTLSize grid_size = MTLSizeMake(len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_fri_fold_circle_into_line_first_layer_u32x4(
    void *runtime_ptr,
    void *src_ptr,
    void *dst_ptr,
    void *inverse_y_ptr,
    uint32_t src_log_len,
    const uint32_t *alpha_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        StwoMetalBufferBox *inverse_y = stwo_metal_buffer_box(inverse_y_ptr);
        NSUInteger src_len = ((NSUInteger)1) << src_log_len;
        NSUInteger dst_len = src_len >> 1;
        if (src.len != src_len * 4 || dst.len != dst_len * 4 || inverse_y.len != dst_len) {
            stwo_metal_write_error(error_message, error_message_len, @"FRI first-layer fold expects src u32x4 input, dst u32x4 output, and one inverse-y factor per output element.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"fri_fold_circle_into_line_first_layer_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src.buffer offset:0 atIndex:0];
        [encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [encoder setBuffer:inverse_y.buffer offset:0 atIndex:2];
        [encoder setBytes:alpha_limbs length:sizeof(uint32_t) * 4 atIndex:3];

        MTLSize grid_size = MTLSizeMake(dst_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_pack_secure_column_coords_u32x4(
    void *runtime_ptr,
    void *coord_0_ptr,
    void *coord_1_ptr,
    void *coord_2_ptr,
    void *coord_3_ptr,
    void *dst_ptr,
    uint32_t element_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *coord_0 = stwo_metal_buffer_box(coord_0_ptr);
        StwoMetalBufferBox *coord_1 = stwo_metal_buffer_box(coord_1_ptr);
        StwoMetalBufferBox *coord_2 = stwo_metal_buffer_box(coord_2_ptr);
        StwoMetalBufferBox *coord_3 = stwo_metal_buffer_box(coord_3_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger expected_dst_len = (NSUInteger)element_len * 4u;
        if (
            coord_0.len != element_len || coord_1.len != element_len ||
            coord_2.len != element_len || coord_3.len != element_len ||
            dst.len != expected_dst_len
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Secure-column packing expects four equally sized coordinate buffers and one packed u32x4 destination.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"pack_secure_column_coords_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:coord_0.buffer offset:0 atIndex:0];
        [encoder setBuffer:coord_1.buffer offset:0 atIndex:1];
        [encoder setBuffer:coord_2.buffer offset:0 atIndex:2];
        [encoder setBuffer:coord_3.buffer offset:0 atIndex:3];
        [encoder setBuffer:dst.buffer offset:0 atIndex:4];

        MTLSize grid_size = MTLSizeMake(element_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_unpack_secure_column_coords_u32x4(
    void *runtime_ptr,
    void *src_ptr,
    void *coord_0_ptr,
    void *coord_1_ptr,
    void *coord_2_ptr,
    void *coord_3_ptr,
    uint32_t element_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *coord_0 = stwo_metal_buffer_box(coord_0_ptr);
        StwoMetalBufferBox *coord_1 = stwo_metal_buffer_box(coord_1_ptr);
        StwoMetalBufferBox *coord_2 = stwo_metal_buffer_box(coord_2_ptr);
        StwoMetalBufferBox *coord_3 = stwo_metal_buffer_box(coord_3_ptr);
        NSUInteger expected_src_len = (NSUInteger)element_len * 4u;
        if (
            src.len != expected_src_len ||
            coord_0.len != element_len || coord_1.len != element_len ||
            coord_2.len != element_len || coord_3.len != element_len
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Secure-column unpacking expects one packed u32x4 source and four equally sized coordinate buffers.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"unpack_secure_column_coords_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src.buffer offset:0 atIndex:0];
        [encoder setBuffer:coord_0.buffer offset:0 atIndex:1];
        [encoder setBuffer:coord_1.buffer offset:0 atIndex:2];
        [encoder setBuffer:coord_2.buffer offset:0 atIndex:3];
        [encoder setBuffer:coord_3.buffer offset:0 atIndex:4];

        MTLSize grid_size = MTLSizeMake(element_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_accumulate_secure_columns_coords_u32x4(
    void *runtime_ptr,
    void *lhs_0_ptr,
    void *lhs_1_ptr,
    void *lhs_2_ptr,
    void *lhs_3_ptr,
    void *rhs_0_ptr,
    void *rhs_1_ptr,
    void *rhs_2_ptr,
    void *rhs_3_ptr,
    void *dst_0_ptr,
    void *dst_1_ptr,
    void *dst_2_ptr,
    void *dst_3_ptr,
    uint32_t element_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *lhs_0 = stwo_metal_buffer_box(lhs_0_ptr);
        StwoMetalBufferBox *lhs_1 = stwo_metal_buffer_box(lhs_1_ptr);
        StwoMetalBufferBox *lhs_2 = stwo_metal_buffer_box(lhs_2_ptr);
        StwoMetalBufferBox *lhs_3 = stwo_metal_buffer_box(lhs_3_ptr);
        StwoMetalBufferBox *rhs_0 = stwo_metal_buffer_box(rhs_0_ptr);
        StwoMetalBufferBox *rhs_1 = stwo_metal_buffer_box(rhs_1_ptr);
        StwoMetalBufferBox *rhs_2 = stwo_metal_buffer_box(rhs_2_ptr);
        StwoMetalBufferBox *rhs_3 = stwo_metal_buffer_box(rhs_3_ptr);
        StwoMetalBufferBox *dst_0 = stwo_metal_buffer_box(dst_0_ptr);
        StwoMetalBufferBox *dst_1 = stwo_metal_buffer_box(dst_1_ptr);
        StwoMetalBufferBox *dst_2 = stwo_metal_buffer_box(dst_2_ptr);
        StwoMetalBufferBox *dst_3 = stwo_metal_buffer_box(dst_3_ptr);
        if (
            lhs_0.len != element_len || lhs_1.len != element_len ||
            lhs_2.len != element_len || lhs_3.len != element_len ||
            rhs_0.len != element_len || rhs_1.len != element_len ||
            rhs_2.len != element_len || rhs_3.len != element_len ||
            dst_0.len != element_len || dst_1.len != element_len ||
            dst_2.len != element_len || dst_3.len != element_len
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Secure-column accumulation expects four equally sized lhs columns, four equally sized rhs columns, and four equally sized destinations.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"accumulate_secure_columns_coords_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:lhs_0.buffer offset:0 atIndex:0];
        [encoder setBuffer:lhs_1.buffer offset:0 atIndex:1];
        [encoder setBuffer:lhs_2.buffer offset:0 atIndex:2];
        [encoder setBuffer:lhs_3.buffer offset:0 atIndex:3];
        [encoder setBuffer:rhs_0.buffer offset:0 atIndex:4];
        [encoder setBuffer:rhs_1.buffer offset:0 atIndex:5];
        [encoder setBuffer:rhs_2.buffer offset:0 atIndex:6];
        [encoder setBuffer:rhs_3.buffer offset:0 atIndex:7];
        [encoder setBuffer:dst_0.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst_1.buffer offset:0 atIndex:9];
        [encoder setBuffer:dst_2.buffer offset:0 atIndex:10];
        [encoder setBuffer:dst_3.buffer offset:0 atIndex:11];
        [encoder setBytes:&element_len length:sizeof(element_len) atIndex:12];

        MTLSize grid_size = MTLSizeMake(element_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_lift_accumulate_secure_columns_coords_u32x4(
    void *runtime_ptr,
    void *lifted_0_ptr,
    void *lifted_1_ptr,
    void *lifted_2_ptr,
    void *lifted_3_ptr,
    void *current_0_ptr,
    void *current_1_ptr,
    void *current_2_ptr,
    void *current_3_ptr,
    void *dst_0_ptr,
    void *dst_1_ptr,
    void *dst_2_ptr,
    void *dst_3_ptr,
    uint32_t current_log_size,
    uint32_t log_ratio,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *lifted_0 = stwo_metal_buffer_box(lifted_0_ptr);
        StwoMetalBufferBox *lifted_1 = stwo_metal_buffer_box(lifted_1_ptr);
        StwoMetalBufferBox *lifted_2 = stwo_metal_buffer_box(lifted_2_ptr);
        StwoMetalBufferBox *lifted_3 = stwo_metal_buffer_box(lifted_3_ptr);
        StwoMetalBufferBox *current_0 = stwo_metal_buffer_box(current_0_ptr);
        StwoMetalBufferBox *current_1 = stwo_metal_buffer_box(current_1_ptr);
        StwoMetalBufferBox *current_2 = stwo_metal_buffer_box(current_2_ptr);
        StwoMetalBufferBox *current_3 = stwo_metal_buffer_box(current_3_ptr);
        StwoMetalBufferBox *dst_0 = stwo_metal_buffer_box(dst_0_ptr);
        StwoMetalBufferBox *dst_1 = stwo_metal_buffer_box(dst_1_ptr);
        StwoMetalBufferBox *dst_2 = stwo_metal_buffer_box(dst_2_ptr);
        StwoMetalBufferBox *dst_3 = stwo_metal_buffer_box(dst_3_ptr);
        uint32_t current_len = ((uint32_t)1) << current_log_size;
        uint32_t lifted_len = current_len >> log_ratio;
        if (
            current_0.len != current_len || current_1.len != current_len ||
            current_2.len != current_len || current_3.len != current_len ||
            dst_0.len != current_len || dst_1.len != current_len ||
            dst_2.len != current_len || dst_3.len != current_len ||
            lifted_0.len != lifted_len || lifted_1.len != lifted_len ||
            lifted_2.len != lifted_len || lifted_3.len != lifted_len
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Secure-column lift-and-accumulate expects a power-of-two current length, matching destinations, and lifted columns sized by the log-ratio.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"lift_accumulate_secure_columns_coords_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:lifted_0.buffer offset:0 atIndex:0];
        [encoder setBuffer:lifted_1.buffer offset:0 atIndex:1];
        [encoder setBuffer:lifted_2.buffer offset:0 atIndex:2];
        [encoder setBuffer:lifted_3.buffer offset:0 atIndex:3];
        [encoder setBuffer:current_0.buffer offset:0 atIndex:4];
        [encoder setBuffer:current_1.buffer offset:0 atIndex:5];
        [encoder setBuffer:current_2.buffer offset:0 atIndex:6];
        [encoder setBuffer:current_3.buffer offset:0 atIndex:7];
        [encoder setBuffer:dst_0.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst_1.buffer offset:0 atIndex:9];
        [encoder setBuffer:dst_2.buffer offset:0 atIndex:10];
        [encoder setBuffer:dst_3.buffer offset:0 atIndex:11];
        [encoder setBytes:&current_log_size length:sizeof(current_log_size) atIndex:12];
        [encoder setBytes:&log_ratio length:sizeof(log_ratio) atIndex:13];

        MTLSize grid_size = MTLSizeMake(current_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_fri_fold_circle_into_line_accumulate_coords_u32x4(
    void *runtime_ptr,
    void *src_0_ptr,
    void *src_1_ptr,
    void *src_2_ptr,
    void *src_3_ptr,
    void *dst_0_ptr,
    void *dst_1_ptr,
    void *dst_2_ptr,
    void *dst_3_ptr,
    void *inverse_y_ptr,
    uint32_t src_log_len,
    const uint32_t *alpha_limbs,
    const uint32_t *alpha_sq_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src_0 = stwo_metal_buffer_box(src_0_ptr);
        StwoMetalBufferBox *src_1 = stwo_metal_buffer_box(src_1_ptr);
        StwoMetalBufferBox *src_2 = stwo_metal_buffer_box(src_2_ptr);
        StwoMetalBufferBox *src_3 = stwo_metal_buffer_box(src_3_ptr);
        StwoMetalBufferBox *dst_0 = stwo_metal_buffer_box(dst_0_ptr);
        StwoMetalBufferBox *dst_1 = stwo_metal_buffer_box(dst_1_ptr);
        StwoMetalBufferBox *dst_2 = stwo_metal_buffer_box(dst_2_ptr);
        StwoMetalBufferBox *dst_3 = stwo_metal_buffer_box(dst_3_ptr);
        StwoMetalBufferBox *inverse_y = stwo_metal_buffer_box(inverse_y_ptr);
        NSUInteger src_len = ((NSUInteger)1) << src_log_len;
        NSUInteger dst_len = src_len >> 1;
        if (
            src_0.len != src_len || src_1.len != src_len ||
            src_2.len != src_len || src_3.len != src_len ||
            inverse_y.len != dst_len ||
            dst_0.len != dst_len || dst_1.len != dst_len ||
            dst_2.len != dst_len || dst_3.len != dst_len
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"FRI first-layer accumulation expects four source coordinate buffers, four destination coordinate buffers, and one inverse-y factor per output element.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"fri_fold_circle_into_line_accumulate_coords_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src_0.buffer offset:0 atIndex:0];
        [encoder setBuffer:src_1.buffer offset:0 atIndex:1];
        [encoder setBuffer:src_2.buffer offset:0 atIndex:2];
        [encoder setBuffer:src_3.buffer offset:0 atIndex:3];
        [encoder setBuffer:dst_0.buffer offset:0 atIndex:4];
        [encoder setBuffer:dst_1.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst_2.buffer offset:0 atIndex:6];
        [encoder setBuffer:dst_3.buffer offset:0 atIndex:7];
        [encoder setBuffer:inverse_y.buffer offset:0 atIndex:8];
        [encoder setBytes:alpha_limbs length:sizeof(uint32_t) * 4 atIndex:9];
        [encoder setBytes:alpha_sq_limbs length:sizeof(uint32_t) * 4 atIndex:10];

        MTLSize grid_size = MTLSizeMake(dst_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_fri_fold_circle_into_line_first_layer_coords_u32x4(
    void *runtime_ptr,
    void *src_0_ptr,
    void *src_1_ptr,
    void *src_2_ptr,
    void *src_3_ptr,
    void *dst_0_ptr,
    void *dst_1_ptr,
    void *dst_2_ptr,
    void *dst_3_ptr,
    void *inverse_y_ptr,
    uint32_t src_log_len,
    const uint32_t *alpha_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src_0 = stwo_metal_buffer_box(src_0_ptr);
        StwoMetalBufferBox *src_1 = stwo_metal_buffer_box(src_1_ptr);
        StwoMetalBufferBox *src_2 = stwo_metal_buffer_box(src_2_ptr);
        StwoMetalBufferBox *src_3 = stwo_metal_buffer_box(src_3_ptr);
        StwoMetalBufferBox *dst_0 = stwo_metal_buffer_box(dst_0_ptr);
        StwoMetalBufferBox *dst_1 = stwo_metal_buffer_box(dst_1_ptr);
        StwoMetalBufferBox *dst_2 = stwo_metal_buffer_box(dst_2_ptr);
        StwoMetalBufferBox *dst_3 = stwo_metal_buffer_box(dst_3_ptr);
        StwoMetalBufferBox *inverse_y = stwo_metal_buffer_box(inverse_y_ptr);
        NSUInteger src_len = ((NSUInteger)1) << src_log_len;
        NSUInteger dst_len = src_len >> 1;
        if (
            src_0.len != src_len || src_1.len != src_len ||
            src_2.len != src_len || src_3.len != src_len ||
            inverse_y.len != dst_len ||
            dst_0.len != dst_len || dst_1.len != dst_len ||
            dst_2.len != dst_len || dst_3.len != dst_len
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"FRI first-layer coordinate fold expects four source coordinate buffers, four destination coordinate buffers, and one inverse-y factor per output element.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"fri_fold_circle_into_line_first_layer_coords_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src_0.buffer offset:0 atIndex:0];
        [encoder setBuffer:src_1.buffer offset:0 atIndex:1];
        [encoder setBuffer:src_2.buffer offset:0 atIndex:2];
        [encoder setBuffer:src_3.buffer offset:0 atIndex:3];
        [encoder setBuffer:dst_0.buffer offset:0 atIndex:4];
        [encoder setBuffer:dst_1.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst_2.buffer offset:0 atIndex:6];
        [encoder setBuffer:dst_3.buffer offset:0 atIndex:7];
        [encoder setBuffer:inverse_y.buffer offset:0 atIndex:8];
        [encoder setBytes:alpha_limbs length:sizeof(uint32_t) * 4 atIndex:9];

        MTLSize grid_size = MTLSizeMake(dst_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_fri_fold_line_step_coords_u32x4(
    void *runtime_ptr,
    void *src_0_ptr,
    void *src_1_ptr,
    void *src_2_ptr,
    void *src_3_ptr,
    void *dst_0_ptr,
    void *dst_1_ptr,
    void *dst_2_ptr,
    void *dst_3_ptr,
    void *inverse_x_ptr,
    uint32_t src_log_len,
    const uint32_t *alpha_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src_0 = stwo_metal_buffer_box(src_0_ptr);
        StwoMetalBufferBox *src_1 = stwo_metal_buffer_box(src_1_ptr);
        StwoMetalBufferBox *src_2 = stwo_metal_buffer_box(src_2_ptr);
        StwoMetalBufferBox *src_3 = stwo_metal_buffer_box(src_3_ptr);
        StwoMetalBufferBox *dst_0 = stwo_metal_buffer_box(dst_0_ptr);
        StwoMetalBufferBox *dst_1 = stwo_metal_buffer_box(dst_1_ptr);
        StwoMetalBufferBox *dst_2 = stwo_metal_buffer_box(dst_2_ptr);
        StwoMetalBufferBox *dst_3 = stwo_metal_buffer_box(dst_3_ptr);
        StwoMetalBufferBox *inverse_x = stwo_metal_buffer_box(inverse_x_ptr);
        NSUInteger src_len = ((NSUInteger)1) << src_log_len;
        NSUInteger dst_len = src_len >> 1;
        if (
            src_0.len != src_len || src_1.len != src_len ||
            src_2.len != src_len || src_3.len != src_len ||
            dst_0.len != dst_len || dst_1.len != dst_len ||
            dst_2.len != dst_len || dst_3.len != dst_len ||
            inverse_x.len != dst_len
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"FRI line-fold step expects four source coordinate buffers, four destination coordinate buffers, and one inverse-x factor per output element.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"fri_fold_line_step_coords_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src_0.buffer offset:0 atIndex:0];
        [encoder setBuffer:src_1.buffer offset:0 atIndex:1];
        [encoder setBuffer:src_2.buffer offset:0 atIndex:2];
        [encoder setBuffer:src_3.buffer offset:0 atIndex:3];
        [encoder setBuffer:dst_0.buffer offset:0 atIndex:4];
        [encoder setBuffer:dst_1.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst_2.buffer offset:0 atIndex:6];
        [encoder setBuffer:dst_3.buffer offset:0 atIndex:7];
        [encoder setBuffer:inverse_x.buffer offset:0 atIndex:8];
        [encoder setBytes:alpha_limbs length:sizeof(uint32_t) * 4 atIndex:9];

        MTLSize grid_size = MTLSizeMake(dst_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

/// Async variant: commits the command buffer but does NOT wait.
/// Returns the command buffer as an opaque handle for deferred waiting.
void* stwo_metal_fri_fold_line_step_coords_u32x4_async(
    void *runtime_ptr,
    void *src_0_ptr, void *src_1_ptr, void *src_2_ptr, void *src_3_ptr,
    void *dst_0_ptr, void *dst_1_ptr, void *dst_2_ptr, void *dst_3_ptr,
    void *inverse_x_ptr,
    uint32_t src_log_len,
    const uint32_t *alpha_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src_0 = stwo_metal_buffer_box(src_0_ptr);
        StwoMetalBufferBox *src_1 = stwo_metal_buffer_box(src_1_ptr);
        StwoMetalBufferBox *src_2 = stwo_metal_buffer_box(src_2_ptr);
        StwoMetalBufferBox *src_3 = stwo_metal_buffer_box(src_3_ptr);
        StwoMetalBufferBox *dst_0 = stwo_metal_buffer_box(dst_0_ptr);
        StwoMetalBufferBox *dst_1 = stwo_metal_buffer_box(dst_1_ptr);
        StwoMetalBufferBox *dst_2 = stwo_metal_buffer_box(dst_2_ptr);
        StwoMetalBufferBox *dst_3 = stwo_metal_buffer_box(dst_3_ptr);
        StwoMetalBufferBox *inverse_x = stwo_metal_buffer_box(inverse_x_ptr);
        NSUInteger src_len = ((NSUInteger)1) << src_log_len;
        NSUInteger dst_len = src_len >> 1;

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"fri_fold_line_step_coords_u32x4", error_message, error_message_len);
        if (pipeline == nil) return NULL;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return NULL;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src_0.buffer offset:0 atIndex:0];
        [encoder setBuffer:src_1.buffer offset:0 atIndex:1];
        [encoder setBuffer:src_2.buffer offset:0 atIndex:2];
        [encoder setBuffer:src_3.buffer offset:0 atIndex:3];
        [encoder setBuffer:dst_0.buffer offset:0 atIndex:4];
        [encoder setBuffer:dst_1.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst_2.buffer offset:0 atIndex:6];
        [encoder setBuffer:dst_3.buffer offset:0 atIndex:7];
        [encoder setBuffer:inverse_x.buffer offset:0 atIndex:8];
        [encoder setBytes:alpha_limbs length:sizeof(uint32_t) * 4 atIndex:9];
        MTLSize grid_size = MTLSizeMake(dst_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        return (__bridge_retained void *)command_buffer;
    }
}

bool stwo_metal_fri_fold_line_step_u32x4(
    void *runtime_ptr,
    void *src_ptr,
    void *dst_ptr,
    void *inverse_x_ptr,
    uint32_t src_log_len,
    const uint32_t *alpha_limbs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src = stwo_metal_buffer_box(src_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        StwoMetalBufferBox *inverse_x = stwo_metal_buffer_box(inverse_x_ptr);
        NSUInteger src_len = ((NSUInteger)1) << src_log_len;
        NSUInteger dst_len = src_len >> 1;
        if (src.len != src_len * 4 || dst.len != dst_len * 4 || inverse_x.len != dst_len) {
            stwo_metal_write_error(error_message, error_message_len, @"FRI line-fold step expects src u32x4 input, dst u32x4 output, and one inverse-x factor per output element.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"fri_fold_line_step_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:src.buffer offset:0 atIndex:0];
        [encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [encoder setBuffer:inverse_x.buffer offset:0 atIndex:2];
        [encoder setBytes:alpha_limbs length:sizeof(uint32_t) * 4 atIndex:3];

        MTLSize grid_size = MTLSizeMake(dst_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_accumulate_wide_fibonacci_quotients_u32x4(
    void *runtime_ptr,
    void *trace_ptr,
    void *random_coeff_ptr,
    void *denominator_ptr,
    void *dst_ptr,
    uint32_t domain_log_size,
    uint32_t eval_domain_log_size,
    uint32_t n_constraints,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);
        StwoMetalBufferBox *random_coeff = stwo_metal_buffer_box(random_coeff_ptr);
        StwoMetalBufferBox *denominator = stwo_metal_buffer_box(denominator_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger eval_domain_size = ((NSUInteger)1) << eval_domain_log_size;
        uint32_t eval_domain_size_u32 = ((uint32_t)1) << eval_domain_log_size;
        NSUInteger denominator_len = ((NSUInteger)1) << (eval_domain_log_size - domain_log_size);
        NSUInteger trace_columns = (NSUInteger)n_constraints + 2;
        if (trace.len != trace_columns * eval_domain_size ||
            random_coeff.len != ((NSUInteger)n_constraints) * 4 ||
            denominator.len != denominator_len ||
            dst.len != eval_domain_size * 4) {
            stwo_metal_write_error(error_message, error_message_len, @"Wide-fibonacci quotient accumulation expects column-major trace evaluations, one qm31 random coefficient per constraint, one denominator inverse per coset, and a u32x4 destination.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"accumulate_wide_fibonacci_quotients_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace.buffer offset:0 atIndex:0];
        [encoder setBuffer:random_coeff.buffer offset:0 atIndex:1];
        [encoder setBuffer:denominator.buffer offset:0 atIndex:2];
        [encoder setBuffer:dst.buffer offset:0 atIndex:3];
        [encoder setBytes:&eval_domain_size_u32 length:sizeof(eval_domain_size_u32) atIndex:4];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:5];
        [encoder setBytes:&domain_log_size length:sizeof(domain_log_size) atIndex:6];

        MTLSize grid_size = MTLSizeMake(eval_domain_size, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_eval_program_v1_reference_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 reference lane expects canonical packed buffers and lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_reference_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_eval_program_v1_optimized_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    uint32_t max_base_regs,
    uint32_t max_ext_regs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 optimized lane expects canonical packed buffers and lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_optimized_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];
        [encoder setBytes:&max_base_regs length:sizeof(max_base_regs) atIndex:14];
        [encoder setBytes:&max_ext_regs length:sizeof(max_ext_regs) atIndex:15];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_eval_program_v1_reference_u32x4_tg(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    uint32_t threads_per_group,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 reference_tg lane expects canonical packed buffers and lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline;
        if (threads_per_group > 0) {
            pipeline = stwo_metal_pipeline_with_max_threads(
                runtime, @"eval_program_v1_reference_u32x4", (NSUInteger)threads_per_group, error_message, error_message_len);
        } else {
            pipeline = stwo_metal_pipeline(runtime, @"eval_program_v1_reference_u32x4", error_message, error_message_len);
        }
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];

        NSUInteger tg_size = (threads_per_group > 0) ? (NSUInteger)threads_per_group : stwo_metal_threads_per_group(pipeline);
        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(tg_size, 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_eval_program_v1_optimized_u32x4_tg(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    uint32_t max_base_regs,
    uint32_t max_ext_regs,
    uint32_t threads_per_group,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 optimized_tg lane expects canonical packed buffers and lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline;
        if (threads_per_group > 0) {
            pipeline = stwo_metal_pipeline_with_max_threads(
                runtime, @"eval_program_v1_optimized_u32x4", (NSUInteger)threads_per_group, error_message, error_message_len);
        } else {
            pipeline = stwo_metal_pipeline(runtime, @"eval_program_v1_optimized_u32x4", error_message, error_message_len);
        }
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];
        [encoder setBytes:&max_base_regs length:sizeof(max_base_regs) atIndex:14];
        [encoder setBytes:&max_ext_regs length:sizeof(max_ext_regs) atIndex:15];

        NSUInteger tg_size = (threads_per_group > 0) ? (NSUInteger)threads_per_group : stwo_metal_threads_per_group(pipeline);
        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(tg_size, 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// --- Async eval_program_v1 dispatch (Variant A only) ---
// Returns a retained command buffer handle without waiting for completion.
// Caller must later call stwo_metal_command_buffer_wait to block + release,
// or stwo_metal_command_buffer_release to discard.

void *stwo_metal_eval_program_v1_reference_async_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 reference async lane expects canonical packed buffers and lengths.");
            return NULL;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_reference_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return NULL;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return NULL;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return NULL;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        // Do NOT waitUntilCompleted — return the handle for deferred waiting.
        return (__bridge_retained void *)command_buffer;
    }
}

void *stwo_metal_eval_program_v1_optimized_async_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    uint32_t max_base_regs,
    uint32_t max_ext_regs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 optimized async lane expects canonical packed buffers and lengths.");
            return NULL;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_optimized_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return NULL;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return NULL;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return NULL;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];
        [encoder setBytes:&max_base_regs length:sizeof(max_base_regs) atIndex:14];
        [encoder setBytes:&max_ext_regs length:sizeof(max_ext_regs) atIndex:15];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        // Do NOT waitUntilCompleted — return the handle for deferred waiting.
        return (__bridge_retained void *)command_buffer;
    }
}

bool stwo_metal_eval_program_v1_reference_b_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 reference_b lane expects canonical packed buffers and lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_reference_b_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_eval_program_v1_optimized_b_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    uint32_t max_base_regs,
    uint32_t max_ext_regs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 optimized_b lane expects canonical packed buffers and lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_optimized_b_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];
        [encoder setBytes:&max_base_regs length:sizeof(max_base_regs) atIndex:14];
        [encoder setBytes:&max_ext_regs length:sizeof(max_ext_regs) atIndex:15];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_eval_program_v1_reference_c_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 reference_c lane expects canonical packed buffers and lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_reference_c_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_eval_program_v1_optimized_c_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *base_insts_ptr,
    void *ext_insts_ptr,
    void *constraint_roots_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_preprocessed_columns,
    uint32_t n_base_params,
    uint32_t n_ext_params,
    uint32_t n_base_insts,
    uint32_t n_ext_insts,
    uint32_t n_constraints,
    uint32_t max_base_regs,
    uint32_t max_ext_regs,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *base_insts = stwo_metal_buffer_box(base_insts_ptr);
        StwoMetalBufferBox *ext_insts = stwo_metal_buffer_box(ext_insts_ptr);
        StwoMetalBufferBox *constraint_roots = stwo_metal_buffer_box(constraint_roots_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        BOOL preprocessed_ok =
            (n_preprocessed_columns == 0u) ||
            (preprocessed_values.len == (NSUInteger)n_preprocessed_columns * row_count);
        BOOL base_params_ok =
            (n_base_params == 0u) ||
            (base_params.len == (NSUInteger)n_base_params);
        BOOL ext_params_ok =
            (n_ext_params == 0u) ||
            (ext_params.len == (NSUInteger)n_ext_params * 4u);

        if (interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            !preprocessed_ok ||
            !base_params_ok ||
            !ext_params_ok ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            base_insts.len != (NSUInteger)n_base_insts * 4u ||
            ext_insts.len != (NSUInteger)n_ext_insts * 5u ||
            constraint_roots.len != (NSUInteger)n_constraints ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"MetalEvaluationProgramV1 optimized_c lane expects canonical packed buffers and lengths.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_optimized_c_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:base_insts.buffer offset:0 atIndex:6];
        [encoder setBuffer:ext_insts.buffer offset:0 atIndex:7];
        [encoder setBuffer:constraint_roots.buffer offset:0 atIndex:8];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBytes:&n_base_insts length:sizeof(n_base_insts) atIndex:11];
        [encoder setBytes:&n_ext_insts length:sizeof(n_ext_insts) atIndex:12];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:13];
        [encoder setBytes:&max_base_regs length:sizeof(max_base_regs) atIndex:14];
        [encoder setBytes:&max_ext_regs length:sizeof(max_ext_regs) atIndex:15];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_eval_program_v1_wide_fibonacci_u32x4(
    void *runtime_ptr,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *random_coeff_powers_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_interactions,
    uint32_t n_constraints,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        if (n_interactions < 2u ||
            interaction_offsets.len != (NSUInteger)n_interactions + 1u ||
            random_coeff_powers.len != (NSUInteger)n_constraints * 4u ||
            dst.len != (NSUInteger)row_count * 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"Wide-fibonacci overlay expects canonical packed trace interaction offsets, randomness, and destination buffers.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"eval_program_v1_wide_fibonacci_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:2];
        [encoder setBuffer:dst.buffer offset:0 atIndex:3];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:4];
        [encoder setBytes:&n_constraints length:sizeof(n_constraints) atIndex:5];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_sampled_values_v1_wide_fibonacci_u32x4(
    void *runtime_ptr,
    void *tree_descs_ptr,
    void *column_descs_ptr,
    void *values_ptr,
    void *point_x_ptr,
    void *dst_ptr,
    uint32_t n_trees,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *tree_descs = stwo_metal_buffer_box(tree_descs_ptr);
        StwoMetalBufferBox *column_descs = stwo_metal_buffer_box(column_descs_ptr);
        StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptr);
        StwoMetalBufferBox *point_x = stwo_metal_buffer_box(point_x_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        if (n_trees == 0u ||
            tree_descs.len != (NSUInteger)n_trees * 2u ||
            point_x.len != 4u ||
            dst.len != 4u) {
            stwo_metal_write_error(error_message, error_message_len, @"Sampled-values V1 wide-fibonacci lane expects canonical tree descriptors, one secure-field point coordinate, and a single secure-field destination.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"sampled_values_v1_wide_fibonacci_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:tree_descs.buffer offset:0 atIndex:0];
        [encoder setBuffer:column_descs.buffer offset:0 atIndex:1];
        [encoder setBuffer:values.buffer offset:0 atIndex:2];
        [encoder setBuffer:point_x.buffer offset:0 atIndex:3];
        [encoder setBuffer:dst.buffer offset:0 atIndex:4];
        [encoder setBytes:&n_trees length:sizeof(n_trees) atIndex:5];

        MTLSize grid_size = MTLSizeMake(1, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(1, 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_accumulate_partial_numerators_u32x4(
    void *runtime_ptr,
    void *columns_ptr,
    void *column_indices_ptr,
    void *b_coeffs_ptr,
    void *c_coeffs_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_terms,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *columns = stwo_metal_buffer_box(columns_ptr);
        StwoMetalBufferBox *column_indices = stwo_metal_buffer_box(column_indices_ptr);
        StwoMetalBufferBox *b_coeffs = stwo_metal_buffer_box(b_coeffs_ptr);
        StwoMetalBufferBox *c_coeffs = stwo_metal_buffer_box(c_coeffs_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        if (
            row_count == 0u ||
            columns.len % row_count != 0u ||
            column_indices.len != n_terms ||
            b_coeffs.len != ((NSUInteger)n_terms) * 4u ||
            c_coeffs.len != ((NSUInteger)n_terms) * 4u ||
            dst.len != ((NSUInteger)row_count) * 4u
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Partial numerator accumulation expects flattened base columns, one column index per term, one qm31 b/c coefficient per term, and a packed u32x4 destination.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"accumulate_partial_numerators_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:columns.buffer offset:0 atIndex:0];
        [encoder setBuffer:column_indices.buffer offset:0 atIndex:1];
        [encoder setBuffer:b_coeffs.buffer offset:0 atIndex:2];
        [encoder setBuffer:c_coeffs.buffer offset:0 atIndex:3];
        [encoder setBuffer:dst.buffer offset:0 atIndex:4];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:5];
        [encoder setBytes:&n_terms length:sizeof(n_terms) atIndex:6];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_accumulate_partial_numerators_batched_u32x4(
    void *runtime_ptr,
    void *columns_ptr,
    void *column_indices_ptr,
    void *b_coeffs_ptr,
    void *c_coeffs_ptr,
    void *term_offsets_ptr,
    void *term_counts_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t n_batches,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *columns = stwo_metal_buffer_box(columns_ptr);
        StwoMetalBufferBox *column_indices = stwo_metal_buffer_box(column_indices_ptr);
        StwoMetalBufferBox *b_coeffs = stwo_metal_buffer_box(b_coeffs_ptr);
        StwoMetalBufferBox *c_coeffs = stwo_metal_buffer_box(c_coeffs_ptr);
        StwoMetalBufferBox *term_offsets = stwo_metal_buffer_box(term_offsets_ptr);
        StwoMetalBufferBox *term_counts = stwo_metal_buffer_box(term_counts_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        if (row_count == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"Batched partial numerator accumulation requires a non-zero row count.");
            return false;
        }
        if (columns.len % row_count != 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"Batched partial numerator accumulation expects flattened base columns with an integral number of rows.");
            return false;
        }
        if (term_offsets.len != n_batches) {
            stwo_metal_write_error(error_message, error_message_len, @"Batched partial numerator accumulation expects one term offset per batch.");
            return false;
        }
        if (term_counts.len != n_batches) {
            stwo_metal_write_error(error_message, error_message_len, @"Batched partial numerator accumulation expects one term count per batch.");
            return false;
        }
        if (column_indices.len * 4u != b_coeffs.len) {
            stwo_metal_write_error(error_message, error_message_len, @"Batched partial numerator accumulation expects one qm31 b coefficient per column index.");
            return false;
        }
        if (column_indices.len * 4u != c_coeffs.len) {
            stwo_metal_write_error(error_message, error_message_len, @"Batched partial numerator accumulation expects one qm31 c coefficient per column index.");
            return false;
        }
        if (dst.len != (NSUInteger)(row_count * n_batches * 4u)) {
            stwo_metal_write_error(error_message, error_message_len, @"Batched partial numerator accumulation expects one qm31 output per (batch, row).");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"accumulate_partial_numerators_batched_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:columns.buffer offset:0 atIndex:0];
        [encoder setBuffer:column_indices.buffer offset:0 atIndex:1];
        [encoder setBuffer:b_coeffs.buffer offset:0 atIndex:2];
        [encoder setBuffer:c_coeffs.buffer offset:0 atIndex:3];
        [encoder setBuffer:term_offsets.buffer offset:0 atIndex:4];
        [encoder setBuffer:term_counts.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst.buffer offset:0 atIndex:6];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:7];
        [encoder setBytes:&n_batches length:sizeof(n_batches) atIndex:8];
        NSUInteger total_rows = (NSUInteger)row_count * (NSUInteger)n_batches;
        MTLSize grid_size = MTLSizeMake(total_rows, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// Fused accumulate + unpack: encodes accumulate_partial_numerators_batched +
// N unpack_secure_column_coords into a SINGLE command buffer, eliminating N
// GPU round-trips and the intermediate clone_range copies.
bool stwo_metal_accumulate_and_unpack_partial_numerators_batched_u32x4(
    void *runtime_ptr,
    void *columns_ptr,
    void *column_indices_ptr,
    void *b_coeffs_ptr,
    void *c_coeffs_ptr,
    void *term_offsets_ptr,
    void *term_counts_ptr,
    uint32_t row_count,
    uint32_t n_batches,
    // Pre-allocated output coordinate buffers: n_batches * 4 entries
    // Layout: [batch0_coord0, batch0_coord1, batch0_coord2, batch0_coord3,
    //          batch1_coord0, ..., batchN_coord3]
    void **output_coord_buffers,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *columns = stwo_metal_buffer_box(columns_ptr);
        StwoMetalBufferBox *column_indices = stwo_metal_buffer_box(column_indices_ptr);
        StwoMetalBufferBox *b_coeffs = stwo_metal_buffer_box(b_coeffs_ptr);
        StwoMetalBufferBox *c_coeffs = stwo_metal_buffer_box(c_coeffs_ptr);
        StwoMetalBufferBox *term_offsets = stwo_metal_buffer_box(term_offsets_ptr);
        StwoMetalBufferBox *term_counts = stwo_metal_buffer_box(term_counts_ptr);

        if (row_count == 0u || n_batches == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"Fused accumulate+unpack requires non-zero row count and batch count.");
            return false;
        }

        // Allocate intermediate accumulate output buffer (packed QM31).
        NSUInteger accum_len = (NSUInteger)row_count * (NSUInteger)n_batches * 4u;
        id<MTLBuffer> accum_buffer = [runtime.device newBufferWithLength:(accum_len * sizeof(uint32_t))
                                                                options:MTLResourceStorageModePrivate];
        if (accum_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate intermediate accumulate buffer.");
            return false;
        }

        // Get pipeline states.
        id<MTLComputePipelineState> accum_pipeline =
            stwo_metal_pipeline(runtime, @"accumulate_partial_numerators_batched_u32x4", error_message, error_message_len);
        if (accum_pipeline == nil) return false;

        id<MTLComputePipelineState> unpack_pipeline =
            stwo_metal_pipeline(runtime, @"unpack_secure_column_coords_u32x4", error_message, error_message_len);
        if (unpack_pipeline == nil) return false;

        // Single command buffer for all work.
        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        // Encoder 1: accumulate partial numerators (all batches).
        {
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create accumulate encoder.");
                return false;
            }
            [encoder setComputePipelineState:accum_pipeline];
            [encoder setBuffer:columns.buffer offset:0 atIndex:0];
            [encoder setBuffer:column_indices.buffer offset:0 atIndex:1];
            [encoder setBuffer:b_coeffs.buffer offset:0 atIndex:2];
            [encoder setBuffer:c_coeffs.buffer offset:0 atIndex:3];
            [encoder setBuffer:term_offsets.buffer offset:0 atIndex:4];
            [encoder setBuffer:term_counts.buffer offset:0 atIndex:5];
            [encoder setBuffer:accum_buffer offset:0 atIndex:6];
            [encoder setBytes:&row_count length:sizeof(row_count) atIndex:7];
            [encoder setBytes:&n_batches length:sizeof(n_batches) atIndex:8];
            NSUInteger total_rows = (NSUInteger)row_count * (NSUInteger)n_batches;
            MTLSize grid_size = MTLSizeMake(total_rows, 1, 1);
            MTLSize tg_size = MTLSizeMake(stwo_metal_threads_per_group(accum_pipeline), 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:tg_size];
            [encoder endEncoding];
        }

        // Encoders 2..N+1: unpack each batch's packed QM31 → 4 coordinate buffers.
        // Reads from accum_buffer at batch_offset; no intermediate copy needed.
        NSUInteger batch_stride_bytes = (NSUInteger)row_count * 4u * sizeof(uint32_t);
        for (uint32_t batch_idx = 0; batch_idx < n_batches; ++batch_idx) {
            StwoMetalBufferBox *c0 = stwo_metal_buffer_box(output_coord_buffers[batch_idx * 4 + 0]);
            StwoMetalBufferBox *c1 = stwo_metal_buffer_box(output_coord_buffers[batch_idx * 4 + 1]);
            StwoMetalBufferBox *c2 = stwo_metal_buffer_box(output_coord_buffers[batch_idx * 4 + 2]);
            StwoMetalBufferBox *c3 = stwo_metal_buffer_box(output_coord_buffers[batch_idx * 4 + 3]);

            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create unpack encoder.");
                return false;
            }
            [encoder setComputePipelineState:unpack_pipeline];
            [encoder setBuffer:accum_buffer offset:(batch_idx * batch_stride_bytes) atIndex:0];
            [encoder setBuffer:c0.buffer offset:0 atIndex:1];
            [encoder setBuffer:c1.buffer offset:0 atIndex:2];
            [encoder setBuffer:c2.buffer offset:0 atIndex:3];
            [encoder setBuffer:c3.buffer offset:0 atIndex:4];
            MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
            MTLSize tg_size = MTLSizeMake(stwo_metal_threads_per_group(unpack_pipeline), 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:tg_size];
            [encoder endEncoding];
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Fused accumulate+unpack kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_accumulate_and_unpack_partial_numerators_indirect_batched_u32x4(
    void *runtime_ptr,
    // Array of n_unique_cols column buffer pointers.
    void **column_buffer_ptrs,
    uint32_t n_unique_cols,
    void *column_indices_ptr,
    void *b_coeffs_ptr,
    void *c_coeffs_ptr,
    void *term_offsets_ptr,
    void *term_counts_ptr,
    uint32_t row_count,
    uint32_t n_batches,
    // Pre-allocated output coordinate buffers: n_batches * 4 entries
    void **output_coord_buffers,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *column_indices = stwo_metal_buffer_box(column_indices_ptr);
        StwoMetalBufferBox *b_coeffs = stwo_metal_buffer_box(b_coeffs_ptr);
        StwoMetalBufferBox *c_coeffs = stwo_metal_buffer_box(c_coeffs_ptr);
        StwoMetalBufferBox *term_offsets = stwo_metal_buffer_box(term_offsets_ptr);
        StwoMetalBufferBox *term_counts = stwo_metal_buffer_box(term_counts_ptr);

        if (row_count == 0u || n_batches == 0u) {
            stwo_metal_write_error(error_message, error_message_len, @"Indirect accumulate+unpack requires non-zero row count and batch count.");
            return false;
        }

        // Build GPU address buffer: one uint64_t per unique column, containing
        // the GPU virtual address of each column's MTLBuffer.
        id<MTLBuffer> addr_buffer = [runtime.device newBufferWithLength:(n_unique_cols * sizeof(uint64_t))
                                                                options:MTLResourceStorageModeShared];
        if (addr_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate GPU address buffer for indirect numerators.");
            return false;
        }
        uint64_t *addr_contents = (uint64_t *)addr_buffer.contents;
        for (uint32_t i = 0; i < n_unique_cols; ++i) {
            StwoMetalBufferBox *col = stwo_metal_buffer_box(column_buffer_ptrs[i]);
            addr_contents[i] = col.buffer.gpuAddress;
        }

        // Allocate intermediate accumulate output buffer (packed QM31).
        NSUInteger accum_len = (NSUInteger)row_count * (NSUInteger)n_batches * 4u;
        id<MTLBuffer> accum_buffer = [runtime.device newBufferWithLength:(accum_len * sizeof(uint32_t))
                                                                options:MTLResourceStorageModePrivate];
        if (accum_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate intermediate accumulate buffer for indirect numerators.");
            return false;
        }

        // Get pipeline states.
        id<MTLComputePipelineState> accum_pipeline =
            stwo_metal_pipeline(runtime, @"accumulate_partial_numerators_indirect_batched_u32x4", error_message, error_message_len);
        if (accum_pipeline == nil) return false;

        id<MTLComputePipelineState> unpack_pipeline =
            stwo_metal_pipeline(runtime, @"unpack_secure_column_coords_u32x4", error_message, error_message_len);
        if (unpack_pipeline == nil) return false;

        // Single command buffer for all work.
        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        // Encoder 1: accumulate partial numerators via indirect column addresses.
        {
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create indirect accumulate encoder.");
                return false;
            }
            [encoder setComputePipelineState:accum_pipeline];
            [encoder setBuffer:addr_buffer offset:0 atIndex:0];
            [encoder setBuffer:column_indices.buffer offset:0 atIndex:1];
            [encoder setBuffer:b_coeffs.buffer offset:0 atIndex:2];
            [encoder setBuffer:c_coeffs.buffer offset:0 atIndex:3];
            [encoder setBuffer:term_offsets.buffer offset:0 atIndex:4];
            [encoder setBuffer:term_counts.buffer offset:0 atIndex:5];
            [encoder setBuffer:accum_buffer offset:0 atIndex:6];
            [encoder setBytes:&row_count length:sizeof(row_count) atIndex:7];
            [encoder setBytes:&n_batches length:sizeof(n_batches) atIndex:8];
            // Mark all column buffers as used so Metal doesn't evict them.
            for (uint32_t i = 0; i < n_unique_cols; ++i) {
                StwoMetalBufferBox *col = stwo_metal_buffer_box(column_buffer_ptrs[i]);
                [encoder useResource:col.buffer usage:MTLResourceUsageRead];
            }
            NSUInteger total_rows = (NSUInteger)row_count * (NSUInteger)n_batches;
            MTLSize grid_size = MTLSizeMake(total_rows, 1, 1);
            MTLSize tg_size = MTLSizeMake(stwo_metal_threads_per_group(accum_pipeline), 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:tg_size];
            [encoder endEncoding];
        }

        // Encoders 2..N+1: unpack each batch's packed QM31 -> 4 coordinate buffers.
        NSUInteger batch_stride_bytes = (NSUInteger)row_count * 4u * sizeof(uint32_t);
        for (uint32_t batch_idx = 0; batch_idx < n_batches; ++batch_idx) {
            StwoMetalBufferBox *c0 = stwo_metal_buffer_box(output_coord_buffers[batch_idx * 4 + 0]);
            StwoMetalBufferBox *c1 = stwo_metal_buffer_box(output_coord_buffers[batch_idx * 4 + 1]);
            StwoMetalBufferBox *c2 = stwo_metal_buffer_box(output_coord_buffers[batch_idx * 4 + 2]);
            StwoMetalBufferBox *c3 = stwo_metal_buffer_box(output_coord_buffers[batch_idx * 4 + 3]);

            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create unpack encoder.");
                return false;
            }
            [encoder setComputePipelineState:unpack_pipeline];
            [encoder setBuffer:accum_buffer offset:(batch_idx * batch_stride_bytes) atIndex:0];
            [encoder setBuffer:c0.buffer offset:0 atIndex:1];
            [encoder setBuffer:c1.buffer offset:0 atIndex:2];
            [encoder setBuffer:c2.buffer offset:0 atIndex:3];
            [encoder setBuffer:c3.buffer offset:0 atIndex:4];
            MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
            MTLSize tg_size = MTLSizeMake(stwo_metal_threads_per_group(unpack_pipeline), 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:tg_size];
            [encoder endEncoding];
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Indirect accumulate+unpack kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_compute_quotients_and_combine_u32x4(
    void *runtime_ptr,
    void *partial_coord_0_ptr,
    void *partial_coord_1_ptr,
    void *partial_coord_2_ptr,
    void *partial_coord_3_ptr,
    void *sample_points_ptr,
    void *first_linear_terms_ptr,
    void *partial_log_sizes_ptr,
    void *partial_offsets_ptr,
    void *domain_x_ptr,
    void *domain_y_ptr,
    void *dst_ptr,
    uint32_t lifting_log_size,
    uint32_t n_accumulations,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *partial_coord_0 = stwo_metal_buffer_box(partial_coord_0_ptr);
        StwoMetalBufferBox *partial_coord_1 = stwo_metal_buffer_box(partial_coord_1_ptr);
        StwoMetalBufferBox *partial_coord_2 = stwo_metal_buffer_box(partial_coord_2_ptr);
        StwoMetalBufferBox *partial_coord_3 = stwo_metal_buffer_box(partial_coord_3_ptr);
        StwoMetalBufferBox *sample_points = stwo_metal_buffer_box(sample_points_ptr);
        StwoMetalBufferBox *first_linear_terms = stwo_metal_buffer_box(first_linear_terms_ptr);
        StwoMetalBufferBox *partial_log_sizes = stwo_metal_buffer_box(partial_log_sizes_ptr);
        StwoMetalBufferBox *partial_offsets = stwo_metal_buffer_box(partial_offsets_ptr);
        StwoMetalBufferBox *domain_x = stwo_metal_buffer_box(domain_x_ptr);
        StwoMetalBufferBox *domain_y = stwo_metal_buffer_box(domain_y_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger row_count = ((NSUInteger)1) << lifting_log_size;
        if (
            partial_coord_0.len != partial_coord_1.len ||
            partial_coord_0.len != partial_coord_2.len ||
            partial_coord_0.len != partial_coord_3.len ||
            sample_points.len != ((NSUInteger)n_accumulations) * 8u ||
            first_linear_terms.len != ((NSUInteger)n_accumulations) * 4u ||
            partial_log_sizes.len != n_accumulations ||
            partial_offsets.len != n_accumulations ||
            domain_x.len != row_count ||
            domain_y.len != row_count ||
            dst.len != row_count * 4u
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Quotient combination expects four flattened partial-numerator coordinate buffers, eight sample-point limbs per accumulation, one qm31 first-linear term per accumulation, one log-size and offset per accumulation, domain x/y buffers for the lifting domain, and a packed qm31 destination.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"compute_quotients_and_combine_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:partial_coord_0.buffer offset:0 atIndex:0];
        [encoder setBuffer:partial_coord_1.buffer offset:0 atIndex:1];
        [encoder setBuffer:partial_coord_2.buffer offset:0 atIndex:2];
        [encoder setBuffer:partial_coord_3.buffer offset:0 atIndex:3];
        [encoder setBuffer:sample_points.buffer offset:0 atIndex:4];
        [encoder setBuffer:first_linear_terms.buffer offset:0 atIndex:5];
        [encoder setBuffer:partial_log_sizes.buffer offset:0 atIndex:6];
        [encoder setBuffer:partial_offsets.buffer offset:0 atIndex:7];
        [encoder setBuffer:domain_x.buffer offset:0 atIndex:8];
        [encoder setBuffer:domain_y.buffer offset:0 atIndex:9];
        [encoder setBuffer:dst.buffer offset:0 atIndex:10];
        [encoder setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:11];
        [encoder setBytes:&n_accumulations length:sizeof(n_accumulations) atIndex:12];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_compute_quotients_and_combine_packed_u32x4(
    void *runtime_ptr,
    void *partials_ptr,
    void *sample_points_ptr,
    void *first_linear_terms_ptr,
    void *partial_log_sizes_ptr,
    void *partial_offsets_ptr,
    void *domain_x_ptr,
    void *domain_y_ptr,
    void *dst_ptr,
    uint32_t lifting_log_size,
    uint32_t n_accumulations,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *partials = stwo_metal_buffer_box(partials_ptr);
        StwoMetalBufferBox *sample_points = stwo_metal_buffer_box(sample_points_ptr);
        StwoMetalBufferBox *first_linear_terms = stwo_metal_buffer_box(first_linear_terms_ptr);
        StwoMetalBufferBox *partial_log_sizes = stwo_metal_buffer_box(partial_log_sizes_ptr);
        StwoMetalBufferBox *partial_offsets = stwo_metal_buffer_box(partial_offsets_ptr);
        StwoMetalBufferBox *domain_x = stwo_metal_buffer_box(domain_x_ptr);
        StwoMetalBufferBox *domain_y = stwo_metal_buffer_box(domain_y_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger row_count = ((NSUInteger)1) << lifting_log_size;
        if (
            partials.len % 4u != 0u ||
            sample_points.len != ((NSUInteger)n_accumulations) * 8u ||
            first_linear_terms.len != ((NSUInteger)n_accumulations) * 4u ||
            partial_log_sizes.len != n_accumulations ||
            partial_offsets.len != n_accumulations ||
            domain_x.len != row_count ||
            domain_y.len != row_count ||
            dst.len != row_count * 4u
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Packed quotient combination expects one packed partial-numerator qm31 buffer, eight sample-point limbs per accumulation, one qm31 first-linear term per accumulation, one log-size and offset per accumulation, domain x/y buffers for the lifting domain, and a packed qm31 destination.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"compute_quotients_and_combine_packed_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:partials.buffer offset:0 atIndex:0];
        [encoder setBuffer:sample_points.buffer offset:0 atIndex:1];
        [encoder setBuffer:first_linear_terms.buffer offset:0 atIndex:2];
        [encoder setBuffer:partial_log_sizes.buffer offset:0 atIndex:3];
        [encoder setBuffer:partial_offsets.buffer offset:0 atIndex:4];
        [encoder setBuffer:domain_x.buffer offset:0 atIndex:5];
        [encoder setBuffer:domain_y.buffer offset:0 atIndex:6];
        [encoder setBuffer:dst.buffer offset:0 atIndex:7];
        [encoder setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:8];
        [encoder setBytes:&n_accumulations length:sizeof(n_accumulations) atIndex:9];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_compute_quotients_and_combine_indirect_packed_u32x4(
    void *runtime_ptr,
    void *const *partial_buffer_ptrs,
    void *sample_points_ptr,
    void *first_linear_terms_ptr,
    void *partial_log_sizes_ptr,
    void *partial_offsets_ptr,
    void *domain_x_ptr,
    void *domain_y_ptr,
    void *dst_ptr,
    uint32_t lifting_log_size,
    uint32_t n_accumulations,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *sample_points = stwo_metal_buffer_box(sample_points_ptr);
        StwoMetalBufferBox *first_linear_terms = stwo_metal_buffer_box(first_linear_terms_ptr);
        StwoMetalBufferBox *partial_log_sizes = stwo_metal_buffer_box(partial_log_sizes_ptr);
        StwoMetalBufferBox *partial_offsets = stwo_metal_buffer_box(partial_offsets_ptr);
        StwoMetalBufferBox *domain_x = stwo_metal_buffer_box(domain_x_ptr);
        StwoMetalBufferBox *domain_y = stwo_metal_buffer_box(domain_y_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger row_count = ((NSUInteger)1) << lifting_log_size;
        if (
            n_accumulations == 0 ||
            partial_buffer_ptrs == NULL ||
            sample_points.len != ((NSUInteger)n_accumulations) * 8u ||
            first_linear_terms.len != ((NSUInteger)n_accumulations) * 4u ||
            partial_log_sizes.len != n_accumulations ||
            partial_offsets.len != n_accumulations ||
            domain_x.len != row_count ||
            domain_y.len != row_count ||
            dst.len != row_count * 4u
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Indirect packed quotient combination expects one packed partial-numerator buffer pointer per accumulation, eight sample-point limbs per accumulation, one qm31 first-linear term per accumulation, one log-size and offset per accumulation, domain x/y buffers for the lifting domain, and a packed qm31 destination.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"compute_quotients_and_combine_indirect_packed_u32x4", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        // Build GPU address buffer: one uint64_t per accumulation.
        NSUInteger addr_buf_len = n_accumulations * sizeof(uint64_t);
        id<MTLBuffer> addr_buffer = [runtime.device
            newBufferWithLength:addr_buf_len
            options:MTLResourceStorageModeShared];
        if (addr_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to allocate GPU address buffer for indirect packed quotient combination.");
            return false;
        }
        uint64_t *addrs = (uint64_t *)addr_buffer.contents;
        for (uint32_t i = 0; i < n_accumulations; i++) {
            StwoMetalBufferBox *partial = stwo_metal_buffer_box(partial_buffer_ptrs[i]);
            addrs[i] = partial.buffer.gpuAddress;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:addr_buffer offset:0 atIndex:0];
        [encoder setBuffer:sample_points.buffer offset:0 atIndex:1];
        [encoder setBuffer:first_linear_terms.buffer offset:0 atIndex:2];
        [encoder setBuffer:partial_log_sizes.buffer offset:0 atIndex:3];
        [encoder setBuffer:partial_offsets.buffer offset:0 atIndex:4];
        [encoder setBuffer:domain_x.buffer offset:0 atIndex:5];
        [encoder setBuffer:domain_y.buffer offset:0 atIndex:6];
        [encoder setBuffer:dst.buffer offset:0 atIndex:7];
        [encoder setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:8];
        [encoder setBytes:&n_accumulations length:sizeof(n_accumulations) atIndex:9];

        // Mark all partial buffers as GPU-readable for hazard tracking.
        for (uint32_t i = 0; i < n_accumulations; i++) {
            StwoMetalBufferBox *partial = stwo_metal_buffer_box(partial_buffer_ptrs[i]);
            [encoder useResource:partial.buffer usage:MTLResourceUsageRead];
        }

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_blake2s_build_leaves_lifted_u32(
    void *runtime_ptr,
    void *flat_columns_ptr,
    void *column_offsets_ptr,
    void *column_log_sizes_ptr,
    void *dst_ptr,
    uint32_t n_columns,
    uint32_t lifting_log_size,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *flat_columns = stwo_metal_buffer_box(flat_columns_ptr);
        StwoMetalBufferBox *column_offsets = stwo_metal_buffer_box(column_offsets_ptr);
        StwoMetalBufferBox *column_log_sizes = stwo_metal_buffer_box(column_log_sizes_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger row_count = ((NSUInteger)1) << lifting_log_size;
        if (
            column_offsets.len != n_columns ||
            column_log_sizes.len != n_columns ||
            dst.len != row_count * 8u
        ) {
            stwo_metal_write_error(error_message, error_message_len, @"Lifted Blake2s leaf construction expects flattened base columns, one offset and one log-size per column, and a packed eight-word destination per lifted row.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"blake2s_build_leaves_lifted_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:flat_columns.buffer offset:0 atIndex:0];
        [encoder setBuffer:column_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:column_log_sizes.buffer offset:0 atIndex:2];
        [encoder setBuffer:dst.buffer offset:0 atIndex:3];
        [encoder setBytes:&n_columns length:sizeof(n_columns) atIndex:4];
        [encoder setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:5];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// Single-pass leaf builder using GPU virtual addresses.  Reads directly from
// original column buffers (zero copy), keeps Blake2s state in registers.
bool stwo_metal_blake2s_build_leaves_lifted_fast_u32(
    void *runtime_ptr,
    void *const *column_buffers_ptr,
    void *dst_ptr,
    const uint32_t *column_log_sizes,
    uint32_t n_columns,
    uint32_t lifting_log_size,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger row_count = ((NSUInteger)1) << lifting_log_size;

        if (n_columns == 0 || dst.len != row_count * 8u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Fast lifted Blake2s leaf construction: invalid arguments.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime, @"blake2s_build_leaves_lifted_fast_u32",
            error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        // Build GPU address buffer and column log sizes buffer from pool.
        StwoMetalBufferPool *pool = [StwoMetalBufferPool sharedPoolForDevice:runtime.device];
        NSUInteger addr_buf_len = n_columns * sizeof(uint64_t);
        id<MTLBuffer> addr_buffer = [pool acquireWithByteSize:addr_buf_len];
        if (addr_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to allocate GPU address buffer.");
            return false;
        }
        uint64_t *addrs = (uint64_t *)addr_buffer.contents;
        for (uint32_t i = 0; i < n_columns; i++) {
            StwoMetalBufferBox *col = stwo_metal_buffer_box(column_buffers_ptr[i]);
            addrs[i] = col.buffer.gpuAddress;
        }

        NSUInteger log_sizes_buf_len = n_columns * sizeof(uint32_t);
        id<MTLBuffer> log_sizes_buffer = [pool acquireWithByteSize:log_sizes_buf_len];
        if (log_sizes_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to allocate log sizes buffer.");
            [pool returnBuffer:addr_buffer];
            return false;
        }
        memcpy(log_sizes_buffer.contents, column_log_sizes,
               n_columns * sizeof(uint32_t));

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            [pool returnBuffer:addr_buffer];
            [pool returnBuffer:log_sizes_buffer];
            return false;
        }

        id<MTLComputeCommandEncoder> encoder =
            [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            [pool returnBuffer:addr_buffer];
            [pool returnBuffer:log_sizes_buffer];
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:addr_buffer offset:0 atIndex:0];
        [encoder setBuffer:log_sizes_buffer offset:0 atIndex:1];
        [encoder setBuffer:dst.buffer offset:0 atIndex:2];
        [encoder setBytes:&n_columns length:sizeof(n_columns) atIndex:3];
        [encoder setBytes:&lifting_log_size
                   length:sizeof(lifting_log_size) atIndex:4];

        // Mark all column buffers as GPU-readable so the command buffer
        // tracks hazards correctly.
        for (uint32_t i = 0; i < n_columns; i++) {
            StwoMetalBufferBox *col =
                stwo_metal_buffer_box(column_buffers_ptr[i]);
            [encoder useResource:col.buffer usage:MTLResourceUsageRead];
        }

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size
            threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];
        [pool returnBuffer:addr_buffer];
        [pool returnBuffer:log_sizes_buffer];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_blake2s_build_leaves_lifted_wide_chunk_u32(
    void *runtime_ptr,
    void *const *column_buffers_ptr,
    void *state_ptr,
    void *dst_ptr,
    const uint32_t *column_log_sizes,
    uint32_t n_columns,
    uint32_t lifting_log_size,
    uint32_t processed_bytes_before,
    uint32_t is_first_chunk,
    uint32_t is_final_chunk,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        if (n_columns == 0 || n_columns > 16u) {
            stwo_metal_write_error(error_message, error_message_len, @"Wide lifted Blake2s chunking requires between one and sixteen source columns per dispatch.");
            return false;
        }
        if (column_buffers_ptr == NULL || column_log_sizes == NULL) {
            stwo_metal_write_error(error_message, error_message_len, @"Wide lifted Blake2s chunking requires source-column buffers and per-column log sizes.");
            return false;
        }

        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *state = stwo_metal_buffer_box(state_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger row_count = ((NSUInteger)1) << lifting_log_size;
        if (state.len != row_count * 8u || dst.len != row_count * 8u) {
            stwo_metal_write_error(error_message, error_message_len, @"Wide lifted Blake2s chunking expects state and destination buffers with eight words per lifted row.");
            return false;
        }

        StwoMetalBufferBox *column_boxes[16] = { nil };
        for (uint32_t i = 0; i < n_columns; ++i) {
            if (column_buffers_ptr[i] == NULL) {
                stwo_metal_write_error(error_message, error_message_len, @"Wide lifted Blake2s chunking received a null source column buffer.");
                return false;
            }
            column_boxes[i] = stwo_metal_buffer_box(column_buffers_ptr[i]);
            NSUInteger expected_len = ((NSUInteger)1) << column_log_sizes[i];
            if (column_boxes[i].len != expected_len || column_log_sizes[i] > lifting_log_size) {
                stwo_metal_write_error(error_message, error_message_len, @"Wide lifted Blake2s chunking requires each source column length to match its log size and not exceed the lifting size.");
                return false;
            }
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"blake2s_build_leaves_lifted_wide_chunk_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        for (uint32_t i = 0; i < 16u; ++i) {
            id<MTLBuffer> buffer = i < n_columns ? column_boxes[i].buffer : nil;
            [encoder setBuffer:buffer offset:0 atIndex:i];
        }
        [encoder setBuffer:state.buffer offset:0 atIndex:16];
        [encoder setBuffer:dst.buffer offset:0 atIndex:17];
        [encoder setBytes:column_log_sizes length:n_columns * sizeof(uint32_t) atIndex:18];
        [encoder setBytes:&n_columns length:sizeof(n_columns) atIndex:19];
        [encoder setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:20];
        [encoder setBytes:&processed_bytes_before length:sizeof(processed_bytes_before) atIndex:21];
        [encoder setBytes:&is_first_chunk length:sizeof(is_first_chunk) atIndex:22];
        [encoder setBytes:&is_final_chunk length:sizeof(is_final_chunk) atIndex:23];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

/// Batched wide leaf builder: all column chunks in ONE command buffer.
/// Eliminates N-1 waitUntilCompleted round-trips for N chunks.
bool stwo_metal_blake2s_build_leaves_lifted_wide_batched_u32(
    void *runtime_ptr,
    void *const *all_column_buffers_ptr,
    void *state_ptr,
    void *dst_ptr,
    const uint32_t *all_column_log_sizes,
    uint32_t total_columns,
    uint32_t lifting_log_size,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        if (total_columns == 0) {
            return true;
        }

        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *state = stwo_metal_buffer_box(state_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        NSUInteger row_count = ((NSUInteger)1) << lifting_log_size;

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"blake2s_build_leaves_lifted_wide_chunk_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);

        uint32_t n_chunks = (total_columns + 15u) / 16u;
        uint32_t processed_bytes_before = 0;

        for (uint32_t chunk_index = 0; chunk_index < n_chunks; ++chunk_index) {
            uint32_t chunk_start = chunk_index * 16u;
            uint32_t chunk_n = total_columns - chunk_start;
            if (chunk_n > 16u) chunk_n = 16u;
            uint32_t is_first_chunk = (chunk_index == 0) ? 1u : 0u;
            uint32_t is_final_chunk = (chunk_index + 1 == n_chunks) ? 1u : 0u;

            StwoMetalBufferBox *column_boxes[16] = { nil };
            for (uint32_t i = 0; i < chunk_n; ++i) {
                column_boxes[i] = stwo_metal_buffer_box(all_column_buffers_ptr[chunk_start + i]);
            }

            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                return false;
            }

            [encoder setComputePipelineState:pipeline];
            for (uint32_t i = 0; i < 16u; ++i) {
                id<MTLBuffer> buffer = i < chunk_n ? column_boxes[i].buffer : nil;
                [encoder setBuffer:buffer offset:0 atIndex:i];
            }
            [encoder setBuffer:state.buffer offset:0 atIndex:16];
            [encoder setBuffer:dst.buffer offset:0 atIndex:17];
            [encoder setBytes:&all_column_log_sizes[chunk_start] length:chunk_n * sizeof(uint32_t) atIndex:18];
            [encoder setBytes:&chunk_n length:sizeof(chunk_n) atIndex:19];
            [encoder setBytes:&lifting_log_size length:sizeof(lifting_log_size) atIndex:20];
            [encoder setBytes:&processed_bytes_before length:sizeof(processed_bytes_before) atIndex:21];
            [encoder setBytes:&is_first_chunk length:sizeof(is_first_chunk) atIndex:22];
            [encoder setBytes:&is_final_chunk length:sizeof(is_final_chunk) atIndex:23];

            [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
            [encoder endEncoding];

            processed_bytes_before += chunk_n * 4u;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_blake2s_build_next_layer_u32(
    void *runtime_ptr,
    void *prev_layer_ptr,
    void *dst_ptr,
    uint32_t next_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *prev_layer = stwo_metal_buffer_box(prev_layer_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);
        if (prev_layer.len != ((NSUInteger)next_len) * 16u || dst.len != ((NSUInteger)next_len) * 8u) {
            stwo_metal_write_error(error_message, error_message_len, @"Blake2s next-layer hashing expects sixteen packed words per parent input row and eight packed words per output row.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(runtime, @"blake2s_build_next_layer_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:prev_layer.buffer offset:0 atIndex:0];
        [encoder setBuffer:dst.buffer offset:0 atIndex:1];
        [encoder setBytes:&next_len length:sizeof(next_len) atIndex:2];

        MTLSize grid_size = MTLSizeMake(next_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_blake2s_build_merkle_layers_u32(
    void *runtime_ptr,
    void *leaf_layer_ptr,
    void *const *layer_ptrs,
    uint32_t leaf_log_size,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *src_layer = stwo_metal_buffer_box(leaf_layer_ptr);
        if (src_layer.len != (((NSUInteger)1u) << leaf_log_size) * 8u) {
            stwo_metal_write_error(error_message, error_message_len, @"Packed Blake2s leaf layers must contain eight words per leaf hash.");
            return false;
        }
        if (leaf_log_size > 0u && layer_ptrs == NULL) {
            stwo_metal_write_error(error_message, error_message_len, @"Merkle-layer output pointers must be present when upper layers are requested.");
            return false;
        }

        id<MTLComputePipelineState> pipeline =
            stwo_metal_pipeline(runtime, @"blake2s_build_next_layer_u32", error_message, error_message_len);
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        uint32_t next_len = ((uint32_t)1u) << leaf_log_size;
        for (uint32_t layer_index = 0u; layer_index < leaf_log_size; ++layer_index) {
            next_len >>= 1u;
            StwoMetalBufferBox *dst_layer = stwo_metal_buffer_box(layer_ptrs[layer_index]);
            if (dst_layer.len != ((NSUInteger)next_len) * 8u) {
                stwo_metal_write_error(error_message, error_message_len, @"Packed Blake2s parent layers must contain eight words per hash.");
                return false;
            }

            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
                return false;
            }

            [encoder setComputePipelineState:pipeline];
            [encoder setBuffer:src_layer.buffer offset:0 atIndex:0];
            [encoder setBuffer:dst_layer.buffer offset:0 atIndex:1];
            [encoder setBytes:&next_len length:sizeof(next_len) atIndex:2];

            MTLSize grid_size = MTLSizeMake(next_len, 1, 1);
            MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
            [encoder endEncoding];

            src_layer = dst_layer;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// Fused leaf-build + layer-build in a single command buffer.
// Eliminates the CPU round-trip (waitUntilCompleted) between the two phases,
// letting Metal pipeline the leaf→layer GPU transition.
bool stwo_metal_blake2s_build_merkle_tree_fast_u32(
    void *runtime_ptr,
    void *const *column_buffers_ptr,
    void *leaf_layer_ptr,
    void *const *layer_ptrs,
    const uint32_t *column_log_sizes,
    uint32_t n_columns,
    uint32_t lifting_log_size,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *leaf_dst = stwo_metal_buffer_box(leaf_layer_ptr);
        NSUInteger row_count = ((NSUInteger)1) << lifting_log_size;

        if (n_columns == 0 || leaf_dst.len != row_count * 8u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Fused Merkle tree: invalid arguments.");
            return false;
        }

        // --- Pipeline states ---
        id<MTLComputePipelineState> leaf_pipeline = stwo_metal_pipeline(
            runtime, @"blake2s_build_leaves_lifted_fast_u32",
            error_message, error_message_len);
        if (leaf_pipeline == nil) return false;

        id<MTLComputePipelineState> layer_pipeline = stwo_metal_pipeline(
            runtime, @"blake2s_build_next_layer_u32",
            error_message, error_message_len);
        if (layer_pipeline == nil) return false;

        // --- GPU address buffer and log sizes buffer from pool ---
        StwoMetalBufferPool *pool = [StwoMetalBufferPool sharedPoolForDevice:runtime.device];
        NSUInteger addr_buf_len = n_columns * sizeof(uint64_t);
        id<MTLBuffer> addr_buffer = [pool acquireWithByteSize:addr_buf_len];
        if (addr_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to allocate GPU address buffer.");
            return false;
        }
        uint64_t *addrs = (uint64_t *)addr_buffer.contents;
        for (uint32_t i = 0; i < n_columns; i++) {
            StwoMetalBufferBox *col = stwo_metal_buffer_box(column_buffers_ptr[i]);
            addrs[i] = col.buffer.gpuAddress;
        }

        NSUInteger log_sizes_buf_len = n_columns * sizeof(uint32_t);
        id<MTLBuffer> log_sizes_buffer = [pool acquireWithByteSize:log_sizes_buf_len];
        if (log_sizes_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to allocate log sizes buffer.");
            [pool returnBuffer:addr_buffer];
            return false;
        }
        memcpy(log_sizes_buffer.contents, column_log_sizes,
               n_columns * sizeof(uint32_t));

        // --- Single command buffer for the entire tree ---
        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        // --- Encoder 1: Leaf building ---
        {
            id<MTLComputeCommandEncoder> encoder =
                [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len,
                    @"Failed to create leaf compute encoder.");
                return false;
            }

            [encoder setComputePipelineState:leaf_pipeline];
            [encoder setBuffer:addr_buffer offset:0 atIndex:0];
            [encoder setBuffer:log_sizes_buffer offset:0 atIndex:1];
            [encoder setBuffer:leaf_dst.buffer offset:0 atIndex:2];
            [encoder setBytes:&n_columns length:sizeof(n_columns) atIndex:3];
            [encoder setBytes:&lifting_log_size
                       length:sizeof(lifting_log_size) atIndex:4];

            for (uint32_t i = 0; i < n_columns; i++) {
                StwoMetalBufferBox *col =
                    stwo_metal_buffer_box(column_buffers_ptr[i]);
                [encoder useResource:col.buffer usage:MTLResourceUsageRead];
            }

            MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
            MTLSize threadgroup_size = MTLSizeMake(
                stwo_metal_threads_per_group(leaf_pipeline), 1, 1);
            [encoder dispatchThreads:grid_size
                threadsPerThreadgroup:threadgroup_size];
            [encoder endEncoding];
        }

        // --- Encoders 2..N+1: Layer building (same command buffer) ---
        StwoMetalBufferBox *src_layer = leaf_dst;
        uint32_t next_len = ((uint32_t)1u) << lifting_log_size;
        for (uint32_t layer_index = 0u; layer_index < lifting_log_size; ++layer_index) {
            next_len >>= 1u;
            StwoMetalBufferBox *dst_layer = stwo_metal_buffer_box(layer_ptrs[layer_index]);

            id<MTLComputeCommandEncoder> encoder =
                [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len,
                    @"Failed to create layer compute encoder.");
                return false;
            }

            [encoder setComputePipelineState:layer_pipeline];
            [encoder setBuffer:src_layer.buffer offset:0 atIndex:0];
            [encoder setBuffer:dst_layer.buffer offset:0 atIndex:1];
            [encoder setBytes:&next_len length:sizeof(next_len) atIndex:2];

            MTLSize grid_size = MTLSizeMake(next_len, 1, 1);
            MTLSize threadgroup_size = MTLSizeMake(
                stwo_metal_threads_per_group(layer_pipeline), 1, 1);
            [encoder dispatchThreads:grid_size
                threadsPerThreadgroup:threadgroup_size];
            [encoder endEncoding];

            src_layer = dst_layer;
        }

        // --- Single commit + wait for entire tree ---
        [command_buffer commit];
        [command_buffer waitUntilCompleted];
        [pool returnBuffer:addr_buffer];
        [pool returnBuffer:log_sizes_buffer];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_generate_wide_fibonacci_trace_u32(
    void *runtime_ptr,
    void *input_a_ptr,
    void *input_b_ptr,
    void *trace_ptr,
    uint32_t input_log_len,
    uint32_t n_columns,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *input_a = stwo_metal_buffer_box(input_a_ptr);
        StwoMetalBufferBox *input_b = stwo_metal_buffer_box(input_b_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);
        uint32_t input_len_u32 = ((uint32_t)1) << input_log_len;
        NSUInteger input_len = (NSUInteger)input_len_u32;
        NSUInteger trace_len = input_len * (NSUInteger)n_columns;
        if (n_columns < 2u) {
            stwo_metal_write_error(error_message, error_message_len, @"Wide-fibonacci trace generation requires at least two columns.");
            return false;
        }
        if (input_a.len != input_len || input_b.len != input_len || trace.len != trace_len) {
            stwo_metal_write_error(error_message, error_message_len, @"Wide-fibonacci trace generation expects equal power-of-two inputs and a contiguous column-major output buffer.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"generate_wide_fibonacci_trace_u32",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:input_a.buffer offset:0 atIndex:0];
        [encoder setBuffer:input_b.buffer offset:0 atIndex:1];
        [encoder setBuffer:trace.buffer offset:0 atIndex:2];
        [encoder setBytes:&input_len_u32 length:sizeof(input_len_u32) atIndex:3];
        [encoder setBytes:&n_columns length:sizeof(n_columns) atIndex:4];

        MTLSize grid_size = MTLSizeMake(input_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len, command_buffer.error.localizedDescription ?: @"Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// JIT-compiled V1 evaluation kernel dispatch
// ---------------------------------------------------------------------------

bool stwo_metal_eval_compiled_program_v1_u32x4(
    void *runtime_ptr,
    const char *shader_source,
    size_t shader_source_len,
    const char *kernel_name,
    size_t kernel_name_len,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *dst_ptr,
    uint32_t row_count,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        NSString *nameStr = [[NSString alloc] initWithBytes:kernel_name
                                                     length:kernel_name_len
                                                   encoding:NSUTF8StringEncoding];
        NSString *sourceStr = [[NSString alloc] initWithBytes:shader_source
                                                       length:shader_source_len
                                                     encoding:NSUTF8StringEncoding];

        id<MTLComputePipelineState> pipeline = stwo_metal_jit_pipeline_cached(
            runtime, sourceStr, nameStr, 0, error_message, error_message_len);
        if (pipeline == nil) return false;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription ?: @"JIT-compiled kernel execution failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// JIT-compiled V1 fused composition kernel dispatch
// ---------------------------------------------------------------------------
//
// Evaluates the constraint program AND applies denom_inv multiplication AND
// writes output directly to 4 coordinate buffers.  This eliminates the
// GPU->CPU->GPU round-trip in the composition pipeline.

bool stwo_metal_eval_compiled_fused_composition_v1(
    void *runtime_ptr,
    const char *shader_source,
    size_t shader_source_len,
    const char *kernel_name,
    size_t kernel_name_len,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *denom_inv_ptr,
    void *coord_0_ptr,
    void *coord_1_ptr,
    void *coord_2_ptr,
    void *coord_3_ptr,
    uint32_t row_count,
    uint32_t log_n_rows,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *denom_inv = stwo_metal_buffer_box(denom_inv_ptr);
        StwoMetalBufferBox *coord_0 = stwo_metal_buffer_box(coord_0_ptr);
        StwoMetalBufferBox *coord_1 = stwo_metal_buffer_box(coord_1_ptr);
        StwoMetalBufferBox *coord_2 = stwo_metal_buffer_box(coord_2_ptr);
        StwoMetalBufferBox *coord_3 = stwo_metal_buffer_box(coord_3_ptr);

        NSString *nameStr = [[NSString alloc] initWithBytes:kernel_name
                                                     length:kernel_name_len
                                                   encoding:NSUTF8StringEncoding];
        NSString *sourceStr = [[NSString alloc] initWithBytes:shader_source
                                                       length:shader_source_len
                                                     encoding:NSUTF8StringEncoding];

        id<MTLComputePipelineState> pipeline = stwo_metal_jit_pipeline_cached(
            runtime, sourceStr, nameStr, 0, error_message, error_message_len);
        if (pipeline == nil) return false;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:denom_inv.buffer offset:0 atIndex:6];
        [encoder setBuffer:coord_0.buffer offset:0 atIndex:7];
        [encoder setBuffer:coord_1.buffer offset:0 atIndex:8];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];
        [encoder setBuffer:coord_2.buffer offset:0 atIndex:11];
        [encoder setBuffer:coord_3.buffer offset:0 atIndex:12];
        [encoder setBytes:&log_n_rows length:sizeof(log_n_rows) atIndex:13];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription ?: @"Fused composition kernel execution failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// JIT-compiled V1 evaluation kernel dispatch — threadgroup size variant
// ---------------------------------------------------------------------------

bool stwo_metal_eval_compiled_program_v1_u32x4_tg(
    void *runtime_ptr,
    const char *shader_source,
    size_t shader_source_len,
    const char *kernel_name,
    size_t kernel_name_len,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *dst_ptr,
    uint32_t row_count,
    uint32_t threads_per_group,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        NSString *nameStr = [[NSString alloc] initWithBytes:kernel_name
                                                     length:kernel_name_len
                                                   encoding:NSUTF8StringEncoding];

        NSString *sourceStr = [[NSString alloc] initWithBytes:shader_source
                                                       length:shader_source_len
                                                     encoding:NSUTF8StringEncoding];

        id<MTLComputePipelineState> pipeline = stwo_metal_jit_pipeline_cached(
            runtime, sourceStr, nameStr, threads_per_group, error_message, error_message_len);
        if (pipeline == nil) return false;

        NSUInteger tg_size = (threads_per_group > 0)
            ? (NSUInteger)threads_per_group
            : stwo_metal_threads_per_group(pipeline);

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(tg_size, 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription ?: @"JIT-compiled kernel execution failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// JIT-compiled V1 evaluation kernel dispatch — async (non-blocking) variant
// ---------------------------------------------------------------------------
//
// Like stwo_metal_eval_compiled_program_v1_u32x4 but returns immediately after
// committing the command buffer. The caller must wait (or release) the returned
// handle via stwo_metal_command_buffer_wait / stwo_metal_command_buffer_release
// before reading dst buffer contents.
//
// Returns true and stores a retained command-buffer handle in *out_handle on
// success. Returns false (and writes an error message) on any setup failure.

bool stwo_metal_eval_compiled_program_v1_u32x4_async(
    void *runtime_ptr,
    const char *shader_source,
    size_t shader_source_len,
    const char *kernel_name,
    size_t kernel_name_len,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *dst_ptr,
    uint32_t row_count,
    void **out_handle,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        NSString *nameStr = [[NSString alloc] initWithBytes:kernel_name
                                                     length:kernel_name_len
                                                   encoding:NSUTF8StringEncoding];
        NSString *sourceStr = [[NSString alloc] initWithBytes:shader_source
                                                       length:shader_source_len
                                                     encoding:NSUTF8StringEncoding];

        id<MTLComputePipelineState> pipeline = stwo_metal_jit_pipeline_cached(
            runtime, sourceStr, nameStr, 0, error_message, error_message_len);
        if (pipeline == nil) return false;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len, @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        // Do NOT waitUntilCompleted — return the handle for deferred waiting.
        *out_handle = (__bridge_retained void *)command_buffer;
        return true;
    }
}

// ---------------------------------------------------------------------------
// Fused blit+compute dispatch for JIT-compiled V1 evaluation kernels (async)
// ---------------------------------------------------------------------------
//
// Combines GPU-side buffer concatenation (via blit encoder) with the JIT
// compute kernel dispatch into a single command buffer.  This eliminates
// the CPU memmove bottleneck in the GPU pass-through path: instead of
// sequentially memmove-ing each column into a flat buffer on the CPU,
// the GPU's DMA engine performs the copies in parallel.
//
// column_buffers:   array of MTLBuffer pointers (one per column).
// column_lengths:   array of element counts for each column (should all be n_rows).
// n_columns:        total number of column buffers.
// interaction_offsets_ptr: pre-built interaction offsets buffer.
// random_coeff_powers_ptr: pre-built random coefficient powers buffer.
// dst_ptr:          output buffer (n_rows * 4 elements).
// row_count:        number of rows in each column.
// out_handle:       receives the retained command buffer handle on success.

bool stwo_metal_eval_compiled_fused_blit_async(
    void *runtime_ptr,
    const char *shader_source,
    size_t shader_source_len,
    const char *kernel_name,
    size_t kernel_name_len,
    void **column_buffer_ptrs,
    const size_t *column_lengths,
    size_t n_columns,
    void *interaction_offsets_ptr,
    void *random_coeff_powers_ptr,
    void *dst_ptr,
    uint32_t row_count,
    void **out_handle,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        NSString *nameStr = [[NSString alloc] initWithBytes:kernel_name
                                                     length:kernel_name_len
                                                   encoding:NSUTF8StringEncoding];
        NSString *sourceStr = [[NSString alloc] initWithBytes:shader_source
                                                       length:shader_source_len
                                                     encoding:NSUTF8StringEncoding];

        id<MTLComputePipelineState> pipeline = stwo_metal_jit_pipeline_cached(
            runtime, sourceStr, nameStr, 0, error_message, error_message_len);
        if (pipeline == nil) return false;

        // Allocate the flat trace buffer on GPU (uninitialized — blit will fill it).
        size_t total_elements = (size_t)n_columns * (size_t)row_count;
        id<MTLBuffer> trace_buffer = [runtime.device newBufferWithLength:total_elements * sizeof(uint32_t)
                                                                options:MTLResourceStorageModePrivate];
        if (trace_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to allocate flat trace buffer for fused blit+compute.");
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer for fused blit+compute.");
            return false;
        }

        // Phase 1: Blit encoder — copy each column into the flat trace buffer.
        id<MTLBlitCommandEncoder> blit = [command_buffer blitCommandEncoder];
        if (blit == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal blit encoder.");
            return false;
        }

        size_t dst_byte_offset = 0;
        for (size_t i = 0; i < n_columns; ++i) {
            StwoMetalBufferBox *col = stwo_metal_buffer_box(column_buffer_ptrs[i]);
            size_t col_bytes = column_lengths[i] * sizeof(uint32_t);
            [blit copyFromBuffer:col.buffer
                    sourceOffset:0
                        toBuffer:trace_buffer
               destinationOffset:dst_byte_offset
                            size:col_bytes];
            dst_byte_offset += col_bytes;
        }
        [blit endEncoding];

        // Phase 2: Compute encoder — dispatch the JIT kernel.
        // Metal guarantees sequential execution within a command buffer,
        // so the compute encoder will see the blit results without explicit barriers.
        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder for fused dispatch.");
            return false;
        }

        // Create empty placeholder buffers for preprocessed/base_params/ext_params
        // (the GPU pass-through path doesn't use them).
        id<MTLBuffer> empty_buf = [runtime.device newBufferWithLength:sizeof(uint32_t)
                                                              options:MTLResourceStorageModeShared];
        memset(empty_buf.contents, 0, sizeof(uint32_t));

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:empty_buf offset:0 atIndex:2]; // preprocessed_values
        [encoder setBuffer:empty_buf offset:0 atIndex:3]; // base_params
        [encoder setBuffer:empty_buf offset:0 atIndex:4]; // ext_params
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        // Do NOT waitUntilCompleted — return the handle for deferred waiting.
        *out_handle = (__bridge_retained void *)command_buffer;
        return true;
    }
}

// ---------------------------------------------------------------------------
// Batched command buffer: create + encode + commit
// ---------------------------------------------------------------------------
//
// These three functions allow the Rust side to batch multiple JIT-compiled
// component dispatches into a single Metal command buffer.  Instead of N
// separate command buffers (one per component), the caller:
//   1. Creates one command buffer via stwo_metal_command_buffer_create.
//   2. Encodes N compute dispatches via stwo_metal_encode_compiled_program_v1.
//   3. Commits the buffer via stwo_metal_command_buffer_commit (non-blocking).
//   4. Waits once via the existing stwo_metal_command_buffer_wait.
//
// Within a single command buffer Metal guarantees sequential execution of
// encoders, but can pipeline resource preparation, reducing per-dispatch
// scheduling overhead.

/// Create an uncommitted MTLCommandBuffer.  Returns a retained handle.
void *stwo_metal_command_buffer_create(
    void *runtime_ptr,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        id<MTLCommandBuffer> cb = [runtime.queue commandBuffer];
        if (cb == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer for batched dispatch.");
            return NULL;
        }
        return (__bridge_retained void *)cb;
    }
}

/// Encode one JIT-compiled V1 evaluation kernel dispatch into an existing
/// (uncommitted) command buffer.  Does NOT commit.
bool stwo_metal_encode_compiled_program_v1(
    void *runtime_ptr,
    void *command_buffer_ptr,
    const char *shader_source,
    size_t shader_source_len,
    const char *kernel_name,
    size_t kernel_name_len,
    void *trace_values_ptr,
    void *interaction_offsets_ptr,
    void *preprocessed_values_ptr,
    void *base_params_ptr,
    void *ext_params_ptr,
    void *random_coeff_powers_ptr,
    void *dst_ptr,
    uint32_t row_count,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        id<MTLCommandBuffer> command_buffer = (__bridge id<MTLCommandBuffer>)command_buffer_ptr;
        StwoMetalBufferBox *trace_values = stwo_metal_buffer_box(trace_values_ptr);
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *preprocessed_values = stwo_metal_buffer_box(preprocessed_values_ptr);
        StwoMetalBufferBox *base_params = stwo_metal_buffer_box(base_params_ptr);
        StwoMetalBufferBox *ext_params = stwo_metal_buffer_box(ext_params_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        NSString *nameStr = [[NSString alloc] initWithBytes:kernel_name
                                                     length:kernel_name_len
                                                   encoding:NSUTF8StringEncoding];
        NSString *sourceStr = [[NSString alloc] initWithBytes:shader_source
                                                       length:shader_source_len
                                                     encoding:NSUTF8StringEncoding];

        id<MTLComputePipelineState> pipeline = stwo_metal_jit_pipeline_cached(
            runtime, sourceStr, nameStr, 0, error_message, error_message_len);
        if (pipeline == nil) return false;

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder for batched dispatch.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:preprocessed_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:base_params.buffer offset:0 atIndex:3];
        [encoder setBuffer:ext_params.buffer offset:0 atIndex:4];
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        return true;
    }
}

/// Encode one fused blit+compute dispatch into an existing (uncommitted)
/// command buffer.  Does NOT commit.
bool stwo_metal_encode_compiled_fused_blit_v1(
    void *runtime_ptr,
    void *command_buffer_ptr,
    const char *shader_source,
    size_t shader_source_len,
    const char *kernel_name,
    size_t kernel_name_len,
    void **column_buffer_ptrs,
    const size_t *column_lengths,
    size_t n_columns,
    void *interaction_offsets_ptr,
    void *random_coeff_powers_ptr,
    void *dst_ptr,
    uint32_t row_count,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        id<MTLCommandBuffer> command_buffer = (__bridge id<MTLCommandBuffer>)command_buffer_ptr;
        StwoMetalBufferBox *interaction_offsets = stwo_metal_buffer_box(interaction_offsets_ptr);
        StwoMetalBufferBox *random_coeff_powers = stwo_metal_buffer_box(random_coeff_powers_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        NSString *nameStr = [[NSString alloc] initWithBytes:kernel_name
                                                     length:kernel_name_len
                                                   encoding:NSUTF8StringEncoding];
        NSString *sourceStr = [[NSString alloc] initWithBytes:shader_source
                                                       length:shader_source_len
                                                     encoding:NSUTF8StringEncoding];

        id<MTLComputePipelineState> pipeline = stwo_metal_jit_pipeline_cached(
            runtime, sourceStr, nameStr, 0, error_message, error_message_len);
        if (pipeline == nil) return false;

        // Allocate flat trace buffer on GPU.
        size_t total_elements = (size_t)n_columns * (size_t)row_count;
        id<MTLBuffer> trace_buffer = [runtime.device newBufferWithLength:total_elements * sizeof(uint32_t)
                                                                options:MTLResourceStorageModePrivate];
        if (trace_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to allocate flat trace buffer for batch fused blit+compute.");
            return false;
        }

        // Phase 1: Blit encoder — copy columns into flat trace buffer.
        id<MTLBlitCommandEncoder> blit = [command_buffer blitCommandEncoder];
        if (blit == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal blit encoder (batch fused).");
            return false;
        }

        size_t dst_byte_offset = 0;
        for (size_t i = 0; i < n_columns; ++i) {
            StwoMetalBufferBox *col = stwo_metal_buffer_box(column_buffer_ptrs[i]);
            size_t col_bytes = column_lengths[i] * sizeof(uint32_t);
            [blit copyFromBuffer:col.buffer
                    sourceOffset:0
                        toBuffer:trace_buffer
               destinationOffset:dst_byte_offset
                            size:col_bytes];
            dst_byte_offset += col_bytes;
        }
        [blit endEncoding];

        // Phase 2: Compute encoder.
        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder for batch fused dispatch.");
            return false;
        }

        id<MTLBuffer> empty_buf = [runtime.device newBufferWithLength:sizeof(uint32_t)
                                                              options:MTLResourceStorageModeShared];
        memset(empty_buf.contents, 0, sizeof(uint32_t));

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_buffer offset:0 atIndex:0];
        [encoder setBuffer:interaction_offsets.buffer offset:0 atIndex:1];
        [encoder setBuffer:empty_buf offset:0 atIndex:2]; // preprocessed_values
        [encoder setBuffer:empty_buf offset:0 atIndex:3]; // base_params
        [encoder setBuffer:empty_buf offset:0 atIndex:4]; // ext_params
        [encoder setBuffer:random_coeff_powers.buffer offset:0 atIndex:5];
        [encoder setBuffer:dst.buffer offset:0 atIndex:9];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:10];

        MTLSize grid_size = MTLSizeMake(row_count, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        return true;
    }
}

/// Commit a command buffer (non-blocking).  The caller must wait on the
/// original retained handle via stwo_metal_command_buffer_wait.
void stwo_metal_command_buffer_commit(void *command_buffer_ptr) {
    if (command_buffer_ptr == NULL) {
        return;
    }
    @autoreleasepool {
        id<MTLCommandBuffer> cb = (__bridge id<MTLCommandBuffer>)command_buffer_ptr;
        [cb commit];
    }
}

// ---------------------------------------------------------------------------
// GPU Blake2s PoW grind
// ---------------------------------------------------------------------------
//
// Dispatches the `blake2s_grind` Metal kernel to search for the smallest nonce
// whose Blake2s hash has at least `pow_bits` trailing zeros.
//
// prefix_digest: 8 x uint32 — the Blake2s hash of (POW_PREFIX || [0;12] || digest || pow_bits).
// pow_bits: required trailing zeros.
// nonce_hi: the high 32 bits of the nonce (iterated on the CPU side).
// batch_size: number of nonce_lo candidates to try (threads dispatched).
// out_nonce_lo: on success, receives the smallest nonce_lo found; UINT32_MAX if none found.
//
// Returns true on success (even if no nonce was found), false on Metal error.
bool stwo_metal_blake2s_grind_batch(
    void *runtime_ptr,
    const uint32_t *prefix_digest,
    uint32_t pow_bits,
    uint32_t nonce_hi,
    uint32_t batch_size,
    uint32_t *out_nonce_lo,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime, @"blake2s_grind", error_message, error_message_len
        );
        if (pipeline == nil) return false;

        // Acquire result buffer from pool (1 x uint32, initialized to UINT32_MAX).
        StwoMetalBufferPool *pool = [StwoMetalBufferPool sharedPoolForDevice:runtime.device];
        id<MTLBuffer> result_buffer = [pool acquireWithByteSize:sizeof(uint32_t)];
        if (result_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"blake2s_grind: failed to allocate result buffer.");
            return false;
        }
        ((uint32_t *)result_buffer.contents)[0] = UINT32_MAX;

        // Pack params: [pow_bits, nonce_hi].
        uint32_t params[2] = { pow_bits, nonce_hi };

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];

        [encoder setComputePipelineState:pipeline];
        [encoder setBytes:prefix_digest length:sizeof(uint32_t) * 8 atIndex:0];
        [encoder setBytes:params length:sizeof(params) atIndex:1];
        [encoder setBuffer:result_buffer offset:0 atIndex:2];

        MTLSize grid_size = MTLSizeMake(batch_size, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1
        );
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription ?: @"blake2s_grind kernel failed.");
            return false;
        }

        *out_nonce_lo = ((uint32_t *)result_buffer.contents)[0];
        [pool returnBuffer:result_buffer];
        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: memory_id_to_big trace (big values)
// ---------------------------------------------------------------------------

bool stwo_metal_witness_memory_id_to_big_trace(
    void *runtime_ptr,
    void *big_values_ptr,
    void *mults_ptr,
    void *trace_ptr,
    uint32_t n_values,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *big_values = stwo_metal_buffer_box(big_values_ptr);
        StwoMetalBufferBox *mults = stwo_metal_buffer_box(mults_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        // Validate buffer sizes.
        if (big_values.len != (NSUInteger)n_values * 8u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_id_to_big: big_values buffer length mismatch.");
            return false;
        }
        if (mults.len != (NSUInteger)n_values) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_id_to_big: mults buffer length mismatch.");
            return false;
        }
        // 29 columns * column_length
        NSUInteger expected_trace_len = (NSUInteger)29u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_id_to_big: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_memory_id_to_big_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:big_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:mults.buffer offset:0 atIndex:1];
        [encoder setBuffer:trace.buffer offset:0 atIndex:2];
        [encoder setBytes:&n_values length:sizeof(n_values) atIndex:3];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:4];

        MTLSize grid_size = MTLSizeMake((NSUInteger)column_length, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_memory_id_to_big_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: memory_id_to_big trace (small values)
// ---------------------------------------------------------------------------

bool stwo_metal_witness_memory_id_to_big_small_trace(
    void *runtime_ptr,
    void *small_values_ptr,
    void *mults_ptr,
    void *trace_ptr,
    uint32_t n_values,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *small_values = stwo_metal_buffer_box(small_values_ptr);
        StwoMetalBufferBox *mults = stwo_metal_buffer_box(mults_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        // Validate buffer sizes.
        if (small_values.len != (NSUInteger)n_values * 4u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_id_to_big_small: small_values buffer length mismatch.");
            return false;
        }
        if (mults.len != (NSUInteger)n_values) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_id_to_big_small: mults buffer length mismatch.");
            return false;
        }
        // 9 columns * column_length (8 value limbs + 1 multiplicity)
        NSUInteger expected_trace_len = (NSUInteger)9u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_id_to_big_small: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_memory_id_to_big_small_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:small_values.buffer offset:0 atIndex:0];
        [encoder setBuffer:mults.buffer offset:0 atIndex:1];
        [encoder setBuffer:trace.buffer offset:0 atIndex:2];
        [encoder setBytes:&n_values length:sizeof(n_values) atIndex:3];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:4];

        MTLSize grid_size = MTLSizeMake((NSUInteger)column_length, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_memory_id_to_big_small_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: memory_address_to_id trace
// ---------------------------------------------------------------------------

bool stwo_metal_witness_memory_addr_to_id_trace(
    void *runtime_ptr,
    void *ids_ptr,
    void *mults_ptr,
    void *trace_ptr,
    uint32_t n_ids,
    uint32_t column_length,
    uint32_t split,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *ids = stwo_metal_buffer_box(ids_ptr);
        StwoMetalBufferBox *mults = stwo_metal_buffer_box(mults_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        if (ids.len != (NSUInteger)n_ids) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_addr_to_id: ids buffer length mismatch.");
            return false;
        }
        if (mults.len != (NSUInteger)n_ids) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_addr_to_id: mults buffer length mismatch.");
            return false;
        }
        NSUInteger n_trace_columns = (NSUInteger)split * 2u;
        NSUInteger expected_trace_len = n_trace_columns * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_memory_addr_to_id: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_memory_addr_to_id_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:ids.buffer offset:0 atIndex:0];
        [encoder setBuffer:mults.buffer offset:0 atIndex:1];
        [encoder setBuffer:trace.buffer offset:0 atIndex:2];
        [encoder setBytes:&n_ids length:sizeof(n_ids) atIndex:3];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:4];
        [encoder setBytes:&split length:sizeof(split) atIndex:5];

        NSUInteger total_threads = (NSUInteger)split * (NSUInteger)column_length;
        MTLSize grid_size = MTLSizeMake(total_threads, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_memory_addr_to_id_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: add_opcode_small trace
// ---------------------------------------------------------------------------

bool stwo_metal_witness_add_opcode_small_trace(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *inputs = stwo_metal_buffer_box(inputs_ptr);
        StwoMetalBufferBox *address_to_id = stwo_metal_buffer_box(address_to_id_ptr);
        StwoMetalBufferBox *big_values = stwo_metal_buffer_box(big_values_ptr);
        StwoMetalBufferBox *small_values = stwo_metal_buffer_box(small_values_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        // Validate inputs buffer: needs at least n_rows * 3 entries (pc, ap, fp)
        if (inputs.len < (NSUInteger)n_rows * 3u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_add_opcode_small: inputs buffer length mismatch.");
            return false;
        }
        // 39 columns * column_length
        NSUInteger expected_trace_len = (NSUInteger)39u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_add_opcode_small: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_add_opcode_small_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:inputs.buffer offset:0 atIndex:0];
        [encoder setBuffer:address_to_id.buffer offset:0 atIndex:1];
        [encoder setBuffer:big_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:small_values.buffer offset:0 atIndex:3];
        [encoder setBuffer:trace.buffer offset:0 atIndex:4];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:5];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:6];

        MTLSize grid_size = MTLSizeMake((NSUInteger)column_length, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_add_opcode_small_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: assert_eq_opcode_double_deref trace
// ---------------------------------------------------------------------------

bool stwo_metal_witness_assert_eq_double_deref_trace(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *inputs = stwo_metal_buffer_box(inputs_ptr);
        StwoMetalBufferBox *address_to_id = stwo_metal_buffer_box(address_to_id_ptr);
        StwoMetalBufferBox *big_values = stwo_metal_buffer_box(big_values_ptr);
        StwoMetalBufferBox *small_values = stwo_metal_buffer_box(small_values_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        if (inputs.len < (NSUInteger)n_rows * 3u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_assert_eq_double_deref: inputs buffer length mismatch.");
            return false;
        }
        // 19 columns * column_length
        NSUInteger expected_trace_len = (NSUInteger)19u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_assert_eq_double_deref: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_assert_eq_double_deref_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:inputs.buffer offset:0 atIndex:0];
        [encoder setBuffer:address_to_id.buffer offset:0 atIndex:1];
        [encoder setBuffer:big_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:small_values.buffer offset:0 atIndex:3];
        [encoder setBuffer:trace.buffer offset:0 atIndex:4];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:5];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:6];

        MTLSize grid_size = MTLSizeMake((NSUInteger)column_length, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_assert_eq_double_deref_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: jnz_opcode_taken trace (47 columns)
// ---------------------------------------------------------------------------

bool stwo_metal_witness_jnz_opcode_taken_trace(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *inputs = stwo_metal_buffer_box(inputs_ptr);
        StwoMetalBufferBox *address_to_id = stwo_metal_buffer_box(address_to_id_ptr);
        StwoMetalBufferBox *big_values = stwo_metal_buffer_box(big_values_ptr);
        StwoMetalBufferBox *small_values = stwo_metal_buffer_box(small_values_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        if (inputs.len < (NSUInteger)n_rows * 3u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_jnz_opcode_taken: inputs buffer length mismatch.");
            return false;
        }
        NSUInteger expected_trace_len = (NSUInteger)47u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_jnz_opcode_taken: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_jnz_opcode_taken_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:inputs.buffer offset:0 atIndex:0];
        [encoder setBuffer:address_to_id.buffer offset:0 atIndex:1];
        [encoder setBuffer:big_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:small_values.buffer offset:0 atIndex:3];
        [encoder setBuffer:trace.buffer offset:0 atIndex:4];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:5];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:6];

        MTLSize grid_size = MTLSizeMake((NSUInteger)column_length, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_jnz_opcode_taken_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: jump_opcode_rel_imm trace (13 columns)
// ---------------------------------------------------------------------------

bool stwo_metal_witness_jump_opcode_rel_imm_trace(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *inputs = stwo_metal_buffer_box(inputs_ptr);
        StwoMetalBufferBox *address_to_id = stwo_metal_buffer_box(address_to_id_ptr);
        StwoMetalBufferBox *big_values = stwo_metal_buffer_box(big_values_ptr);
        StwoMetalBufferBox *small_values = stwo_metal_buffer_box(small_values_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        if (inputs.len < (NSUInteger)n_rows * 3u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_jump_opcode_rel_imm: inputs buffer length mismatch.");
            return false;
        }
        NSUInteger expected_trace_len = (NSUInteger)13u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_jump_opcode_rel_imm: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_jump_opcode_rel_imm_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:inputs.buffer offset:0 atIndex:0];
        [encoder setBuffer:address_to_id.buffer offset:0 atIndex:1];
        [encoder setBuffer:big_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:small_values.buffer offset:0 atIndex:3];
        [encoder setBuffer:trace.buffer offset:0 atIndex:4];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:5];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:6];

        MTLSize grid_size = MTLSizeMake((NSUInteger)column_length, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_jump_opcode_rel_imm_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: call_opcode_rel_imm trace (24 columns)
// ---------------------------------------------------------------------------

bool stwo_metal_witness_call_opcode_rel_imm_trace(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *inputs = stwo_metal_buffer_box(inputs_ptr);
        StwoMetalBufferBox *address_to_id = stwo_metal_buffer_box(address_to_id_ptr);
        StwoMetalBufferBox *big_values = stwo_metal_buffer_box(big_values_ptr);
        StwoMetalBufferBox *small_values = stwo_metal_buffer_box(small_values_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        if (inputs.len < (NSUInteger)n_rows * 3u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_call_opcode_rel_imm: inputs buffer length mismatch.");
            return false;
        }
        NSUInteger expected_trace_len = (NSUInteger)24u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_call_opcode_rel_imm: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_call_opcode_rel_imm_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:inputs.buffer offset:0 atIndex:0];
        [encoder setBuffer:address_to_id.buffer offset:0 atIndex:1];
        [encoder setBuffer:big_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:small_values.buffer offset:0 atIndex:3];
        [encoder setBuffer:trace.buffer offset:0 atIndex:4];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:5];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:6];

        MTLSize grid_size = MTLSizeMake((NSUInteger)column_length, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_call_opcode_rel_imm_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness generation: ret_opcode trace (16 columns)
// ---------------------------------------------------------------------------

bool stwo_metal_witness_ret_opcode_trace(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *inputs = stwo_metal_buffer_box(inputs_ptr);
        StwoMetalBufferBox *address_to_id = stwo_metal_buffer_box(address_to_id_ptr);
        StwoMetalBufferBox *big_values = stwo_metal_buffer_box(big_values_ptr);
        StwoMetalBufferBox *small_values = stwo_metal_buffer_box(small_values_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        if (inputs.len < (NSUInteger)n_rows * 3u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_ret_opcode: inputs buffer length mismatch.");
            return false;
        }
        NSUInteger expected_trace_len = (NSUInteger)16u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_ret_opcode: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_ret_opcode_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:inputs.buffer offset:0 atIndex:0];
        [encoder setBuffer:address_to_id.buffer offset:0 atIndex:1];
        [encoder setBuffer:big_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:small_values.buffer offset:0 atIndex:3];
        [encoder setBuffer:trace.buffer offset:0 atIndex:4];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:5];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:6];

        MTLSize grid_size = MTLSizeMake((NSUInteger)column_length, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_ret_opcode_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Interaction trace: memory_id_to_big (big values)
// ---------------------------------------------------------------------------

bool stwo_metal_interaction_trace_id_to_big(
    void *runtime_ptr,
    void *limbs_ptr,
    void *mults_ptr,
    void *alpha_powers_ptr,
    void *z_ptr,
    void *relation_ids_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t id_offset,
    uint32_t large_id_base,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *limbs = stwo_metal_buffer_box(limbs_ptr);
        StwoMetalBufferBox *mults = stwo_metal_buffer_box(mults_ptr);
        StwoMetalBufferBox *alpha_powers = stwo_metal_buffer_box(alpha_powers_ptr);
        StwoMetalBufferBox *z = stwo_metal_buffer_box(z_ptr);
        StwoMetalBufferBox *relation_ids = stwo_metal_buffer_box(relation_ids_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        // Validate buffer sizes.
        if (limbs.len != (NSUInteger)28u * (NSUInteger)n_rows) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_id_to_big: limbs buffer length mismatch.");
            return false;
        }
        if (mults.len != (NSUInteger)n_rows) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_id_to_big: mults buffer length mismatch.");
            return false;
        }
        // 8 QM31 columns = 32 M31 columns
        NSUInteger expected_trace_len = (NSUInteger)32u * (NSUInteger)n_rows;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_id_to_big: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"interaction_trace_id_to_big_fractions",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:limbs.buffer offset:0 atIndex:0];
        [encoder setBuffer:mults.buffer offset:0 atIndex:1];
        [encoder setBuffer:alpha_powers.buffer offset:0 atIndex:2];
        [encoder setBuffer:z.buffer offset:0 atIndex:3];
        [encoder setBuffer:relation_ids.buffer offset:0 atIndex:4];
        [encoder setBuffer:trace.buffer offset:0 atIndex:5];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:6];
        [encoder setBytes:&id_offset length:sizeof(id_offset) atIndex:7];
        [encoder setBytes:&large_id_base length:sizeof(large_id_base) atIndex:8];

        MTLSize grid_size = MTLSizeMake((NSUInteger)n_rows, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"interaction_trace_id_to_big kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Interaction trace: memory_id_to_big (small values)
// ---------------------------------------------------------------------------

bool stwo_metal_interaction_trace_id_to_big_small(
    void *runtime_ptr,
    void *limbs_ptr,
    void *mults_ptr,
    void *alpha_powers_ptr,
    void *z_ptr,
    void *relation_ids_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *limbs = stwo_metal_buffer_box(limbs_ptr);
        StwoMetalBufferBox *mults = stwo_metal_buffer_box(mults_ptr);
        StwoMetalBufferBox *alpha_powers = stwo_metal_buffer_box(alpha_powers_ptr);
        StwoMetalBufferBox *z = stwo_metal_buffer_box(z_ptr);
        StwoMetalBufferBox *relation_ids = stwo_metal_buffer_box(relation_ids_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        // Validate buffer sizes.
        if (limbs.len != (NSUInteger)8u * (NSUInteger)n_rows) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_id_to_big_small: limbs buffer length mismatch.");
            return false;
        }
        if (mults.len != (NSUInteger)n_rows) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_id_to_big_small: mults buffer length mismatch.");
            return false;
        }
        // 3 QM31 columns = 12 M31 columns
        NSUInteger expected_trace_len = (NSUInteger)12u * (NSUInteger)n_rows;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_id_to_big_small: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"interaction_trace_id_to_big_small_fractions",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:limbs.buffer offset:0 atIndex:0];
        [encoder setBuffer:mults.buffer offset:0 atIndex:1];
        [encoder setBuffer:alpha_powers.buffer offset:0 atIndex:2];
        [encoder setBuffer:z.buffer offset:0 atIndex:3];
        [encoder setBuffer:relation_ids.buffer offset:0 atIndex:4];
        [encoder setBuffer:trace.buffer offset:0 atIndex:5];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:6];

        MTLSize grid_size = MTLSizeMake((NSUInteger)n_rows, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"interaction_trace_id_to_big_small kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Interaction trace: memory_address_to_id
// ---------------------------------------------------------------------------

bool stwo_metal_interaction_trace_addr_to_id(
    void *runtime_ptr,
    void *ids_ptr,
    void *mults_ptr,
    void *alpha_powers_ptr,
    void *z_ptr,
    void *relation_id_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t split,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *ids = stwo_metal_buffer_box(ids_ptr);
        StwoMetalBufferBox *mults = stwo_metal_buffer_box(mults_ptr);
        StwoMetalBufferBox *alpha_powers = stwo_metal_buffer_box(alpha_powers_ptr);
        StwoMetalBufferBox *z = stwo_metal_buffer_box(z_ptr);
        StwoMetalBufferBox *relation_id = stwo_metal_buffer_box(relation_id_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        // Validate buffer sizes.
        if (ids.len != (NSUInteger)split * (NSUInteger)n_rows) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_addr_to_id: ids buffer length mismatch.");
            return false;
        }
        if (mults.len != (NSUInteger)split * (NSUInteger)n_rows) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_addr_to_id: mults buffer length mismatch.");
            return false;
        }
        // SPLIT/2 QM31 columns = SPLIT/2 * 4 M31 columns
        NSUInteger n_logup_cols = (NSUInteger)split / 2u;
        NSUInteger expected_trace_len = n_logup_cols * 4u * (NSUInteger)n_rows;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_addr_to_id: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"interaction_trace_addr_to_id_fractions",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:ids.buffer offset:0 atIndex:0];
        [encoder setBuffer:mults.buffer offset:0 atIndex:1];
        [encoder setBuffer:alpha_powers.buffer offset:0 atIndex:2];
        [encoder setBuffer:z.buffer offset:0 atIndex:3];
        [encoder setBuffer:relation_id.buffer offset:0 atIndex:4];
        [encoder setBuffer:trace.buffer offset:0 atIndex:5];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:6];
        [encoder setBytes:&split length:sizeof(split) atIndex:7];

        MTLSize grid_size = MTLSizeMake((NSUInteger)n_rows, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"interaction_trace_addr_to_id kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Interaction trace: generic (data-driven, all component types)
// ---------------------------------------------------------------------------

bool stwo_metal_interaction_trace_generic(
    void *runtime_ptr,
    void *values_ptr,
    void *descriptors_ptr,
    void *alpha_powers_ptr,
    void *z_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t n_logup_cols,
    uint32_t n_rows_real,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *values = stwo_metal_buffer_box(values_ptr);
        StwoMetalBufferBox *descriptors = stwo_metal_buffer_box(descriptors_ptr);
        StwoMetalBufferBox *alpha_powers = stwo_metal_buffer_box(alpha_powers_ptr);
        StwoMetalBufferBox *z = stwo_metal_buffer_box(z_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        NSUInteger expected_trace_len = (NSUInteger)n_logup_cols * 4u * (NSUInteger)n_rows;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"interaction_trace_generic: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"interaction_trace_generic_fractions",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:values.buffer offset:0 atIndex:0];
        [encoder setBuffer:descriptors.buffer offset:0 atIndex:1];
        [encoder setBuffer:alpha_powers.buffer offset:0 atIndex:2];
        [encoder setBuffer:z.buffer offset:0 atIndex:3];
        [encoder setBuffer:trace.buffer offset:0 atIndex:4];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:5];
        [encoder setBytes:&n_logup_cols length:sizeof(n_logup_cols) atIndex:6];
        [encoder setBytes:&n_rows_real length:sizeof(n_rows_real) atIndex:7];

        MTLSize grid_size = MTLSizeMake((NSUInteger)n_rows, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"interaction_trace_generic kernel failed.");
            return false;
        }

        return true;
    }
}


// Witness generation: range_check trace (generic for all range-check components)
// ---------------------------------------------------------------------------

bool stwo_metal_witness_range_check_trace(
    void *runtime_ptr,
    void *mults_ptr,
    void *trace_ptr,
    uint32_t n_columns,
    uint32_t column_length,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *mults = stwo_metal_buffer_box(mults_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        NSUInteger expected_len = (NSUInteger)n_columns * (NSUInteger)column_length;
        if (mults.len != expected_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_range_check: mults buffer length mismatch.");
            return false;
        }
        if (trace.len != expected_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_range_check: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_range_check_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:mults.buffer offset:0 atIndex:0];
        [encoder setBuffer:trace.buffer offset:0 atIndex:1];
        [encoder setBytes:&n_columns length:sizeof(n_columns) atIndex:2];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:3];

        NSUInteger total_threads = (NSUInteger)column_length;
        MTLSize grid_size = MTLSizeMake(total_threads, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_range_check_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Witness trace: verify_instruction (instruction field decoding)
// ---------------------------------------------------------------------------

bool stwo_metal_witness_verify_instruction_trace(
    void *runtime_ptr,
    void *inputs_ptr,
    void *mults_ptr,
    void *addr_to_id_ptr,
    void *trace_ptr,
    uint32_t n_rows,
    uint32_t column_length,
    uint32_t addr_to_id_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *inputs = stwo_metal_buffer_box(inputs_ptr);
        StwoMetalBufferBox *mults = stwo_metal_buffer_box(mults_ptr);
        StwoMetalBufferBox *addr_to_id = stwo_metal_buffer_box(addr_to_id_ptr);
        StwoMetalBufferBox *trace = stwo_metal_buffer_box(trace_ptr);

        if (inputs.len != (NSUInteger)n_rows * 7u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_verify_instruction: inputs buffer length mismatch.");
            return false;
        }
        if (mults.len != (NSUInteger)n_rows) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_verify_instruction: mults buffer length mismatch.");
            return false;
        }
        if (addr_to_id.len != (NSUInteger)addr_to_id_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_verify_instruction: addr_to_id buffer length mismatch.");
            return false;
        }
        NSUInteger expected_trace_len = 17u * (NSUInteger)column_length;
        if (trace.len != expected_trace_len) {
            stwo_metal_write_error(error_message, error_message_len,
                @"witness_verify_instruction: trace output buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            @"witness_verify_instruction_trace",
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:inputs.buffer offset:0 atIndex:0];
        [encoder setBuffer:mults.buffer offset:0 atIndex:1];
        [encoder setBuffer:addr_to_id.buffer offset:0 atIndex:2];
        [encoder setBuffer:trace.buffer offset:0 atIndex:3];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:4];
        [encoder setBytes:&column_length length:sizeof(column_length) atIndex:5];
        [encoder setBytes:&addr_to_id_len length:sizeof(addr_to_id_len) atIndex:6];

        NSUInteger total_threads = (NSUInteger)column_length;
        MTLSize grid_size = MTLSizeMake(total_threads, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"witness_verify_instruction_trace kernel failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// Barycentric evaluation: sum(eval_values[i] * weights[i]) over QM31.
// ---------------------------------------------------------------------------

bool stwo_metal_barycentric_eval_at_point_u32(
    void *runtime_ptr,
    void *eval_values_ptr,
    void *weights_ptr,
    void *dst_ptr,
    uint32_t n_elements,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *eval_values = stwo_metal_buffer_box(eval_values_ptr);
        StwoMetalBufferBox *weights = stwo_metal_buffer_box(weights_ptr);
        StwoMetalBufferBox *dst = stwo_metal_buffer_box(dst_ptr);

        if (eval_values.len != (NSUInteger)n_elements) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Barycentric eval expects eval_values length to match n_elements.");
            return false;
        }
        if (weights.len != (NSUInteger)(n_elements * 4u)) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Barycentric eval expects weights buffer with 4 * n_elements u32 values (QM31).");
            return false;
        }
        if (dst.len < 4u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Barycentric eval expects a destination buffer with at least 4 u32 values (one QM31).");
            return false;
        }

        id<MTLComputePipelineState> terms_pipeline =
            stwo_metal_pipeline(runtime, @"barycentric_eval_terms_u32", error_message, error_message_len);
        if (terms_pipeline == nil) {
            return false;
        }
        id<MTLComputePipelineState> reduce_pipeline =
            stwo_metal_pipeline(runtime, @"gkr_sum_reduce_pairs_u32x4", error_message, error_message_len);
        if (reduce_pipeline == nil) {
            return false;
        }

        // Round n_elements up to the next power of two for reduction.
        uint32_t padded = 1u;
        while (padded < n_elements) {
            padded <<= 1u;
        }

        // Allocate two temporary QM31 buffers for ping-pong reduction.
        NSUInteger temp_bytes = (NSUInteger)(padded * 4u) * sizeof(uint32_t);
        id<MTLBuffer> temp_a = [runtime.device newBufferWithLength:temp_bytes
                                                           options:MTLResourceStorageModeShared];
        id<MTLBuffer> temp_b = [runtime.device newBufferWithLength:temp_bytes
                                                           options:MTLResourceStorageModeShared];
        if (temp_a == nil || temp_b == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to allocate Metal barycentric evaluation temporary buffers.");
            return false;
        }

        // Zero the padding region of temp_a so unused slots are zero.
        if (padded > n_elements) {
            memset((uint8_t *)temp_a.contents + (NSUInteger)(n_elements * 4u) * sizeof(uint32_t),
                   0,
                   (NSUInteger)((padded - n_elements) * 4u) * sizeof(uint32_t));
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer for barycentric eval.");
            return false;
        }

        // Pass 1: Compute per-element terms = eval_values[i] * weights[i].
        {
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            if (encoder == nil) {
                stwo_metal_write_error(error_message, error_message_len,
                    @"Failed to create Metal compute encoder for barycentric terms.");
                return false;
            }

            [encoder setComputePipelineState:terms_pipeline];
            [encoder setBuffer:eval_values.buffer offset:0 atIndex:0];
            [encoder setBuffer:weights.buffer offset:0 atIndex:1];
            [encoder setBuffer:temp_a offset:0 atIndex:2];
            [encoder setBytes:&n_elements length:sizeof(n_elements) atIndex:3];
            [encoder dispatchThreads:MTLSizeMake(n_elements, 1, 1)
                threadsPerThreadgroup:MTLSizeMake(stwo_metal_threads_per_group(terms_pipeline), 1, 1)];
            [encoder endEncoding];
        }

        // Pass 2: Pairwise reduction until a single QM31 remains.
        id<MTLBuffer> final_buffer = stwo_metal_encode_qm31_pair_reduction(
            command_buffer,
            reduce_pipeline,
            temp_a,
            temp_b,
            padded,
            error_message,
            error_message_len
        );
        if (final_buffer == nil) {
            return false;
        }

        // Copy the single QM31 result into the destination buffer.
        {
            id<MTLBlitCommandEncoder> blit = [command_buffer blitCommandEncoder];
            if (blit == nil) {
                stwo_metal_write_error(error_message, error_message_len,
                    @"Failed to create Metal blit encoder for barycentric result copy.");
                return false;
            }
            [blit copyFromBuffer:final_buffer sourceOffset:0
                        toBuffer:dst.buffer destinationOffset:0
                            size:4u * sizeof(uint32_t)];
            [blit endEncoding];
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"Barycentric eval Metal kernel execution failed.");
            return false;
        }

        return true;
    }
}

// ---------------------------------------------------------------------------
// GPU Merkle tree decommitment: bulk gather of hash witnesses
// ---------------------------------------------------------------------------
bool stwo_metal_merkle_decommit_gather(
    void *runtime_ptr,
    void **layer_ptrs,
    uint32_t n_layers,
    const uint32_t **per_layer_indices,
    const uint32_t *per_layer_counts,
    uint32_t *out_hashes,
    uint32_t total_gathers,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);

        if (total_gathers == 0) {
            return true;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime, @"merkle_decommit_gather", error_message, error_message_len
        );
        if (pipeline == nil) return false;

        NSUInteger out_bytes = (NSUInteger)total_gathers * 8u * sizeof(uint32_t);
        id<MTLBuffer> output_buffer = [runtime.device
            newBufferWithLength:out_bytes
            options:MTLResourceStorageModeShared];
        if (output_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"merkle_decommit_gather: failed to allocate output buffer.");
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        uint32_t output_offset_hashes = 0;

        for (uint32_t layer = 0; layer < n_layers; ++layer) {
            uint32_t count = per_layer_counts[layer];
            if (count == 0) continue;

            StwoMetalBufferBox *layer_box = stwo_metal_buffer_box(layer_ptrs[layer]);

            NSUInteger idx_bytes = (NSUInteger)count * sizeof(uint32_t);
            id<MTLBuffer> indices_buffer = [runtime.device
                newBufferWithBytes:per_layer_indices[layer]
                length:idx_bytes
                options:MTLResourceStorageModeShared];
            if (indices_buffer == nil) {
                stwo_metal_write_error(error_message, error_message_len,
                    @"merkle_decommit_gather: failed to allocate index buffer.");
                return false;
            }

            uint32_t params[1] = { count };

            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:pipeline];
            [encoder setBuffer:layer_box.buffer offset:0 atIndex:0];
            [encoder setBuffer:indices_buffer offset:0 atIndex:1];
            [encoder setBuffer:output_buffer
                        offset:(NSUInteger)output_offset_hashes * 8u * sizeof(uint32_t)
                       atIndex:2];
            [encoder setBytes:params length:sizeof(params) atIndex:3];

            MTLSize grid_size = MTLSizeMake(count, 1, 1);
            MTLSize threadgroup_size = MTLSizeMake(
                stwo_metal_threads_per_group(pipeline), 1, 1);
            [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
            [encoder endEncoding];

            output_offset_hashes += count;
        }

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"merkle_decommit_gather kernel failed.");
            return false;
        }

        memcpy(out_hashes, output_buffer.contents, out_bytes);
        return true;
    }
}


// ---------------------------------------------------------------------------
// Multiplicity accumulation: generic dispatch for atomic mults kernels.
//
// All 6 opcode mults kernels share the same buffer layout:
//   buffer(0): inputs            [n_rows * 3]  uint (pc, ap, fp)
//   buffer(1): address_to_id     [table_size]  uint
//   buffer(2): big_values        [n_big * 8]   uint
//   buffer(3): small_values      [n_small * 4] uint
//   buffer(4): addr_to_id_mults  [table_size]  atomic_uint
//   buffer(5): id_to_big_mults   [n_big]       atomic_uint
//   buffer(6): id_to_small_mults [n_small]     atomic_uint
//   buffer(7): n_rows            uint constant
// ---------------------------------------------------------------------------

static bool stwo_metal_dispatch_mults_kernel(
    void *runtime_ptr,
    NSString *kernel_name,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *addr_to_id_mults_ptr,
    void *id_to_big_mults_ptr,
    void *id_to_small_mults_ptr,
    uint32_t n_rows,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *inputs = stwo_metal_buffer_box(inputs_ptr);
        StwoMetalBufferBox *address_to_id = stwo_metal_buffer_box(address_to_id_ptr);
        StwoMetalBufferBox *big_values = stwo_metal_buffer_box(big_values_ptr);
        StwoMetalBufferBox *small_values = stwo_metal_buffer_box(small_values_ptr);
        StwoMetalBufferBox *addr_to_id_mults = stwo_metal_buffer_box(addr_to_id_mults_ptr);
        StwoMetalBufferBox *id_to_big_mults = stwo_metal_buffer_box(id_to_big_mults_ptr);
        StwoMetalBufferBox *id_to_small_mults = stwo_metal_buffer_box(id_to_small_mults_ptr);

        if (inputs.len < (NSUInteger)n_rows * 3u) {
            stwo_metal_write_error(error_message, error_message_len,
                @"mults_accumulate: inputs buffer length mismatch.");
            return false;
        }

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime,
            kernel_name,
            error_message,
            error_message_len
        );
        if (pipeline == nil) {
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:inputs.buffer offset:0 atIndex:0];
        [encoder setBuffer:address_to_id.buffer offset:0 atIndex:1];
        [encoder setBuffer:big_values.buffer offset:0 atIndex:2];
        [encoder setBuffer:small_values.buffer offset:0 atIndex:3];
        [encoder setBuffer:addr_to_id_mults.buffer offset:0 atIndex:4];
        [encoder setBuffer:id_to_big_mults.buffer offset:0 atIndex:5];
        [encoder setBuffer:id_to_small_mults.buffer offset:0 atIndex:6];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:7];

        MTLSize grid_size = MTLSizeMake((NSUInteger)n_rows, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"mults_accumulate kernel failed.");
            return false;
        }

        return true;
    }
}

// Per-opcode C entry points for multiplicity accumulation.

bool stwo_metal_mults_add_opcode_small(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *addr_to_id_mults_ptr,
    void *id_to_big_mults_ptr,
    void *id_to_small_mults_ptr,
    uint32_t n_rows,
    char *error_message,
    size_t error_message_len
) {
    return stwo_metal_dispatch_mults_kernel(
        runtime_ptr, @"mults_add_opcode_small",
        inputs_ptr, address_to_id_ptr, big_values_ptr, small_values_ptr,
        addr_to_id_mults_ptr, id_to_big_mults_ptr, id_to_small_mults_ptr,
        n_rows, error_message, error_message_len);
}

bool stwo_metal_mults_assert_eq_double_deref(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *addr_to_id_mults_ptr,
    void *id_to_big_mults_ptr,
    void *id_to_small_mults_ptr,
    uint32_t n_rows,
    char *error_message,
    size_t error_message_len
) {
    return stwo_metal_dispatch_mults_kernel(
        runtime_ptr, @"mults_assert_eq_double_deref",
        inputs_ptr, address_to_id_ptr, big_values_ptr, small_values_ptr,
        addr_to_id_mults_ptr, id_to_big_mults_ptr, id_to_small_mults_ptr,
        n_rows, error_message, error_message_len);
}

bool stwo_metal_mults_jnz_opcode_taken(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *addr_to_id_mults_ptr,
    void *id_to_big_mults_ptr,
    void *id_to_small_mults_ptr,
    uint32_t n_rows,
    char *error_message,
    size_t error_message_len
) {
    return stwo_metal_dispatch_mults_kernel(
        runtime_ptr, @"mults_jnz_opcode_taken",
        inputs_ptr, address_to_id_ptr, big_values_ptr, small_values_ptr,
        addr_to_id_mults_ptr, id_to_big_mults_ptr, id_to_small_mults_ptr,
        n_rows, error_message, error_message_len);
}

bool stwo_metal_mults_jump_opcode_rel_imm(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *addr_to_id_mults_ptr,
    void *id_to_big_mults_ptr,
    void *id_to_small_mults_ptr,
    uint32_t n_rows,
    char *error_message,
    size_t error_message_len
) {
    return stwo_metal_dispatch_mults_kernel(
        runtime_ptr, @"mults_jump_opcode_rel_imm",
        inputs_ptr, address_to_id_ptr, big_values_ptr, small_values_ptr,
        addr_to_id_mults_ptr, id_to_big_mults_ptr, id_to_small_mults_ptr,
        n_rows, error_message, error_message_len);
}

bool stwo_metal_mults_call_opcode_rel_imm(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *addr_to_id_mults_ptr,
    void *id_to_big_mults_ptr,
    void *id_to_small_mults_ptr,
    uint32_t n_rows,
    char *error_message,
    size_t error_message_len
) {
    return stwo_metal_dispatch_mults_kernel(
        runtime_ptr, @"mults_call_opcode_rel_imm",
        inputs_ptr, address_to_id_ptr, big_values_ptr, small_values_ptr,
        addr_to_id_mults_ptr, id_to_big_mults_ptr, id_to_small_mults_ptr,
        n_rows, error_message, error_message_len);
}

bool stwo_metal_mults_ret_opcode(
    void *runtime_ptr,
    void *inputs_ptr,
    void *address_to_id_ptr,
    void *big_values_ptr,
    void *small_values_ptr,
    void *addr_to_id_mults_ptr,
    void *id_to_big_mults_ptr,
    void *id_to_small_mults_ptr,
    uint32_t n_rows,
    char *error_message,
    size_t error_message_len
) {
    return stwo_metal_dispatch_mults_kernel(
        runtime_ptr, @"mults_ret_opcode",
        inputs_ptr, address_to_id_ptr, big_values_ptr, small_values_ptr,
        addr_to_id_mults_ptr, id_to_big_mults_ptr, id_to_small_mults_ptr,
        n_rows, error_message, error_message_len);
}

// ---------------------------------------------------------------------------
// Interaction values from trace: shared dispatch for opcode interaction kernels
// ---------------------------------------------------------------------------

static bool stwo_metal_dispatch_interaction_values_kernel(
    void *runtime_ptr,
    NSString *kernel_name,
    void *trace_cols_ptr,
    void *output_ptr,
    uint32_t n_rows,
    uint32_t col_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_cols = stwo_metal_buffer_box(trace_cols_ptr);
        StwoMetalBufferBox *output = stwo_metal_buffer_box(output_ptr);

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime, kernel_name, error_message, error_message_len);
        if (pipeline == nil) return false;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_cols.buffer offset:0 atIndex:0];
        [encoder setBuffer:output.buffer offset:0 atIndex:1];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:2];
        [encoder setBytes:&col_len length:sizeof(col_len) atIndex:3];

        MTLSize grid_size = MTLSizeMake((NSUInteger)col_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"interaction values kernel failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_interaction_values_ret_opcode(
    void *runtime_ptr, void *trace_cols_ptr, void *output_ptr,
    uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_interaction_values_kernel(
        runtime_ptr, @"interaction_values_ret_opcode",
        trace_cols_ptr, output_ptr, n_rows, col_len,
        error_message, error_message_len);
}

bool stwo_metal_interaction_values_jnz_opcode_taken(
    void *runtime_ptr, void *trace_cols_ptr, void *output_ptr,
    uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_interaction_values_kernel(
        runtime_ptr, @"interaction_values_jnz_opcode_taken",
        trace_cols_ptr, output_ptr, n_rows, col_len,
        error_message, error_message_len);
}

bool stwo_metal_interaction_values_assert_eq_double_deref(
    void *runtime_ptr, void *trace_cols_ptr, void *output_ptr,
    uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_interaction_values_kernel(
        runtime_ptr, @"interaction_values_assert_eq_double_deref",
        trace_cols_ptr, output_ptr, n_rows, col_len,
        error_message, error_message_len);
}

bool stwo_metal_interaction_values_jump_opcode_rel_imm(
    void *runtime_ptr, void *trace_cols_ptr, void *output_ptr,
    uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_interaction_values_kernel(
        runtime_ptr, @"interaction_values_jump_opcode_rel_imm",
        trace_cols_ptr, output_ptr, n_rows, col_len,
        error_message, error_message_len);
}

bool stwo_metal_interaction_values_call_opcode_rel_imm(
    void *runtime_ptr, void *trace_cols_ptr, void *output_ptr,
    uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_interaction_values_kernel(
        runtime_ptr, @"interaction_values_call_opcode_rel_imm",
        trace_cols_ptr, output_ptr, n_rows, col_len,
        error_message, error_message_len);
}

// ---------------------------------------------------------------------------
// Fused interaction trace kernels: single-pass trace→logup fractions
// ---------------------------------------------------------------------------

static bool stwo_metal_dispatch_fused_interaction_kernel(
    void *runtime_ptr,
    NSString *kernel_name,
    void *trace_cols_ptr,
    void *alpha_powers_ptr,
    void *z_ptr,
    void *output_ptr,
    uint32_t n_rows,
    uint32_t col_len,
    char *error_message,
    size_t error_message_len
) {
    @autoreleasepool {
        StwoMetalRuntimeBox *runtime = stwo_metal_runtime_box(runtime_ptr);
        StwoMetalBufferBox *trace_cols = stwo_metal_buffer_box(trace_cols_ptr);
        StwoMetalBufferBox *alpha_powers = stwo_metal_buffer_box(alpha_powers_ptr);
        StwoMetalBufferBox *z = stwo_metal_buffer_box(z_ptr);
        StwoMetalBufferBox *output = stwo_metal_buffer_box(output_ptr);

        id<MTLComputePipelineState> pipeline = stwo_metal_pipeline(
            runtime, kernel_name, error_message, error_message_len);
        if (pipeline == nil) return false;

        id<MTLCommandBuffer> command_buffer = [runtime.queue commandBuffer];
        if (command_buffer == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal command buffer.");
            return false;
        }

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        if (encoder == nil) {
            stwo_metal_write_error(error_message, error_message_len,
                @"Failed to create Metal compute encoder.");
            return false;
        }

        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:trace_cols.buffer offset:0 atIndex:0];
        [encoder setBuffer:alpha_powers.buffer offset:0 atIndex:1];
        [encoder setBuffer:z.buffer offset:0 atIndex:2];
        [encoder setBuffer:output.buffer offset:0 atIndex:3];
        [encoder setBytes:&n_rows length:sizeof(n_rows) atIndex:4];
        [encoder setBytes:&col_len length:sizeof(col_len) atIndex:5];

        MTLSize grid_size = MTLSizeMake((NSUInteger)col_len, 1, 1);
        MTLSize threadgroup_size = MTLSizeMake(
            stwo_metal_threads_per_group(pipeline), 1, 1);
        [encoder dispatchThreads:grid_size threadsPerThreadgroup:threadgroup_size];
        [encoder endEncoding];

        [command_buffer commit];
        [command_buffer waitUntilCompleted];

        if (command_buffer.status == MTLCommandBufferStatusError) {
            stwo_metal_write_error(error_message, error_message_len,
                command_buffer.error.localizedDescription
                    ?: @"fused interaction trace kernel failed.");
            return false;
        }

        return true;
    }
}

bool stwo_metal_fused_interaction_ret_opcode(
    void *runtime_ptr, void *trace_cols_ptr, void *alpha_powers_ptr,
    void *z_ptr, void *output_ptr, uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_fused_interaction_kernel(
        runtime_ptr, @"interaction_trace_fused_ret_opcode",
        trace_cols_ptr, alpha_powers_ptr, z_ptr, output_ptr,
        n_rows, col_len, error_message, error_message_len);
}

bool stwo_metal_fused_interaction_jump_opcode_rel_imm(
    void *runtime_ptr, void *trace_cols_ptr, void *alpha_powers_ptr,
    void *z_ptr, void *output_ptr, uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_fused_interaction_kernel(
        runtime_ptr, @"interaction_trace_fused_jump_opcode_rel_imm",
        trace_cols_ptr, alpha_powers_ptr, z_ptr, output_ptr,
        n_rows, col_len, error_message, error_message_len);
}

bool stwo_metal_fused_interaction_assert_eq_double_deref(
    void *runtime_ptr, void *trace_cols_ptr, void *alpha_powers_ptr,
    void *z_ptr, void *output_ptr, uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_fused_interaction_kernel(
        runtime_ptr, @"interaction_trace_fused_assert_eq_double_deref",
        trace_cols_ptr, alpha_powers_ptr, z_ptr, output_ptr,
        n_rows, col_len, error_message, error_message_len);
}

bool stwo_metal_fused_interaction_jnz_opcode_taken(
    void *runtime_ptr, void *trace_cols_ptr, void *alpha_powers_ptr,
    void *z_ptr, void *output_ptr, uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_fused_interaction_kernel(
        runtime_ptr, @"interaction_trace_fused_jnz_opcode_taken",
        trace_cols_ptr, alpha_powers_ptr, z_ptr, output_ptr,
        n_rows, col_len, error_message, error_message_len);
}

bool stwo_metal_fused_interaction_call_opcode_rel_imm(
    void *runtime_ptr, void *trace_cols_ptr, void *alpha_powers_ptr,
    void *z_ptr, void *output_ptr, uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_fused_interaction_kernel(
        runtime_ptr, @"interaction_trace_fused_call_opcode_rel_imm",
        trace_cols_ptr, alpha_powers_ptr, z_ptr, output_ptr,
        n_rows, col_len, error_message, error_message_len);
}

bool stwo_metal_fused_interaction_add_opcode_small(
    void *runtime_ptr, void *trace_cols_ptr, void *alpha_powers_ptr,
    void *z_ptr, void *output_ptr, uint32_t n_rows, uint32_t col_len,
    char *error_message, size_t error_message_len
) {
    return stwo_metal_dispatch_fused_interaction_kernel(
        runtime_ptr, @"interaction_trace_fused_add_opcode_small",
        trace_cols_ptr, alpha_powers_ptr, z_ptr, output_ptr,
        n_rows, col_len, error_message, error_message_len);
}
