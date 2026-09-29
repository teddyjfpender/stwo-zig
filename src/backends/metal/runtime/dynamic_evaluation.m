#import <objc/runtime.h>

static const NSUInteger STWO_ZIG_EVAL_LIBRARY_ENTRY_LIMIT = 8u;
static const uint64_t STWO_ZIG_EVAL_LIBRARY_BYTE_LIMIT = 64u * 1024u * 1024u;
static const NSUInteger STWO_ZIG_EVAL_PIPELINE_ENTRY_LIMIT = 64u;
static const uint64_t STWO_ZIG_EVAL_PIPELINE_BYTE_LIMIT = 16u * 1024u * 1024u;
// Metal does not expose PSO allocation size. Charge every resident entry a
// conservative fixed cost so both the count and the accounting budget bound it.
static const uint64_t STWO_ZIG_EVAL_PIPELINE_ENTRY_BYTES = 256u * 1024u;

// Diagnostic occupancy sweep. Resolve once per plan, retaining the same
// authenticated pipeline and hard limits for every subsequent dispatch.
static NSUInteger eval_dispatch_width(id<MTLComputePipelineState> pipeline, uint32_t rows) {
    NSUInteger requested = 256u;
    const char *control = getenv("STWO_METAL_EVAL_THREADS_PER_GROUP");
    if (control != NULL && control[0] != '\0') {
        char *end = NULL;
        unsigned long parsed = strtoul(control, &end, 10);
        if (end != control && *end == '\0' && parsed >= 32u && parsed <= 1024u &&
            (parsed & (parsed - 1u)) == 0u) requested = (NSUInteger)parsed;
    }
    return MIN(requested, MIN((NSUInteger)rows, pipeline.maxTotalThreadsPerThreadgroup));
}

@interface StwoZigEvalCacheState : NSObject
@property(nonatomic, strong) StwoZigEvalRuntimeIdentity *runtimeIdentity;
@property(nonatomic, strong) NSMutableArray<StwoZigEvalLibraryKey *> *libraryLru;
@property(nonatomic, strong) NSMutableArray<StwoZigEvalPipelineKey *> *pipelineLru;
@property(nonatomic, strong) NSMutableDictionary<StwoZigEvalLibraryKey *, NSNumber *> *libraryCosts;
@property(nonatomic, strong) NSMutableDictionary<StwoZigEvalPipelineKey *, NSNumber *> *pipelineCosts;
@property(nonatomic) uint64_t libraryBytes;
@property(nonatomic) uint64_t pipelineBytes;
@property(nonatomic) uint64_t libraryPeakEntries;
@property(nonatomic) uint64_t libraryPeakBytes;
@property(nonatomic) uint64_t pipelinePeakEntries;
@property(nonatomic) uint64_t pipelinePeakBytes;
@property(nonatomic) uint64_t libraryEvictions;
@property(nonatomic) uint64_t libraryRejections;
@property(nonatomic) uint64_t pipelineEvictions;
@property(nonatomic) uint64_t pipelineInvalidations;
@property(nonatomic) uint64_t pipelineRejections;
@end

@implementation StwoZigEvalCacheState
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _libraryLru = [NSMutableArray array];
        _pipelineLru = [NSMutableArray array];
        _libraryCosts = [NSMutableDictionary dictionary];
        _pipelineCosts = [NSMutableDictionary dictionary];
    }
    return self;
}
@end

static const void *STWO_ZIG_EVAL_CACHE_STATE_KEY = &STWO_ZIG_EVAL_CACHE_STATE_KEY;

static StwoZigEvalCacheState *eval_cache_state(StwoZigMetalRuntime *runtime) {
    StwoZigEvalCacheState *state = objc_getAssociatedObject(runtime, STWO_ZIG_EVAL_CACHE_STATE_KEY);
    if (state == nil) {
        state = [StwoZigEvalCacheState new];
        state.runtimeIdentity = eval_runtime_identity(runtime.device);
        objc_setAssociatedObject(runtime, STWO_ZIG_EVAL_CACHE_STATE_KEY, state,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return state;
}

static void touch_eval_cache_key(NSMutableArray *lru, id key) {
    [lru removeObject:key];
    [lru addObject:key];
}

void *stwo_zig_metal_eval_prepare(
    void *runtime_ptr, const char *source_bytes, size_t source_len,
    const char *name_bytes, size_t name_len, const uint32_t *arguments,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || source_bytes == NULL || source_len == 0u ||
        name_bytes == NULL || name_len == 0u || arguments == NULL || arguments[10] == 0u) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSString *source = [[NSString alloc] initWithBytes:source_bytes length:source_len encoding:NSUTF8StringEncoding];
        NSString *name = [[NSString alloc] initWithBytes:name_bytes length:name_len encoding:NSUTF8StringEncoding];
        if (source == nil || name == nil) {
            write_error(error_message, error_message_len, @"Invalid Metal evaluation source encoding"); return NULL;
        }
        MTLCompileOptions *options = [MTLCompileOptions new];
        stwo_zig_configure_safe_metal_compile_options(options);
        NSError *error = nil;
        id<MTLLibrary> library = [runtime.device newLibraryWithSource:source options:options error:&error];
        if (library == nil) {
            write_error(error_message, error_message_len,
                        error.localizedDescription ?: @"Failed to compile Metal evaluation program");
            return NULL;
        }
        id<MTLComputePipelineState> pipeline = make_pipeline(runtime.device, library, name, error_message, error_message_len);
        if (pipeline == nil) return NULL;
        StwoZigEvalPlan *plan = [StwoZigEvalPlan new];
        plan.pipeline = pipeline;
        plan.arguments = [runtime.device newBufferWithBytes:arguments length:14u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.rowCount = arguments[10];
        plan.dispatchWidth = eval_dispatch_width(pipeline, plan.rowCount);
        if (plan.arguments == nil) {
            write_error(error_message, error_message_len, @"Metal evaluation argument allocation failed"); return NULL;
        }
        return (__bridge_retained void *)plan;
    }
}

static bool serialize_eval_archive(StwoZigEvalLibrary *library, NSError **error, bool *didSerialize) {
    return eval_archive_store_flush_library(library, error, didSerialize);
}

static void remove_eval_pipeline(
    StwoZigMetalRuntime *runtime,
    StwoZigEvalCacheState *state,
    StwoZigEvalPipelineKey *key,
    bool invalidated
) {
    NSNumber *cost = state.pipelineCosts[key];
    if (cost == nil) return;
    state.pipelineBytes -= cost.unsignedLongLongValue;
    [state.pipelineCosts removeObjectForKey:key];
    [state.pipelineLru removeObject:key];
    [runtime.evalPipelines removeObjectForKey:key];
    if (invalidated) state.pipelineInvalidations += 1u;
    else state.pipelineEvictions += 1u;
}

static void invalidate_eval_library_pipelines(
    StwoZigMetalRuntime *runtime,
    StwoZigEvalCacheState *state,
    StwoZigEvalLibraryKey *libraryKey
) {
    NSArray<StwoZigEvalPipelineKey *> *keys = [state.pipelineLru copy];
    for (StwoZigEvalPipelineKey *key in keys) {
        if ([key.libraryKey isEqual:libraryKey]) remove_eval_pipeline(runtime, state, key, true);
    }
}

static void evict_eval_library(
    StwoZigMetalRuntime *runtime,
    StwoZigEvalCacheState *state,
    StwoZigEvalLibraryKey *key
) {
    StwoZigEvalLibrary *library = runtime.evalLibraries[key];
    if (library != nil && library.archiveDirty) {
        NSError *error = nil;
        bool didSerialize = false;
        if (!serialize_eval_archive(library, &error, &didSerialize)) {
            fprintf(stderr, "Failed to serialize evicted Metal binary archive: %s\n",
                    error.localizedDescription.UTF8String ?: "unknown Metal error");
        } else if (didSerialize) {
            runtime.evalArchiveSerializations += 1u;
        }
    }
    invalidate_eval_library_pipelines(runtime, state, key);
    NSNumber *cost = state.libraryCosts[key];
    if (cost != nil) state.libraryBytes -= cost.unsignedLongLongValue;
    [state.libraryCosts removeObjectForKey:key];
    [state.libraryLru removeObject:key];
    [runtime.evalLibraries removeObjectForKey:key];
    state.libraryEvictions += 1u;
}

static void cache_eval_library(
    StwoZigMetalRuntime *runtime,
    StwoZigEvalLibrary *library,
    StwoZigEvalLibraryKey *key,
    uint64_t byteCost
) {
    StwoZigEvalCacheState *state = eval_cache_state(runtime);
    if (byteCost > STWO_ZIG_EVAL_LIBRARY_BYTE_LIMIT) {
        state.libraryRejections += 1u;
        return;
    }
    while (state.libraryLru.count >= STWO_ZIG_EVAL_LIBRARY_ENTRY_LIMIT ||
           state.libraryBytes > STWO_ZIG_EVAL_LIBRARY_BYTE_LIMIT - byteCost) {
        evict_eval_library(runtime, state, state.libraryLru.firstObject);
    }
    runtime.evalLibraries[key] = library;
    state.libraryCosts[key] = @(byteCost);
    state.libraryBytes += byteCost;
    touch_eval_cache_key(state.libraryLru, key);
    state.libraryPeakEntries = MAX(state.libraryPeakEntries, (uint64_t)state.libraryLru.count);
    state.libraryPeakBytes = MAX(state.libraryPeakBytes, state.libraryBytes);
}

static void cache_eval_pipeline(
    StwoZigMetalRuntime *runtime,
    id<MTLComputePipelineState> pipeline,
    StwoZigEvalPipelineKey *key
) {
    StwoZigEvalCacheState *state = eval_cache_state(runtime);
    const uint64_t byteCost = STWO_ZIG_EVAL_PIPELINE_ENTRY_BYTES;
    if (byteCost > STWO_ZIG_EVAL_PIPELINE_BYTE_LIMIT) {
        state.pipelineRejections += 1u;
        return;
    }
    while (state.pipelineLru.count >= STWO_ZIG_EVAL_PIPELINE_ENTRY_LIMIT ||
           state.pipelineBytes > STWO_ZIG_EVAL_PIPELINE_BYTE_LIMIT - byteCost) {
        remove_eval_pipeline(runtime, state, state.pipelineLru.firstObject, false);
    }
    runtime.evalPipelines[key] = pipeline;
    state.pipelineCosts[key] = @(byteCost);
    state.pipelineBytes += byteCost;
    touch_eval_cache_key(state.pipelineLru, key);
    state.pipelinePeakEntries = MAX(state.pipelinePeakEntries, (uint64_t)state.pipelineLru.count);
    state.pipelinePeakBytes = MAX(state.pipelinePeakBytes, state.pipelineBytes);
}

static void stwo_zig_metal_dynamic_cache_stats(
    StwoZigMetalRuntime *runtime,
    StwoZigPipelineCacheStats *stats
) {
    StwoZigEvalCacheState *state = eval_cache_state(runtime);
    stats->library_cache_entries = (uint64_t)state.libraryLru.count;
    stats->library_cache_bytes = state.libraryBytes;
    stats->library_cache_peak_entries = state.libraryPeakEntries;
    stats->library_cache_peak_bytes = state.libraryPeakBytes;
    stats->library_cache_evictions = state.libraryEvictions;
    stats->library_cache_rejections = state.libraryRejections;
    stats->pipeline_cache_entries = (uint64_t)state.pipelineLru.count;
    stats->pipeline_cache_bytes = state.pipelineBytes;
    stats->pipeline_cache_peak_entries = state.pipelinePeakEntries;
    stats->pipeline_cache_peak_bytes = state.pipelinePeakBytes;
    stats->pipeline_cache_evictions = state.pipelineEvictions;
    stats->pipeline_cache_invalidations = state.pipelineInvalidations;
    stats->pipeline_cache_rejections = state.pipelineRejections;
    stats->library_cache_entry_limit = STWO_ZIG_EVAL_LIBRARY_ENTRY_LIMIT;
    stats->library_cache_byte_limit = STWO_ZIG_EVAL_LIBRARY_BYTE_LIMIT;
    stats->pipeline_cache_entry_limit = STWO_ZIG_EVAL_PIPELINE_ENTRY_LIMIT;
    stats->pipeline_cache_byte_limit = STWO_ZIG_EVAL_PIPELINE_BYTE_LIMIT;
}

static id<MTLComputePipelineState> resolve_eval_pipeline(
    StwoZigMetalRuntime *runtime, StwoZigEvalLibrary *library, NSString *name,
    char *error_message, size_t error_message_len
) {
    @synchronized(runtime) {
        CFAbsoluteTime prepareStart = CFAbsoluteTimeGetCurrent();
        @try {
            if (library.runtimeOwner != runtime || library.library.device != runtime.device) {
                write_error(error_message, error_message_len,
                            @"Metal evaluation library belongs to a different runtime or device");
                return nil;
            }
            StwoZigEvalPipelineKey *pipelineKey = nil;
            if (library.cacheKey != nil) {
                StwoZigEvalLibrary *resident = runtime.evalLibraries[library.cacheKey];
                if (resident == nil) {
                    cache_eval_library(runtime, library, library.cacheKey, library.cacheByteCost);
                    resident = runtime.evalLibraries[library.cacheKey];
                } else {
                    touch_eval_cache_key(eval_cache_state(runtime).libraryLru, library.cacheKey);
                }
                if (resident != nil) pipelineKey = eval_pipeline_key(library.cacheKey, name);
                if (pipelineKey != nil) {
                    id<MTLComputePipelineState> cached = runtime.evalPipelines[pipelineKey];
                    if (cached != nil) {
                        runtime.evalPipelineCacheHits += 1u;
                        touch_eval_cache_key(eval_cache_state(runtime).pipelineLru, pipelineKey);
                        return cached;
                    }
                }
            }

            id<MTLFunction> function = [library.library newFunctionWithName:name];
            if (function == nil) {
                write_error(error_message, error_message_len,
                            [NSString stringWithFormat:@"Missing Metal function %@", name]);
                return nil;
            }

            NSError *error = nil;
            id<MTLComputePipelineState> pipeline = nil;
            @synchronized(library) {
                MTLComputePipelineDescriptor *descriptor = [MTLComputePipelineDescriptor new];
                descriptor.computeFunction = function;
                if (library.archive != nil) {
                    descriptor.binaryArchives = @[library.archive];

                    if (library.archiveLoaded) {
                        pipeline = [runtime.device newComputePipelineStateWithDescriptor:descriptor
                            options:MTLPipelineOptionFailOnBinaryArchiveMiss reflection:nil error:&error];
                        if (pipeline != nil) runtime.evalBinaryArchiveHits += 1u;
                    }
                }
                if (pipeline == nil) {
                    NSError *archiveLookupError = error;
                    error = nil;
                    runtime.evalDirectCompiles += 1u;
                    pipeline = [runtime.device newComputePipelineStateWithFunction:function error:&error];
                    if (pipeline == nil) {
                        write_error(error_message, error_message_len,
                            error.localizedDescription ?: archiveLookupError.localizedDescription ?:
                            @"Failed to compile Metal evaluation pipeline");
                        return nil;
                    }
                    if (library.archive != nil) runtime.evalBinaryArchiveMisses += 1u;
                    // Persistence is best-effort. The directly compiled PSO is already correct;
                    // archive lock, merge, and publication failures must not fail proving.
                    (void)eval_archive_store_publish_pipeline(runtime, library, descriptor);
                }
            }

            if (pipeline == nil) {
                write_error(error_message, error_message_len,
                            error.localizedDescription ?: @"Failed to resolve Metal evaluation pipeline");
                return nil;
            }
            stwo_zig_metal_profile_name_pipeline(pipeline, name);
            if (pipelineKey != nil) cache_eval_pipeline(runtime, pipeline, pipelineKey);
            return pipeline;
        } @finally {
            runtime.evalPipelinePreparationSeconds += CFAbsoluteTimeGetCurrent() - prepareStart;
        }
    }
}

static id<MTLLibrary> eval_library_from_data(
    id<MTLDevice> device,
    NSData *libraryData,
    NSError **error
) {
    void *ownedBytes = malloc(libraryData.length);
    if (ownedBytes == NULL) return nil;
    memcpy(ownedBytes, libraryData.bytes, libraryData.length);
    dispatch_data_t data = dispatch_data_create(
        ownedBytes,
        libraryData.length,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^{ free(ownedBytes); }
    );
    if (data == nil) {
        free(ownedBytes);
        return nil;
    }
    return [device newLibraryWithData:data error:error];
}

void *stwo_zig_metal_eval_library_load(
    void *runtime_ptr, const char *path_bytes, size_t path_len,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || path_bytes == NULL || path_len == 0u) return NULL;
    @autoreleasepool {
        CFAbsoluteTime prepareStart = CFAbsoluteTimeGetCurrent();
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSString *path = [[NSString alloc] initWithBytes:path_bytes length:path_len encoding:NSUTF8StringEncoding];
        if (path == nil) { write_error(error_message, error_message_len, @"Invalid metallib path encoding"); return NULL; }
        NSString *canonicalPath = [[path stringByStandardizingPath] stringByResolvingSymlinksInPath];
        NSError *error = nil;
        NSData *libraryData = [NSData dataWithContentsOfFile:canonicalPath
            options:NSDataReadingMappedIfSafe error:&error];
        if (libraryData == nil || libraryData.length == 0u) {
            write_error(error_message, error_message_len,
                        error.localizedDescription ?: @"Failed to read Metal evaluation library");
            return NULL;
        }
        NSString *libraryDigest = eval_sha256_hex(libraryData.bytes, libraryData.length);
        if (libraryDigest == nil || libraryDigest.length != CC_SHA256_DIGEST_LENGTH * 2u) {
            write_error(error_message, error_message_len, @"Failed to identify Metal evaluation library");
            return NULL;
        }
        @synchronized(runtime) {
            StwoZigEvalLibraryKey *cacheKey = eval_library_key(
                eval_cache_state(runtime).runtimeIdentity,
                StwoZigEvalLibraryKindMetallib,
                libraryDigest,
                (uint64_t)libraryData.length
            );
            if (cacheKey == nil) {
                write_error(error_message, error_message_len, @"Failed to key Metal evaluation library");
                return NULL;
            }
            StwoZigEvalLibrary *cached = runtime.evalLibraries[cacheKey];
            if (cached != nil) {
                if (cached.sourceBytes == nil || ![cached.sourceBytes isEqualToData:libraryData]) {
                    write_error(error_message, error_message_len, @"Metal library cache identity collision");
                    return NULL;
                }
                runtime.evalLibraryCacheHits += 1u;
                touch_eval_cache_key(eval_cache_state(runtime).libraryLru, cacheKey);
                return (__bridge_retained void *)cached;
            }
            runtime.evalLibraryCacheMisses += 1u;
            @try {
                id<MTLLibrary> metalLibrary = eval_library_from_data(runtime.device, libraryData, &error);
                if (metalLibrary == nil) {
                    write_error(error_message, error_message_len,
                                error.localizedDescription ?: @"Failed to load Metal evaluation library");
                    return NULL;
                }
                StwoZigEvalLibrary *result = [StwoZigEvalLibrary new];
                result.library = metalLibrary;
                result.cacheKey = cacheKey;
                result.sourceBytes = libraryData;
                result.runtimeOwner = runtime;
                result.cacheByteCost = (uint64_t)libraryData.length;
                result.archiveKey = eval_archive_key(cacheKey);
                eval_archive_store_prepare_library(runtime, result);
                cache_eval_library(runtime, result, cacheKey, (uint64_t)libraryData.length);
                return (__bridge_retained void *)result;
            } @finally {
                runtime.evalLibraryPreparationSeconds += CFAbsoluteTimeGetCurrent() - prepareStart;
            }
        }
    }
}

void *stwo_zig_metal_eval_library_compile(
    void *runtime_ptr, const char *source_bytes, size_t source_len,
    char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || source_bytes == NULL || source_len == 0u) return NULL;
    @autoreleasepool {
        CFAbsoluteTime prepareStart = CFAbsoluteTimeGetCurrent();
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSString *source = [[NSString alloc] initWithBytes:source_bytes length:source_len encoding:NSUTF8StringEncoding];
        if (source == nil) {
            write_error(error_message, error_message_len, @"Invalid Metal source library encoding");
            return NULL;
        }
        NSString *sourceDigest = eval_sha256_hex(source_bytes, source_len);
        NSData *sourceData = [NSData dataWithBytes:source_bytes length:source_len];
        if (sourceDigest == nil || sourceDigest.length != CC_SHA256_DIGEST_LENGTH * 2u || sourceData == nil) {
            write_error(error_message, error_message_len, @"Failed to identify Metal source library");
            return NULL;
        }
        @synchronized(runtime) {
            StwoZigEvalLibraryKey *cacheKey = eval_library_key(
                eval_cache_state(runtime).runtimeIdentity,
                StwoZigEvalLibraryKindSource,
                sourceDigest,
                (uint64_t)source_len
            );
            if (cacheKey == nil) {
                write_error(error_message, error_message_len, @"Failed to key Metal source library");
                return NULL;
            }
            StwoZigEvalLibrary *cached = runtime.evalLibraries[cacheKey];
            if (cached != nil) {
                if (cached.sourceBytes == nil || ![cached.sourceBytes isEqualToData:sourceData]) {
                    write_error(error_message, error_message_len, @"Metal source cache identity collision");
                    return NULL;
                }
                runtime.evalLibraryCacheHits += 1u;
                touch_eval_cache_key(eval_cache_state(runtime).libraryLru, cacheKey);
                return (__bridge_retained void *)cached;
            }
            runtime.evalLibraryCacheMisses += 1u;
            @try {
                MTLCompileOptions *options = [MTLCompileOptions new];
                stwo_zig_configure_safe_metal_compile_options(options);
                NSError *error = nil;
                id<MTLLibrary> library = [runtime.device newLibraryWithSource:source options:options error:&error];
                if (library == nil) {
                    write_error(error_message, error_message_len,
                                error.localizedDescription ?: @"Failed to compile Metal source library");
                    return NULL;
                }
                StwoZigEvalLibrary *result = [StwoZigEvalLibrary new];
                result.library = library;
                result.cacheKey = cacheKey;
                result.sourceBytes = sourceData;
                result.runtimeOwner = runtime;
                result.cacheByteCost = (uint64_t)sourceData.length;
                result.archiveKey = eval_archive_key(cacheKey);
                eval_archive_store_prepare_library(runtime, result);
                cache_eval_library(runtime, result, cacheKey, (uint64_t)sourceData.length);
                return (__bridge_retained void *)result;
            } @finally {
                runtime.evalLibraryPreparationSeconds += CFAbsoluteTimeGetCurrent() - prepareStart;
            }
        }
    }
}

void stwo_zig_metal_eval_library_destroy(void *library_ptr) {
    if (library_ptr == NULL) return;
    StwoZigEvalLibrary *library = (__bridge StwoZigEvalLibrary *)library_ptr;
    if (library.archiveDirty) {
        NSError *error = nil;
        bool didSerialize = false;
        if (!serialize_eval_archive(library, &error, &didSerialize)) {
            fprintf(stderr, "Failed to serialize released Metal binary archive: %s\n",
                    error.localizedDescription.UTF8String ?: "unknown Metal error");
        } else if (didSerialize) {
            StwoZigMetalRuntime *runtime = library.runtimeOwner;
            if (runtime != nil) {
                @synchronized(runtime) { runtime.evalArchiveSerializations += 1u; }
            }
        }
    }
    CFRelease(library_ptr);
}

void *stwo_zig_metal_witness_prepare_library(
    void *runtime_ptr, void *library_ptr, const char *name_bytes, size_t name_len,
    const uint32_t *arguments, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || library_ptr == NULL || name_bytes == NULL || name_len == 0u ||
        arguments == NULL || arguments[7] == 0u) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigEvalLibrary *library = (__bridge StwoZigEvalLibrary *)library_ptr;
        NSString *name = [[NSString alloc] initWithBytes:name_bytes length:name_len encoding:NSUTF8StringEncoding];
        if (name == nil) { write_error(error_message, error_message_len, @"Invalid Metal witness function encoding"); return NULL; }
        id<MTLComputePipelineState> pipeline =
            resolve_eval_pipeline(runtime, library, name, error_message, error_message_len);
        if (pipeline == nil) return NULL;
        StwoZigWitnessPlan *plan = [StwoZigWitnessPlan new];
        plan.pipeline = pipeline;
        plan.arguments = [runtime.device newBufferWithBytes:arguments length:11u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.rowCount = arguments[7];
        if (plan.arguments == nil) { write_error(error_message, error_message_len, @"Metal witness argument allocation failed"); return NULL; }
        return (__bridge_retained void *)plan;
    }
}

void stwo_zig_metal_witness_plan_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

bool stwo_zig_metal_witness_prepared(
    void *runtime_ptr, void *arena_ptr, void *plan_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || plan_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigWitnessPlan *plan = (__bridge StwoZigWitnessPlan *)plan_ptr;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        [encoder setComputePipelineState:plan.pipeline]; [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBuffer:plan.arguments offset:0 atIndex:1];
        NSUInteger width = MIN((NSUInteger)256u, MIN((NSUInteger)plan.rowCount, plan.pipeline.maxTotalThreadsPerThreadgroup));
        [encoder dispatchThreads:MTLSizeMake(plan.rowCount, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) { write_error(error_message, error_message_len, command.error.localizedDescription); return false; }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}

void *stwo_zig_metal_eval_prepare_library(
    void *runtime_ptr, void *library_ptr, const char *name_bytes, size_t name_len,
    const uint32_t *arguments, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || library_ptr == NULL || name_bytes == NULL || name_len == 0u ||
        arguments == NULL || arguments[10] == 0u) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigEvalLibrary *library = (__bridge StwoZigEvalLibrary *)library_ptr;
        NSString *name = [[NSString alloc] initWithBytes:name_bytes length:name_len encoding:NSUTF8StringEncoding];
        if (name == nil) { write_error(error_message, error_message_len, @"Invalid Metal function encoding"); return NULL; }
        id<MTLComputePipelineState> pipeline =
            resolve_eval_pipeline(runtime, library, name, error_message, error_message_len);
        if (pipeline == nil) return NULL;
        StwoZigEvalPlan *plan = [StwoZigEvalPlan new];
        plan.pipeline = pipeline;
        plan.arguments = [runtime.device newBufferWithBytes:arguments length:14u * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        plan.rowCount = arguments[10];
        plan.dispatchWidth = eval_dispatch_width(pipeline, plan.rowCount);
        if (plan.arguments == nil) { write_error(error_message, error_message_len, @"Metal evaluation argument allocation failed"); return NULL; }
        return (__bridge_retained void *)plan;
    }
}

bool stwo_zig_metal_eval_library_serialize(
    void *library_ptr, char *error_message, size_t error_message_len
) {
    if (library_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigEvalLibrary *library = (__bridge StwoZigEvalLibrary *)library_ptr;
        NSError *error = nil;
        bool didSerialize = false;
        if (!serialize_eval_archive(library, &error, &didSerialize)) {
            write_error(error_message, error_message_len, error.localizedDescription ?: @"Failed to serialize Metal binary archive");
            return false;
        }
        StwoZigMetalRuntime *runtimeOwner = library.runtimeOwner;
        if (didSerialize && runtimeOwner != nil) {
            @synchronized(runtimeOwner) {
                runtimeOwner.evalArchiveSerializations += 1u;
            }
        }
        return true;
    }
}

void stwo_zig_metal_eval_destroy(void *plan_ptr) {
    if (plan_ptr != NULL) CFRelease(plan_ptr);
}

void *stwo_zig_metal_eval_batch_prepare(
    const void *const *plan_ptrs, uint32_t plan_count,
    char *error_message, size_t error_message_len
) {
    if (plan_ptrs == NULL || plan_count == 0u) return NULL;
    @autoreleasepool {
        NSMutableArray<StwoZigEvalPlan *> *plans = [NSMutableArray arrayWithCapacity:plan_count];
        for (uint32_t i = 0; i < plan_count; ++i) {
            if (plan_ptrs[i] == NULL) {
                write_error(error_message, error_message_len, @"Null Metal evaluation plan in batch"); return NULL;
            }
            [plans addObject:(__bridge StwoZigEvalPlan *)plan_ptrs[i]];
        }
        StwoZigEvalBatch *batch = [StwoZigEvalBatch new];
        batch.plans = plans;
        return (__bridge_retained void *)batch;
    }
}

void stwo_zig_metal_eval_batch_destroy(void *batch_ptr) {
    if (batch_ptr != NULL) CFRelease(batch_ptr);
}

bool stwo_zig_metal_eval_batch_prepared(
    void *runtime_ptr, void *arena_ptr, void *batch_ptr,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if (runtime_ptr == NULL || arena_ptr == NULL || batch_ptr == NULL) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> arena = (__bridge id<MTLBuffer>)arena_ptr;
        StwoZigEvalBatch *batch = (__bridge StwoZigEvalBatch *)batch_ptr;
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        for (StwoZigEvalPlan *plan in batch.plans) {
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            [encoder setComputePipelineState:plan.pipeline];
            [encoder setBuffer:arena offset:0 atIndex:0];
            [encoder setBuffer:plan.arguments offset:0 atIndex:1];
            [encoder dispatchThreads:MTLSizeMake(plan.rowCount, 1u, 1u) threadsPerThreadgroup:MTLSizeMake(plan.dispatchWidth, 1u, 1u)];
            [encoder endEncoding];
        }
        [command commit]; [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription); return false;
        }
        if (gpu_milliseconds) *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        return true;
    }
}
