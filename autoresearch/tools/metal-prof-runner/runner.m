// stwo-prof generic Metal kernel runner.
//
// Compiles a .metal source at runtime (profiling lane only — production
// admission still rejects JIT), binds buffers in declaration order, and
// times each dispatch with command-buffer GPUStartTime/GPUEndTime. Emits
// one JSON object on stdout.
//
// Usage:
//   runner --caps
//   runner --source k.metal --entry name --grid 1048576 [--tg 256]
//          [--iters 50] [--buffers f32:1048576,f32:1048576,f32:1048576]
//
// Buffer spec: comma-separated type:elements with type in {f32,u32,u64}.
// Buffer 0 is zero-filled (treated as output); the rest get deterministic
// pseudo-random fill so runs are reproducible.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

static NSString *argValue(NSArray<NSString *> *args, NSString *flag, NSString *fallback) {
    NSUInteger i = [args indexOfObject:flag];
    if (i == NSNotFound || i + 1 >= args.count) return fallback;
    return args[i + 1];
}

static void fail(NSString *message) {
    fprintf(stderr, "metal-prof-runner: %s\n", message.UTF8String);
    exit(1);
}

int main(void) {
    @autoreleasepool {
        NSArray<NSString *> *args = [[NSProcessInfo processInfo] arguments];
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) fail(@"no Metal device");

        if ([args containsObject:@"--caps"]) {
            NSDictionary *caps = @{
                @"device" : device.name,
                @"unified_memory" : @(device.hasUnifiedMemory),
                @"max_threadgroup_memory_bytes" : @(device.maxThreadgroupMemoryLength),
                @"max_threads_per_threadgroup" : @(device.maxThreadsPerThreadgroup.width),
                @"recommended_working_set_bytes" : @(device.recommendedMaxWorkingSetSize),
            };
            NSData *json = [NSJSONSerialization dataWithJSONObject:caps options:0 error:nil];
            printf("%s\n", [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding].UTF8String);
            return 0;
        }

        NSString *sourcePath = argValue(args, @"--source", nil);
        NSString *entry = argValue(args, @"--entry", nil);
        if (!sourcePath || !entry) fail(@"--source and --entry are required");
        NSUInteger grid = (NSUInteger)[argValue(args, @"--grid", @"1048576") longLongValue];
        NSUInteger tg = (NSUInteger)[argValue(args, @"--tg", @"256") longLongValue];
        NSUInteger iters = (NSUInteger)[argValue(args, @"--iters", @"50") longLongValue];
        NSString *bufferSpec = argValue(args, @"--buffers", @"f32:1048576,f32:1048576,f32:1048576");

        NSError *error = nil;
        NSString *source = [NSString stringWithContentsOfFile:sourcePath
                                                     encoding:NSUTF8StringEncoding
                                                        error:&error];
        if (!source) fail([NSString stringWithFormat:@"cannot read %@", sourcePath]);
        id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
        if (!library) fail([NSString stringWithFormat:@"compile failed: %@", error.localizedDescription]);
        id<MTLFunction> fn = [library newFunctionWithName:entry];
        if (!fn) fail([NSString stringWithFormat:@"entry '%@' not found", entry]);
        id<MTLComputePipelineState> pso = [device newComputePipelineStateWithFunction:fn error:&error];
        if (!pso) fail([NSString stringWithFormat:@"pipeline failed: %@", error.localizedDescription]);

        NSMutableArray<id<MTLBuffer>> *buffers = [NSMutableArray array];
        NSUInteger index = 0;
        for (NSString *spec in [bufferSpec componentsSeparatedByString:@","]) {
            NSArray<NSString *> *parts = [spec componentsSeparatedByString:@":"];
            if (parts.count != 2) fail(@"buffer spec must be type:elements");
            NSUInteger elems = (NSUInteger)[parts[1] longLongValue];
            NSUInteger width = [parts[0] isEqualToString:@"u64"] ? 8 : 4;
            id<MTLBuffer> buffer = [device newBufferWithLength:elems * width
                                                       options:MTLResourceStorageModeShared];
            if (index > 0) { // deterministic fill; buffer 0 stays zeroed as output
                uint32_t *words = (uint32_t *)buffer.contents;
                uint64_t state = 0x9E3779B97F4A7C15ULL + index;
                for (NSUInteger w = 0; w < (elems * width) / 4; w++) {
                    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
                    words[w] = (uint32_t)(state >> 33);
                }
            }
            [buffers addObject:buffer];
            index++;
        }

        id<MTLCommandQueue> queue = [device newCommandQueue];
        MTLSize gridSize = MTLSizeMake(grid, 1, 1);
        MTLSize tgSize = MTLSizeMake(MIN(tg, pso.maxTotalThreadsPerThreadgroup), 1, 1);

        NSMutableArray<NSNumber *> *gpuMs = [NSMutableArray array];
        NSUInteger warmup = 3;
        for (NSUInteger it = 0; it < iters + warmup; it++) {
            id<MTLCommandBuffer> cb = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:pso];
            for (NSUInteger b = 0; b < buffers.count; b++) {
                [enc setBuffer:buffers[b] offset:0 atIndex:b];
            }
            [enc dispatchThreads:gridSize threadsPerThreadgroup:tgSize];
            [enc endEncoding];
            [cb commit];
            [cb waitUntilCompleted];
            if (cb.error) fail([NSString stringWithFormat:@"command failed: %@", cb.error]);
            if (it >= warmup) {
                [gpuMs addObject:@((cb.GPUEndTime - cb.GPUStartTime) * 1000.0)];
            }
        }

        NSArray<NSNumber *> *sorted = [gpuMs sortedArrayUsingSelector:@selector(compare:)];
        double median = sorted[sorted.count / 2].doubleValue;
        NSDictionary *result = @{
            @"device" : device.name,
            @"entry" : entry,
            @"grid" : @(grid),
            @"threadgroup" : @(tgSize.width),
            @"iterations" : @(iters),
            @"gpu_ms_median" : @(median),
            @"gpu_ms_min" : @(sorted.firstObject.doubleValue),
            @"gpu_ms_max" : @(sorted.lastObject.doubleValue),
            @"pipeline" : @{
                @"max_total_threads_per_threadgroup" : @(pso.maxTotalThreadsPerThreadgroup),
                @"thread_execution_width" : @(pso.threadExecutionWidth),
                @"static_threadgroup_memory_bytes" : @(pso.staticThreadgroupMemoryLength),
            },
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:result options:0 error:nil];
        printf("%s\n", [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding].UTF8String);
    }
    return 0;
}
