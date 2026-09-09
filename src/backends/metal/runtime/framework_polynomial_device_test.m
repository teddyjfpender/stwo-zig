#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// Test-only source compilation. Production admission must use pinned AOT code.
@interface StwoFrameworkPolynomialDeviceTest : NSObject
@property(nonatomic, strong) id<MTLDevice> device;
@property(nonatomic, strong) id<MTLCommandQueue> queue;
@property(nonatomic, strong) id<MTLComputePipelineState> pipeline;
@end
@implementation StwoFrameworkPolynomialDeviceTest
@end

void *stwo_framework_polynomial_test_create(
    const char *source, size_t source_length,
    const char *name, size_t name_length
) {
    @autoreleasepool {
        StwoFrameworkPolynomialDeviceTest *context = [StwoFrameworkPolynomialDeviceTest new];
        context.device = MTLCreateSystemDefaultDevice();
        context.queue = [context.device newCommandQueue];
        if (context.device == nil || context.queue == nil) return NULL;
        NSString *source_string = [[NSString alloc] initWithBytes:source length:source_length
                                                       encoding:NSUTF8StringEncoding];
        NSString *name_string = [[NSString alloc] initWithBytes:name length:name_length
                                                     encoding:NSUTF8StringEncoding];
        MTLCompileOptions *options = [MTLCompileOptions new];
        options.fastMathEnabled = NO;
        NSError *error = nil;
        id<MTLLibrary> library = [context.device newLibraryWithSource:source_string
                                                              options:options error:&error];
        id<MTLFunction> function = [library newFunctionWithName:name_string];
        if (function != nil)
            context.pipeline = [context.device newComputePipelineStateWithFunction:function error:&error];
        if (context.pipeline == nil) {
            NSLog(@"framework-polynomial test compilation failed: %@", error);
            return NULL;
        }
        return (__bridge_retained void *)context;
    }
}

void stwo_framework_polynomial_test_destroy(void *opaque) {
    if (opaque != NULL) {
        __unused id released = CFBridgingRelease(opaque);
    }
}

// No field arithmetic here: upload, execute the generated kernel, download.
// Output contains a guard tail; surplus threads exercise the kernel row guard.
bool stwo_framework_polynomial_test_run(
    void *opaque,
    const uint32_t *tree0, size_t tree0_words,
    const uint32_t *tree1, size_t tree1_words,
    const uint32_t *tree2, size_t tree2_words,
    const uint64_t *offsets, size_t offset_count,
    const uint32_t *profile, size_t profile_words,
    const uint32_t *relations, size_t relation_words,
    const uint32_t *powers, size_t power_words,
    uint32_t *output, size_t output_words,
    uint32_t row_count, const uint32_t *denominators, uint32_t denominator_count,
    uint32_t repetitions
) {
    if (opaque == NULL || row_count == 0 || denominator_count == 0 ||
        repetitions == 0 || output_words < (size_t)row_count * 4u) return false;
    @autoreleasepool {
        StwoFrameworkPolynomialDeviceTest *context = (__bridge StwoFrameworkPolynomialDeviceTest *)opaque;
        const void *data[] = {tree0, tree1, tree2, offsets, profile, relations, powers, output};
        const size_t bytes[] = {
            tree0_words * 4u, tree1_words * 4u, tree2_words * 4u, offset_count * 8u,
            profile_words * 4u, relation_words * 4u, power_words * 4u, output_words * 4u
        };
        id<MTLBuffer> buffers[8];
        for (NSUInteger i = 0; i < 8; ++i) {
            if (data[i] == NULL || bytes[i] == 0) return false;
            buffers[i] = [context.device newBufferWithBytes:data[i] length:bytes[i]
                                                    options:MTLResourceStorageModeShared];
            if (buffers[i] == nil) return false;
        }
        id<MTLCommandBuffer> command = [context.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (command == nil || encoder == nil) return false;
        [encoder setComputePipelineState:context.pipeline];
        for (NSUInteger i = 0; i < 8; ++i) [encoder setBuffer:buffers[i] offset:0 atIndex:i];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:8];
        [encoder setBytes:denominators length:(size_t)denominator_count * 4u atIndex:9];
        [encoder setBytes:&denominator_count length:sizeof(denominator_count) atIndex:10];
        const NSUInteger width = MIN(context.pipeline.maxTotalThreadsPerThreadgroup,
                                     context.pipeline.threadExecutionWidth * 8u);
        for (uint32_t iteration = 0; iteration < repetitions; ++iteration) {
            [encoder dispatchThreads:MTLSizeMake(row_count + 7u, 1u, 1u)
                threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
            if (iteration + 1u < repetitions)
                [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        }
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            NSLog(@"framework-polynomial test execution failed: %@", command.error);
            return false;
        }
        memcpy(output, buffers[7].contents, bytes[7]);
        return true;
    }
}
