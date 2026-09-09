#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// Focused test-only probe linked solely into test-composition-task-profile.
// It mirrors the production generated kernels' shared-output read/add/write
// dependency without requiring a proof-resident trace.
bool stwo_zig_metal_test_composition_dispatch_barrier(
    uint32_t mode,
    bool reverse,
    uint32_t *result,
    uint32_t row_count
) {
    if (result == NULL || row_count == 0u || mode > 1u) return false;
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (device == nil || queue == nil) return false;
        static NSString *source =
            @"#include <metal_stdlib>\n"
             "using namespace metal;\n"
             "kernel void add_shared_output(device uint *out [[buffer(0)]],\n"
             "                              constant uint &value [[buffer(1)]],\n"
             "                              uint row [[thread_position_in_grid]]) {\n"
             "  uint sum = out[row] + value;\n"
             "  out[row] = sum >= 0x7fffffffu ? sum - 0x7fffffffu : sum;\n"
             "}\n";
        MTLCompileOptions *options = [MTLCompileOptions new];
        options.fastMathEnabled = NO;
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:source
                                                    options:options
                                                      error:&error];
        id<MTLFunction> function = [library newFunctionWithName:@"add_shared_output"];
        id<MTLComputePipelineState> pipeline =
            function == nil ? nil : [device newComputePipelineStateWithFunction:function
                                                                     error:&error];
        if (library == nil || function == nil || pipeline == nil) {
            NSLog(@"composition-barrier Metal compilation failed: %@", error);
            return false;
        }
        const NSUInteger byte_count = (NSUInteger)row_count * sizeof(uint32_t);
        id<MTLBuffer> output = [device newBufferWithLength:byte_count
                                                   options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> command = [queue commandBuffer];
        if (pipeline == nil || output == nil || output.contents == NULL || command == nil)
            return false;
        memset(output.contents, 0, byte_count);

        const uint32_t values[2] = { reverse ? 11u : 7u, reverse ? 7u : 11u };
        const NSUInteger width = MIN(
            pipeline.maxTotalThreadsPerThreadgroup,
            pipeline.threadExecutionWidth * 8u
        );
        if (mode == 0u) {
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            if (encoder == nil) return false;
            [encoder setComputePipelineState:pipeline];
            for (uint32_t index = 0u; index < 2u; ++index) {
                [encoder setBuffer:output offset:0u atIndex:0];
                [encoder setBytes:&values[index] length:sizeof(uint32_t) atIndex:1];
                [encoder dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
                    threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                if (index == 0u)
                    [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
            }
            [encoder endEncoding];
        } else {
            for (uint32_t index = 0u; index < 2u; ++index) {
                id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
                if (encoder == nil) return false;
                [encoder setComputePipelineState:pipeline];
                [encoder setBuffer:output offset:0u atIndex:0];
                [encoder setBytes:&values[index] length:sizeof(uint32_t) atIndex:1];
                [encoder dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
                    threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
                [encoder endEncoding];
            }
        }
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) return false;
        memcpy(result, output.contents, byte_count);
        return true;
    }
}

// Executes the exact address arithmetic used by generated RISC-V polynomial
// kernels without allocating a 2^24-row trace. This catches the silent uint
// aliases 256->0 and 339->83 while proving the widened Metal expression.
bool stwo_zig_metal_test_wide_column_offsets(
    uint64_t (*wide_offsets)[4],
    uint32_t (*wrapped_offsets)[4]
) {
    if (wide_offsets == NULL || wrapped_offsets == NULL) return false;
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (device == nil || queue == nil) return false;
        static NSString *source =
            @"#include <metal_stdlib>\n"
             "using namespace metal;\n"
             "kernel void wide_offsets(device ulong *wide [[buffer(0)]],\n"
             "                         device uint *wrapped [[buffer(1)]],\n"
             "                         uint index [[thread_position_in_grid]]) {\n"
             "  uint columns[4] = {254u, 255u, 256u, 339u};\n"
             "  uint column = columns[index];\n"
             "  uint rows = 1u << 24u;\n"
             "  uint row = 7u;\n"
             "  wide[index] = ulong(column) * ulong(rows) + ulong(row);\n"
             "  wrapped[index] = column * rows + row;\n"
             "}\n";
        MTLCompileOptions *options = [MTLCompileOptions new];
        options.fastMathEnabled = NO;
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:source
                                                    options:options
                                                      error:&error];
        id<MTLFunction> function = [library newFunctionWithName:@"wide_offsets"];
        id<MTLComputePipelineState> pipeline =
            function == nil ? nil : [device newComputePipelineStateWithFunction:function
                                                                     error:&error];
        if (library == nil || function == nil || pipeline == nil) {
            NSLog(@"wide-column-offset Metal compilation failed: %@", error);
            return false;
        }
        id<MTLBuffer> wide = [device newBufferWithLength:sizeof(*wide_offsets)
                                                 options:MTLResourceStorageModeShared];
        id<MTLBuffer> wrapped = [device newBufferWithLength:sizeof(*wrapped_offsets)
                                                    options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> command = [queue commandBuffer];
        if (wide == nil || wrapped == nil || command == nil ||
            wide.contents == NULL || wrapped.contents == NULL)
            return false;
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (encoder == nil) return false;
        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:wide offset:0u atIndex:0];
        [encoder setBuffer:wrapped offset:0u atIndex:1];
        [encoder dispatchThreads:MTLSizeMake(4u, 1u, 1u)
            threadsPerThreadgroup:MTLSizeMake(4u, 1u, 1u)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            NSLog(@"wide-column-offset Metal execution failed: %@", command.error);
            return false;
        }
        memcpy(wide_offsets, wide.contents, sizeof(*wide_offsets));
        memcpy(wrapped_offsets, wrapped.contents, sizeof(*wrapped_offsets));
        return true;
    }
}
