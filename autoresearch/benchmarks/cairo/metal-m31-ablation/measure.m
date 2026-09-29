#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint32_t prime = 0x7fffffffu;
static double execute(id<MTLCommandQueue> queue, id<MTLComputePipelineState> pipeline,
                      id<MTLBuffer> a, id<MTLBuffer> b, id<MTLBuffer> out,
                      uint32_t rows, uint32_t rounds) {
    id<MTLCommandBuffer> command = [queue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:a offset:0 atIndex:0];
    [encoder setBuffer:b offset:0 atIndex:1];
    [encoder setBuffer:out offset:0 atIndex:2];
    [encoder setBytes:&rounds length:sizeof(rounds) atIndex:3];
    NSUInteger width = MIN((NSUInteger)256, pipeline.maxTotalThreadsPerThreadgroup);
    [encoder dispatchThreads:MTLSizeMake(rows, 1, 1) threadsPerThreadgroup:MTLSizeMake(width, 1, 1)];
    [encoder endEncoding];
    [command commit]; [command waitUntilCompleted];
    if (command.status == MTLCommandBufferStatusError) {
        fprintf(stderr, "%s\n", command.error.description.UTF8String); exit(2);
    }
    return (command.GPUEndTime - command.GPUStartTime) * 1000.0;
}
static uint32_t reference(uint32_t a, uint32_t b, uint32_t rounds) {
    for (uint32_t r = 0; r < rounds; ++r) {
        a = (uint32_t)(((uint64_t)a * b + 43u) % prime);
        b = (b + 97u) % prime;
    }
    return a;
}
int main(int argc, char **argv) { @autoreleasepool {
    if (argc != 5) { fprintf(stderr, "usage: measure library rows rounds repeats\n"); return 2; }
    uint32_t rows = (uint32_t)strtoul(argv[2], NULL, 10);
    uint32_t rounds = (uint32_t)strtoul(argv[3], NULL, 10);
    uint32_t repeats = (uint32_t)strtoul(argv[4], NULL, 10);
    if (rows < 4096 || rows > (1u << 26) || rounds == 0 || rounds > 4096 || repeats < 3 || repeats > 100) return 2;
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (device == nil) return 2;
    NSError *error = nil;
    id<MTLLibrary> library = [device newLibraryWithURL:[NSURL fileURLWithPath:@(argv[1])] error:&error];
    if (library == nil) { fprintf(stderr, "%s\n", error.description.UTF8String); return 2; }
    NSArray *names = @[@"wide_variant", @"narrow_fold_variant", @"split_product_variant"];
    NSMutableArray *pipelines = [NSMutableArray array];
    NSMutableArray *prepare = [NSMutableArray array];
    NSMutableArray *initial = [NSMutableArray array];
    NSMutableArray *samples = [NSMutableArray array];
    for (NSString *name in names) {
        CFAbsoluteTime started = CFAbsoluteTimeGetCurrent();
        id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:[library newFunctionWithName:name] error:&error];
        if (pipeline == nil) { fprintf(stderr, "%s\n", error.description.UTF8String); return 2; }
        [pipelines addObject:pipeline];
        [prepare addObject:@((CFAbsoluteTimeGetCurrent() - started) * 1000.0)];
        [samples addObject:[NSMutableArray array]];
    }
    id<MTLCommandQueue> queue = [device newCommandQueue];
    NSUInteger bytes = (NSUInteger)rows * sizeof(uint32_t);
    id<MTLBuffer> a = [device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> b = [device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> out = [device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
    uint32_t *baseline = malloc(bytes);
    if (a == nil || b == nil || out == nil || baseline == NULL) return 2;
    uint32_t *av = a.contents, *bv = b.contents;
    uint32_t seed = 0x613ab2f7u;
    for (uint32_t row = 0; row < rows; ++row) {
        seed = seed * 1664525u + 1013904223u; av[row] = seed % prime;
        seed = seed * 1664525u + 1013904223u; bv[row] = seed % prime;
    }
    const uint32_t edges[] = {0, 1, 2, 15, 65535, 65536, prime - 2, prime - 1};
    for (uint32_t x = 0; x < 8; ++x) for (uint32_t y = 0; y < 8; ++y) {
        av[x * 8 + y] = edges[x]; bv[x * 8 + y] = edges[y];
    }
    for (NSUInteger variant = 0; variant < 3; ++variant) {
        [initial addObject:@(execute(queue, pipelines[variant], a, b, out, rows, rounds))];
        if (variant == 0) memcpy(baseline, out.contents, bytes);
        else if (memcmp(baseline, out.contents, bytes) != 0) return 3;
    }
    for (uint32_t row = 0; row < 4096; ++row)
        if (baseline[row] != reference(av[row], bv[row], rounds)) return 3;
    for (uint32_t round = 0; round < repeats; ++round) for (uint32_t item = 0; item < 3; ++item) {
        uint32_t variant = (round & 1u) ? 2u - item : item;
        [samples[variant] addObject:@(execute(queue, pipelines[variant], a, b, out, rows, rounds))];
        if (memcmp(baseline, out.contents, bytes) != 0) return 3;
    }
    NSMutableArray *results = [NSMutableArray array];
    for (NSUInteger variant = 0; variant < 3; ++variant) {
        NSArray *sorted = [samples[variant] sortedArrayUsingSelector:@selector(compare:)];
        [results addObject:@{@"kernel":names[variant], @"prepare_ms":prepare[variant],
            @"initial_gpu_ms":initial[variant], @"samples_gpu_ms":samples[variant],
            @"median_gpu_ms":sorted[repeats / 2]}];
    }
    NSDictionary *receipt = @{@"schema":@"stwo-metal-m31-ablation-v1", @"status":@"qualified",
        @"device":device.name, @"rows":@(rows), @"rounds_per_row":@(rounds), @"repeats":@(repeats),
        @"exact_variant_comparison_rows":@(rows), @"cpu_reference_rows":@4096,
        @"boundary_operand_pairs":@64, @"schedule":@"ABC,CBA alternating; initial GPU trials retained separately",
        @"results":results};
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:receipt options:NSJSONWritingPrettyPrinted error:&error];
    if (encoded == nil) return 2;
    fwrite(encoded.bytes, 1, encoded.length, stdout); fputc('\n', stdout);
    free(baseline);
    return 0;
} }
