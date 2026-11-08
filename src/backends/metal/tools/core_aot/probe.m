#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <dispatch/dispatch.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#import "../../backends/metal/runtime/compile_options.h"

static void write_error(char *destination, size_t length, NSString *message) {
    if (destination == NULL || length == 0u) return;
    const char *utf8 = message.UTF8String ?: "Metal core library probe failed";
    snprintf(destination, length, "%s", utf8);
}

static NSString *first_name(NSSet<NSString *> *names) {
    return [[names allObjects] sortedArrayUsingSelector:@selector(compare:)].firstObject ?: @"<none>";
}

typedef struct {
    uint32_t secure[12];
    uint32_t queries[13];
} TranscriptOutput;

static bool dispatch_transcript_kernel(
    id<MTLDevice> device,
    id<MTLLibrary> library,
    id<MTLCommandQueue> queue,
    id<MTLBuffer> arena,
    NSString *name,
    const uint32_t *parameters,
    size_t parameter_count,
    NSString **failure
) {
    id<MTLFunction> function = [library newFunctionWithName:name];
    if (function == nil) {
        *failure = [NSString stringWithFormat:@"Parity kernel is missing: %@", name];
        return false;
    }
    NSError *pipeline_error = nil;
    id<MTLComputePipelineState> pipeline =
        [device newComputePipelineStateWithFunction:function error:&pipeline_error];
    if (pipeline == nil) {
        *failure = pipeline_error.localizedDescription ?: @"Failed to create transcript pipeline";
        return false;
    }
    id<MTLCommandBuffer> command = [queue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (command == nil || encoder == nil) {
        *failure = @"Failed to allocate transcript command resources";
        return false;
    }
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:arena offset:0 atIndex:0];
    for (size_t index = 0u; index < parameter_count; ++index) {
        [encoder setBytes:&parameters[index] length:sizeof(uint32_t) atIndex:index + 1u];
    }
    [encoder dispatchThreads:MTLSizeMake(1u, 1u, 1u)
        threadsPerThreadgroup:MTLSizeMake(1u, 1u, 1u)];
    [encoder endEncoding];
    [command commit];
    [command waitUntilCompleted];
    if (command.status != MTLCommandBufferStatusCompleted) {
        *failure = command.error.localizedDescription ?: @"Transcript command did not complete";
        return false;
    }
    return true;
}

static bool run_transcript(
    id<MTLDevice> device,
    id<MTLLibrary> library,
    const uint32_t transcript_source[12],
    TranscriptOutput *output,
    NSString **failure
) {
    const uint32_t state_base = 0u;
    const uint32_t source_base = 32u;
    const uint32_t secure_base = 128u;
    const uint32_t query_base = 192u;
    id<MTLBuffer> arena = [device newBufferWithLength:256u * sizeof(uint32_t)
                                              options:MTLResourceStorageModeShared];
    id<MTLCommandQueue> queue = [device newCommandQueue];
    if (arena == nil || queue == nil) {
        *failure = @"Failed to allocate transcript arena";
        return false;
    }
    memset(arena.contents, 0, arena.length);
    memcpy((uint32_t *)arena.contents + source_base, transcript_source, 12u * sizeof(uint32_t));

    const uint32_t init_parameters[] = {state_base};
    const uint32_t mix_parameters[] = {state_base, source_base, 12u};
    const uint32_t secure_parameters[] = {state_base, secure_base, 3u};
    const uint32_t query_parameters[] = {state_base, query_base, 24u, 13u};
    if (!dispatch_transcript_kernel(device, library, queue, arena,
            @"stwo_zig_transcript_init_resident", init_parameters, 1u, failure) ||
        !dispatch_transcript_kernel(device, library, queue, arena,
            @"stwo_zig_transcript_mix_resident", mix_parameters, 3u, failure) ||
        !dispatch_transcript_kernel(device, library, queue, arena,
            @"stwo_zig_transcript_draw_secure_resident", secure_parameters, 3u, failure) ||
        !dispatch_transcript_kernel(device, library, queue, arena,
            @"stwo_zig_transcript_draw_queries_resident", query_parameters, 4u, failure)) {
        return false;
    }
    const uint32_t *words = arena.contents;
    memcpy(output->secure, words + secure_base, sizeof(output->secure));
    memcpy(output->queries, words + query_base, sizeof(output->queries));
    return true;
}

static bool verify_kernel_parity(
    id<MTLDevice> device,
    id<MTLLibrary> aot_library,
    const uint8_t *source_bytes,
    size_t source_len,
    const uint32_t transcript_source[12],
    const uint32_t expected_secure[12],
    const uint32_t expected_queries[13],
    NSString **failure
) {
    NSString *source = [[NSString alloc] initWithBytes:source_bytes
                                                length:source_len
                                              encoding:NSUTF8StringEncoding];
    if (source == nil) {
        *failure = @"Native source is not valid UTF-8";
        return false;
    }
    MTLCompileOptions *options = [MTLCompileOptions new];
    stwo_zig_configure_safe_metal_compile_options(options);
    NSError *compile_error = nil;
    id<MTLLibrary> jit_library = [device newLibraryWithSource:source
                                                     options:options
                                                       error:&compile_error];
    if (jit_library == nil) {
        *failure = compile_error.localizedDescription ?: @"Failed to compile JIT parity library";
        return false;
    }

    TranscriptOutput aot_output;
    TranscriptOutput jit_output;
    if (!run_transcript(device, aot_library, transcript_source, &aot_output, failure) ||
        !run_transcript(device, jit_library, transcript_source, &jit_output, failure)) return false;
    if (memcmp(&aot_output, &jit_output, sizeof(aot_output)) != 0) {
        *failure = @"AOT and JIT transcript outputs differ";
        return false;
    }
    if (memcmp(aot_output.secure, expected_secure, sizeof(aot_output.secure)) != 0) {
        *failure = @"Transcript secure draw disagrees with the host Blake2s channel";
        return false;
    }
    if (memcmp(aot_output.queries, expected_queries, sizeof(aot_output.queries)) != 0) {
        *failure = @"Transcript queries disagree with the host Blake2s channel";
        return false;
    }
    return true;
}

bool stwo_zig_metal_core_probe(
    const uint8_t *metallib_bytes,
    size_t metallib_len,
    const uint8_t *source_bytes,
    size_t source_len,
    const uint32_t *transcript_source,
    size_t transcript_source_len,
    const uint32_t *expected_secure,
    size_t expected_secure_len,
    const uint32_t *expected_queries,
    size_t expected_queries_len,
    const char *const *expected_names,
    size_t expected_count,
    char *error_message,
    size_t error_message_len
) {
    if (metallib_bytes == NULL || metallib_len == 0u ||
        source_bytes == NULL || source_len == 0u ||
        transcript_source == NULL || transcript_source_len != 12u ||
        expected_secure == NULL || expected_secure_len != 12u ||
        expected_queries == NULL || expected_queries_len != 13u ||
        expected_names == NULL || expected_count == 0u) {
        write_error(error_message, error_message_len, @"Invalid Metal core probe input");
        return false;
    }

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            write_error(error_message, error_message_len, @"No Metal device available");
            return false;
        }

        void *owned_bytes = malloc(metallib_len);
        if (owned_bytes == NULL) {
            write_error(error_message, error_message_len, @"Failed to copy metallib bytes");
            return false;
        }
        memcpy(owned_bytes, metallib_bytes, metallib_len);
        dispatch_data_t data = dispatch_data_create(
            owned_bytes,
            metallib_len,
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
            ^{ free(owned_bytes); }
        );
        if (data == nil) {
            free(owned_bytes);
            write_error(error_message, error_message_len, @"Failed to wrap metallib bytes");
            return false;
        }

        NSError *load_error = nil;
        id<MTLLibrary> library = [device newLibraryWithData:data error:&load_error];
        if (library == nil) {
            write_error(
                error_message,
                error_message_len,
                load_error.localizedDescription ?: @"Failed to load metallib"
            );
            return false;
        }

        NSMutableArray<NSString *> *expected_array =
            [NSMutableArray arrayWithCapacity:expected_count];
        for (size_t index = 0u; index < expected_count; ++index) {
            if (expected_names[index] == NULL) {
                write_error(error_message, error_message_len, @"Null expected Metal function name");
                return false;
            }
            NSString *name = [NSString stringWithUTF8String:expected_names[index]];
            if (name == nil || name.length == 0u) {
                write_error(error_message, error_message_len, @"Invalid expected Metal function name");
                return false;
            }
            [expected_array addObject:name];
        }

        NSSet<NSString *> *expected = [NSSet setWithArray:expected_array];
        NSArray<NSString *> *actual_array = library.functionNames;
        NSSet<NSString *> *actual = [NSSet setWithArray:actual_array];
        if (expected.count != expected_count || actual_array.count != expected_count ||
            actual.count != expected_count || ![actual isEqualToSet:expected]) {
            NSMutableSet<NSString *> *missing = [expected mutableCopy];
            [missing minusSet:actual];
            NSMutableSet<NSString *> *unexpected = [actual mutableCopy];
            [unexpected minusSet:expected];
            write_error(
                error_message,
                error_message_len,
                [NSString stringWithFormat:
                    @"Metal export mismatch: expected=%zu actual=%lu missing=%@ unexpected=%@",
                    expected_count,
                    (unsigned long)actual_array.count,
                    first_name(missing),
                    first_name(unexpected)]
            );
            return false;
        }

        for (NSString *name in expected_array) {
            id<MTLFunction> function = [library newFunctionWithName:name];
            if (function == nil || function.functionType != MTLFunctionTypeKernel) {
                write_error(
                    error_message,
                    error_message_len,
                    [NSString stringWithFormat:@"Invalid Metal kernel export %@", name]
                );
                return false;
            }
            if (function.functionConstantsDictionary.count != 0u) {
                write_error(
                    error_message,
                    error_message_len,
                    [NSString stringWithFormat:@"Unexpected function constants for %@", name]
                );
                return false;
            }
        }
        NSString *parity_failure = nil;
        if (!verify_kernel_parity(
                device,
                library,
                source_bytes,
                source_len,
                transcript_source,
                expected_secure,
                expected_queries,
                &parity_failure)) {
            write_error(
                error_message,
                error_message_len,
                parity_failure ?: @"AOT/JIT parity dispatch failed"
            );
            return false;
        }
        return true;
    }
}
