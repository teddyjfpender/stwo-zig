#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#import "runtime_profile.m"
#import "runtime/compile_options.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "runtime/abi.h"
#include "runtime/object_model.h"


typedef struct {
    __unsafe_unretained StwoZigMetalTree *tree;
    __unsafe_unretained id<MTLBuffer> buffer;
    size_t wordOffset;
    size_t availableWords;
} StwoZigResidentColumnBinding;

static id<MTLComputePipelineState> stwo_zig_commitment_leaves_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake3V1) return runtime.blake3Leaves;
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.leaves;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31Leaves;
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_direct_leaves_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake3V1) return runtime.blake3LeavesWide;
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.leavesWide;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31LeavesWide;
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_parents_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.parents;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31Parents;
    if (family == StwoZigCommitmentHashFamilyBlake3V1) return runtime.blake3Parents;
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_parents_sparse_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.parentsSparse;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31ParentsSparse;
    if (family == StwoZigCommitmentHashFamilyBlake3V1) return runtime.blake3ParentsSparse;
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_parent_tail_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.parentTailSparse;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31ParentTailSparse;
    if (family == StwoZigCommitmentHashFamilyBlake3V1) return runtime.blake3ParentTailSparse;
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_leaf_absorb_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family, bool compact
) {
    if (family == StwoZigCommitmentHashFamilyBlake2sV1)
        return compact ? runtime.leafAbsorbCompactResident : runtime.leafAbsorbResident;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return compact ? runtime.poseidon2M31LeafAbsorbCompactResident :
            runtime.poseidon2M31LeafAbsorbResident;
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_fri_leaves_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake3V1) return runtime.blake3FriPackedLeavesResident;
    if (family == StwoZigCommitmentHashFamilyBlake2sV1)
        return runtime.friPackedLeavesResident;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31FriPackedLeavesResident;
    return nil;
}

static uint32_t stwo_zig_commitment_leaf_state_words(uint32_t family) {
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return 8u;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1) return 16u;
    return 0u;
}

static bool stwo_zig_tree_resident_column(
    NSArray<StwoZigMetalTree *> *trees,
    const uint32_t *column,
    size_t column_words,
    StwoZigResidentColumnBinding *binding
) {
    if (column == NULL || binding == NULL) return false;
    uintptr_t address = (uintptr_t)column;
    for (StwoZigMetalTree *tree in trees) {
        NSArray<id<MTLBuffer>> *buffers = tree.residentColumnBuffers;
        const uintptr_t *begins = tree.residentColumnHostBegins.bytes;
        const size_t *counts = tree.residentColumnWordCounts.bytes;
        // Direct Poseidon commitments use u64 arena offsets because their
        // aggregate backing may exceed 2^32 words.  This map only locates the
        // already proof-owned Metal buffer; it never promotes or uploads a
        // host slice into residency.
        uint32_t offset_word_bytes = tree.residentColumnOffsetWordBytes;
        const uint32_t *narrow_offsets = offset_word_bytes == sizeof(uint32_t)
            ? tree.residentColumnWordOffsets.bytes : NULL;
        const uint64_t *wide_offsets = offset_word_bytes == sizeof(uint64_t)
            ? tree.residentColumnWordOffsets.bytes : NULL;
        NSUInteger count = tree.residentColumnHostBegins.length / sizeof(uintptr_t);
        if ((buffers.count == 1u || buffers.count == count) && begins != NULL && counts != NULL &&
            (narrow_offsets != NULL || wide_offsets != NULL) &&
            tree.residentColumnHostBegins.length == count * sizeof(uintptr_t) &&
            tree.residentColumnWordCounts.length == count * sizeof(size_t) &&
            count <= NSUIntegerMax / offset_word_bytes &&
            tree.residentColumnWordOffsets.length == count * offset_word_bytes) {
            for (NSUInteger index = 0u; index < count; ++index) {
                uintptr_t begin = begins[index];
                size_t words = counts[index];
                if (address < begin || (address - begin) % sizeof(uint32_t) != 0u)
                    continue;
                size_t offset = (address - begin) / sizeof(uint32_t);
                if (offset > words || column_words > words - offset) continue;
                id<MTLBuffer> buffer = buffers[buffers.count == 1u ? 0u : index];
                uint64_t resident_offset = wide_offsets != NULL
                    ? wide_offsets[index] : (uint64_t)narrow_offsets[index];
                size_t buffer_words = buffer.length / sizeof(uint32_t);
                if (buffer == nil || resident_offset > (uint64_t)buffer_words ||
                    (uint64_t)offset > (uint64_t)buffer_words - resident_offset)
                    continue;
                size_t device_offset = (size_t)(resident_offset + (uint64_t)offset);
                if (column_words > buffer_words - device_offset) continue;
                binding->tree = tree;
                binding->buffer = buffer;
                binding->wordOffset = device_offset;
                binding->availableWords = words - offset;
                return true;
            }
        }

        // Compatibility for trees built by older/specialized epochs while
        // their callers migrate to the multi-arena map.
        uintptr_t begin = tree.residentColumnsHostBegin;
        size_t words = tree.residentColumnsWordCount;
        if (tree.residentColumns == nil || address < begin ||
            (address - begin) % sizeof(uint32_t) != 0u)
            continue;
        size_t offset = (address - begin) / sizeof(uint32_t);
        if (offset <= words && column_words <= words - offset) {
            binding->tree = tree;
            binding->buffer = tree.residentColumns;
            binding->wordOffset = offset;
            binding->availableWords = words - offset;
            return true;
        }
    }
    return false;
}

// Composition-domain scratch is a proof-local typed owner created from the
// retained coefficients of already committed columns.  It is deliberately a
// separate resolver input: arbitrary host trace clones must never enter the
// proof-resident tree map, while the wider degree-bounded evaluation still
// needs a no-copy device binding for the generated AIR kernels.
static bool stwo_zig_composition_domain_column(
    void *buffer_ptr,
    const uint32_t *host_begin,
    size_t host_words,
    const uint32_t *column,
    size_t column_words,
    StwoZigResidentColumnBinding *binding
) {
    if (buffer_ptr == NULL || host_begin == NULL || host_words == 0u ||
        column == NULL || binding == NULL)
        return false;
    id<MTLBuffer> buffer = (__bridge id<MTLBuffer>)buffer_ptr;
    if (buffer == nil || buffer.contents != host_begin ||
        buffer.length / sizeof(uint32_t) != host_words)
        return false;
    uintptr_t begin = (uintptr_t)host_begin;
    uintptr_t address = (uintptr_t)column;
    if (address < begin || (address - begin) % sizeof(uint32_t) != 0u)
        return false;
    size_t offset = (address - begin) / sizeof(uint32_t);
    if (offset > host_words || column_words > host_words - offset)
        return false;
    binding->tree = nil;
    binding->buffer = buffer;
    binding->wordOffset = offset;
    binding->availableWords = host_words - offset;
    return true;
}

static bool stwo_zig_polynomial_input_column(
    NSArray<StwoZigMetalTree *> *trees,
    void *composition_buffer,
    const uint32_t *composition_host_begin,
    size_t composition_host_words,
    const uint32_t *column,
    size_t column_words,
    StwoZigResidentColumnBinding *binding
) {
    return stwo_zig_tree_resident_column(trees, column, column_words, binding) ||
        stwo_zig_composition_domain_column(
            composition_buffer,
            composition_host_begin,
            composition_host_words,
            column,
            column_words,
            binding
        );
}

static uint32_t tree_layer_word_offset(StwoZigMetalTree *tree, NSUInteger level) {
    if (tree.layerWordOffsets == nil) return 0u;
    return ((const uint32_t *)tree.layerWordOffsets.bytes)[level];
}

static uint32_t tree_layer_word_length(StwoZigMetalTree *tree, NSUInteger level) {
    if (tree.layerWordLengths == nil)
        return (uint32_t)(tree.layers[level].length / sizeof(uint32_t));
    return ((const uint32_t *)tree.layerWordLengths.bytes)[level];
}

@interface StwoZigCommandEpoch : NSObject
@property(nonatomic, strong) StwoZigMetalRuntime *runtime;
@property(nonatomic, strong) id<MTLBuffer> arena;
@property(nonatomic, strong) id<MTLCommandBuffer> command;
@property(nonatomic, strong) NSMutableArray *retainedPlans;
@property(nonatomic, strong) StwoZigResidentMerklePlan *residentMerklePlan;
@property(nonatomic) StwoZigCommandEpochState state;
@property(nonatomic) BOOL residentMerkleAdopted;
@property(nonatomic) uint64_t computeEncoders;
@property(nonatomic) uint64_t blitEncoders;
@property(nonatomic) uint64_t dispatches;
@end
@implementation StwoZigCommandEpoch
@end

static bool encode_composition_lde_counted(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena,
    StwoZigCompositionLdePlan *plan, id<MTLCommandBuffer> command,
    uint64_t *compute_encoders, uint64_t *dispatches
);
static bool encode_merkle_parent_chain_prepared(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena, StwoZigMerkleParentChain *plan,
    id<MTLCommandBuffer> command, uint64_t *compute_encoders, uint64_t *dispatches
);

static void write_error(char *destination, size_t length, NSString *message) {
    if (destination == NULL || length == 0) return;
    const char *utf8 = message.UTF8String ?: "Metal error";
    snprintf(destination, length, "%s", utf8);
}

static id<MTLComputePipelineState> make_pipeline(
    id<MTLDevice> device,
    id<MTLLibrary> library,
    NSString *name,
    char *error_message,
    size_t error_message_len
) {
    id<MTLFunction> function = [library newFunctionWithName:name];
    if (function == nil) {
        write_error(error_message, error_message_len,
                    [NSString stringWithFormat:@"Missing Metal function %@", name]);
        return nil;
    }
    NSError *error = nil;
    id<MTLComputePipelineState> pipeline =
        [device newComputePipelineStateWithFunction:function error:&error];
    if (pipeline == nil) {
        write_error(error_message, error_message_len,
                    error.localizedDescription ?: @"Failed to create Metal pipeline");
    }
    stwo_zig_metal_profile_name_pipeline(pipeline, name);
    return pipeline;
}

static id<MTLBuffer> alias_shared_buffer(id<MTLDevice> device, void *bytes, size_t length);

#include "runtime/library_setup.m"

static void bind_qm31_coordinate_kernel(
    id<MTLComputeCommandEncoder> encoder, id<MTLBuffer> source,
    id<MTLBuffer> coordinates, uint32_t value_count, id<MTLBuffer> leaves,
    id<MTLBuffer> leaf_seed, uint32_t prefix_bytes, uint32_t write_leaf
) {
    [encoder setBuffer:source offset:0u atIndex:0];
    [encoder setBuffer:coordinates offset:0u atIndex:1];
    [encoder setBytes:&value_count length:sizeof(value_count) atIndex:2];
    [encoder setBuffer:leaves offset:0u atIndex:3];
    [encoder setBuffer:leaf_seed offset:0u atIndex:4];
    [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:5];
    [encoder setBytes:&write_leaf length:sizeof(write_leaf) atIndex:6];
}

static void bind_fri_line_kernel(
    id<MTLComputeCommandEncoder> encoder, id<MTLBuffer> source,
    NSUInteger inverse_offset, id<MTLBuffer> inverse, id<MTLBuffer> alpha,
    NSUInteger alpha_offset, id<MTLBuffer> destination, uint32_t destination_count,
    id<MTLBuffer> coordinates, id<MTLBuffer> leaves, id<MTLBuffer> leaf_seed,
    uint32_t prefix_bytes, uint32_t prepare_next
) {
    [encoder setBuffer:source offset:0u atIndex:0];
    [encoder setBuffer:inverse offset:inverse_offset atIndex:1];
    [encoder setBuffer:alpha offset:alpha_offset atIndex:2];
    [encoder setBuffer:destination offset:0u atIndex:3];
    [encoder setBytes:&destination_count length:sizeof(destination_count) atIndex:4];
    [encoder setBuffer:coordinates offset:0u atIndex:5];
    [encoder setBuffer:leaves offset:0u atIndex:6];
    [encoder setBuffer:leaf_seed offset:0u atIndex:7];
    [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:8];
    [encoder setBytes:&prepare_next length:sizeof(prepare_next) atIndex:9];
}

static void encode_fri_inverse_domain(
    StwoZigMetalRuntime *runtime, id<MTLComputeCommandEncoder> encoder,
    id<MTLBuffer> destination, NSUInteger destination_offset,
    uint32_t value_count, uint32_t initial_index, uint32_t step_size,
    uint32_t mode
) {
    uint32_t log_size = 0u;
    for (uint32_t count = value_count; count > 1u; count >>= 1u) log_size += 1u;
    uint32_t destination_words = (uint32_t)(destination_offset / sizeof(uint32_t));
    [encoder setComputePipelineState:runtime.quotientDomainPointsResident];
    [encoder setBuffer:destination offset:0u atIndex:0];
    [encoder setBytes:&destination_words length:sizeof(destination_words) atIndex:1];
    [encoder setBytes:&value_count length:sizeof(value_count) atIndex:2];
    [encoder setBytes:&log_size length:sizeof(log_size) atIndex:3];
    [encoder setBytes:&initial_index length:sizeof(initial_index) atIndex:4];
    [encoder setBytes:&step_size length:sizeof(step_size) atIndex:5];
    [encoder setBytes:&mode length:sizeof(mode) atIndex:6];
    NSUInteger width = MIN(runtime.quotientDomainPointsResident.maxTotalThreadsPerThreadgroup,
                           runtime.quotientDomainPointsResident.threadExecutionWidth * 8u);
    [encoder dispatchThreads:MTLSizeMake(value_count, 1u, 1u)
         threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
}

#import "runtime/initialization.m"

// One translation unit keeps plan types and encoder helpers private to the stable C ABI.
#import "runtime/runtime_queries.m"
#import "runtime/proof_of_work.m"
#import "runtime/fri_fold_commit.m"
#import "runtime/fri_plans.m"
#import "runtime/transcript_decommitment.m"
#import "runtime/witness_primitives.m"
#import "runtime/resource_plans.m"
#import "runtime/circle_plans.m"
#import "runtime/merkle_epochs.m"
#import "runtime/blake2_leaf_stream.m"
#import "runtime/auxiliary_plans.m"
#import "runtime/cache_identity.m"
#import "runtime/archive_store.m"
#import "runtime/dynamic_evaluation.m"
#import "runtime/base_polynomial.m"
#import "runtime/framework_polynomial.m"
#import "runtime/lookup_polynomial.m"
#import "runtime/composition.m"
#import "runtime/composition_recurrence.m"
#import "runtime/prepared_auxiliary.m"
#import "runtime/circle_legacy.m"
#import "runtime/circle_commit_epoch.m"
#import "runtime/polynomial_evaluation.m"
#import "runtime/quotient_planning.m"
#import "runtime/quotient_completion.m"
// Segmented quotient dispatch binds only the source run's covered batch range.
#import "runtime/quotients.m"
#import "runtime/native_coefficient_fold.m"
#import "runtime/lifecycle_and_tree.m"
#import "runtime/cached_column_views.m"

size_t stwo_zig_metal_runtime_identity(void *runtime_ptr, char *output, size_t output_len) {
    @autoreleasepool {
        if (runtime_ptr == NULL) return 0u;
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSData *encoded = [eval_runtime_identity(runtime.device).canonical
            dataUsingEncoding:NSUTF8StringEncoding];
        if (encoded.length == 0u) return 0u;
        if (output != NULL && output_len >= encoded.length)
            memcpy(output, encoded.bytes, encoded.length);
        return encoded.length;
    }
}

#include "runtime/framework_interaction.m"
#include "runtime/secure_polynomial_catalog_v1.m"
#include "runtime/secure_equations_v1.m"
#include "runtime/secure_coefficient_ingress_v1.m"
#include "runtime/secure_resident_columns_v1.m"
#include "runtime/secure_interaction_v1.m"
