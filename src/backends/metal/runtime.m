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
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.leaves;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31Leaves;
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_direct_leaves_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.leaves;
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
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_parents_sparse_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.parentsSparse;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31ParentsSparse;
    return nil;
}

static id<MTLComputePipelineState> stwo_zig_commitment_parent_tail_pipeline(
    StwoZigMetalRuntime *runtime, uint32_t family
) {
    if (family == StwoZigCommitmentHashFamilyBlake2sV1) return runtime.parentTailSparse;
    if (family == StwoZigCommitmentHashFamilyPoseidon2M31V1)
        return runtime.poseidon2M31ParentTailSparse;
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
        if (buffers.count == 1u && begins != NULL && counts != NULL &&
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
                id<MTLBuffer> buffer = buffers[0];
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

static StwoZigMetalRuntime *create_runtime_from_library(
    id<MTLDevice> device,
    id<MTLLibrary> library,
    bool include_deferred,
    char *error_message,
    size_t error_message_len
) {
    if (device == nil || library == nil) return nil;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = [StwoZigMetalRuntime new];
        runtime.device = device;
        runtime.queue = stwo_zig_metal_profile_queue([device newCommandQueue], device);
        runtime.riscvPolynomialPipelines = [NSMutableDictionary dictionaryWithCapacity:61u];
        runtime.evalLibraries = [NSMutableDictionary dictionary];
        runtime.evalPipelines = [NSMutableDictionary dictionary];
        runtime.quadraticRecurrenceTrace = make_pipeline(device, library, @"stwo_zig_quadratic_recurrence_trace",
                                                         error_message, error_message_len);
        runtime.quadraticRecurrenceIfftWide = make_pipeline(device, library, @"stwo_zig_quadratic_recurrence_ifft_fused_wide",
                                                            error_message, error_message_len);
        runtime.leaves = make_pipeline(device, library, @"stwo_zig_blake2s_leaves",
                                       error_message, error_message_len);
        runtime.poseidon2M31Leaves = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_leaves",
                                                  error_message, error_message_len);
        runtime.poseidon2M31LeavesWide = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_leaves_wide",
                                                      error_message, error_message_len);
        runtime.proofOfWork = make_pipeline(device, library, @"stwo_zig_blake2s_pow_search",
                                           error_message, error_message_len);
        runtime.parents = make_pipeline(device, library, @"stwo_zig_blake2s_parents",
                                        error_message, error_message_len);
        runtime.poseidon2M31Parents = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_parents",
                                                   error_message, error_message_len);
        runtime.quotients = make_pipeline(device, library, @"stwo_zig_quotient_rows",
                                          error_message, error_message_len);
        runtime.rawQuotients = make_pipeline(device, library, @"stwo_zig_quotient_rows_raw",
                                             error_message, error_message_len);
        runtime.polynomialEval = make_pipeline(device, library, @"stwo_zig_eval_polynomials",
                                               error_message, error_message_len);
        runtime.polynomialBasis = make_pipeline(device, library, @"stwo_zig_eval_basis",
                                                error_message, error_message_len);
        runtime.sampledBarycentricDomain = make_pipeline(device, library, @"stwo_zig_sampled_barycentric_domain_v1",
                                                         error_message, error_message_len);
        runtime.sampledBarycentricScale = make_pipeline(device, library, @"stwo_zig_sampled_barycentric_scale_v1",
                                                        error_message, error_message_len);
        runtime.sampledBarycentricParts = make_pipeline(device, library, @"stwo_zig_sampled_barycentric_parts_v1",
                                                        error_message, error_message_len);
        runtime.sampledBarycentricInverseDirect = make_pipeline(device, library, @"stwo_zig_sampled_barycentric_inverse_direct_v1",
                                                                error_message, error_message_len);
        runtime.sampledBarycentricInverseTree = make_pipeline(device, library, @"stwo_zig_sampled_barycentric_inverse_tree_v1",
                                                              error_message, error_message_len);
        runtime.sampledBarycentricFinish = make_pipeline(device, library, @"stwo_zig_sampled_barycentric_finish_v1",
                                                         error_message, error_message_len);
        runtime.sampledBarycentricEvaluateMany = make_pipeline(device, library, @"stwo_zig_sampled_barycentric_evaluate_many_v1",
                                                               error_message, error_message_len);
        runtime.sampledBarycentricReduce = make_pipeline(device, library, @"stwo_zig_sampled_barycentric_reduce_v1",
                                                         error_message, error_message_len);
        runtime.circleIfftFirst = make_pipeline(device, library, @"stwo_zig_circle_ifft_first", error_message, error_message_len);
        runtime.circleIfftLayer = make_pipeline(device, library, @"stwo_zig_circle_ifft_layer", error_message, error_message_len);
        runtime.circleRfftLayer = make_pipeline(device, library, @"stwo_zig_circle_rfft_layer", error_message, error_message_len);
        runtime.circleRfftLast = make_pipeline(device, library, @"stwo_zig_circle_rfft_last", error_message, error_message_len);
        runtime.circleRescale = make_pipeline(device, library, @"stwo_zig_circle_rescale", error_message, error_message_len);
        runtime.circleExpand = make_pipeline(device, library, @"stwo_zig_circle_expand_coefficients", error_message, error_message_len);
        runtime.circleIfftFused = make_pipeline(device, library, @"stwo_zig_circle_ifft_fused_tail", error_message, error_message_len);
        runtime.circleIfftFusedWide = make_pipeline(device, library, @"stwo_zig_circle_ifft_fused_tail_wide", error_message, error_message_len);
        runtime.circleRfftFused = make_pipeline(device, library, @"stwo_zig_circle_rfft_fused_tail", error_message, error_message_len);
        runtime.quotientNumerator = make_pipeline(device, library, @"stwo_zig_quotient_numerator_raw", error_message, error_message_len);
        runtime.quotientFinalize = make_pipeline(device, library, @"stwo_zig_quotient_finalize", error_message, error_message_len);
        runtime.quotientPartialsRaw = make_pipeline(device, library, @"stwo_zig_quotient_partials_raw", error_message, error_message_len);
        runtime.quotientCombinePartialsRaw = make_pipeline(device, library, @"stwo_zig_quotient_combine_partials_raw", error_message, error_message_len);
        runtime.quotientDomainPointsResident = make_pipeline(device, library, @"stwo_zig_quotient_domain_points_resident", error_message, error_message_len);
        runtime.quotientDenominatorsResident = make_pipeline(device, library, @"stwo_zig_quotient_denominators_resident", error_message, error_message_len);
        runtime.quotientCombineResident = make_pipeline(device, library, @"stwo_zig_quotient_combine_resident", error_message, error_message_len);
        runtime.quotientCoefficientsResident = make_pipeline(device, library, @"stwo_zig_quotient_coefficients_resident", error_message, error_message_len);
        runtime.friFoldCircle = make_pipeline(device, library, @"stwo_zig_fri_fold_circle", error_message, error_message_len);
        runtime.friFoldLine = make_pipeline(device, library, @"stwo_zig_fri_fold_line", error_message, error_message_len);
        runtime.friFold3Resident = make_pipeline(device, library, @"stwo_zig_fri_fold3_resident", error_message, error_message_len);
        runtime.friFold2Resident = make_pipeline(device, library, @"stwo_zig_fri_fold2_resident", error_message, error_message_len);
        runtime.friPackedLeavesResident = make_pipeline(device, library, @"stwo_zig_fri_packed_leaves_resident", error_message, error_message_len);
        runtime.poseidon2M31FriPackedLeavesResident = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_fri_packed_leaves_resident", error_message, error_message_len);
        runtime.friFinalLineResident = make_pipeline(device, library, @"stwo_zig_fri_final_line_resident", error_message, error_message_len);
        runtime.transcriptInitResident = make_pipeline(device, library, @"stwo_zig_transcript_init_resident", error_message, error_message_len);
        runtime.transcriptMixResident = make_pipeline(device, library, @"stwo_zig_transcript_mix_resident", error_message, error_message_len);
        runtime.transcriptDrawSecureResident = make_pipeline(device, library, @"stwo_zig_transcript_draw_secure_resident", error_message, error_message_len);
        runtime.transcriptDrawQueriesResident = make_pipeline(device, library, @"stwo_zig_transcript_draw_queries_resident", error_message, error_message_len);
        runtime.decommitNormalizeQueriesResident = make_pipeline(device, library, @"stwo_zig_decommit_normalize_queries_resident", error_message, error_message_len);
        runtime.decommitPrepareFriQueriesResident = make_pipeline(device, library, @"stwo_zig_decommit_prepare_fri_queries_resident", error_message, error_message_len);
        runtime.decommitGatherFriValuesResident = make_pipeline(device, library, @"stwo_zig_decommit_gather_fri_values_resident", error_message, error_message_len);
        runtime.decommitPrepareTraceQueriesResident = make_pipeline(device, library, @"stwo_zig_decommit_prepare_trace_queries_resident", error_message, error_message_len);
        runtime.decommitGatherTraceValuesResident = make_pipeline(device, library, @"stwo_zig_decommit_gather_trace_values_resident", error_message, error_message_len);
        runtime.decommitGatherTreeValuesResident = make_pipeline(device, library, @"stwo_zig_decommit_gather_tree_values_resident", error_message, error_message_len);
        runtime.decommitGatherTreeValuesResidentWide = make_pipeline(device, library, @"stwo_zig_decommit_gather_tree_values_resident_wide", error_message, error_message_len);
        runtime.decommitAssembleFriResident = make_pipeline(device, library, @"stwo_zig_decommit_assemble_fri_resident", error_message, error_message_len);
        runtime.decommitSparseParentResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_parent_resident", error_message, error_message_len);
        runtime.decommitSparseLeavesResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_leaves_resident", error_message, error_message_len);
        runtime.decommitSparseLeafGroupResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_leaf_group_resident", error_message, error_message_len);
        runtime.decommitAssembleTraceResident = make_pipeline(device, library, @"stwo_zig_decommit_assemble_trace_resident", error_message, error_message_len);
        runtime.qm31ToCoordinates = make_pipeline(device, library, @"stwo_zig_qm31_to_coordinates", error_message, error_message_len);
        runtime.leafAbsorbResident = make_pipeline(device, library, @"stwo_zig_blake2s_leaf_absorb_resident", error_message, error_message_len);
        runtime.leafAbsorbCompactResident = make_pipeline(device, library, @"stwo_zig_blake2s_leaf_absorb_compact_resident", error_message, error_message_len);
        runtime.poseidon2M31LeafAbsorbResident = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_leaf_absorb_resident", error_message, error_message_len);
        runtime.poseidon2M31LeafAbsorbCompactResident = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_leaf_absorb_compact_resident", error_message, error_message_len);
        runtime.poseidon2M31LeafStateDigestResidentV1 = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_leaf_state_digest_resident_v1", error_message, error_message_len);
        runtime.parentsPlainSparse = make_pipeline(device, library, @"stwo_zig_blake2s_parents_plain_sparse", error_message, error_message_len);
        runtime.clearArenaSpans = make_pipeline(device, library, @"stwo_zig_clear_arena_spans", error_message, error_message_len);
        runtime.circleExpandSparse = make_pipeline(device, library, @"stwo_zig_circle_expand_sparse", error_message, error_message_len);
        runtime.circleCopySparse = make_pipeline(device, library, @"stwo_zig_circle_copy_sparse", error_message, error_message_len);
        runtime.circleIfftFirstSparse = make_pipeline(device, library, @"stwo_zig_circle_ifft_first_sparse", error_message, error_message_len);
        runtime.circleIfftLayerSparse = make_pipeline(device, library, @"stwo_zig_circle_ifft_layer_sparse", error_message, error_message_len);
        runtime.circleRescaleSparse = make_pipeline(device, library, @"stwo_zig_circle_rescale_sparse", error_message, error_message_len);
        runtime.circleRfftLayerSparse = make_pipeline(device, library, @"stwo_zig_circle_rfft_layer_sparse", error_message, error_message_len);
        runtime.circleRfftRadix4Sparse = make_pipeline(device, library, @"stwo_zig_circle_rfft_radix4_sparse", error_message, error_message_len);
        runtime.circleRfftLastSparse = make_pipeline(device, library, @"stwo_zig_circle_rfft_last_sparse", error_message, error_message_len);
        runtime.circleRfftFusedSparse = make_pipeline(device, library, @"stwo_zig_circle_rfft_fused_tail_sparse", error_message, error_message_len);
        runtime.circleRfftFusedSparseWide = make_pipeline(device, library, @"stwo_zig_circle_rfft_fused_tail_sparse_wide", error_message, error_message_len);
        runtime.circleRfftLayerSparseWide = make_pipeline(device, library, @"stwo_zig_circle_rfft_layer_sparse_wide", error_message, error_message_len);
        runtime.circleRfftLastSparseWide = make_pipeline(device, library, @"stwo_zig_circle_rfft_last_sparse_wide", error_message, error_message_len);
        runtime.relationFused = make_pipeline(device, library, @"stwo_zig_relation_fused", error_message, error_message_len);
        runtime.relationBlockScan = make_pipeline(device, library, @"stwo_zig_relation_block_scan", error_message, error_message_len);
        runtime.relationScanBlocks = make_pipeline(device, library, @"stwo_zig_relation_scan_blocks", error_message, error_message_len);
        runtime.relationScanFinalize = make_pipeline(device, library, @"stwo_zig_relation_scan_finalize", error_message, error_message_len);
        runtime.parentsSparse = make_pipeline(device, library, @"stwo_zig_blake2s_parents_sparse", error_message, error_message_len);
        runtime.parentTailSparse = make_pipeline(device, library, @"stwo_zig_blake2s_parent_tail_sparse", error_message, error_message_len);
        runtime.poseidon2M31ParentsSparse = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_parents_sparse", error_message, error_message_len);
        runtime.poseidon2M31ParentTailSparse = make_pipeline(device, library, @"stwo_zig_poseidon2_m31_parent_tail_sparse", error_message, error_message_len);
        runtime.poseidon2ChannelPowSearch = make_pipeline(device, library, @"stwo_zig_poseidon2_channel_pow_search", error_message, error_message_len);
        runtime.compactGather = make_pipeline(device, library, @"stwo_zig_compact_gather", error_message, error_message_len);
        runtime.compactRadixHistogram = make_pipeline(device, library, @"stwo_zig_compact_radix_histogram", error_message, error_message_len);
        runtime.compactRadixPrefix = make_pipeline(device, library, @"stwo_zig_compact_radix_prefix", error_message, error_message_len);
        runtime.compactRadixScatter = make_pipeline(device, library, @"stwo_zig_compact_radix_scatter", error_message, error_message_len);
        runtime.compactHeads = make_pipeline(device, library, @"stwo_zig_compact_heads", error_message, error_message_len);
        runtime.compactScanLocal = make_pipeline(device, library, @"stwo_zig_compact_scan_local", error_message, error_message_len);
        runtime.compactScanBlocks = make_pipeline(device, library, @"stwo_zig_compact_scan_blocks", error_message, error_message_len);
        runtime.compactScanAdd = make_pipeline(device, library, @"stwo_zig_compact_scan_add", error_message, error_message_len);
        runtime.compactClearOutputs = make_pipeline(device, library, @"stwo_zig_compact_clear_outputs", error_message, error_message_len);
        runtime.compactScatter = make_pipeline(device, library, @"stwo_zig_compact_scatter", error_message, error_message_len);
        runtime.compactFinalize = make_pipeline(device, library, @"stwo_zig_compact_finalize", error_message, error_message_len);
        runtime.compositionLift = make_pipeline(device, library, @"stwo_zig_composition_lift_accumulate", error_message, error_message_len);
        runtime.compositionSplit = make_pipeline(device, library, @"stwo_zig_composition_split_coordinates", error_message, error_message_len);
        runtime.compositionExpand = make_pipeline(device, library, @"stwo_zig_composition_expand_sparse", error_message, error_message_len);
        runtime.compositionRandomPowers = make_pipeline(device, library, @"stwo_zig_composition_random_powers", error_message, error_message_len);
        runtime.compositionExtParams = make_pipeline(device, library, @"stwo_zig_composition_ext_params", error_message, error_message_len);

        // BEGIN GENERATED RISC-V POLYNOMIAL PIPELINES.
        // Keep this block in manifest order. Each content-addressed function
        // name is bound once so the runtime initializer remains auditable.
        NSString *riscvPolynomialName00 = @"stwo_zig_base_poly_e3d97ada62a6ad9f06872ffebf334097";
        runtime.riscvPolynomialPipelines[riscvPolynomialName00] = make_pipeline(
            device, library, riscvPolynomialName00, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName00] == nil) return NULL;
        NSString *riscvPolynomialName01 = @"stwo_zig_base_poly_94bb6ee080d963f1a9b89ba8836e6cbf";
        runtime.riscvPolynomialPipelines[riscvPolynomialName01] = make_pipeline(
            device, library, riscvPolynomialName01, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName01] == nil) return NULL;
        NSString *riscvPolynomialName02 = @"stwo_zig_base_poly_43fb3f4df23ca371514fbd130360efba";
        runtime.riscvPolynomialPipelines[riscvPolynomialName02] = make_pipeline(
            device, library, riscvPolynomialName02, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName02] == nil) return NULL;
        NSString *riscvPolynomialName03 = @"stwo_zig_base_poly_c435f0a2ee25c59eec1ebd9f12b995cd";
        runtime.riscvPolynomialPipelines[riscvPolynomialName03] = make_pipeline(
            device, library, riscvPolynomialName03, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName03] == nil) return NULL;
        NSString *riscvPolynomialName04 = @"stwo_zig_base_poly_116f3173573043d8dc56aa23e5c1fac4";
        runtime.riscvPolynomialPipelines[riscvPolynomialName04] = make_pipeline(
            device, library, riscvPolynomialName04, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName04] == nil) return NULL;
        NSString *riscvPolynomialName05 = @"stwo_zig_base_poly_63ea0b65e576f67691cdb43d14a7590b";
        runtime.riscvPolynomialPipelines[riscvPolynomialName05] = make_pipeline(
            device, library, riscvPolynomialName05, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName05] == nil) return NULL;
        NSString *riscvPolynomialName06 = @"stwo_zig_base_poly_782a4d5d838c828e4ae55bb81b63e389";
        runtime.riscvPolynomialPipelines[riscvPolynomialName06] = make_pipeline(
            device, library, riscvPolynomialName06, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName06] == nil) return NULL;
        NSString *riscvPolynomialName07 = @"stwo_zig_base_poly_0b0c9beaa20a9460c6d8ecfdfe560eba";
        runtime.riscvPolynomialPipelines[riscvPolynomialName07] = make_pipeline(
            device, library, riscvPolynomialName07, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName07] == nil) return NULL;
        NSString *riscvPolynomialName08 = @"stwo_zig_base_poly_766a542bb547c7b4eaf4c8a8fb9eef52";
        runtime.riscvPolynomialPipelines[riscvPolynomialName08] = make_pipeline(
            device, library, riscvPolynomialName08, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName08] == nil) return NULL;
        NSString *riscvPolynomialName09 = @"stwo_zig_base_poly_a995060c2a616369140d09438c7dac67";
        runtime.riscvPolynomialPipelines[riscvPolynomialName09] = make_pipeline(
            device, library, riscvPolynomialName09, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName09] == nil) return NULL;
        NSString *riscvPolynomialName10 = @"stwo_zig_base_poly_9228c4a31e483b8e787375ff1354be9a";
        runtime.riscvPolynomialPipelines[riscvPolynomialName10] = make_pipeline(
            device, library, riscvPolynomialName10, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName10] == nil) return NULL;
        NSString *riscvPolynomialName11 = @"stwo_zig_base_poly_c20d068f8ff248590d22364c7c7d5649";
        runtime.riscvPolynomialPipelines[riscvPolynomialName11] = make_pipeline(
            device, library, riscvPolynomialName11, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName11] == nil) return NULL;
        NSString *riscvPolynomialName12 = @"stwo_zig_base_poly_4a95ed38e5a6795e8a84b0817ddd37e1";
        runtime.riscvPolynomialPipelines[riscvPolynomialName12] = make_pipeline(
            device, library, riscvPolynomialName12, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName12] == nil) return NULL;
        NSString *riscvPolynomialName13 = @"stwo_zig_base_poly_706ca0b14e34ec043cbf5f04e14fb315";
        runtime.riscvPolynomialPipelines[riscvPolynomialName13] = make_pipeline(
            device, library, riscvPolynomialName13, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName13] == nil) return NULL;
        NSString *riscvPolynomialName14 = @"stwo_zig_base_poly_40d34cb41f90634e26f0b2bb88a77110";
        runtime.riscvPolynomialPipelines[riscvPolynomialName14] = make_pipeline(
            device, library, riscvPolynomialName14, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName14] == nil) return NULL;
        NSString *riscvPolynomialName15 = @"stwo_zig_base_poly_5d744c2fbb612ce7e9954dfd6cc1b4b7";
        runtime.riscvPolynomialPipelines[riscvPolynomialName15] = make_pipeline(
            device, library, riscvPolynomialName15, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName15] == nil) return NULL;
        NSString *riscvPolynomialName16 = @"stwo_zig_base_poly_903175038c36e2a6aad8376003874197";
        runtime.riscvPolynomialPipelines[riscvPolynomialName16] = make_pipeline(
            device, library, riscvPolynomialName16, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName16] == nil) return NULL;
        NSString *riscvPolynomialName17 = @"stwo_zig_lookup_poly_a5980ef351d2fafc7a22e5aa40300954";
        runtime.riscvPolynomialPipelines[riscvPolynomialName17] = make_pipeline(
            device, library, riscvPolynomialName17, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName17] == nil) return NULL;
        NSString *riscvPolynomialName18 = @"stwo_zig_lookup_poly_e5715747fc906de9684a84af2d392d1e";
        runtime.riscvPolynomialPipelines[riscvPolynomialName18] = make_pipeline(
            device, library, riscvPolynomialName18, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName18] == nil) return NULL;
        NSString *riscvPolynomialName19 = @"stwo_zig_lookup_poly_8a132b1e9e82b54afcec47fe86f30324";
        runtime.riscvPolynomialPipelines[riscvPolynomialName19] = make_pipeline(
            device, library, riscvPolynomialName19, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName19] == nil) return NULL;
        NSString *riscvPolynomialName20 = @"stwo_zig_lookup_poly_bed36219333c2c4ad3c08cfdfda0e8a2";
        runtime.riscvPolynomialPipelines[riscvPolynomialName20] = make_pipeline(
            device, library, riscvPolynomialName20, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName20] == nil) return NULL;
        NSString *riscvPolynomialName21 = @"stwo_zig_lookup_poly_020adcddb227238a71dcd523f9c87a7f";
        runtime.riscvPolynomialPipelines[riscvPolynomialName21] = make_pipeline(
            device, library, riscvPolynomialName21, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName21] == nil) return NULL;
        NSString *riscvPolynomialName22 = @"stwo_zig_lookup_poly_d6611c9189072c08839d56f6496f63ed";
        runtime.riscvPolynomialPipelines[riscvPolynomialName22] = make_pipeline(
            device, library, riscvPolynomialName22, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName22] == nil) return NULL;
        NSString *riscvPolynomialName23 = @"stwo_zig_lookup_poly_94aa7ee9c1399f0ac1615227be890e54";
        runtime.riscvPolynomialPipelines[riscvPolynomialName23] = make_pipeline(
            device, library, riscvPolynomialName23, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName23] == nil) return NULL;
        NSString *riscvPolynomialName24 = @"stwo_zig_lookup_poly_ff8f5638e589be25d994070f031c73f4";
        runtime.riscvPolynomialPipelines[riscvPolynomialName24] = make_pipeline(
            device, library, riscvPolynomialName24, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName24] == nil) return NULL;
        NSString *riscvPolynomialName25 = @"stwo_zig_lookup_poly_04a5ee0118c370d4f4be88a43aa90c1b";
        runtime.riscvPolynomialPipelines[riscvPolynomialName25] = make_pipeline(
            device, library, riscvPolynomialName25, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName25] == nil) return NULL;
        NSString *riscvPolynomialName26 = @"stwo_zig_lookup_poly_71a7dea9a6d87e457404d7286bf51e2b";
        runtime.riscvPolynomialPipelines[riscvPolynomialName26] = make_pipeline(
            device, library, riscvPolynomialName26, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName26] == nil) return NULL;
        NSString *riscvPolynomialName27 = @"stwo_zig_lookup_poly_c98fc3b8440d536b2dd11e209cf33406";
        runtime.riscvPolynomialPipelines[riscvPolynomialName27] = make_pipeline(
            device, library, riscvPolynomialName27, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName27] == nil) return NULL;
        NSString *riscvPolynomialName28 = @"stwo_zig_lookup_poly_c7ef2b87fccb92355969d231b02a1d52";
        runtime.riscvPolynomialPipelines[riscvPolynomialName28] = make_pipeline(
            device, library, riscvPolynomialName28, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName28] == nil) return NULL;
        NSString *riscvPolynomialName29 = @"stwo_zig_lookup_poly_7187bd253b26502c413540ac56eccb23";
        runtime.riscvPolynomialPipelines[riscvPolynomialName29] = make_pipeline(
            device, library, riscvPolynomialName29, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName29] == nil) return NULL;
        NSString *riscvPolynomialName30 = @"stwo_zig_lookup_poly_ae8631b5be628fa89a790444be02b7b1";
        runtime.riscvPolynomialPipelines[riscvPolynomialName30] = make_pipeline(
            device, library, riscvPolynomialName30, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName30] == nil) return NULL;
        NSString *riscvPolynomialName31 = @"stwo_zig_lookup_poly_d7203c97e13213534f5bd98272130f81";
        runtime.riscvPolynomialPipelines[riscvPolynomialName31] = make_pipeline(
            device, library, riscvPolynomialName31, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName31] == nil) return NULL;
        NSString *riscvPolynomialName32 = @"stwo_zig_lookup_poly_fe8c4b8e3259f973cd85613a2dd582bc";
        runtime.riscvPolynomialPipelines[riscvPolynomialName32] = make_pipeline(
            device, library, riscvPolynomialName32, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName32] == nil) return NULL;
        NSString *riscvPolynomialName33 = @"stwo_zig_lookup_poly_43726bbe802a5a24b6c16a4bc093608b";
        runtime.riscvPolynomialPipelines[riscvPolynomialName33] = make_pipeline(
            device, library, riscvPolynomialName33, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName33] == nil) return NULL;
        NSString *riscvPolynomialName34 = @"stwo_zig_lookup_poly_v2_6e35df3dbb1bb66f7c23e82cdf0f6705509c4f08e5719edab77049660d8e632d";
        runtime.riscvPolynomialPipelines[riscvPolynomialName34] = make_pipeline(
            device, library, riscvPolynomialName34, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName34] == nil) return NULL;
        NSString *riscvPolynomialName35 = @"stwo_zig_lookup_poly_v2_253283e6dfe6bf332f2e466400c1f09394999e7935e86d6bb99a351d8d0b1f49";
        runtime.riscvPolynomialPipelines[riscvPolynomialName35] = make_pipeline(
            device, library, riscvPolynomialName35, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName35] == nil) return NULL;
        NSString *riscvPolynomialName36 = @"stwo_zig_lookup_poly_v2_28bc2d54b9a33dccb35df8513dc35a810077488a2f4be0c88b5d36a55a9e8bf8";
        runtime.riscvPolynomialPipelines[riscvPolynomialName36] = make_pipeline(
            device, library, riscvPolynomialName36, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName36] == nil) return NULL;
        NSString *riscvPolynomialName37 = @"stwo_zig_lookup_poly_v2_be13b51301211f686fd16c2f88309d8f847af74402b7d38c61ef79b645d99f79";
        runtime.riscvPolynomialPipelines[riscvPolynomialName37] = make_pipeline(
            device, library, riscvPolynomialName37, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName37] == nil) return NULL;
        NSString *riscvPolynomialName38 = @"stwo_zig_lookup_poly_v2_275d7261fb64f5cf5fc049ceac6422a7d6e64f153e09f81ddcf3311c1e2ffaa6";
        runtime.riscvPolynomialPipelines[riscvPolynomialName38] = make_pipeline(
            device, library, riscvPolynomialName38, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName38] == nil) return NULL;
        NSString *riscvPolynomialName39 = @"stwo_zig_lookup_poly_v2_c21e7087e658c83a4ea68ba0339efa466e9023c10538de1236d5e94f360cd70f";
        runtime.riscvPolynomialPipelines[riscvPolynomialName39] = make_pipeline(
            device, library, riscvPolynomialName39, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName39] == nil) return NULL;
        NSString *riscvPolynomialName40 = @"stwo_zig_lookup_poly_v2_6e0f5b41382a11695ffc997f00f28eb2a1fd365fac56419e6a58bd35fcecaebc";
        runtime.riscvPolynomialPipelines[riscvPolynomialName40] = make_pipeline(
            device, library, riscvPolynomialName40, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName40] == nil) return NULL;
        NSString *riscvPolynomialName41 = @"stwo_zig_lookup_poly_v2_330b38988296b847ce7943460949e4339ec66db537e4d03491747b2c39b920c0";
        runtime.riscvPolynomialPipelines[riscvPolynomialName41] = make_pipeline(
            device, library, riscvPolynomialName41, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName41] == nil) return NULL;
        NSString *riscvPolynomialName42 = @"stwo_zig_lookup_poly_v2_77f9c3e7ba9b17eb361ff2af6220464a5777f3a52ef415c3524ac42ab6e32f2c";
        runtime.riscvPolynomialPipelines[riscvPolynomialName42] = make_pipeline(
            device, library, riscvPolynomialName42, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName42] == nil) return NULL;
        NSString *riscvPolynomialName43 = @"stwo_zig_lookup_poly_v2_69a3e73ed85579645e6ee7eee831fcd273dc41967143d39561a8b07d44d4b8b7";
        runtime.riscvPolynomialPipelines[riscvPolynomialName43] = make_pipeline(
            device, library, riscvPolynomialName43, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName43] == nil) return NULL;
        NSString *riscvPolynomialName44 = @"stwo_zig_lookup_poly_v2_17d893819094787c341d61e34fc145d907ae4f229fc5bdf675450f9cbfc783e7";
        runtime.riscvPolynomialPipelines[riscvPolynomialName44] = make_pipeline(
            device, library, riscvPolynomialName44, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName44] == nil) return NULL;
        NSString *riscvPolynomialName45 = @"stwo_zig_lookup_poly_v2_c52d555f957bd0bb3a403a52ba9a00707ea38b95680598413ab0c999a4f2e212";
        runtime.riscvPolynomialPipelines[riscvPolynomialName45] = make_pipeline(
            device, library, riscvPolynomialName45, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName45] == nil) return NULL;
        NSString *riscvPolynomialName46 = @"stwo_zig_lookup_poly_v2_1d2cb31b377e1584858df2e1571ab50af833573e09a8e92b509736d894751ff5";
        runtime.riscvPolynomialPipelines[riscvPolynomialName46] = make_pipeline(
            device, library, riscvPolynomialName46, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName46] == nil) return NULL;
        NSString *riscvPolynomialName47 = @"stwo_zig_lookup_poly_v2_a58738eaf81c1bd3c20292b4d470433552c7c5bef4faf841e4da8e2a5a04681a";
        runtime.riscvPolynomialPipelines[riscvPolynomialName47] = make_pipeline(
            device, library, riscvPolynomialName47, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName47] == nil) return NULL;
        NSString *riscvPolynomialName48 = @"stwo_zig_lookup_poly_v2_a5c335d39317cb0ece5d0ffe5dd536cba3b9c4c84da54f5c8876a3b6cd5520f4";
        runtime.riscvPolynomialPipelines[riscvPolynomialName48] = make_pipeline(
            device, library, riscvPolynomialName48, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName48] == nil) return NULL;
        NSString *riscvPolynomialName49 = @"stwo_zig_lookup_poly_v2_23bb5dc1410c56ceab84080bd3239e6c9156f3761b93508f773dee7e448a70dc";
        runtime.riscvPolynomialPipelines[riscvPolynomialName49] = make_pipeline(
            device, library, riscvPolynomialName49, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName49] == nil) return NULL;
        NSString *riscvPolynomialName50 = @"stwo_zig_lookup_poly_v2_64c076e4946245d3c0f988997bf90b10774d23a6344d856e147c744b2df6d98c";
        runtime.riscvPolynomialPipelines[riscvPolynomialName50] = make_pipeline(
            device, library, riscvPolynomialName50, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName50] == nil) return NULL;
        NSString *riscvPolynomialName51 = @"stwo_zig_base_poly_8ae392ed1a7274608734b90ddc05e147";
        runtime.riscvPolynomialPipelines[riscvPolynomialName51] = make_pipeline(
            device, library, riscvPolynomialName51, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName51] == nil) return NULL;
        NSString *riscvPolynomialName52 = @"stwo_zig_base_poly_7be9f94a181c86f487035579b75a3c09";
        runtime.riscvPolynomialPipelines[riscvPolynomialName52] = make_pipeline(
            device, library, riscvPolynomialName52, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName52] == nil) return NULL;
        NSString *riscvPolynomialName53 = @"stwo_zig_base_poly_252a366d21097cfa39ddc55b4c8d3732";
        runtime.riscvPolynomialPipelines[riscvPolynomialName53] = make_pipeline(
            device, library, riscvPolynomialName53, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName53] == nil) return NULL;
        NSString *riscvPolynomialName54 = @"stwo_zig_base_poly_3ff26f48f99514ff96f9e6242e02689c";
        runtime.riscvPolynomialPipelines[riscvPolynomialName54] = make_pipeline(
            device, library, riscvPolynomialName54, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName54] == nil) return NULL;
        NSString *riscvPolynomialName55 = @"stwo_zig_lookup_poly_bfaf5e2aa44bc0bce57377b16d8362a7";
        runtime.riscvPolynomialPipelines[riscvPolynomialName55] = make_pipeline(
            device, library, riscvPolynomialName55, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName55] == nil) return NULL;
        NSString *riscvPolynomialName56 = @"stwo_zig_base_poly_e13d2efe7ad236638a213d15673065f1";
        runtime.riscvPolynomialPipelines[riscvPolynomialName56] = make_pipeline(
            device, library, riscvPolynomialName56, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName56] == nil) return NULL;
        NSString *riscvPolynomialName57 = @"stwo_zig_base_poly_e7e0dab59a4ca045df197c03e1cde944";
        runtime.riscvPolynomialPipelines[riscvPolynomialName57] = make_pipeline(
            device, library, riscvPolynomialName57, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName57] == nil) return NULL;
        NSString *riscvPolynomialName58 = @"stwo_zig_base_poly_b0c8b0812b31ac11d0ed355fdffceaeb";
        runtime.riscvPolynomialPipelines[riscvPolynomialName58] = make_pipeline(
            device, library, riscvPolynomialName58, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName58] == nil) return NULL;
        NSString *riscvPolynomialName59 = @"stwo_zig_base_poly_ba19de000ba4a34803e344cadd255681";
        runtime.riscvPolynomialPipelines[riscvPolynomialName59] = make_pipeline(
            device, library, riscvPolynomialName59, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName59] == nil) return NULL;
        NSString *riscvPolynomialName60 = @"stwo_zig_lookup_poly_eadeb11637b6b8b330635af67876a763";
        runtime.riscvPolynomialPipelines[riscvPolynomialName60] = make_pipeline(
            device, library, riscvPolynomialName60, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName60] == nil) return NULL;
        // END GENERATED RISC-V POLYNOMIAL PIPELINES.

        if (runtime.queue == nil || runtime.quadraticRecurrenceTrace == nil ||
            runtime.quadraticRecurrenceIfftWide == nil ||
            runtime.leaves == nil || runtime.parents == nil ||
            runtime.poseidon2M31Leaves == nil || runtime.poseidon2M31LeavesWide == nil ||
            runtime.poseidon2M31Parents == nil ||
            runtime.quotients == nil || runtime.rawQuotients == nil || runtime.polynomialEval == nil ||
            runtime.polynomialBasis == nil ||
            runtime.sampledBarycentricDomain == nil ||
            runtime.sampledBarycentricScale == nil ||
            runtime.sampledBarycentricParts == nil ||
            runtime.sampledBarycentricInverseDirect == nil ||
            runtime.sampledBarycentricInverseTree == nil ||
            runtime.sampledBarycentricFinish == nil ||
            runtime.sampledBarycentricEvaluateMany == nil ||
            runtime.sampledBarycentricReduce == nil ||
            runtime.circleIfftFirst == nil || runtime.circleIfftLayer == nil ||
            runtime.circleRfftLayer == nil || runtime.circleRfftLast == nil || runtime.circleRescale == nil ||
            runtime.circleExpand == nil || runtime.circleIfftFused == nil || runtime.circleIfftFusedWide == nil ||
            runtime.circleRfftFused == nil ||
            runtime.quotientNumerator == nil || runtime.quotientFinalize == nil ||
            runtime.quotientPartialsRaw == nil || runtime.quotientCombinePartialsRaw == nil ||
            runtime.quotientDomainPointsResident == nil || runtime.quotientDenominatorsResident == nil ||
            runtime.quotientCombineResident == nil || runtime.quotientCoefficientsResident == nil ||
            runtime.friFoldCircle == nil || runtime.friFoldLine == nil || runtime.friFold3Resident == nil ||
            runtime.friFold2Resident == nil || runtime.friPackedLeavesResident == nil ||
            runtime.poseidon2M31FriPackedLeavesResident == nil || runtime.friFinalLineResident == nil ||
            runtime.transcriptInitResident == nil || runtime.transcriptMixResident == nil ||
            runtime.transcriptDrawSecureResident == nil || runtime.transcriptDrawQueriesResident == nil ||
            runtime.decommitNormalizeQueriesResident == nil || runtime.decommitPrepareFriQueriesResident == nil ||
            runtime.decommitGatherFriValuesResident == nil || runtime.decommitPrepareTraceQueriesResident == nil ||
            runtime.decommitGatherTraceValuesResident == nil || runtime.decommitGatherTreeValuesResident == nil ||
            runtime.decommitGatherTreeValuesResidentWide == nil ||
            runtime.qm31ToCoordinates == nil ||
            runtime.proofOfWork == nil ||
            runtime.decommitAssembleFriResident == nil ||
            runtime.decommitSparseParentResident == nil || runtime.decommitAssembleTraceResident == nil ||
            runtime.decommitSparseLeavesResident == nil ||
            runtime.decommitSparseLeafGroupResident == nil || runtime.clearArenaSpans == nil ||
            runtime.leafAbsorbResident == nil || runtime.leafAbsorbCompactResident == nil ||
            runtime.poseidon2M31LeafAbsorbResident == nil || runtime.poseidon2M31LeafAbsorbCompactResident == nil ||
            runtime.poseidon2M31LeafStateDigestResidentV1 == nil ||
            runtime.parentsPlainSparse == nil ||
            runtime.circleExpandSparse == nil ||
            runtime.circleCopySparse == nil || runtime.circleIfftFirstSparse == nil ||
            runtime.circleIfftLayerSparse == nil || runtime.circleRescaleSparse == nil ||
            runtime.circleRfftLayerSparse == nil || runtime.circleRfftRadix4Sparse == nil ||
            runtime.circleRfftLastSparse == nil || runtime.circleRfftFusedSparse == nil ||
            runtime.circleRfftFusedSparseWide == nil ||
            runtime.circleRfftLayerSparseWide == nil || runtime.circleRfftLastSparseWide == nil) return NULL;
        if (runtime.relationFused == nil || runtime.relationBlockScan == nil ||
            runtime.relationScanBlocks == nil || runtime.relationScanFinalize == nil ||
            runtime.parentsSparse == nil || runtime.parentTailSparse == nil ||
            runtime.poseidon2M31ParentsSparse == nil || runtime.poseidon2M31ParentTailSparse == nil ||
            runtime.poseidon2ChannelPowSearch == nil ||
            runtime.compactGather == nil || runtime.compactRadixHistogram == nil || runtime.compactRadixPrefix == nil ||
            runtime.compactRadixScatter == nil || runtime.compactHeads == nil || runtime.compactScanLocal == nil ||
            runtime.compactScanBlocks == nil || runtime.compactScanAdd == nil || runtime.compactClearOutputs == nil ||
            runtime.compactScatter == nil || runtime.compactFinalize == nil || runtime.compositionLift == nil ||
            runtime.compositionSplit == nil || runtime.compositionExpand == nil || runtime.compositionRandomPowers == nil ||
            runtime.compositionExtParams == nil) return NULL;
        if (include_deferred) {
            runtime.witnessFeedCounts = make_pipeline(device, library, @"stwo_zig_witness_feed_counts", error_message, error_message_len);
            runtime.witnessInputGatherResident = make_pipeline(device, library, @"stwo_zig_witness_input_gather_resident", error_message, error_message_len);
            runtime.executionTableSplitResident = make_pipeline(device, library, @"stwo_zig_execution_table_split_resident", error_message, error_message_len);
            runtime.memoryAddressBaseTraceResident = make_pipeline(device, library, @"stwo_zig_memory_address_base_trace_resident", error_message, error_message_len);
            runtime.memoryValueBaseTraceResident = make_pipeline(device, library, @"stwo_zig_memory_value_base_trace_resident", error_message, error_message_len);
            runtime.memoryRc99CountResident = make_pipeline(device, library, @"stwo_zig_memory_rc99_count_resident", error_message, error_message_len);
            runtime.publicMemorySeedResident = make_pipeline(device, library, @"stwo_zig_public_memory_seed_resident", error_message, error_message_len);
            runtime.fixedTableLookup = make_pipeline(device, library, @"stwo_zig_fixed_table_lookup_sparse", error_message, error_message_len);
            runtime.felt252Oracle = make_pipeline(device, library, @"stwo_zig_felt252_oracle", error_message, error_message_len);
            runtime.ecOpWitness = make_pipeline(device, library, @"stwo_zig_ec_op_witness", error_message, error_message_len);
            runtime.ecOpLookup = make_pipeline(device, library, @"stwo_zig_ec_op_lookup", error_message, error_message_len);
            runtime.ecOpBaseFinalize = make_pipeline(device, library, @"stwo_zig_ec_op_base_finalize", error_message, error_message_len);
            if (runtime.witnessFeedCounts == nil || runtime.witnessInputGatherResident == nil ||
                runtime.executionTableSplitResident == nil || runtime.memoryAddressBaseTraceResident == nil ||
                runtime.memoryValueBaseTraceResident == nil || runtime.memoryRc99CountResident == nil ||
                runtime.publicMemorySeedResident == nil || runtime.fixedTableLookup == nil ||
                runtime.felt252Oracle == nil || runtime.ecOpWitness == nil ||
                runtime.ecOpLookup == nil || runtime.ecOpBaseFinalize == nil) return NULL;
        }
        return runtime;
    }
}

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
#import "runtime/auxiliary_plans.m"
#import "runtime/cache_identity.m"
#import "runtime/archive_store.m"
#import "runtime/dynamic_evaluation.m"
#import "runtime/base_polynomial.m"
#import "runtime/lookup_polynomial.m"
#import "runtime/composition.m"
#import "runtime/composition_recurrence.m"
#import "runtime/prepared_auxiliary.m"
#import "runtime/circle_legacy.m"
#import "runtime/circle_commit_epoch.m"
#import "runtime/polynomial_evaluation.m"
#import "runtime/quotient_planning.m"
#import "runtime/quotient_completion.m"
#import "runtime/quotients.m"
#import "runtime/lifecycle_and_tree.m"

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
