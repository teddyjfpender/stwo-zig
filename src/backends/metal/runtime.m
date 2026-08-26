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
        const uint32_t *offsets = tree.residentColumnWordOffsets.bytes;
        NSUInteger count = tree.residentColumnHostBegins.length / sizeof(uintptr_t);
        if (buffers.count == 1u && begins != NULL && counts != NULL && offsets != NULL &&
            tree.residentColumnHostBegins.length == count * sizeof(uintptr_t) &&
            tree.residentColumnWordCounts.length == count * sizeof(size_t) &&
            tree.residentColumnWordOffsets.length == count * sizeof(uint32_t)) {
            for (NSUInteger index = 0u; index < count; ++index) {
                uintptr_t begin = begins[index];
                size_t words = counts[index];
                if (address < begin || (address - begin) % sizeof(uint32_t) != 0u)
                    continue;
                size_t offset = (address - begin) / sizeof(uint32_t);
                if (offset > words || column_words > words - offset) continue;
                id<MTLBuffer> buffer = buffers[0];
                size_t device_offset = (size_t)offsets[index] + offset;
                if (buffer == nil || device_offset > buffer.length / sizeof(uint32_t) ||
                    column_words > buffer.length / sizeof(uint32_t) - device_offset)
                    continue;
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
        runtime.riscvPolynomialPipelines = [NSMutableDictionary dictionaryWithCapacity:34u];
        runtime.evalLibraries = [NSMutableDictionary dictionary];
        runtime.evalPipelines = [NSMutableDictionary dictionary];
        runtime.quadraticRecurrenceTrace = make_pipeline(device, library, @"stwo_zig_quadratic_recurrence_trace",
                                                         error_message, error_message_len);
        runtime.quadraticRecurrenceIfftWide = make_pipeline(device, library, @"stwo_zig_quadratic_recurrence_ifft_fused_wide",
                                                            error_message, error_message_len);
        runtime.leaves = make_pipeline(device, library, @"stwo_zig_blake2s_leaves",
                                       error_message, error_message_len);
        runtime.parents = make_pipeline(device, library, @"stwo_zig_blake2s_parents",
                                        error_message, error_message_len);
        runtime.quotients = make_pipeline(device, library, @"stwo_zig_quotient_rows",
                                          error_message, error_message_len);
        runtime.rawQuotients = make_pipeline(device, library, @"stwo_zig_quotient_rows_raw",
                                             error_message, error_message_len);
        runtime.polynomialEval = make_pipeline(device, library, @"stwo_zig_eval_polynomials",
                                               error_message, error_message_len);
        runtime.polynomialBasis = make_pipeline(device, library, @"stwo_zig_eval_basis",
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
        runtime.decommitAssembleFriResident = make_pipeline(device, library, @"stwo_zig_decommit_assemble_fri_resident", error_message, error_message_len);
        runtime.decommitSparseParentResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_parent_resident", error_message, error_message_len);
        runtime.decommitSparseLeavesResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_leaves_resident", error_message, error_message_len);
        runtime.decommitSparseLeafGroupResident = make_pipeline(device, library, @"stwo_zig_decommit_sparse_leaf_group_resident", error_message, error_message_len);
        runtime.decommitAssembleTraceResident = make_pipeline(device, library, @"stwo_zig_decommit_assemble_trace_resident", error_message, error_message_len);
        runtime.qm31ToCoordinates = make_pipeline(device, library, @"stwo_zig_qm31_to_coordinates", error_message, error_message_len);
        runtime.leafAbsorbResident = make_pipeline(device, library, @"stwo_zig_blake2s_leaf_absorb_resident", error_message, error_message_len);
        runtime.leafAbsorbCompactResident = make_pipeline(device, library, @"stwo_zig_blake2s_leaf_absorb_compact_resident", error_message, error_message_len);
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
        NSString *riscvPolynomialName00 = @"stwo_zig_base_poly_450551d90acd324ebbd24fcf112b6e2a";
        runtime.riscvPolynomialPipelines[riscvPolynomialName00] = make_pipeline(
            device, library, riscvPolynomialName00, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName00] == nil) return NULL;
        NSString *riscvPolynomialName01 = @"stwo_zig_base_poly_c14a50f654a9c7e71379b41a108194ff";
        runtime.riscvPolynomialPipelines[riscvPolynomialName01] = make_pipeline(
            device, library, riscvPolynomialName01, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName01] == nil) return NULL;
        NSString *riscvPolynomialName02 = @"stwo_zig_base_poly_f3458c84073cbe0a1a0cc8d255a028f0";
        runtime.riscvPolynomialPipelines[riscvPolynomialName02] = make_pipeline(
            device, library, riscvPolynomialName02, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName02] == nil) return NULL;
        NSString *riscvPolynomialName03 = @"stwo_zig_base_poly_a2a6593402647f120c2a259a1710c6e3";
        runtime.riscvPolynomialPipelines[riscvPolynomialName03] = make_pipeline(
            device, library, riscvPolynomialName03, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName03] == nil) return NULL;
        NSString *riscvPolynomialName04 = @"stwo_zig_base_poly_a972dafabb2bf5eee1d1cdb560f3572e";
        runtime.riscvPolynomialPipelines[riscvPolynomialName04] = make_pipeline(
            device, library, riscvPolynomialName04, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName04] == nil) return NULL;
        NSString *riscvPolynomialName05 = @"stwo_zig_base_poly_09e5f90f9696d165cc36093de2564888";
        runtime.riscvPolynomialPipelines[riscvPolynomialName05] = make_pipeline(
            device, library, riscvPolynomialName05, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName05] == nil) return NULL;
        NSString *riscvPolynomialName06 = @"stwo_zig_base_poly_a74fd0125263cc1e887ee5d726ac99a0";
        runtime.riscvPolynomialPipelines[riscvPolynomialName06] = make_pipeline(
            device, library, riscvPolynomialName06, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName06] == nil) return NULL;
        NSString *riscvPolynomialName07 = @"stwo_zig_base_poly_3b018614b76f63e7a28e127029c18704";
        runtime.riscvPolynomialPipelines[riscvPolynomialName07] = make_pipeline(
            device, library, riscvPolynomialName07, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName07] == nil) return NULL;
        NSString *riscvPolynomialName08 = @"stwo_zig_base_poly_aa55ec34af78d3f2b74d4b3d06c708a8";
        runtime.riscvPolynomialPipelines[riscvPolynomialName08] = make_pipeline(
            device, library, riscvPolynomialName08, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName08] == nil) return NULL;
        NSString *riscvPolynomialName09 = @"stwo_zig_base_poly_0ade2040c246f9cad3919da46161d2fd";
        runtime.riscvPolynomialPipelines[riscvPolynomialName09] = make_pipeline(
            device, library, riscvPolynomialName09, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName09] == nil) return NULL;
        NSString *riscvPolynomialName10 = @"stwo_zig_base_poly_6301135c98c38c29971098b60b459397";
        runtime.riscvPolynomialPipelines[riscvPolynomialName10] = make_pipeline(
            device, library, riscvPolynomialName10, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName10] == nil) return NULL;
        NSString *riscvPolynomialName11 = @"stwo_zig_base_poly_95bca92bf8e5c8c0cd1438e06c6c8963";
        runtime.riscvPolynomialPipelines[riscvPolynomialName11] = make_pipeline(
            device, library, riscvPolynomialName11, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName11] == nil) return NULL;
        NSString *riscvPolynomialName12 = @"stwo_zig_base_poly_373e28e4ebf898ce291ed734807dfa00";
        runtime.riscvPolynomialPipelines[riscvPolynomialName12] = make_pipeline(
            device, library, riscvPolynomialName12, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName12] == nil) return NULL;
        NSString *riscvPolynomialName13 = @"stwo_zig_base_poly_1d58ef609255595a37488e277d52585c";
        runtime.riscvPolynomialPipelines[riscvPolynomialName13] = make_pipeline(
            device, library, riscvPolynomialName13, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName13] == nil) return NULL;
        NSString *riscvPolynomialName14 = @"stwo_zig_base_poly_208adea2af3accc5bd53faa7807024bb";
        runtime.riscvPolynomialPipelines[riscvPolynomialName14] = make_pipeline(
            device, library, riscvPolynomialName14, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName14] == nil) return NULL;
        NSString *riscvPolynomialName15 = @"stwo_zig_base_poly_9b9a12367c3aeb8830ac01bf757fa64a";
        runtime.riscvPolynomialPipelines[riscvPolynomialName15] = make_pipeline(
            device, library, riscvPolynomialName15, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName15] == nil) return NULL;
        NSString *riscvPolynomialName16 = @"stwo_zig_base_poly_ebe47c5c0304bddea66f3a2b7c9cd55c";
        runtime.riscvPolynomialPipelines[riscvPolynomialName16] = make_pipeline(
            device, library, riscvPolynomialName16, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName16] == nil) return NULL;
        NSString *riscvPolynomialName17 = @"stwo_zig_lookup_poly_6bd1123655f7e5fc662f4e397524645b";
        runtime.riscvPolynomialPipelines[riscvPolynomialName17] = make_pipeline(
            device, library, riscvPolynomialName17, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName17] == nil) return NULL;
        NSString *riscvPolynomialName18 = @"stwo_zig_lookup_poly_60369e534e1e31666bb1684e6745500b";
        runtime.riscvPolynomialPipelines[riscvPolynomialName18] = make_pipeline(
            device, library, riscvPolynomialName18, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName18] == nil) return NULL;
        NSString *riscvPolynomialName19 = @"stwo_zig_lookup_poly_cae77cf99f2127b1108dc5c1609cc16b";
        runtime.riscvPolynomialPipelines[riscvPolynomialName19] = make_pipeline(
            device, library, riscvPolynomialName19, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName19] == nil) return NULL;
        NSString *riscvPolynomialName20 = @"stwo_zig_lookup_poly_d1b44ec0cc8a532f04e4e39fd0bb648e";
        runtime.riscvPolynomialPipelines[riscvPolynomialName20] = make_pipeline(
            device, library, riscvPolynomialName20, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName20] == nil) return NULL;
        NSString *riscvPolynomialName21 = @"stwo_zig_lookup_poly_88bafd2b2b2bb614f3a37e2e93f88f8f";
        runtime.riscvPolynomialPipelines[riscvPolynomialName21] = make_pipeline(
            device, library, riscvPolynomialName21, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName21] == nil) return NULL;
        NSString *riscvPolynomialName22 = @"stwo_zig_lookup_poly_f0435e9fbbd4a7a98c7c5162bee7d7a9";
        runtime.riscvPolynomialPipelines[riscvPolynomialName22] = make_pipeline(
            device, library, riscvPolynomialName22, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName22] == nil) return NULL;
        NSString *riscvPolynomialName23 = @"stwo_zig_lookup_poly_cc2c95d2bff4c999fee2f44e08222252";
        runtime.riscvPolynomialPipelines[riscvPolynomialName23] = make_pipeline(
            device, library, riscvPolynomialName23, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName23] == nil) return NULL;
        NSString *riscvPolynomialName24 = @"stwo_zig_lookup_poly_b52a532ad3c7e42bdece0624fb56b8aa";
        runtime.riscvPolynomialPipelines[riscvPolynomialName24] = make_pipeline(
            device, library, riscvPolynomialName24, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName24] == nil) return NULL;
        NSString *riscvPolynomialName25 = @"stwo_zig_lookup_poly_b15f9ad4a9abfc83a7cdec6c46ee4ade";
        runtime.riscvPolynomialPipelines[riscvPolynomialName25] = make_pipeline(
            device, library, riscvPolynomialName25, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName25] == nil) return NULL;
        NSString *riscvPolynomialName26 = @"stwo_zig_lookup_poly_fcc84457fa16172e164408c12324b2c2";
        runtime.riscvPolynomialPipelines[riscvPolynomialName26] = make_pipeline(
            device, library, riscvPolynomialName26, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName26] == nil) return NULL;
        NSString *riscvPolynomialName27 = @"stwo_zig_lookup_poly_ff9bf971cfa80d96e0aa0e50e4b1b89d";
        runtime.riscvPolynomialPipelines[riscvPolynomialName27] = make_pipeline(
            device, library, riscvPolynomialName27, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName27] == nil) return NULL;
        NSString *riscvPolynomialName28 = @"stwo_zig_lookup_poly_b63d26046143c546183c7769fee7803a";
        runtime.riscvPolynomialPipelines[riscvPolynomialName28] = make_pipeline(
            device, library, riscvPolynomialName28, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName28] == nil) return NULL;
        NSString *riscvPolynomialName29 = @"stwo_zig_lookup_poly_60da0a81177c1f7c118d91080a104856";
        runtime.riscvPolynomialPipelines[riscvPolynomialName29] = make_pipeline(
            device, library, riscvPolynomialName29, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName29] == nil) return NULL;
        NSString *riscvPolynomialName30 = @"stwo_zig_lookup_poly_d71f7ff4122659b75334f16e7282cd1e";
        runtime.riscvPolynomialPipelines[riscvPolynomialName30] = make_pipeline(
            device, library, riscvPolynomialName30, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName30] == nil) return NULL;
        NSString *riscvPolynomialName31 = @"stwo_zig_lookup_poly_2933fad233d8d72eaaaac264f1f08e46";
        runtime.riscvPolynomialPipelines[riscvPolynomialName31] = make_pipeline(
            device, library, riscvPolynomialName31, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName31] == nil) return NULL;
        NSString *riscvPolynomialName32 = @"stwo_zig_lookup_poly_55f49d22b3eefd58176c82e98f534eb1";
        runtime.riscvPolynomialPipelines[riscvPolynomialName32] = make_pipeline(
            device, library, riscvPolynomialName32, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName32] == nil) return NULL;
        NSString *riscvPolynomialName33 = @"stwo_zig_lookup_poly_34a73d9627a19782b2486c6dcd96f1fe";
        runtime.riscvPolynomialPipelines[riscvPolynomialName33] = make_pipeline(
            device, library, riscvPolynomialName33, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName33] == nil) return NULL;
        NSString *riscvPolynomialName34 = @"stwo_zig_lookup_poly_v2_4495e1dc5d58d71f640d011e5e267fc06fe6adfe54e6405fa20aab1ab4a4f496";
        runtime.riscvPolynomialPipelines[riscvPolynomialName34] = make_pipeline(
            device, library, riscvPolynomialName34, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName34] == nil) return NULL;
        NSString *riscvPolynomialName35 = @"stwo_zig_lookup_poly_v2_faadbe548bfa104ae056599d5e4910f9812fc7ddf9179da65d5d5e6fba234d35";
        runtime.riscvPolynomialPipelines[riscvPolynomialName35] = make_pipeline(
            device, library, riscvPolynomialName35, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName35] == nil) return NULL;
        NSString *riscvPolynomialName36 = @"stwo_zig_lookup_poly_v2_9ed05c9eac769627c64b0e915e2630d0a51bb6325410ea144d9669b85c480514";
        runtime.riscvPolynomialPipelines[riscvPolynomialName36] = make_pipeline(
            device, library, riscvPolynomialName36, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName36] == nil) return NULL;
        NSString *riscvPolynomialName37 = @"stwo_zig_lookup_poly_v2_198678cb3ba8974d902c91452544c7f63c81fc0d10de3a87f612c1e9cb9437a8";
        runtime.riscvPolynomialPipelines[riscvPolynomialName37] = make_pipeline(
            device, library, riscvPolynomialName37, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName37] == nil) return NULL;
        NSString *riscvPolynomialName38 = @"stwo_zig_lookup_poly_v2_ec1cb673e29351c380eb472b19293e7ea97ab2030393f54c7bcbb1426ae83aa2";
        runtime.riscvPolynomialPipelines[riscvPolynomialName38] = make_pipeline(
            device, library, riscvPolynomialName38, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName38] == nil) return NULL;
        NSString *riscvPolynomialName39 = @"stwo_zig_lookup_poly_v2_edade529adf1f7eb6b09313aad8cc71ff739a71d11e2b40cb6101daf378d8489";
        runtime.riscvPolynomialPipelines[riscvPolynomialName39] = make_pipeline(
            device, library, riscvPolynomialName39, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName39] == nil) return NULL;
        NSString *riscvPolynomialName40 = @"stwo_zig_lookup_poly_v2_c95e5383b34ea4ad55aaff5bc8ca9054b9fb9abe15db39e6409374e0dd3b5617";
        runtime.riscvPolynomialPipelines[riscvPolynomialName40] = make_pipeline(
            device, library, riscvPolynomialName40, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName40] == nil) return NULL;
        NSString *riscvPolynomialName41 = @"stwo_zig_lookup_poly_v2_b64e1478588595c7a3f7c71371ef1e6f1ceae3dd055c9eb56aa4081cf93e97d1";
        runtime.riscvPolynomialPipelines[riscvPolynomialName41] = make_pipeline(
            device, library, riscvPolynomialName41, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName41] == nil) return NULL;
        NSString *riscvPolynomialName42 = @"stwo_zig_lookup_poly_v2_b9e7c8afba03add7dd116b67fd791e19256bc093b6eb47e41ca9ee411608c58a";
        runtime.riscvPolynomialPipelines[riscvPolynomialName42] = make_pipeline(
            device, library, riscvPolynomialName42, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName42] == nil) return NULL;
        NSString *riscvPolynomialName43 = @"stwo_zig_lookup_poly_v2_b777199dcff0d3dbb81372f98612beda7bd12bf2d2bc7725f1dab500e07c39d9";
        runtime.riscvPolynomialPipelines[riscvPolynomialName43] = make_pipeline(
            device, library, riscvPolynomialName43, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName43] == nil) return NULL;
        NSString *riscvPolynomialName44 = @"stwo_zig_lookup_poly_v2_a0710166b8b3057556c2f5907836c0c82fe3b92fccff4633d504c0ff510b6d93";
        runtime.riscvPolynomialPipelines[riscvPolynomialName44] = make_pipeline(
            device, library, riscvPolynomialName44, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName44] == nil) return NULL;
        NSString *riscvPolynomialName45 = @"stwo_zig_lookup_poly_v2_bd8284d4f0c5a7d0cd9dd1f4879d721c70992754e1d5aadf02df9e4f86c15d2c";
        runtime.riscvPolynomialPipelines[riscvPolynomialName45] = make_pipeline(
            device, library, riscvPolynomialName45, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName45] == nil) return NULL;
        NSString *riscvPolynomialName46 = @"stwo_zig_lookup_poly_v2_099cc5bddab2ff60effcbef0d7863f6a78e0d7a9fcc78fa43d9603f6798904b3";
        runtime.riscvPolynomialPipelines[riscvPolynomialName46] = make_pipeline(
            device, library, riscvPolynomialName46, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName46] == nil) return NULL;
        NSString *riscvPolynomialName47 = @"stwo_zig_lookup_poly_v2_e622d001a5cd368b6efef022e0db61a1ab9e30842ef91e4135c0dc5cbd18eb19";
        runtime.riscvPolynomialPipelines[riscvPolynomialName47] = make_pipeline(
            device, library, riscvPolynomialName47, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName47] == nil) return NULL;
        NSString *riscvPolynomialName48 = @"stwo_zig_lookup_poly_v2_1cab02ea628504e58cb4a0dbf15dbca36cccc7cad4f36949bb10265a08cd44cc";
        runtime.riscvPolynomialPipelines[riscvPolynomialName48] = make_pipeline(
            device, library, riscvPolynomialName48, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName48] == nil) return NULL;
        NSString *riscvPolynomialName49 = @"stwo_zig_lookup_poly_v2_74e0c5ba6845f3d863a1b821d0f22ea76e38570ccd234b537ea4fb9e8f19bf77";
        runtime.riscvPolynomialPipelines[riscvPolynomialName49] = make_pipeline(
            device, library, riscvPolynomialName49, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName49] == nil) return NULL;
        NSString *riscvPolynomialName50 = @"stwo_zig_lookup_poly_v2_e9b9d5d433a734c48921694aa7185fafe3fb15e7bd89dc42261cc4290f894352";
        runtime.riscvPolynomialPipelines[riscvPolynomialName50] = make_pipeline(
            device, library, riscvPolynomialName50, error_message, error_message_len);
        if (runtime.riscvPolynomialPipelines[riscvPolynomialName50] == nil) return NULL;
        // END GENERATED RISC-V POLYNOMIAL PIPELINES.

        if (runtime.queue == nil || runtime.quadraticRecurrenceTrace == nil ||
            runtime.quadraticRecurrenceIfftWide == nil ||
            runtime.leaves == nil || runtime.parents == nil ||
            runtime.quotients == nil || runtime.rawQuotients == nil || runtime.polynomialEval == nil ||
            runtime.polynomialBasis == nil || runtime.circleIfftFirst == nil || runtime.circleIfftLayer == nil ||
            runtime.circleRfftLayer == nil || runtime.circleRfftLast == nil || runtime.circleRescale == nil ||
            runtime.circleExpand == nil || runtime.circleIfftFused == nil || runtime.circleIfftFusedWide == nil ||
            runtime.circleRfftFused == nil ||
            runtime.quotientNumerator == nil || runtime.quotientFinalize == nil ||
            runtime.quotientPartialsRaw == nil || runtime.quotientCombinePartialsRaw == nil ||
            runtime.quotientDomainPointsResident == nil || runtime.quotientDenominatorsResident == nil ||
            runtime.quotientCombineResident == nil || runtime.quotientCoefficientsResident == nil ||
            runtime.friFoldCircle == nil || runtime.friFoldLine == nil || runtime.friFold3Resident == nil ||
            runtime.friFold2Resident == nil || runtime.friPackedLeavesResident == nil || runtime.friFinalLineResident == nil ||
            runtime.transcriptInitResident == nil || runtime.transcriptMixResident == nil ||
            runtime.transcriptDrawSecureResident == nil || runtime.transcriptDrawQueriesResident == nil ||
            runtime.decommitNormalizeQueriesResident == nil || runtime.decommitPrepareFriQueriesResident == nil ||
            runtime.decommitGatherFriValuesResident == nil || runtime.decommitPrepareTraceQueriesResident == nil ||
            runtime.decommitGatherTraceValuesResident == nil || runtime.qm31ToCoordinates == nil ||
            runtime.decommitAssembleFriResident == nil ||
            runtime.decommitSparseParentResident == nil || runtime.decommitAssembleTraceResident == nil ||
            runtime.decommitSparseLeavesResident == nil ||
            runtime.decommitSparseLeafGroupResident == nil || runtime.clearArenaSpans == nil ||
            runtime.leafAbsorbResident == nil || runtime.leafAbsorbCompactResident == nil ||
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
