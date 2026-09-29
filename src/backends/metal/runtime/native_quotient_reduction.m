// Native-height reduction across any number of segmented source buffers.
// A shared planar partial owns at most 256 MiB. Serial encoders accumulate
// each run into the same geometry bucket; the tiled lift sees one planar
// descriptor per bucket instead of every original coefficient-weighted column.
@interface StwoZigNativeQuotientReduction : NSObject
@property(nonatomic, strong) NSData *bucketOffsets;
@property(nonatomic, strong) NSData *syntheticViews;
@property(nonatomic) uint32_t partialWords;
@property(nonatomic) uint32_t reducedViews;
@end
@implementation StwoZigNativeQuotientReduction
@end

static StwoZigNativeQuotientReduction *stwo_native_quotient_reduction_plan(
    const StwoZigRawQuotientSourceViewV2 *views, uint32_t count,
    uint32_t batches, uint32_t rows
) {
    if (views == NULL || count == 0u || batches == 0u ||
        (size_t)batches > SIZE_MAX / (32u * sizeof(uint32_t))) return nil;
    const size_t buckets = (size_t)batches * 32u;
    NSMutableData *countsData = [NSMutableData dataWithLength:buckets * sizeof(uint32_t)];
    NSMutableData *offsetData = [NSMutableData dataWithLength:buckets * sizeof(uint32_t)];
    NSMutableData *synthetic = [NSMutableData data];
    if (countsData == nil || offsetData == nil || synthetic == nil) return nil;
    uint32_t *counts = countsData.mutableBytes;
    uint32_t *offsets = offsetData.mutableBytes;
    memset(offsets, 0xff, offsetData.length);
    for (uint32_t i = 0u; i < count; ++i) {
        if (!stwo_zig_raw_quotient_source_view_geometry_is_valid(&views[i], rows, batches)) return nil;
        const size_t bucket = (size_t)views[i].batch * 32u + views[i].shift;
        if (counts[bucket] == UINT32_MAX) return nil;
        ++counts[bucket];
    }
    const uint32_t capWords = (256u * 1024u * 1024u) / sizeof(uint32_t);
    uint32_t words = 0u, reduced = 0u;
    // Shortest domains first: they remove the most repeated full-domain work
    // per retained byte. The threshold covers the four coordinate planes and
    // avoids paying an extra dispatch for a small number of original views.
    for (uint32_t shift = 31u; shift >= 4u; --shift) {
        const uint32_t length = rows >> (shift - 1u);
        if (length == 0u || length > capWords / 4u) continue;
        for (uint32_t batch = 0u; batch < batches; ++batch) {
            const size_t bucket = (size_t)batch * 32u + shift;
            if (counts[bucket] < 8u || length * 4u > capWords - words) continue;
            offsets[bucket] = words;
            // One descriptor represents all four already weighted planes.
            // The numerator encoder reads the QM31 directly, without four
            // artificial scalar multiplications or four descriptor scans.
            StwoZigRawQuotientView view = {
                .offset = words, .length = length, .batch = batch,
                .shift = shift, .direct = 0u,
            };
            [synthetic appendBytes:&view length:sizeof(view)];
            words += length * 4u;
            reduced += counts[bucket];
        }
    }
    if (words == 0u) return nil;
    StwoZigNativeQuotientReduction *plan = [StwoZigNativeQuotientReduction new];
    plan.bucketOffsets = offsetData;
    plan.syntheticViews = synthetic;
    plan.partialWords = words;
    plan.reducedViews = reduced;
    return plan;
}

static bool stwo_encode_native_quotient_run(
    StwoZigMetalRuntime *runtime, id<MTLCommandBuffer> command,
    StwoZigNativeQuotientReduction *plan, id<MTLBuffer> source,
    NSUInteger sourceOffset, NSMutableData *directViews,
    uint32_t batches, uint32_t rows, id<MTLBuffer> partials,
    NSMutableArray<id<MTLBuffer>> *owners,
    void *budgetContext, StwoZigExternalBudgetAdmitV1 admit
) {
    const uint32_t *offsets = plan.bucketOffsets.bytes;
    const StwoZigRawQuotientView *input = directViews.bytes;
    const size_t count = directViews.length / sizeof(*input);
    NSMutableData *mapped = [NSMutableData data];
    NSMutableData *direct = [NSMutableData data];
    for (size_t i = 0u; i < count; ++i) {
        const StwoZigRawQuotientView v = input[i];
        if (offsets[(size_t)v.batch * 32u + v.shift] == UINT32_MAX) {
            [direct appendBytes:&v length:sizeof(v)];
        } else {
            const StwoZigResidentRawQuotientView native = {
                .offset = v.offset, .length = v.length, .batch = v.batch,
                .shift = v.shift, .direct = v.direct,
                .coeff_a = v.coeff_a, .coeff_b = v.coeff_b,
                .coeff_c = v.coeff_c, .coeff_d = v.coeff_d, .source_slot = 0u,
            };
            [mapped appendBytes:&native length:sizeof(native)];
        }
    }
    if (mapped.length == 0u) return true;
    NSData *batchViews = nil, *batchOffsets = nil;
    NSData *grouped = nil, *groups = nil, *starts = nil, *batchGroups = nil;
    uint32_t groupCount = 0u, totalRows = 0u, unusedWords = 0u;
    const uint32_t mappedCount = (uint32_t)(mapped.length / sizeof(StwoZigResidentRawQuotientView));
    if (!stwo_zig_bucket_resident_raw_quotient_views(mapped, mappedCount, batches, &batchViews, &batchOffsets) ||
        !stwo_zig_prepare_resident_quotient_groups(batchViews, batchOffsets, mappedCount, batches, rows,
            &grouped, &groups, &starts, &batchGroups, &groupCount, &totalRows, &unusedWords)) return false;
    NSMutableData *rebased = [groups mutableCopy];
    StwoZigResidentRawQuotientGroup *mutableGroups = rebased.mutableBytes;
    const StwoZigResidentRawQuotientView *groupedViews = grouped.bytes;
    for (uint32_t i = 0u; i < groupCount; ++i) {
        const StwoZigResidentRawQuotientView first = groupedViews[mutableGroups[i].view_start];
        mutableGroups[i].partial_offset = offsets[(size_t)first.batch * 32u + first.shift];
        if (mutableGroups[i].partial_offset == UINT32_MAX ||
            mutableGroups[i].partial_offset > plan.partialWords ||
            mutableGroups[i].row_count > (plan.partialWords - mutableGroups[i].partial_offset) / 4u) return false;
    }
    id<MTLBuffer> viewBuffer = stwo_quotient_owned_buffer(runtime.device, grouped.bytes, grouped.length,
        MTLResourceStorageModeShared, budgetContext, admit);
    id<MTLBuffer> groupBuffer = stwo_quotient_owned_buffer(runtime.device, rebased.bytes, rebased.length,
        MTLResourceStorageModeShared, budgetContext, admit);
    id<MTLBuffer> startBuffer = stwo_quotient_owned_buffer(runtime.device, starts.bytes, starts.length,
        MTLResourceStorageModeShared, budgetContext, admit);
    if (viewBuffer == nil || groupBuffer == nil || startBuffer == nil) return false;
    [owners addObjectsFromArray:@[viewBuffer, groupBuffer, startBuffer]];
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    encoder.label = @"stwo_zig_quotient_native_segment_partials";
    [encoder setComputePipelineState:runtime.quotientPartialsRaw];
    for (NSUInteger slot = 0u; slot < 4u; ++slot) [encoder setBuffer:source offset:sourceOffset atIndex:slot];
    [encoder setBuffer:viewBuffer offset:0u atIndex:4];
    [encoder setBuffer:groupBuffer offset:0u atIndex:5];
    [encoder setBuffer:startBuffer offset:0u atIndex:6];
    [encoder setBytes:&groupCount length:sizeof(groupCount) atIndex:7];
    [encoder setBytes:&totalRows length:sizeof(totalRows) atIndex:8];
    [encoder setBuffer:partials offset:0u atIndex:9];
    const uint32_t accumulate = 1u;
    [encoder setBytes:&accumulate length:sizeof(accumulate) atIndex:10];
    NSUInteger width = MIN(runtime.quotientPartialsRaw.maxTotalThreadsPerThreadgroup,
                           runtime.quotientPartialsRaw.threadExecutionWidth * 8u);
    [encoder dispatchThreads:MTLSizeMake(totalRows, 1u, 1u)
       threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
    [encoder endEncoding];
    [directViews setData:direct];
    return true;
}
