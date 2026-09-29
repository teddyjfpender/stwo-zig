// Segmented quotient reduction owns one bounded row tile, reused after every
// finalize encoder. Source bindings and view buffers are prepared only once.
// Global row indices govern lifting/domain reads; tile rows govern scratch.
static uint32_t stwo_quotient_numerator_tile_rows(uint32_t rows, uint32_t batches, bool parity) {
    if (parity || batches == 0u) return rows;
    const uint64_t budget = UINT64_C(256) * 1024u * 1024u;
    const uint64_t row_bytes = (uint64_t)batches * 16u;
    uint64_t limit = MAX(UINT64_C(1), budget / row_bytes);
    uint32_t tile = 1u;
    while (tile < rows && (uint64_t)tile * 2u <= limit) tile *= 2u;
    return tile;
}

typedef struct {
    __unsafe_unretained id<MTLBuffer> source;
    __unsafe_unretained id<MTLBuffer> views;
    NSUInteger source_offset;
    uint32_t view_count, first_batch, batch_count, planar;
} StwoZigQuotientSegmentDispatch;

static void stwo_encode_quotient_numerator_tile(
    StwoZigMetalRuntime *runtime, id<MTLCommandBuffer> command,
    StwoZigQuotientSegmentDispatch segment, id<MTLBuffer> numerators,
    uint32_t rows, uint32_t tile_rows, uint32_t row_start
) {
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    [encoder setComputePipelineState:runtime.quotientNumerator];
    [encoder setBuffer:segment.source offset:segment.source_offset atIndex:0];
    [encoder setBuffer:segment.views offset:0u atIndex:1];
    [encoder setBytes:&segment.view_count length:sizeof(segment.view_count) atIndex:2];
    [encoder setBuffer:numerators offset:(NSUInteger)segment.first_batch * tile_rows * 16u atIndex:3];
    [encoder setBytes:&segment.batch_count length:sizeof(segment.batch_count) atIndex:4];
    [encoder setBytes:&rows length:sizeof(rows) atIndex:5];
    [encoder setBytes:&tile_rows length:sizeof(tile_rows) atIndex:6];
    [encoder setBytes:&row_start length:sizeof(row_start) atIndex:7];
    [encoder setBytes:&segment.planar length:sizeof(segment.planar) atIndex:8];
    NSUInteger width = MIN(runtime.quotientNumerator.maxTotalThreadsPerThreadgroup,
                            runtime.quotientNumerator.threadExecutionWidth * 8u);
    [encoder dispatchThreads:MTLSizeMake(tile_rows, 1u, 1u)
         threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
    [encoder endEncoding];
}

static void stwo_encode_quotient_finalize_tile(
    StwoZigMetalRuntime *runtime, id<MTLCommandBuffer> command,
    id<MTLBuffer> numerators, id<MTLBuffer> samples, id<MTLBuffer> linear,
    uint32_t batches, id<MTLBuffer> domain_x, NSUInteger x_offset,
    id<MTLBuffer> domain_y, NSUInteger y_offset, id<MTLBuffer> output,
    uint32_t rows, uint32_t tile_rows, uint32_t row_start
) {
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    [encoder setComputePipelineState:runtime.quotientFinalize];
    [encoder setBuffer:numerators offset:0u atIndex:0];
    [encoder setBuffer:samples offset:0u atIndex:1];
    [encoder setBuffer:linear offset:0u atIndex:2];
    [encoder setBytes:&batches length:sizeof(batches) atIndex:3];
    [encoder setBuffer:domain_x offset:x_offset atIndex:4];
    [encoder setBuffer:domain_y offset:y_offset atIndex:5];
    [encoder setBuffer:output offset:0u atIndex:6];
    [encoder setBytes:&rows length:sizeof(rows) atIndex:7];
    [encoder setBytes:&tile_rows length:sizeof(tile_rows) atIndex:8];
    [encoder setBytes:&row_start length:sizeof(row_start) atIndex:9];
    NSUInteger width = MIN(runtime.quotientFinalize.maxTotalThreadsPerThreadgroup,
                            runtime.quotientFinalize.threadExecutionWidth * 8u);
    [encoder dispatchThreads:MTLSizeMake(tile_rows, 1u, 1u)
         threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
    [encoder endEncoding];
}
