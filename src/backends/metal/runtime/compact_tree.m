// Copy only query-retained upper layers. The caller reserves the new arena
// before entering; publication follows the join, so failure preserves the
// complete tree and its resident-column bindings. Called before tree sharing.
bool stwo_zig_metal_tree_prune_bottom_v1(
    void *runtime_ptr, void *tree_ptr, uint32_t bottom_layers, size_t arena_bytes
) {
    if (runtime_ptr == NULL || tree_ptr == NULL || bottom_layers == 0u) return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)tree_ptr;
        if (tree.runtimeOwner != runtime || tree.logSize >= 31u ||
            bottom_layers > tree.logSize || tree.prunedBottomLayers != 0u) return false;
        // Some resident recipes place columns and hashes in one arena. Moving
        // hash views cannot reclaim that arena while the columns still pin it.
        // Keep those trees intact rather than adding a second hash allocation.
        for (id<MTLBuffer> hashes in tree.layers) {
            if (hashes == tree.residentColumns) return false;
            for (id<MTLBuffer> columns in tree.residentColumnBuffers)
                if (hashes == columns) return false;
        }
        const uint32_t retained_log = tree.logSize - bottom_layers;
        uint64_t expected_bytes = 0u;
        for (uint32_t log = 0u; log <= retained_log; ++log) {
            expected_bytes = (expected_bytes + 255u) & ~UINT64_C(255);
            expected_bytes += (UINT64_C(1) << log) * 32u;
        }
        if (expected_bytes != arena_bytes || expected_bytes > runtime.device.maxBufferLength)
            return false;
        id<MTLBuffer> arena = [runtime.device newBufferWithLength:arena_bytes
                                                      options:MTLResourceStorageModeShared];
        NSMutableArray<id<MTLBuffer>> *layers = [NSMutableArray arrayWithCapacity:tree.logSize + 1u];
        NSMutableData *offset_data = [NSMutableData dataWithLength:(tree.logSize + 1u) * sizeof(uint32_t)];
        NSMutableData *length_data = [NSMutableData dataWithLength:(tree.logSize + 1u) * sizeof(uint32_t)];
        if (arena == nil || layers == nil || offset_data == nil || length_data == nil) return false;
        for (uint32_t level = 0u; level <= tree.logSize; ++level) [layers addObject:arena];
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
        if (command == nil || blit == nil) return false;
        uint32_t *offsets = offset_data.mutableBytes;
        uint32_t *lengths = length_data.mutableBytes;
        NSUInteger cursor = 0u;
        for (uint32_t log = 0u; log <= retained_log; ++log) {
            cursor = (cursor + 255u) & ~(NSUInteger)255u;
            const NSUInteger level = tree.logSize - log;
            const NSUInteger bytes = ((NSUInteger)1u << log) * 32u;
            id<MTLBuffer> source = tree.layers[level];
            const NSUInteger source_offset = (NSUInteger)tree_layer_word_offset(tree, level) * sizeof(uint32_t);
            if (tree_layer_word_length(tree, level) != bytes / sizeof(uint32_t) ||
                source_offset > source.length || bytes > source.length - source_offset ||
                cursor / sizeof(uint32_t) > UINT32_MAX) {
                [blit endEncoding];
                return false;
            }
            offsets[level] = (uint32_t)(cursor / sizeof(uint32_t));
            lengths[level] = (uint32_t)(bytes / sizeof(uint32_t));
            [blit copyFromBuffer:source sourceOffset:source_offset toBuffer:arena
              destinationOffset:cursor size:bytes];
            cursor += bytes;
        }
        [blit endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted || cursor != arena_bytes) return false;
        // Root and all layer references must move together: cascaded FRI trees
        // may share an old arena, which dies after its final tree is compacted.
        tree.layers = layers;
        tree.layerWordOffsets = offset_data;
        tree.layerWordLengths = length_data;
        tree.rootReadback = arena;
        tree.rootReadbackWordOffset = 0u;
        tree.prunedBottomLayers = bottom_layers;
        return true;
    }
}
