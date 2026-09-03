bool stwo_zig_metal_witness_input_gather(
    void *runtime_ptr, void *arena_ptr, const uint32_t *producer_offsets,
    const uint32_t *edge_descriptors, uint32_t edge_count, uint32_t input_width,
    uint32_t total_real_rows, uint32_t consumer_rows, const uint32_t *consumer_offsets,
    uint32_t include_enabler, uint32_t include_iota, double *gpu_milliseconds,
    char *error_message, size_t error_message_len
) {
    uint32_t output_count=input_width+include_enabler+include_iota;
    if(runtime_ptr==NULL||arena_ptr==NULL||producer_offsets==NULL||edge_descriptors==NULL||consumer_offsets==NULL||
       edge_count==0u||input_width==0u||consumer_rows==0u||total_real_rows==0u||total_real_rows>consumer_rows||output_count==0u)return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger words=arena.length/sizeof(uint32_t);
        for(uint32_t i=0u;i<output_count;++i)if((NSUInteger)consumer_offsets[i]+consumer_rows>words)return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.witnessInputGatherResident]; [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBytes:producer_offsets length:(NSUInteger)edge_count*4u atIndex:1];
        [encoder setBytes:edge_descriptors length:(NSUInteger)edge_count*5u*4u atIndex:2];
        uint32_t args[]={edge_count,input_width,total_real_rows,consumer_rows}; for(NSUInteger i=0;i<4u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+3u];
        [encoder setBytes:consumer_offsets length:(NSUInteger)output_count*4u atIndex:7];
        [encoder setBytes:&include_enabler length:4u atIndex:8]; [encoder setBytes:&include_iota length:4u atIndex:9];
        [encoder dispatchThreads:MTLSizeMake(consumer_rows,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)consumer_rows,256u),1u,1u)]; [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_execution_table_split(
    void *runtime_ptr, void *arena_ptr, uint32_t source_offset, uint32_t value_count,
    uint32_t column_rows, uint32_t source_words, uint32_t limb_count,
    const uint32_t *destination_offsets, double *gpu_milliseconds,
    char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL||destination_offsets==NULL||value_count>column_rows||
       column_rows==0u||!((source_words==8u&&limb_count==28u)||(source_words==4u&&limb_count==8u)))return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger words=arena.length/sizeof(uint32_t);
        if((NSUInteger)source_offset+(NSUInteger)value_count*source_words>words)return false;
        for(uint32_t i=0u;i<limb_count;++i)if((NSUInteger)destination_offsets[i]+column_rows>words)return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.executionTableSplitResident]; [encoder setBuffer:arena offset:0 atIndex:0];
        uint32_t args[]={source_offset,value_count,column_rows,source_words,limb_count};
        for(NSUInteger i=0;i<5u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+1u];
        [encoder setBytes:destination_offsets length:(NSUInteger)limb_count*4u atIndex:6];
        [encoder dispatchThreads:MTLSizeMake(column_rows,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)column_rows,256u),1u,1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_memory_address_base_trace(
    void *runtime_ptr, void *arena_ptr, uint32_t raw_address_offset, uint32_t address_count,
    uint32_t multiplicity_offset, uint32_t multiplicity_words, uint32_t row_count,
    const uint32_t *output_offsets, double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL||output_offsets==NULL||row_count==0u||multiplicity_words!=16u*row_count)return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger words=arena.length/4u;
        if((NSUInteger)raw_address_offset+address_count>words||(NSUInteger)multiplicity_offset+multiplicity_words>words)return false;
        for(uint32_t i=0u;i<32u;++i)if((NSUInteger)output_offsets[i]+row_count>words)return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.memoryAddressBaseTraceResident]; [encoder setBuffer:arena offset:0 atIndex:0];
        uint32_t args[]={raw_address_offset,address_count,multiplicity_offset,multiplicity_words,row_count};
        for(NSUInteger i=0;i<5u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+1u];
        [encoder setBytes:output_offsets length:32u*4u atIndex:6];
        [encoder dispatchThreads:MTLSizeMake(row_count,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)row_count,256u),1u,1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_memory_value_base_trace(
    void *runtime_ptr, void *arena_ptr, const uint32_t *source_offsets, uint32_t limb_count,
    uint32_t source_words, uint32_t source_row_offset, uint32_t multiplicity_offset,
    uint32_t multiplicity_words, uint32_t row_count, const uint32_t *output_offsets,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL||source_offsets==NULL||output_offsets==NULL||row_count==0u||
       !((limb_count==28u)||(limb_count==8u))||source_row_offset>multiplicity_words||row_count>multiplicity_words-source_row_offset)return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger words=arena.length/4u; if((NSUInteger)multiplicity_offset+multiplicity_words>words)return false;
        for(uint32_t i=0u;i<limb_count;++i)if((NSUInteger)source_offsets[i]+source_words>words)return false;
        for(uint32_t i=0u;i<=limb_count;++i)if((NSUInteger)output_offsets[i]+row_count>words)return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.memoryValueBaseTraceResident]; [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBytes:source_offsets length:(NSUInteger)limb_count*4u atIndex:1];
        uint32_t args[]={limb_count,source_words,source_row_offset,multiplicity_offset,multiplicity_words,row_count};
        for(NSUInteger i=0;i<6u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+2u];
        [encoder setBytes:output_offsets length:(NSUInteger)(limb_count+1u)*4u atIndex:8];
        [encoder dispatchThreads:MTLSizeMake(row_count,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)row_count,256u),1u,1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_memory_rc99_count(
    void *runtime_ptr, void *arena_ptr, const uint32_t *limb_offsets, uint32_t pair_count,
    uint32_t row_count, uint32_t lut_offset, uint32_t table_size, uint32_t count_offset,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL||limb_offsets==NULL||pair_count==0u||pair_count>14u||row_count==0u||table_size==0u)return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger words=arena.length/4u; if((NSUInteger)lut_offset+table_size>words||(NSUInteger)count_offset+(NSUInteger)table_size*8u>words)return false;
        for(uint32_t i=0u;i<pair_count*2u;++i)if((NSUInteger)limb_offsets[i]+row_count>words)return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.memoryRc99CountResident]; [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBytes:limb_offsets length:(NSUInteger)pair_count*2u*4u atIndex:1];
        uint32_t args[]={pair_count,row_count,lut_offset,table_size,count_offset};
        for(NSUInteger i=0;i<5u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+2u];
        [encoder dispatchThreads:MTLSizeMake(row_count,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)row_count,256u),1u,1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_public_memory_seed(
    void *runtime_ptr, void *arena_ptr, const uint32_t *address_id_pairs, uint32_t entry_count,
    uint32_t address_count_offset, uint32_t address_count_words, uint32_t big_count_offset,
    uint32_t big_count_words, uint32_t small_count_offset, uint32_t small_count_words,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL||address_id_pairs==NULL||entry_count==0u)return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger words=arena.length/4u;
        if((NSUInteger)address_count_offset+address_count_words>words||(NSUInteger)big_count_offset+big_count_words>words||
           (NSUInteger)small_count_offset+small_count_words>words)return false;
        id<MTLBuffer> pairs=[runtime.device newBufferWithBytes:address_id_pairs length:(NSUInteger)entry_count*2u*4u options:MTLResourceStorageModeShared];
        if(pairs==nil)return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.publicMemorySeedResident]; [encoder setBuffer:arena offset:0 atIndex:0]; [encoder setBuffer:pairs offset:0 atIndex:1];
        uint32_t args[]={entry_count,address_count_offset,address_count_words,big_count_offset,big_count_words,small_count_offset,small_count_words};
        for(NSUInteger i=0;i<7u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+2u];
        [encoder dispatchThreads:MTLSizeMake(entry_count,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)entry_count,256u),1u,1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_leaf_absorb_v2(
    void *runtime_ptr, void *arena_ptr, const uint32_t *column_offsets, const uint32_t *column_logs, uint32_t column_count,
    uint32_t state_offset, uint32_t lifting_log, uint32_t first_column, uint32_t is_final, uint32_t prefix_bytes,
    const uint32_t *leaf_seed, uint32_t hash_family, double *gpu_milliseconds,
    char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL||column_offsets==NULL||column_logs==NULL||leaf_seed==NULL||column_count==0u||column_count>16u||lifting_log>=31u||(prefix_bytes!=0u&&prefix_bytes!=64u)||!stwo_zig_valid_commitment_hash_family_v1(hash_family))return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        uint32_t state_words=stwo_zig_commitment_leaf_state_words(hash_family);
        id<MTLComputePipelineState> pipeline=stwo_zig_commitment_leaf_absorb_pipeline(runtime,hash_family,false);
        uint32_t row_count=1u<<lifting_log; NSUInteger words=arena.length/4u; if(state_words==0u||pipeline==nil||(NSUInteger)state_offset+(NSUInteger)row_count*state_words>words)return false;
        for(uint32_t i=0u;i<column_count;++i)if(column_logs[i]>lifting_log||((NSUInteger)column_offsets[i]+((NSUInteger)1u<<column_logs[i])>words))return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:pipeline]; [encoder setBuffer:arena offset:0 atIndex:0];
        [encoder setBytes:column_offsets length:(NSUInteger)column_count*4u atIndex:1]; [encoder setBytes:column_logs length:(NSUInteger)column_count*4u atIndex:2];
        uint32_t args[]={column_count,state_offset,lifting_log,first_column,is_final,prefix_bytes}; for(NSUInteger i=0;i<6u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+3u];
        [encoder setBytes:leaf_seed length:32u atIndex:9];
        [encoder dispatchThreads:MTLSizeMake(row_count,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)row_count,256u),1u,1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_leaf_absorb(
    void *runtime_ptr, void *arena_ptr, const uint32_t *column_offsets, const uint32_t *column_logs, uint32_t column_count,
    uint32_t state_offset, uint32_t lifting_log, uint32_t first_column, uint32_t is_final, uint32_t prefix_bytes,
    const uint32_t *leaf_seed, double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    return stwo_zig_metal_leaf_absorb_v2(runtime_ptr,arena_ptr,column_offsets,column_logs,column_count,
        state_offset,lifting_log,first_column,is_final,prefix_bytes,leaf_seed,
        StwoZigCommitmentHashFamilyBlake2sV1,gpu_milliseconds,error_message,error_message_len);
}

static bool encode_leaf_absorb_compact(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena,
    const uint32_t *column_offsets, const uint32_t *column_logs, uint32_t column_count,
    uint32_t source_state_offset, uint32_t source_state_log, uint32_t destination_state_offset, uint32_t destination_log,
    uint32_t first_column, uint32_t is_final, uint32_t prefix_bytes, const uint32_t *leaf_seed,
    uint32_t hash_family,
    id<MTLCommandBuffer> command, uint64_t *compute_encoders, uint64_t *dispatches
) {
    if(runtime==nil||arena==nil||command==nil||column_offsets==NULL||column_logs==NULL||leaf_seed==NULL||column_count==0u||column_count>16u||destination_log>=31u||(prefix_bytes!=0u&&prefix_bytes!=64u)||!stwo_zig_valid_commitment_hash_family_v1(hash_family))return false;
    if(first_column!=0u&&(source_state_log>destination_log||source_state_log>=31u))return false;
    uint32_t state_words=stwo_zig_commitment_leaf_state_words(hash_family);
    id<MTLComputePipelineState> pipeline=stwo_zig_commitment_leaf_absorb_pipeline(runtime,hash_family,true);
    uint32_t row_count=1u<<destination_log; NSUInteger words=arena.length/4u;
    if(state_words==0u||pipeline==nil||(NSUInteger)destination_state_offset+(NSUInteger)row_count*state_words>words)return false;
    if(first_column!=0u&&((NSUInteger)source_state_offset+((NSUInteger)1u<<source_state_log)*state_words>words))return false;
    for(uint32_t i=0u;i<column_count;++i)if(column_logs[i]>destination_log||((NSUInteger)column_offsets[i]+((NSUInteger)1u<<column_logs[i])>words))return false;
    id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
    if(encoder==nil)return false;
    [encoder setComputePipelineState:pipeline]; [encoder setBuffer:arena offset:0 atIndex:0];
    [encoder setBytes:column_offsets length:(NSUInteger)column_count*4u atIndex:1]; [encoder setBytes:column_logs length:(NSUInteger)column_count*4u atIndex:2];
    uint32_t args[]={column_count,source_state_offset,source_state_log,destination_state_offset,destination_log,first_column,is_final,prefix_bytes};
    for(NSUInteger i=0;i<8u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+3u];
    [encoder setBytes:leaf_seed length:32u atIndex:11];
    [encoder dispatchThreads:MTLSizeMake(row_count,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)row_count,256u),1u,1u)];
    [encoder endEncoding];
    *compute_encoders += 1u; *dispatches += 1u;
    return true;
}

static bool encode_poseidon2_leaf_state_digest_resident_v1(
    StwoZigMetalRuntime *runtime, id<MTLBuffer> arena,
    uint32_t state_offset, uint32_t destination_offset, uint32_t lifting_log,
    id<MTLCommandBuffer> command, uint64_t *compute_encoders, uint64_t *dispatches
) {
    if (runtime == nil || arena == nil || command == nil || lifting_log >= 31u ||
        (state_offset & 63u) != 0u || (destination_offset & 63u) != 0u)
        return false;
    uint64_t row_count = 1ull << lifting_log;
    uint64_t state_begin = state_offset, state_end = state_begin + row_count * 16ull;
    uint64_t digest_begin = destination_offset, digest_end = digest_begin + row_count * 8ull;
    uint64_t arena_words = arena.length / sizeof(uint32_t);
    if (state_end > arena_words || digest_end > arena_words ||
        (state_begin < digest_end && digest_begin < state_end))
        return false;
    id<MTLComputePipelineState> pipeline = runtime.poseidon2M31LeafStateDigestResidentV1;
    if (pipeline == nil) return false;
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (encoder == nil) return false;
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:arena offset:0 atIndex:0];
    [encoder setBytes:&state_offset length:sizeof(state_offset) atIndex:1];
    [encoder setBytes:&destination_offset length:sizeof(destination_offset) atIndex:2];
    [encoder setBytes:&lifting_log length:sizeof(lifting_log) atIndex:3];
    NSUInteger width = MIN((NSUInteger)256u, pipeline.maxTotalThreadsPerThreadgroup);
    [encoder dispatchThreads:MTLSizeMake((NSUInteger)row_count, 1u, 1u)
        threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
    [encoder endEncoding];
    *compute_encoders += 1u;
    *dispatches += 1u;
    return true;
}

bool stwo_zig_metal_leaf_absorb_compact(
    void *runtime_ptr, void *arena_ptr, const uint32_t *column_offsets, const uint32_t *column_logs, uint32_t column_count,
    uint32_t source_state_offset, uint32_t source_state_log, uint32_t destination_state_offset, uint32_t destination_log,
    uint32_t first_column, uint32_t is_final, uint32_t prefix_bytes, const uint32_t *leaf_seed,
    double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL)return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer];
        uint64_t compute_encoders=0u,dispatches=0u;
        if(!encode_leaf_absorb_compact(runtime,arena,column_offsets,column_logs,column_count,source_state_offset,source_state_log,destination_state_offset,destination_log,first_column,is_final,prefix_bytes,leaf_seed,StwoZigCommitmentHashFamilyBlake2sV1,command,&compute_encoders,&dispatches)){
            write_error(error_message,error_message_len,@"Metal compact leaf encoding failed");return false;
        }
        [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_leaf_absorb_compact_v2(
    void *runtime_ptr, void *arena_ptr, const uint32_t *column_offsets, const uint32_t *column_logs, uint32_t column_count,
    uint32_t source_state_offset, uint32_t source_state_log, uint32_t destination_state_offset, uint32_t destination_log,
    uint32_t first_column, uint32_t is_final, uint32_t prefix_bytes, const uint32_t *leaf_seed,
    uint32_t hash_family, double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL)return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; uint64_t compute_encoders=0u,dispatches=0u;
        if(!encode_leaf_absorb_compact(runtime,arena,column_offsets,column_logs,column_count,source_state_offset,source_state_log,destination_state_offset,destination_log,first_column,is_final,prefix_bytes,leaf_seed,hash_family,command,&compute_encoders,&dispatches))return false;
        [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_parent_seeded_v2(
    void *runtime_ptr, void *arena_ptr, uint32_t child_offset, uint32_t destination_offset,
    uint32_t parent_count, const uint32_t *node_seed, uint32_t hash_family, double *gpu_milliseconds,
    char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL||parent_count==0u||node_seed==NULL||!stwo_zig_valid_commitment_hash_family_v1(hash_family))return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger words=arena.length/4u; if((NSUInteger)child_offset+(NSUInteger)parent_count*16u>words||(NSUInteger)destination_offset+(NSUInteger)parent_count*8u>words)return false;
        id<MTLComputePipelineState> pipeline=stwo_zig_commitment_parents_sparse_pipeline(runtime,hash_family); if(pipeline==nil)return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:pipeline]; [encoder setBuffer:arena offset:0 atIndex:0];
        uint32_t args[]={child_offset,destination_offset,parent_count}; for(NSUInteger i=0;i<3u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+1u];
        [encoder setBytes:node_seed length:32u atIndex:4];
        uint32_t prefix_bytes = 64u;
        [encoder setBytes:&prefix_bytes length:sizeof(prefix_bytes) atIndex:5];
        [encoder dispatchThreads:MTLSizeMake(parent_count,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)parent_count,256u),1u,1u)]; [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_parent_seeded(
    void *runtime_ptr, void *arena_ptr, uint32_t child_offset, uint32_t destination_offset,
    uint32_t parent_count, const uint32_t *node_seed, double *gpu_milliseconds,
    char *error_message, size_t error_message_len
) {
    return stwo_zig_metal_parent_seeded_v2(runtime_ptr,arena_ptr,child_offset,destination_offset,
        parent_count,node_seed,StwoZigCommitmentHashFamilyBlake2sV1,gpu_milliseconds,error_message,error_message_len);
}

bool stwo_zig_metal_parent_plain(
    void *runtime_ptr, void *arena_ptr, uint32_t child_offset, uint32_t destination_offset,
    uint32_t parent_count, double *gpu_milliseconds, char *error_message, size_t error_message_len
) {
    if(runtime_ptr==NULL||arena_ptr==NULL||parent_count==0u)return false;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr; id<MTLBuffer> arena=(__bridge id<MTLBuffer>)arena_ptr;
        NSUInteger words=arena.length/4u; if((NSUInteger)child_offset+(NSUInteger)parent_count*16u>words||(NSUInteger)destination_offset+(NSUInteger)parent_count*8u>words)return false;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer]; id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        [encoder setComputePipelineState:runtime.parentsPlainSparse]; [encoder setBuffer:arena offset:0 atIndex:0];
        uint32_t args[]={child_offset,destination_offset,parent_count}; for(NSUInteger i=0;i<3u;++i)[encoder setBytes:&args[i] length:4u atIndex:i+1u];
        [encoder dispatchThreads:MTLSizeMake(parent_count,1u,1u) threadsPerThreadgroup:MTLSizeMake(MIN((NSUInteger)parent_count,256u),1u,1u)]; [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status==MTLCommandBufferStatusError){write_error(error_message,error_message_len,command.error.localizedDescription);return false;}
        if(gpu_milliseconds)*gpu_milliseconds=(command.GPUEndTime-command.GPUStartTime)*1000.0; return true;
    }
}

bool stwo_zig_metal_quadratic_recurrence_trace(
    void *runtime_ptr,
    uint32_t *const *columns,
    uint32_t column_count,
    uint32_t row_count,
    uint32_t log_n_rows,
    const uint32_t *recipe,
    double *gpu_milliseconds,
    uint32_t *copyback_count,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || columns == NULL || recipe == NULL ||
        column_count < 2u || column_count > 256u || row_count == 0u ||
        log_n_rows == 0u || log_n_rows >= 31u ||
        row_count != (1u << log_n_rows)) {
        write_error(error_message, error_message_len, @"Invalid quadratic recurrence trace arguments");
        return false;
    }
    for (uint32_t word = 0u; word < 7u; ++word) {
        if (recipe[word] >= 0x7fffffffu) {
            write_error(error_message, error_message_len, @"Non-canonical quadratic recurrence parameter");
            return false;
        }
    }
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        const size_t column_bytes = (size_t)row_count * sizeof(uint32_t);
        const size_t page_size = (size_t)getpagesize();
        NSMutableArray<id<MTLBuffer>> *buffers = [NSMutableArray arrayWithCapacity:column_count];
        NSMutableData *address_data = [NSMutableData dataWithLength:(NSUInteger)column_count * sizeof(uint64_t)];
        NSMutableData *alias_data = [NSMutableData dataWithLength:(NSUInteger)column_count];
        if (buffers == nil || address_data == nil || alias_data == nil) {
            write_error(error_message, error_message_len, @"Metal trace binding allocation failed");
            return false;
        }
        uint64_t *addresses = address_data.mutableBytes;
        uint8_t *aliases = alias_data.mutableBytes;
        uint32_t copied = 0u;
        bool contiguous = runtime.device.hasUnifiedMemory &&
            ((uintptr_t)columns[0] % page_size) == 0u &&
            column_bytes <= SIZE_MAX / column_count;
        for (uint32_t column = 0u; column < column_count; ++column) {
            if (columns[column] == NULL) {
                write_error(error_message, error_message_len, @"Null quadratic recurrence column");
                return false;
            }
            if (column != 0u)
                contiguous &= columns[column] == columns[0] + (size_t)column * row_count;
        }
        size_t contiguous_bytes = column_bytes * column_count;
        contiguous &= (contiguous_bytes % page_size) == 0u;
        if (contiguous) {
            id<MTLBuffer> buffer = [runtime.device newBufferWithBytesNoCopy:columns[0]
                length:contiguous_bytes options:MTLResourceStorageModeShared deallocator:nil];
            if (buffer == nil || buffer.contents == NULL || buffer.gpuAddress == 0u) {
                write_error(error_message, error_message_len, @"Metal contiguous trace binding failed");
                return false;
            }
            [buffers addObject:buffer];
            for (uint32_t column = 0u; column < column_count; ++column) {
                aliases[column] = 1u;
                addresses[column] = buffer.gpuAddress + (uint64_t)column * column_bytes;
            }
        } else for (uint32_t column = 0u; column < column_count; ++column) {
            bool alias = ((uintptr_t)columns[column] % page_size) == 0u &&
                (column_bytes % page_size) == 0u && runtime.device.hasUnifiedMemory;
            id<MTLBuffer> buffer = alias
                ? [runtime.device newBufferWithBytesNoCopy:columns[column]
                                                    length:column_bytes
                                                   options:MTLResourceStorageModeShared
                                               deallocator:nil]
                : nil;
            if (buffer == nil) {
                alias = false;
                buffer = [runtime.device newBufferWithLength:column_bytes
                                                     options:MTLResourceStorageModeShared];
            }
            if (buffer == nil || buffer.contents == NULL || buffer.gpuAddress == 0u) {
                write_error(error_message, error_message_len, @"Metal trace column binding failed");
                return false;
            }
            aliases[column] = alias ? 1u : 0u;
            copied += alias ? 0u : 1u;
            addresses[column] = buffer.gpuAddress;
            [buffers addObject:buffer];
        }
        id<MTLBuffer> address_buffer = [runtime.device newBufferWithBytes:addresses
                                                                   length:(NSUInteger)column_count * sizeof(uint64_t)
                                                                  options:MTLResourceStorageModeShared];
        if (address_buffer == nil) {
            write_error(error_message, error_message_len, @"Metal trace address binding failed");
            return false;
        }

        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (command == nil || encoder == nil) {
            write_error(error_message, error_message_len, @"Metal trace command allocation failed");
            return false;
        }
        [encoder setComputePipelineState:runtime.quadraticRecurrenceTrace];
        [encoder setBuffer:address_buffer offset:0u atIndex:0u];
        [encoder setBytes:&row_count length:sizeof(row_count) atIndex:1u];
        [encoder setBytes:&log_n_rows length:sizeof(log_n_rows) atIndex:2u];
        [encoder setBytes:&column_count length:sizeof(column_count) atIndex:3u];
        [encoder setBytes:recipe length:7u * sizeof(uint32_t) atIndex:4u];
        for (id<MTLBuffer> buffer in buffers)
            [encoder useResource:buffer usage:MTLResourceUsageWrite];
        NSUInteger width = MIN(runtime.quadraticRecurrenceTrace.maxTotalThreadsPerThreadgroup,
                               runtime.quadraticRecurrenceTrace.threadExecutionWidth * 8u);
        [encoder dispatchThreads:MTLSizeMake(row_count, 1u, 1u)
             threadsPerThreadgroup:MTLSizeMake(width, 1u, 1u)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status == MTLCommandBufferStatusError) {
            write_error(error_message, error_message_len, command.error.localizedDescription);
            return false;
        }
        for (uint32_t column = 0u; column < column_count; ++column) {
            if (aliases[column] == 0u)
                memcpy(columns[column], buffers[column].contents, column_bytes);
        }
        if (gpu_milliseconds != NULL)
            *gpu_milliseconds = (command.GPUEndTime - command.GPUStartTime) * 1000.0;
        if (copyback_count != NULL) *copyback_count = copied;
        return true;
    }
}

void *stwo_zig_metal_buffer_create(
    void *runtime_ptr,
    size_t byte_length,
    void **contents,
    char *error_message,
    size_t error_message_len
) {
    if (runtime_ptr == NULL || byte_length == 0u || contents == NULL) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime = (__bridge StwoZigMetalRuntime *)runtime_ptr;
        if ((uint64_t)byte_length > (uint64_t)runtime.device.maxBufferLength) {
            write_error(error_message, error_message_len,
                        [NSString stringWithFormat:@"Metal buffer length %llu exceeds device maxBufferLength %llu",
                                                   (unsigned long long)byte_length,
                                                   (unsigned long long)runtime.device.maxBufferLength]);
            return NULL;
        }
        id<MTLBuffer> buffer = [runtime.device newBufferWithLength:byte_length
                                                           options:MTLResourceStorageModeShared];
        if (buffer == nil || buffer.contents == NULL) {
            write_error(error_message, error_message_len, @"Metal resident buffer allocation failed");
            return NULL;
        }
        *contents = buffer.contents;
        return (__bridge_retained void *)buffer;
    }
}

void stwo_zig_metal_buffer_destroy(void *buffer) {
    if (buffer == NULL) return;
    @autoreleasepool { __unused id value = (__bridge_transfer id)buffer; }
}
