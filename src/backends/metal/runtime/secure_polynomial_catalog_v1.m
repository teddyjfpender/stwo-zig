// Included by runtime.m. No source compiler/JIT: an independently SHA-pinned
// AOT image and exact schema-derived names are validated by the Zig owner.
uint32_t stwo_zig_secure_polynomial_register_aot(void *runtime_ptr,
    const uint8_t *image,size_t bytes,const char *const *names,const size_t *lengths,uint32_t count) {
    if(runtime_ptr==NULL || image==NULL || bytes==0u || bytes>128u*1024u*1024u ||
        names==NULL || lengths==NULL || count==0u || count>24u) return 256u;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr;
        dispatch_data_t data=dispatch_data_create(image,bytes,dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        NSError *error=nil;
        id<MTLLibrary> library=[runtime.device newLibraryWithData:data error:&error];
        if(library==nil) return 256u;
        NSMutableDictionary *pending=[NSMutableDictionary new];
        for(uint32_t i=0u;i<count;++i) {
            if(names[i]==NULL || lengths[i]==0u || lengths[i]>160u) return 256u;
            NSString *name=[[NSString alloc] initWithBytes:names[i] length:lengths[i] encoding:NSUTF8StringEncoding];
            if(name==nil || pending[name]!=nil) return 256u;
            bool scan=[name isEqualToString:@"stwo_zig_framework_interaction_block_scan_v1"] ||
                [name isEqualToString:@"stwo_zig_framework_interaction_scan_blocks_v1"] ||
                [name isEqualToString:@"stwo_zig_framework_interaction_finalize_v1"];
            bool supported=scan || [name isEqualToString:@"stwo_zig_secure_interaction_mean_v1"] ||
                [name isEqualToString:@"stwo_zig_word_memory_witness_v4"] || [name isEqualToString:@"stwo_zig_range16_witness_v4"] ||
                [name isEqualToString:@"stwo_zig_range16_inverse_table_v1"] || [name isEqualToString:@"stwo_zig_ram_lanes_witness_v1"] ||
                [name hasPrefix:@"stwo_zig_secure_interaction_v1_"] || [name hasPrefix:@"stwo_zig_framework_poly_v1_"];
            if(!supported) return 256u;
            if(runtime.riscvPolynomialPipelines[name]!=nil) {
                if(scan) continue;
                return 256u; // Never replace a live executable under an old key.
            }
            id<MTLFunction> function=[library newFunctionWithName:name];
            if(function==nil) return 256u;
            id<MTLComputePipelineState> pipeline=[runtime.device newComputePipelineStateWithFunction:function error:&error];
            if(pipeline==nil || pipeline.device!=runtime.device || pipeline.maxTotalThreadsPerThreadgroup<256u) return 256u;
            pending[name]=pipeline;
        }
        // Catalog install and execution are owner-serialized. All validation
        // precedes this mutation so a missing symbol leaves no partial roster.
        [runtime.riscvPolynomialPipelines addEntriesFromDictionary:pending];
        return 0u;
    }
}

uint32_t stwo_zig_secure_range_inverse_table(void *runtime_ptr,const uint32_t *z,size_t byte_cap,
    void **result,void **contents,size_t *bytes,double *gpu_ms) {
    if(result) *result=NULL;if(contents) *contents=NULL;if(bytes) *bytes=0u;if(gpu_ms) *gpu_ms=0;
    if(runtime_ptr==NULL || z==NULL || result==NULL || contents==NULL || bytes==NULL || byte_cap<65536u*20u+16u) return 256u;
    for(uint32_t i=0u;i<4u;++i) if(z[i]>=0x7fffffffu) return 256u;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLComputePipelineState> pipeline=runtime.riscvPolynomialPipelines[@"stwo_zig_range16_inverse_table_v1"];
        if(pipeline==nil || 65536u*20u>runtime.device.maxBufferLength) return 256u;
        id<MTLBuffer> metadata=[runtime.device newBufferWithBytes:z length:16u options:MTLResourceStorageModeShared];
        id<MTLBuffer> output=[runtime.device newBufferWithLength:65536u*20u options:MTLResourceStorageModeShared];
        if(metadata==nil || output==nil) return 256u;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        if(command==nil || encoder==nil) return 256u;
        [encoder setComputePipelineState:pipeline];[encoder setBuffer:metadata offset:0 atIndex:0];[encoder setBuffer:output offset:0 atIndex:1];
        [encoder dispatchThreads:MTLSizeMake(65536u,1u,1u) threadsPerThreadgroup:MTLSizeMake(256u,1u,1u)];
        [encoder endEncoding];[command commit];[command waitUntilCompleted];
        if(command.status!=MTLCommandBufferStatusCompleted) return 256u;
        *bytes=output.length;*contents=output.contents;*result=(__bridge_retained void *)output;
        if(gpu_ms) *gpu_ms=(command.GPUEndTime-command.GPUStartTime)*1000.0;
        return 0u;
    }
}

uint32_t stwo_zig_secure_witness_generate(void *runtime_ptr,uint32_t kind,void *source_ptr,
    const uint32_t *claim,uint32_t claim_words,uint32_t rows,size_t byte_cap,
    void **result,void **contents,size_t *bytes,double *gpu_ms) {
    if(result) *result=NULL;if(contents) *contents=NULL;if(bytes) *bytes=0u;if(gpu_ms) *gpu_ms=0;
    if(runtime_ptr==NULL || source_ptr==NULL || result==NULL || contents==NULL || bytes==NULL ||
       kind>2u || rows<2u || rows>(1u<<24u) || (rows&(rows-1u))!=0u) return 256u;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> source=(__bridge id<MTLBuffer>)source_ptr;
        if(source.device!=runtime.device || source.length%4u!=0u) return 256u;
        uint64_t output_bytes=(uint64_t)rows*(kind==0u?39u:(kind==2u?78u:2u))*4u;
        uint64_t metadata_bytes=(kind!=1u?25u:1u)*4u+4u;
        if(output_bytes>runtime.device.maxBufferLength || output_bytes+metadata_bytes>byte_cap) return 256u;
        if(kind!=1u) {
            if(claim==NULL || claim_words!=25u || claim[4]==0u || (uint64_t)claim[4]>(uint64_t)rows*(kind==2u?2u:1u) || claim[5]==0u || claim[5]>24u ||
               rows!=(1u<<claim[5]) || claim[6]>1u || (uint64_t)claim[4]*24u>source.length) return 256u;
            uint64_t first=(uint64_t)claim[0]|((uint64_t)claim[1]<<32u),total=(uint64_t)claim[2]|((uint64_t)claim[3]<<32u);
            if(first>total || claim[4]>total-first || (first==0u)!=(claim[6]==0u)) return 256u;
        } else if(rows!=65536u || claim_words!=0u || source.length<65536u*4u) return 256u;
        NSString *name=kind==0u?@"stwo_zig_word_memory_witness_v4":(kind==2u?@"stwo_zig_ram_lanes_witness_v1":@"stwo_zig_range16_witness_v4");
        id<MTLComputePipelineState> pipeline=runtime.riscvPolynomialPipelines[name];
        if(pipeline==nil || pipeline.device!=runtime.device) return 256u;
        uint32_t zero=0u;
        id<MTLBuffer> metadata=[runtime.device newBufferWithBytes:kind!=1u?claim:&zero length:kind!=1u?100u:4u options:MTLResourceStorageModeShared];
        id<MTLBuffer> status=[runtime.device newBufferWithBytes:&zero length:4u options:MTLResourceStorageModeShared];
        id<MTLBuffer> output=[runtime.device newBufferWithLength:(size_t)output_bytes options:MTLResourceStorageModeShared];
        if(metadata==nil || status==nil || output==nil) return 256u;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        if(command==nil || encoder==nil) return 256u;
        [encoder setComputePipelineState:pipeline];[encoder setBuffer:source offset:0 atIndex:0];
        if(kind!=1u) {
            [encoder setBuffer:metadata offset:0 atIndex:1];[encoder setBuffer:output offset:0 atIndex:2];
            [encoder setBuffer:status offset:0 atIndex:3];[encoder setBytes:&rows length:4u atIndex:4];
        } else { [encoder setBuffer:output offset:0 atIndex:1];[encoder setBuffer:status offset:0 atIndex:2]; }
        [encoder dispatchThreads:MTLSizeMake(rows,1u,1u) threadsPerThreadgroup:MTLSizeMake(256u,1u,1u)];
        [encoder endEncoding];[command commit];[command waitUntilCompleted];
        if(command.status!=MTLCommandBufferStatusCompleted) return 256u;
        uint32_t rejected=*(const uint32_t *)status.contents;if(rejected!=0u) return rejected;
        *bytes=output.length;*contents=output.contents;*result=(__bridge_retained void *)output;
        if(gpu_ms) *gpu_ms=(command.GPUEndTime-command.GPUStartTime)*1000.0;
        return 0u;
    }
}
