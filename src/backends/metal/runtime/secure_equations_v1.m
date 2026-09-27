// Secure typed equations use the existing prepared polynomial pipeline ABI,
// but explicit resident arenas (not StwoZigMetalTree object aliases).
uint32_t stwo_zig_secure_equations_evaluate(void *plan_ptr,
    void *tree0_ptr,void *tree1_ptr,void *tree2_ptr,const uint64_t *offsets,uint32_t inputs,
    const uint32_t *profile,uint32_t profiles,const uint32_t *powers,uint32_t power_words,
    uint32_t rows,const uint32_t *denominators,uint32_t denominator_count,
    void *output_ptr,size_t metadata_cap,double *gpu_ms) {
    if(gpu_ms) *gpu_ms=0;
    if(plan_ptr==NULL || offsets==NULL || profile==NULL || powers==NULL || output_ptr==NULL || denominators==NULL ||
       rows<4u || rows>(1u<<27u) || (rows&(rows-1u))!=0u || denominator_count==0u || denominator_count>8u ||
       (denominator_count&(denominator_count-1u))!=0u) return 256u;
    @autoreleasepool {
        StwoZigFrameworkPolynomialPlan *plan=(__bridge StwoZigFrameworkPolynomialPlan *)plan_ptr;
        StwoZigMetalRuntime *runtime=plan.runtimeOwner;
        if(runtime==nil || inputs!=plan.columnTrees.length/4u || profiles!=plan.profileWordCount ||
           power_words!=plan.powerWordCount || plan.relationWordCount!=4u) return 256u;
        uint64_t metadata_bytes=(uint64_t)inputs*8u+MAX((uint64_t)profiles,1u)*4u+(uint64_t)power_words*4u+16u;
        if(metadata_bytes>metadata_cap || !stwo_framework_canonical(profile,profiles) ||
           !stwo_framework_canonical(powers,power_words) || !stwo_framework_canonical(denominators,denominator_count)) return 256u;
        id<MTLBuffer> trees[3]={(__bridge id<MTLBuffer>)tree0_ptr,(__bridge id<MTLBuffer>)tree1_ptr,(__bridge id<MTLBuffer>)tree2_ptr};
        id<MTLBuffer> output=(__bridge id<MTLBuffer>)output_ptr;
        if(output.device!=runtime.device || output.length<(uint64_t)rows*16u || output.length%4u!=0u) return 256u;
        const uint32_t *tags=plan.columnTrees.bytes;
        for(uint32_t i=0u;i<inputs;++i) {
            uint32_t tag=tags[i];
            if(tag>2u || trees[tag]==nil || trees[tag]==output || trees[tag].device!=runtime.device ||
               trees[tag].length%4u!=0u || offsets[i]>trees[tag].length/4u || rows>trees[tag].length/4u-offsets[i]) return 256u;
        }
        uint32_t zero[4]={0u,0u,0u,0u};
        id<MTLBuffer> offset_buffer=[runtime.device newBufferWithBytes:offsets length:(size_t)inputs*8u options:MTLResourceStorageModeShared];
        id<MTLBuffer> profile_buffer=[runtime.device newBufferWithBytes:profiles?profile:zero length:MAX((size_t)profiles,1u)*4u options:MTLResourceStorageModeShared];
        id<MTLBuffer> reserved=[runtime.device newBufferWithBytes:zero length:16u options:MTLResourceStorageModeShared];
        id<MTLBuffer> power_buffer=[runtime.device newBufferWithBytes:powers length:(size_t)power_words*4u options:MTLResourceStorageModeShared];
        if(offset_buffer==nil || profile_buffer==nil || reserved==nil || power_buffer==nil) return 256u;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        if(command==nil || encoder==nil) return 256u;
        [encoder setComputePipelineState:plan.pipeline];
        for(uint32_t i=0u;i<3u;++i) [encoder setBuffer:trees[i]?:reserved offset:0 atIndex:i];
        [encoder setBuffer:offset_buffer offset:0 atIndex:3];[encoder setBuffer:profile_buffer offset:0 atIndex:4];
        [encoder setBuffer:reserved offset:0 atIndex:5];[encoder setBuffer:power_buffer offset:0 atIndex:6];
        [encoder setBuffer:output offset:0 atIndex:7];[encoder setBytes:&rows length:4u atIndex:8];
        [encoder setBytes:denominators length:(size_t)denominator_count*4u atIndex:9];
        [encoder setBytes:&denominator_count length:4u atIndex:10];
        [encoder dispatchThreads:MTLSizeMake(rows,1u,1u) threadsPerThreadgroup:MTLSizeMake(256u,1u,1u)];
        [encoder endEncoding];[command commit];[command waitUntilCompleted];
        if(command.status!=MTLCommandBufferStatusCompleted) return 256u;
        if(gpu_ms) *gpu_ms=(command.GPUEndTime-command.GPUStartTime)*1000.0;
        return 0u;
    }
}
