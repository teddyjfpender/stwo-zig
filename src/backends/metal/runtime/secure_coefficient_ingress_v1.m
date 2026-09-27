// No-copy retained PCS ingress, checked against the proof-resident LDE map.
typedef struct {
    const uint32_t *coefficients,*evaluations;
    size_t coefficient_words,evaluation_words;
    uint32_t tree_index,column_index,trace_log,evaluation_log;
} StwoSecureCoefficientSourceV1;
_Static_assert(sizeof(StwoSecureCoefficientSourceV1)==48u,"secure coefficient ingress ABI");
_Static_assert(offsetof(StwoSecureCoefficientSourceV1,coefficient_words)==16u,"secure coefficient extent ABI");
_Static_assert(offsetof(StwoSecureCoefficientSourceV1,tree_index)==32u,"secure coefficient tree ABI");
uint32_t stwo_zig_secure_coefficient_gather_v1(void *runtime_ptr,void *const *tree_ptrs,
    uint32_t tree_count,const StwoSecureCoefficientSourceV1 *sources,uint32_t count,
    void *output_ptr,uint32_t rows,size_t cap,double *gpu_ms) {
    if(gpu_ms) *gpu_ms=0;
    if(!runtime_ptr||!tree_ptrs||tree_count!=3u||!sources||!count||count>512u||!output_ptr||rows<8u||rows>(1u<<27u)||(rows&(rows-1u))) return 1u;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> output=(__bridge id<MTLBuffer>)output_ptr;
        size_t output_bytes=(size_t)count*rows*4u,charged=output_bytes;
        if(output.device!=runtime.device||output.length!=output_bytes||output_bytes>cap) return 1u;
        NSMutableArray<StwoZigMetalTree *> *trees=[NSMutableArray arrayWithCapacity:3u];
        for(uint32_t i=0;i<3u;++i) {
            if(!tree_ptrs[i]) return 1u;
            StwoZigMetalTree *tree=(__bridge StwoZigMetalTree *)tree_ptrs[i];
            if(tree.runtimeOwner!=runtime) return 1u;
            [trees addObject:tree];
        }
        NSMutableArray<id<MTLBuffer>> *mapped=[NSMutableArray arrayWithCapacity:count];
        const size_t page=(size_t)getpagesize();
        for(uint32_t i=0;i<count;++i) {
            const StwoSecureCoefficientSourceV1 *s=&sources[i];
            if(s->tree_index>=3u||s->trace_log<1u||s->trace_log>24u||s->evaluation_log>=31u||
               s->coefficient_words!=((size_t)1u<<s->trace_log)||s->evaluation_words!=((size_t)1u<<s->evaluation_log)||
               s->coefficient_words>rows||!s->coefficients||!s->evaluations) return 1u;
            StwoZigResidentColumnBinding binding;
            if(!stwo_zig_tree_resident_column(@[trees[s->tree_index]],s->evaluations,s->evaluation_words,&binding)||binding.buffer==output) return 1u;
            const size_t bytes=s->coefficient_words*4u;
            if((uintptr_t)s->coefficients%page||bytes%page||bytes>cap-charged) return 1u;
            charged+=bytes;
            id<MTLBuffer> coefficients=[runtime.device newBufferWithBytesNoCopy:(void *)s->coefficients length:bytes options:MTLResourceStorageModeShared deallocator:nil];
            if(coefficients==nil||coefficients==output) return 1u;
            [mapped addObject:coefficients];
        }
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer];
        id<MTLBlitCommandEncoder> blit=[command blitCommandEncoder];
        if(!command||!blit) return 1u;
        [blit fillBuffer:output range:NSMakeRange(0,output_bytes) value:0u];
        for(uint32_t i=0;i<count;++i) [blit copyFromBuffer:mapped[i] sourceOffset:0u toBuffer:output destinationOffset:(size_t)i*rows*4u size:sources[i].coefficient_words*4u];
        [blit endEncoding];[command commit];[command waitUntilCompleted];
        if(command.status!=MTLCommandBufferStatusCompleted) return 1u;
        if(gpu_ms) *gpu_ms=(command.GPUEndTime-command.GPUStartTime)*1000.;
        return 0u;
    }
}
uint32_t stwo_zig_secure_clear_quotient_v1(void *runtime_ptr,void *output_ptr,size_t bytes) {
    if(!runtime_ptr||!output_ptr||!bytes||bytes%16u) return 1u;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> output=(__bridge id<MTLBuffer>)output_ptr;
        if(output.device!=runtime.device||output.length!=bytes) return 1u;
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer];
        id<MTLBlitCommandEncoder> blit=[command blitCommandEncoder];
        if(!command||!blit) return 1u;
        [blit fillBuffer:output range:NSMakeRange(0,bytes) value:0u];
        [blit endEncoding];[command commit];[command waitUntilCompleted];
        return command.status==MTLCommandBufferStatusCompleted?0u:1u;
    }
}
