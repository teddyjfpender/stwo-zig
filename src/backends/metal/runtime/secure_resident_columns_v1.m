// Exact borrowed arena extent. Neither host scatter nor host readback occurs.
uint32_t stwo_zig_secure_columns_blit(void *runtime_ptr,void *source_ptr,size_t offset,
    void *destination,size_t bytes,double *gpu_ms) {
    if(gpu_ms) *gpu_ms=0;
    if(runtime_ptr==NULL || source_ptr==NULL || destination==NULL || bytes==0u ||
        ((uintptr_t)destination%16384u)!=0u || bytes%16384u!=0u) return 256u;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr;
        id<MTLBuffer> source=(__bridge id<MTLBuffer>)source_ptr;
        if(source.device!=runtime.device || offset>source.length || bytes>source.length-offset || bytes>runtime.device.maxBufferLength) return 256u;
        id<MTLBuffer> target=[runtime.device newBufferWithBytesNoCopy:destination length:bytes
            options:MTLResourceStorageModeShared deallocator:nil];
        id<MTLCommandBuffer> command=[runtime.queue commandBuffer];
        id<MTLBlitCommandEncoder> encoder=[command blitCommandEncoder];
        if(target==nil || command==nil || encoder==nil) return 256u;
        [encoder copyFromBuffer:source sourceOffset:offset toBuffer:target destinationOffset:0 size:bytes];
        [encoder endEncoding];[command commit];[command waitUntilCompleted];
        if(command.status!=MTLCommandBufferStatusCompleted) return 256u;
        if(gpu_ms) *gpu_ms=(command.GPUEndTime-command.GPUStartTime)*1000.0;
        return 0u;
    }
}

uint32_t stwo_zig_secure_records_upload(void *runtime_ptr,const uint32_t *words,size_t bytes,
    void **result,void **contents) {
    if(result) *result=NULL;if(contents) *contents=NULL;
    if(runtime_ptr==NULL || words==NULL || bytes==0u || bytes%4u!=0u || result==NULL || contents==NULL) return 256u;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr;
        if(bytes>runtime.device.maxBufferLength) return 256u;
        id<MTLBuffer> buffer=[runtime.device newBufferWithBytes:words length:bytes options:MTLResourceStorageModeShared];
        if(buffer==nil) return 256u;
        *contents=buffer.contents;*result=(__bridge_retained void *)buffer;
        return 0u;
    }
}
