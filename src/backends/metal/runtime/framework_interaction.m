// Included by runtime.m; the standalone device gate includes this same runtime
// implementation with a test-only library compiler, never a production JIT.
@interface StwoFrameworkInteractionPlan : NSObject
@property(nonatomic,strong) id runtimeOwner;
@property(nonatomic,strong) id<MTLDevice> device;
@property(nonatomic,strong) id<MTLCommandQueue> queue;
@property(nonatomic,strong) NSArray<id<MTLComputePipelineState>> *pipelines;
@property(nonatomic) uint32_t inputs, profiles, relations, batches, layout;
@property(nonatomic,strong) NSData *inputTrees;
@end
@implementation StwoFrameworkInteractionPlan
@end

static NSArray<NSString *> *stwo_framework_interaction_names(NSString *fraction,uint32_t layout) {
    if(layout==1u) return @[fraction,@"stwo_zig_framework_interaction_cumulative_block_scan_v1",@"stwo_zig_framework_interaction_cumulative_scan_blocks_v1",@"stwo_zig_framework_interaction_cumulative_finalize_v1"];
    return @[fraction,@"stwo_zig_framework_interaction_block_scan_v1",
             @"stwo_zig_framework_interaction_scan_blocks_v1",@"stwo_zig_framework_interaction_finalize_v1"];
}
static void *stwo_framework_interaction_plan(id owner, id<MTLDevice> device, id<MTLCommandQueue> queue,
    NSDictionary<NSString *,id<MTLComputePipelineState>> *admitted, NSString *name,
    const uint32_t *tags,uint32_t inputs,uint32_t profiles,uint32_t relations,uint32_t batches,uint32_t layout) {
    if (device==nil || queue==nil || name==nil || ![name hasPrefix:@"stwo_zig_framework_interaction_v1_"] ||
        tags==NULL || inputs==0u || relations==0u || relations%4u!=0u || (batches==0u || layout>1u)) return NULL;
    for(uint32_t i=0;i<inputs;++i) if(tags[i]>1u && tags[i]!=UINT32_MAX) return NULL;
    NSMutableArray *pipelines=[NSMutableArray new];
    for (NSString *symbol in stwo_framework_interaction_names(name,layout)) {
        id<MTLComputePipelineState> pipeline=admitted[symbol];
        if (pipeline==nil || pipeline.device!=device || pipeline.maxTotalThreadsPerThreadgroup<256u) return NULL;
        [pipelines addObject:pipeline];
    }
    StwoFrameworkInteractionPlan *plan=[StwoFrameworkInteractionPlan new];
    plan.runtimeOwner=owner; plan.device=device; plan.queue=queue; plan.pipelines=pipelines;
    plan.inputs=inputs;plan.profiles=profiles;plan.relations=relations;plan.batches=batches;plan.layout=layout;
    plan.inputTrees=[NSData dataWithBytes:tags length:(size_t)inputs*4u];
    if(plan.inputTrees==nil) return NULL;
    return (__bridge_retained void *)plan;
}
void *stwo_zig_framework_interaction_prepare(void *runtime_ptr,const char *name_bytes,size_t name_len,
    const uint32_t *tags,uint32_t inputs,uint32_t profiles,uint32_t relations,uint32_t batches,uint32_t layout) {
    if (runtime_ptr==NULL || name_bytes==NULL || name_len==0u) return NULL;
    @autoreleasepool {
        StwoZigMetalRuntime *runtime=(__bridge StwoZigMetalRuntime *)runtime_ptr;
        NSString *name=[[NSString alloc] initWithBytes:name_bytes length:name_len encoding:NSUTF8StringEncoding];
        return stwo_framework_interaction_plan(runtime,runtime.device,runtime.queue,runtime.riscvPolynomialPipelines,name,
            tags,inputs,profiles,relations,batches,layout);
    }
}
void stwo_zig_framework_interaction_destroy(void *plan) { if(plan!=NULL) CFRelease(plan); }

uint32_t stwo_zig_framework_interaction_generate(void *plan_ptr,void *tree0_ptr,void *tree1_ptr,
    const uint32_t *tags,const uint64_t *offsets,uint32_t inputs,
    const uint32_t *profiles,uint32_t profile_count,const uint32_t *relations,uint32_t relation_count,
    uint32_t rows,uint32_t batches,void **result,void **contents,size_t *bytes,double *gpu_ms) {
    if(result) *result=NULL; if(contents) *contents=NULL; if(bytes) *bytes=0; if(gpu_ms) *gpu_ms=0;
    if(plan_ptr==NULL || tags==NULL || offsets==NULL || result==NULL || contents==NULL || bytes==NULL ||
        rows<2u || rows>(1u<<24u) || (rows&(rows-1u))!=0u || batches==0u) return 256u;
    @autoreleasepool {
        StwoFrameworkInteractionPlan *plan=(__bridge StwoFrameworkInteractionPlan *)plan_ptr;
        if(inputs!=plan.inputs || profile_count!=plan.profiles || relation_count!=plan.relations || batches!=plan.batches ||
            (profile_count!=0u && profiles==NULL) || relations==NULL) return 256u;
        for(uint32_t i=0;i<profile_count;++i) if(profiles[i]>=0x7fffffffu) return 256u;
        for(uint32_t i=0;i<relation_count;++i) if(relations[i]>=0x7fffffffu) return 256u;
        id<MTLBuffer> trees[2]={(__bridge id<MTLBuffer>)tree0_ptr,(__bridge id<MTLBuffer>)tree1_ptr};
        for(uint32_t slot=0;slot<inputs;++slot) {
            uint32_t tag=tags[slot];
            if(tag!=((const uint32_t *)plan.inputTrees.bytes)[slot]) return 256u;
            if(tag==UINT32_MAX) continue;
            if(tag>1u || trees[tag]==nil || trees[tag].device!=plan.device || trees[tag].length%4u!=0u ||
                offsets[slot]>trees[tag].length/4u || rows>trees[tag].length/4u-offsets[slot]) return 256u;
        }
        uint32_t blocks=(rows+255u)/256u;
        uint32_t scan_batches=plan.layout==1u?1u:batches;
        uint64_t output_words=(uint64_t)batches*4u*((uint64_t)rows+1u);
        uint64_t scratch_words=(uint64_t)scan_batches*blocks*4u;
        if(output_words>plan.device.maxBufferLength/4u || scratch_words>plan.device.maxBufferLength/4u ||
            (uint64_t)inputs*8u>plan.device.maxBufferLength || (uint64_t)relation_count*4u>plan.device.maxBufferLength ||
            (uint64_t)profile_count*4u>plan.device.maxBufferLength || (uint64_t)batches*blocks>UINT32_MAX) return 256u;
        uint32_t zero=0u;
        id<MTLBuffer> offset_buffer=[plan.device newBufferWithBytes:offsets length:(size_t)inputs*8u options:MTLResourceStorageModeShared];
        id<MTLBuffer> profile_buffer=[plan.device newBufferWithBytes:profile_count?profiles:&zero length:MAX((size_t)profile_count,1u)*4u options:MTLResourceStorageModeShared];
        id<MTLBuffer> relation_buffer=[plan.device newBufferWithBytes:relations length:(size_t)relation_count*4u options:MTLResourceStorageModeShared];
        id<MTLBuffer> output=[plan.device newBufferWithLength:(size_t)output_words*4u options:MTLResourceStorageModeShared];
        id<MTLBuffer> scratch=[plan.device newBufferWithLength:(size_t)scratch_words*4u options:MTLResourceStorageModePrivate];
        id<MTLBuffer> status=[plan.device newBufferWithBytes:&zero length:4u options:MTLResourceStorageModeShared];
        if(offset_buffer==nil || profile_buffer==nil || relation_buffer==nil || output==nil || scratch==nil || status==nil) return 256u;
        id<MTLCommandBuffer> command=[plan.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder=[command computeCommandEncoder];
        if(command==nil || encoder==nil) return 256u;
        [encoder setComputePipelineState:plan.pipelines[0]];
        [encoder setBuffer:trees[0]?:profile_buffer offset:0 atIndex:0];
        [encoder setBuffer:trees[1]?:profile_buffer offset:0 atIndex:1];
        [encoder setBuffer:offset_buffer offset:0 atIndex:2];
        [encoder setBuffer:profile_buffer offset:0 atIndex:3];
        [encoder setBuffer:relation_buffer offset:0 atIndex:4];
        [encoder setBuffer:output offset:0 atIndex:5];
        [encoder setBuffer:status offset:0 atIndex:6];
        [encoder setBytes:&rows length:4u atIndex:7];
        [encoder dispatchThreads:MTLSizeMake(rows,1u,1u) threadsPerThreadgroup:MTLSizeMake(256u,1u,1u)];
        [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        [encoder setComputePipelineState:plan.pipelines[1]];
        [encoder setBuffer:output offset:0 atIndex:0]; [encoder setBuffer:scratch offset:0 atIndex:1];
        [encoder setBytes:&rows length:4u atIndex:2]; [encoder setBytes:&blocks length:4u atIndex:3];
        [encoder setBytes:&batches length:4u atIndex:4];
        [encoder dispatchThreadgroups:MTLSizeMake((NSUInteger)scan_batches*blocks,1u,1u) threadsPerThreadgroup:MTLSizeMake(256u,1u,1u)];
        [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        [encoder setComputePipelineState:plan.pipelines[2]];
        [encoder setBytes:&batches length:4u atIndex:4];
        [encoder dispatchThreads:MTLSizeMake(scan_batches,1u,1u) threadsPerThreadgroup:MTLSizeMake(256u,1u,1u)];
        [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
        [encoder setComputePipelineState:plan.pipelines[3]];
        [encoder dispatchThreads:MTLSizeMake(rows,scan_batches,1u) threadsPerThreadgroup:MTLSizeMake(256u,1u,1u)];
        [encoder endEncoding]; [command commit]; [command waitUntilCompleted];
        if(command.status!=MTLCommandBufferStatusCompleted) return 256u;
        uint32_t rejected=*(const uint32_t *)status.contents;
        if(rejected!=0u) return rejected;
        *bytes=output.length;*contents=output.contents;*result=(__bridge_retained void *)output;
        if(gpu_ms) *gpu_ms=(command.GPUEndTime-command.GPUStartTime)*1000.0;
        return 0u;
    }
}
