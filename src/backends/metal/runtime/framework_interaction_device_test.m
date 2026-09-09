#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "object_model.h"
#include "framework_interaction.m"

// Only this focused test translation unit compiles generated source. The
// production implementation above resolves exclusively admitted AOT pipelines.
void *stwo_framework_interaction_test_prepare(const char *source,size_t source_length,const char *name_bytes,size_t name_length,
    const uint32_t *tags,uint32_t inputs,uint32_t profiles,uint32_t relations,uint32_t batches) {
    @autoreleasepool {
        id<MTLDevice> device=MTLCreateSystemDefaultDevice();
        id<MTLCommandQueue> queue=[device newCommandQueue];
        NSString *source_string=[[NSString alloc] initWithBytes:source length:source_length encoding:NSUTF8StringEncoding];
        NSString *name=[[NSString alloc] initWithBytes:name_bytes length:name_length encoding:NSUTF8StringEncoding];
        MTLCompileOptions *options=[MTLCompileOptions new]; options.fastMathEnabled=NO;
        NSError *error=nil;
        id<MTLLibrary> library=[device newLibraryWithSource:source_string options:options error:&error];
        if(library==nil) { NSLog(@"framework interaction compile: %@",error); return NULL; }
        NSMutableDictionary *pipelines=[NSMutableDictionary new];
        for(NSString *symbol in stwo_framework_interaction_names(name)) {
            id<MTLFunction> function=[library newFunctionWithName:symbol];
            id<MTLComputePipelineState> pipeline=[device newComputePipelineStateWithFunction:function error:&error];
            if(pipeline==nil) { NSLog(@"framework interaction pipeline: %@",error); return NULL; }
            pipelines[symbol]=pipeline;
        }
        return stwo_framework_interaction_plan(device,device,queue,pipelines,name,tags,inputs,profiles,relations,batches);
    }
}
void *stwo_framework_interaction_test_upload(void *plan_ptr,const uint32_t *words,size_t length,void **contents) {
    @autoreleasepool {
        StwoFrameworkInteractionPlan *plan=(__bridge StwoFrameworkInteractionPlan *)plan_ptr;
        id<MTLBuffer> buffer=[plan.device newBufferWithBytes:words length:length*4u options:MTLResourceStorageModeShared];
        if(buffer==nil) return NULL;
        *contents=buffer.contents;
        return (__bridge_retained void *)buffer;
    }
}
void stwo_zig_metal_buffer_destroy(void *buffer) { if(buffer!=NULL) CFRelease(buffer); }

bool stwo_framework_interaction_test_reject_metadata(void *opaque) {
    StwoFrameworkInteractionPlan *plan=(__bridge StwoFrameworkInteractionPlan *)opaque;
    uint32_t *relations=calloc(plan.relations,sizeof(uint32_t));
    uint64_t *offsets=calloc(plan.inputs,sizeof(uint64_t));
    uint32_t *tags=calloc(plan.inputs,sizeof(uint32_t));
    memcpy(tags,plan.inputTrees.bytes,plan.inputs*sizeof(uint32_t));
    void *result=NULL,*contents=NULL;size_t bytes=0;double ms=0;uint32_t zero=0;
    bool ok=true;
    // No allocation/publication may happen for a mismatched admitted shape.
    for(uint32_t variant=0u;variant<4u;++variant) {
        if(variant==3u) tags[0]=UINT32_MAX;
        uint32_t status=stwo_zig_framework_interaction_generate(opaque,NULL,NULL,tags,offsets,
            plan.inputs+(variant==0u),&zero,plan.profiles+(variant==1u),relations,plan.relations,
            2u,plan.batches+(variant==2u),&result,&contents,&bytes,&ms);
        ok=ok && status==256u && result==NULL && contents==NULL && bytes==0u;
    }
    free(relations);free(offsets);free(tags);return ok;
}
