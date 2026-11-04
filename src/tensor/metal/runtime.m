// Minimal Metal runtime for the tensor frontend's GPU path.
//
// Follows the stwo-zig Metal backend's conventions (src/backends/metal):
// MTLCreateSystemDefaultDevice, newLibraryWithSource with safe math, shared
// (unified-memory) buffers, one serial compute encoder per command buffer.
// The tensor path only needs a handful of kernels and a flat C ABI, so it does
// not go through the backend's admission/identity machinery; it compiles the
// backend's MSL include files plus the tensor kernels (see metal/gpu.zig).
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdint.h>
#include <string.h>

static void tm_write_error(char *out, size_t len, NSString *msg) {
    if (out == NULL || len == 0) return;
    const char *s = msg.UTF8String ?: "unknown Metal error";
    strncpy(out, s, len - 1);
    out[len - 1] = 0;
}

@interface TmRuntime : NSObject
@property(nonatomic, strong) id<MTLDevice> device;
@property(nonatomic, strong) id<MTLCommandQueue> queue;
@property(nonatomic, strong) id<MTLLibrary> library;
@end
@implementation TmRuntime
@end

@interface TmCmd : NSObject
@property(nonatomic, strong) id<MTLCommandBuffer> cb;
@property(nonatomic, strong) id<MTLComputeCommandEncoder> enc;
@end
@implementation TmCmd
@end

void *tm_create(const char *source, char *err, size_t err_len) {
    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (device == nil) {
            tm_write_error(err, err_len, @"No Metal device available");
            return NULL;
        }
        MTLCompileOptions *options = [MTLCompileOptions new];
        if (@available(macOS 15.0, *)) {
            options.mathMode = MTLMathModeSafe;
        } else {
            options.fastMathEnabled = NO;
        }
        options.languageVersion = MTLLanguageVersion3_1;
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:[NSString stringWithUTF8String:source] options:options error:&error];
        if (library == nil) {
            tm_write_error(err, err_len, error.localizedDescription ?: @"Metal library compilation failed");
            return NULL;
        }
        TmRuntime *rt = [TmRuntime new];
        rt.device = device;
        rt.queue = [device newCommandQueue];
        rt.library = library;
        return (__bridge_retained void *)rt;
    }
}

void tm_destroy(void *rt) {
    if (rt != NULL) {
        TmRuntime *r = (__bridge_transfer TmRuntime *)rt;
        (void)r;
    }
}

void *tm_pipeline(void *rt_ptr, const char *name, char *err, size_t err_len) {
    @autoreleasepool {
        TmRuntime *rt = (__bridge TmRuntime *)rt_ptr;
        id<MTLFunction> fn = [rt.library newFunctionWithName:[NSString stringWithUTF8String:name]];
        if (fn == nil) {
            tm_write_error(err, err_len, [NSString stringWithFormat:@"missing kernel %s", name]);
            return NULL;
        }
        NSError *error = nil;
        id<MTLComputePipelineState> p = [rt.device newComputePipelineStateWithFunction:fn error:&error];
        if (p == nil) {
            tm_write_error(err, err_len, error.localizedDescription ?: @"pipeline creation failed");
            return NULL;
        }
        return (__bridge_retained void *)p;
    }
}

uint32_t tm_pipeline_max_threads(void *p) {
    id<MTLComputePipelineState> pipe = (__bridge id<MTLComputePipelineState>)p;
    return (uint32_t)pipe.maxTotalThreadsPerThreadgroup;
}

void tm_release(void *obj) {
    if (obj != NULL) {
        id o = (__bridge_transfer id)obj;
        (void)o;
    }
}

void *tm_buffer_alloc(void *rt_ptr, size_t len) {
    TmRuntime *rt = (__bridge TmRuntime *)rt_ptr;
    id<MTLBuffer> b = [rt.device newBufferWithLength:(len == 0 ? 16 : len) options:MTLResourceStorageModeShared];
    return b == nil ? NULL : (__bridge_retained void *)b;
}

/// Zero-copy view of host memory (unified memory). `ptr` must be page aligned
/// and `len` a multiple of the page size; returns NULL otherwise.
void *tm_buffer_wrap(void *rt_ptr, void *ptr, size_t len) {
    TmRuntime *rt = (__bridge TmRuntime *)rt_ptr;
    id<MTLBuffer> b = [rt.device newBufferWithBytesNoCopy:ptr length:len options:MTLResourceStorageModeShared deallocator:nil];
    return b == nil ? NULL : (__bridge_retained void *)b;
}

void *tm_buffer_contents(void *buf) {
    id<MTLBuffer> b = (__bridge id<MTLBuffer>)buf;
    return b.contents;
}

void *tm_cmd_begin(void *rt_ptr) {
    TmRuntime *rt = (__bridge TmRuntime *)rt_ptr;
    TmCmd *c = [TmCmd new];
    c.cb = [rt.queue commandBufferWithUnretainedReferences];
    c.enc = [c.cb computeCommandEncoderWithDispatchType:MTLDispatchTypeSerial];
    return (__bridge_retained void *)c;
}

void tm_cmd_pipeline(void *cmd, void *pipe) {
    TmCmd *c = (__bridge TmCmd *)cmd;
    [c.enc setComputePipelineState:(__bridge id<MTLComputePipelineState>)pipe];
}

void tm_cmd_buffer(void *cmd, uint32_t index, void *buf, size_t offset) {
    TmCmd *c = (__bridge TmCmd *)cmd;
    [c.enc setBuffer:(__bridge id<MTLBuffer>)buf offset:offset atIndex:index];
}

void tm_cmd_bytes(void *cmd, uint32_t index, const void *bytes, size_t len) {
    TmCmd *c = (__bridge TmCmd *)cmd;
    [c.enc setBytes:bytes length:len atIndex:index];
}

void tm_cmd_threadgroup_memory(void *cmd, uint32_t index, size_t len) {
    TmCmd *c = (__bridge TmCmd *)cmd;
    [c.enc setThreadgroupMemoryLength:len atIndex:index];
}

void tm_cmd_dispatch(void *cmd, uint32_t gx, uint32_t gy, uint32_t gz, uint32_t tx, uint32_t ty, uint32_t tz) {
    TmCmd *c = (__bridge TmCmd *)cmd;
    [c.enc dispatchThreadgroups:MTLSizeMake(gx, gy, gz) threadsPerThreadgroup:MTLSizeMake(tx, ty, tz)];
}

/// Ends encoding, commits and waits. Returns 0 on success; GPU time in ms.
int tm_cmd_end(void *cmd, double *gpu_ms, char *err, size_t err_len) {
    @autoreleasepool {
        TmCmd *c = (__bridge_transfer TmCmd *)cmd;
        [c.enc endEncoding];
        [c.cb commit];
        [c.cb waitUntilCompleted];
        if (gpu_ms != NULL) *gpu_ms = (c.cb.GPUEndTime - c.cb.GPUStartTime) * 1000.0;
        if (c.cb.status != MTLCommandBufferStatusCompleted) {
            tm_write_error(err, err_len, c.cb.error.localizedDescription ?: @"command buffer failed");
            return 1;
        }
        return 0;
    }
}
