//! M8 GPU-native native segment (stream: native). Contract: gpu_native.zig
//! NativeFactory; design: rv64-m8-gpu-native.md §3.2, §6.
//!
//! STUB (contract landing): every entry fails closed. The native stream
//! replaces it with: device witness from streamed trace chunks (no joins),
//! FIXED adoption from the class cache, MAIN commit into main_resident, local
//! GKR + binding (Stage1), then after the device seal: globals, INTER,
//! composition, OODS, enqueue-only PCS, device checks and device encoding
//! into the segment's slab region (Stage2), with the per-class framing
//! (component Sets, mask points, PcsJob.prepare, composition/INTER plans)
//! built once in `warm`.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

pub const Native = struct {
    pub fn factory(self: *Native) G.NativeFactory {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable = G.NativeFactory.VTable{ .warm = warm, .class_of = classOf, .stage1 = stage1, .stage2 = stage2, .seal = seal, .chunk = chunk };
    fn warm(_: *anyopaque, _: *G.ClassCache) anyerror!void {
        return error.M8GpuNativeNativeNotLanded;
    }
    fn classOf(_: *anyopaque, _: u32, _: u64) anyerror!G.ClassKey {
        return error.M8GpuNativeNativeNotLanded;
    }
    fn stage1(_: *anyopaque, _: *const G.RequestContext, _: u32, _: u32) anyerror!api.Job {
        return error.M8GpuNativeNativeNotLanded;
    }
    fn stage2(_: *anyopaque, _: *const G.RequestContext, _: u32, _: u32) anyerror!api.Job {
        return error.M8GpuNativeNativeNotLanded;
    }
    fn seal(_: *anyopaque, _: *const G.RequestContext, _: u32) anyerror!api.Job {
        return error.M8GpuNativeNativeNotLanded;
    }
    fn chunk(_: *anyopaque, _: *const G.RequestContext, _: G.TraceChunk, _: u32) anyerror!void {
        return error.M8GpuNativeNativeNotLanded;
    }
};

test "native factory stub fails closed" {
    var n = Native{};
    const f = n.factory();
    var cache = G.ClassCache.init(std.testing.allocator);
    defer cache.deinit();
    try std.testing.expectError(error.M8GpuNativeNativeNotLanded, f.vtable.warm(f.ctx, &cache));
    try std.testing.expectError(error.M8GpuNativeNativeNotLanded, f.vtable.class_of(f.ctx, 0, 1));
}
