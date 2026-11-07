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
/// Stage 2 + device seal (piece n-stage2) seam: native_device_stage2.zig
/// `Factory.hooks()`. Not imported here (the light driver test root that
/// builds this file cannot build the Stage-2 dependencies).
pub const Stage2Hooks = struct {
    ctx: *anyopaque,
    seal: *const fn (*anyopaque, *const G.RequestContext, u32) anyerror!api.Job,
    stage2: *const fn (*anyopaque, *const G.RequestContext, u32, u32) anyerror!api.Job,
};

pub const Native = struct {
    /// Stage-2 / seal factory (n-stage2); null = those entries fail closed.
    stage2_hooks: ?Stage2Hooks = null,
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
    fn stage2(raw: *anyopaque, ctx: *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job {
        const self: *Native = @ptrCast(@alignCast(raw));
        const h = self.stage2_hooks orelse return error.M8GpuNativeNativeNotLanded;
        return h.stage2(h.ctx, ctx, segment, device);
    }
    fn seal(raw: *anyopaque, ctx: *const G.RequestContext, device: u32) anyerror!api.Job {
        const self: *Native = @ptrCast(@alignCast(raw));
        const h = self.stage2_hooks orelse return error.M8GpuNativeNativeNotLanded;
        return h.seal(h.ctx, ctx, device);
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
