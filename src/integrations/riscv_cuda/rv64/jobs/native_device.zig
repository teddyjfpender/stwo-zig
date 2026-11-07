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
//!
//! Stage 1 (piece n-stage1) is native_device_stage1.zig: the service binds
//! its registry's `Stage1Hooks` (`Registry.hooks()`) at install; warm,
//! installed, class_of, stage1 and chunk route to it. Unbound they fail
//! closed as before. (Hooks, not an import: this file is also compiled by the
//! driver's light test root, which has no prover modules.)
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

pub const Stage1Hooks = struct {
    ctx: *anyopaque,
    warm: *const fn (*anyopaque, *G.ClassCache) anyerror!void,
    installed: *const fn (*anyopaque, *const G.Installed) anyerror!void,
    class_of: *const fn (*anyopaque, rows: u64) anyerror!G.ClassKey,
    stage1: *const fn (*anyopaque, *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job,
    chunk: *const fn (*anyopaque, *const G.RequestContext, G.TraceChunk) anyerror!void,
};

pub const Native = struct {
    /// Stage-1 registry hooks; null = not bound (fails closed).
    stage1_hooks: ?Stage1Hooks = null,

    pub fn factory(self: *Native) G.NativeFactory {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable = G.NativeFactory.VTable{ .warm = warm, .installed = installed, .class_of = classOf, .stage1 = stage1, .stage2 = stage2, .seal = seal, .chunk = chunk };
    fn hooks(raw: *anyopaque) !Stage1Hooks {
        const self: *Native = @ptrCast(@alignCast(raw));
        return self.stage1_hooks orelse error.M8GpuNativeNativeNotLanded;
    }
    fn warm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        const h = try hooks(raw);
        return h.warm(h.ctx, cache);
    }
    fn installed(raw: *anyopaque, _: *G.ClassCache, info: *const G.Installed) anyerror!void {
        const h = try hooks(raw);
        return h.installed(h.ctx, info);
    }
    fn classOf(raw: *anyopaque, _: u32, rows: u64) anyerror!G.ClassKey {
        const h = try hooks(raw);
        return h.class_of(h.ctx, rows);
    }
    fn stage1(raw: *anyopaque, ctx: *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job {
        const h = try hooks(raw);
        return h.stage1(h.ctx, ctx, segment, device);
    }
    fn stage2(_: *anyopaque, _: *const G.RequestContext, _: u32, _: u32) anyerror!api.Job {
        return error.M8GpuNativeNativeNotLanded;
    }
    fn seal(_: *anyopaque, _: *const G.RequestContext, _: u32) anyerror!api.Job {
        return error.M8GpuNativeNativeNotLanded;
    }
    fn chunk(raw: *anyopaque, ctx: *const G.RequestContext, c: G.TraceChunk, _: u32) anyerror!void {
        const h = try hooks(raw);
        return h.chunk(h.ctx, ctx, c);
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
