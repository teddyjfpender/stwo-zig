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
/// Stage 2 + device seal (piece n-stage2) seam: native_device_stage2.zig
/// `Factory.hooks()`. Not imported here (the light driver test root that
/// builds this file cannot build the Stage-2 dependencies).
pub const Stage2Hooks = struct {
    ctx: *anyopaque,
    seal: *const fn (*anyopaque, *const G.RequestContext, u32) anyerror!api.Job,
    stage2: *const fn (*anyopaque, *const G.RequestContext, u32, u32) anyerror!api.Job,
};

pub const Stage1Hooks = struct {
    ctx: *anyopaque,
    warm: *const fn (*anyopaque, *G.ClassCache) anyerror!void,
    installed: *const fn (*anyopaque, *const G.Installed) anyerror!void,
    class_of: *const fn (*anyopaque, rows: u64) anyerror!G.ClassKey,
    stage1: *const fn (*anyopaque, *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job,
    chunk: *const fn (*anyopaque, *const G.RequestContext, G.TraceChunk) anyerror!void,
};

/// Install-time class mix (stream gn-shape): native_class_build.zig
/// `Builder.hooks()`. `shape` is NativeFactory.shape; `class_of` resolves a
/// segment's class from (block, segment, rows) (the Stage-1 registry's
/// rows-only map is ambiguous across segments and blocks). Not imported here
/// (the light driver test root cannot build the CPU integration).
pub const ShapeHooks = struct {
    ctx: *anyopaque,
    shape: *const fn (*anyopaque, std.mem.Allocator, G.WarmBlock) anyerror![]u64,
    /// `block` null: the unique class of (segment, rows) over warmed blocks.
    class_of: *const fn (*anyopaque, block: ?u64, segment: u32, rows: u64) anyerror!G.ClassKey,
};

pub const CaptureHooks = struct {
    ctx: *anyopaque,
    pack: *const fn (*anyopaque, *const G.RequestContext, G.CapturedSegment, G.ChunkWriter) anyerror!u64,
    captured: *const fn (*anyopaque, *const G.RequestContext, G.CaptureEnd) anyerror!void,
};

pub const Native = struct {
    /// Stage-1 registry hooks; null = not bound (fails closed).
    stage1_hooks: ?Stage1Hooks = null,
    /// Install-time class builder (gn-shape); null = NativeFactory.shape
    /// fails closed with GpuNativeNativeShapeHookMissing and class_of uses
    /// the Stage-1 registry's rows map.
    shape_hooks: ?ShapeHooks = null,

    /// Stage-2 / seal factory (n-stage2); null = those entries fail closed.
    stage2_hooks: ?Stage2Hooks = null,
    capture_hooks: ?CaptureHooks = null,
    resolved: G.NativeFactory.VTable = undefined,
    pub fn factory(self: *Native) G.NativeFactory {
        self.resolved = vtable;
        if (self.capture_hooks != null) {
            self.resolved.pack = pack;
            self.resolved.captured = captured;
        }
        return .{ .ctx = self, .vtable = &self.resolved };
    }
    const vtable = G.NativeFactory.VTable{ .warm = warm, .installed = installed, .class_of = classOf, .stage1 = stage1, .stage2 = stage2, .seal = seal, .chunk = chunk, .shape = shape, .class_of_block = classOfBlock };
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
    fn classOf(raw: *anyopaque, segment: u32, rows: u64) anyerror!G.ClassKey {
        const self: *Native = @ptrCast(@alignCast(raw));
        if (self.shape_hooks) |sh| return sh.class_of(sh.ctx, null, segment, rows);
        const h = try hooks(raw);
        return h.class_of(h.ctx, rows);
    }
    fn classOfBlock(raw: *anyopaque, block: u64, segment: u32, rows: u64) anyerror!G.ClassKey {
        const self: *Native = @ptrCast(@alignCast(raw));
        if (self.shape_hooks) |sh| return sh.class_of(sh.ctx, block, segment, rows);
        return classOf(raw, segment, rows);
    }
    fn shape(raw: *anyopaque, a: std.mem.Allocator, wb: G.WarmBlock) anyerror![]u64 {
        const self: *Native = @ptrCast(@alignCast(raw));
        const sh = self.shape_hooks orelse return error.GpuNativeNativeShapeHookMissing;
        return sh.shape(sh.ctx, a, wb);
    }
    fn stage1(raw: *anyopaque, ctx: *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job {
        const h = try hooks(raw);
        return h.stage1(h.ctx, ctx, segment, device);
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
    fn chunk(raw: *anyopaque, ctx: *const G.RequestContext, c: G.TraceChunk, _: u32) anyerror!void {
        const h = try hooks(raw);
        return h.chunk(h.ctx, ctx, c);
    }
    fn pack(raw: *anyopaque, ctx: *const G.RequestContext, cs: G.CapturedSegment, writer: G.ChunkWriter) anyerror!u64 {
        const self: *Native = @ptrCast(@alignCast(raw));
        const h = self.capture_hooks orelse return error.GpuNativeCaptureNoPacker;
        return h.pack(h.ctx, ctx, cs, writer);
    }
    fn captured(raw: *anyopaque, ctx: *const G.RequestContext, ce: G.CaptureEnd) anyerror!void {
        const self: *Native = @ptrCast(@alignCast(raw));
        const h = self.capture_hooks orelse return error.GpuNativeCaptureNoPacker;
        return h.captured(h.ctx, ctx, ce);
    }
};

test "native factory stub fails closed" {
    var n = Native{};
    const f = n.factory();
    var cache = G.ClassCache.init(std.testing.allocator);
    defer cache.deinit();
    try std.testing.expectError(error.M8GpuNativeNativeNotLanded, f.vtable.warm(f.ctx, &cache));
    try std.testing.expectError(error.M8GpuNativeNativeNotLanded, f.vtable.class_of(f.ctx, 0, 1));
    try std.testing.expectError(error.GpuNativeNativeShapeHookMissing, f.vtable.shape.?(f.ctx, std.testing.allocator, undefined));
}

test "native factory shape hooks route shape and (block, segment, rows) class_of" {
    const Fake = struct {
        calls: u32 = 0,
        fn shapeFn(raw: *anyopaque, a: std.mem.Allocator, wb: G.WarmBlock) anyerror![]u64 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            const out = try a.alloc(u64, 2);
            out[0] = wb.block;
            out[1] = 7;
            return out;
        }
        fn classFn(_: *anyopaque, block: ?u64, segment: u32, rows: u64) anyerror!G.ClassKey {
            var k: G.ClassKey = @splat(0);
            k[0] = @truncate(block orelse 0xff);
            k[1] = @truncate(segment);
            k[2] = @truncate(rows);
            return k;
        }
    };
    var fake = Fake{};
    var n = Native{ .shape_hooks = .{ .ctx = &fake, .shape = Fake.shapeFn, .class_of = Fake.classFn } };
    const f = n.factory();
    const rows = try f.vtable.shape.?(f.ctx, std.testing.allocator, .{ .block = 9, .capture = undefined });
    defer std.testing.allocator.free(rows);
    try std.testing.expectEqualSlices(u64, &.{ 9, 7 }, rows);
    try std.testing.expectEqual(@as(u32, 1), fake.calls);
    const k1 = try f.vtable.class_of(f.ctx, 3, 5);
    try std.testing.expectEqual(@as(u8, 0xff), k1[0]);
    const k2 = try f.vtable.class_of_block.?(f.ctx, 9, 3, 5);
    try std.testing.expectEqualSlices(u8, &.{ 9, 3, 5 }, k2[0..3]);
}
