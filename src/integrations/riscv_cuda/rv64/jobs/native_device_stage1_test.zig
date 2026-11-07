//! Host tests of native_device_stage1.zig (no device): resident layout,
//! chunk ingress format (incl. negatives), check-spec bounds, registry
//! protocol (class miss, seal, request words, chunk order, release).
const std = @import("std");
const testing = std.testing;
const G = @import("gpu_native.zig");
const S1 = @import("native_device_stage1.zig");
const ND = @import("native_device.zig");
const api = @import("api.zig");

test "resident layout: 64-word aligned regions in order, views bounded" {
    const l = S1.ResidentLayout.of(1000, 130, 65, 9 + 32 + 16);
    try testing.expectEqual(@as(usize, 0), l.main);
    try testing.expectEqual(@as(usize, 1024), l.binding);
    try testing.expectEqual(@as(usize, 1024 + 192), l.section);
    try testing.expectEqual(@as(usize, 1024 + 192 + 128), l.authority);
    try testing.expectEqual(@as(usize, 1024 + 192 + 128 + 64), l.checkpoint);
    try testing.expectEqual(@as(usize, 1024 + 192 + 128 + 64 + 64), l.words);
    var backing: [1472]u32 = undefined;
    const r = api.DeviceBuffer{ .ptr = &backing, .words = backing.len };
    try testing.expectEqual(@as(usize, 1000), (try l.mainView(r)).words);
    try testing.expectEqual(@as(usize, 65), (try l.sectionView(r)).words);
    try testing.expect((try l.authorityView(r)).ptr == r.ptr + l.authority);
    try testing.expectError(error.GpuNativeMainResidentTooSmall, l.bindingView(.{ .ptr = &backing, .words = l.words - 1 }));
    const ck = try l.checkpointView(r);
    try testing.expectEqual(@as(usize, 16), ck.words);
    try testing.expect(ck.ptr == r.ptr + 1408);
    try testing.expectError(error.GpuNativeMainResidentTooSmall, l.checkpointView(.{ .ptr = &backing, .words = l.words - 1 }));
}

test "guards: snapshot words [8,16) and traversal header words [8,20) as the legacy validators read them" {
    // channel.zig Snapshot: digest 8, draws, cursor, status, reserved, chain (u64 LE), padding 2.
    const chain: u64 = 0x4a4f4253_0000_0011;
    try testing.expectEqualSlices(u32, &.{ 3, 17, 0, 0, 0x11, 0x4a4f4253, 0, 0 }, &S1.snapshotGuard(3, 17, chain));
    const DC = @import("channel.zig");
    var snap: DC.Snapshot = .{ .digest = @splat(9), .draws = 3, .cursor = 17, .status = 0, .reserved = 0, .chain = chain, .padding = .{ 0, 0 } };
    const words = std.mem.bytesAsSlice(u32, std.mem.asBytes(&snap));
    try testing.expectEqualSlices(u32, words[8..16], &S1.snapshotGuard(3, 17, chain));
    // gkr.zig Header.validate: cursor 2L, draws 1, layers L, count, next_layer L, phase 2.
    const hg = S1.headerGuard(5, 3, 0x47524b53_0000_0000);
    try testing.expectEqualSlices(u32, &.{ 1, 10, 0, 0, 0, 0x47524b53, 0, 0, 5, 3, 5, 2 }, &hg);
    snap.status = 1;
    try testing.expect(!std.mem.eql(u32, words[8..16], &S1.snapshotGuard(3, 17, chain)));
}

test "witness coverage: chunk runs must tile the image exactly" {
    const a = testing.allocator;
    const d = [_]u32{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const c0 = try chunkWords(a, &.{ .{ .dst = 4, .src = 0, .words = 4 }, .{ .dst = 0, .src = 4, .words = 2 } }, &d);
    defer a.free(c0);
    const c1 = try chunkWords(a, &.{.{ .dst = 2, .src = 0, .words = 2 }}, &d);
    defer a.free(c1);
    const ch = [_]G.TraceChunk{ .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 1, .last = false, .words = c0 }, .{ .segment = 0, .sequence = 1, .first_row = 1, .rows = 1, .last = true, .words = c1 } };
    try S1.validateCoverage(a, &ch, 8);
    try testing.expectError(error.NativeStage1WitnessCoverage, S1.validateCoverage(a, &ch, 9)); // tail gap
    try testing.expectError(error.NativeStage1WitnessCoverage, S1.validateCoverage(a, ch[0..1], 8)); // hole [2,4)
    const c2 = try chunkWords(a, &.{.{ .dst = 3, .src = 0, .words = 1 }}, &d);
    defer a.free(c2);
    const over = [_]G.TraceChunk{ ch[0], ch[1], .{ .segment = 0, .sequence = 2, .first_row = 2, .rows = 1, .last = true, .words = c2 } };
    try testing.expectError(error.NativeStage1WitnessCoverage, S1.validateCoverage(a, &over, 8)); // overlap
}

fn chunkWords(a: std.mem.Allocator, runs: []const S1.Run, data: []const u32) ![]u32 {
    const out = try a.alloc(u32, S1.chunk_header_words + 6 * runs.len + data.len);
    out[0] = @intCast(runs.len);
    out[1] = 0;
    @memcpy(out[S1.chunk_header_words..][0 .. 6 * runs.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(runs)));
    @memcpy(out[S1.chunk_header_words + 6 * runs.len ..], data);
    return out;
}

test "chunk format v1: runs and data decode; out-of-range runs and bad headers refuse" {
    const a = testing.allocator;
    const data = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const ok = try chunkWords(a, &.{ .{ .dst = 0, .src = 0, .words = 4 }, .{ .dst = 60, .src = 4, .words = 2 } }, &data);
    defer a.free(ok);
    const runs = try S1.chunkRuns(ok);
    try testing.expectEqual(@as(usize, 2), runs.len);
    try testing.expectEqual(@as(u64, 60), runs[1].dst);
    try testing.expectEqualSlices(u32, &data, try S1.chunkData(ok));
    try S1.validateChunk(ok, 64);
    try testing.expectError(error.NativeStage1ChunkRunOutOfRange, S1.validateChunk(ok, 61)); // dst run past the image
    const src_over = try chunkWords(a, &.{.{ .dst = 0, .src = 3, .words = 4 }}, &data);
    defer a.free(src_over);
    try testing.expectError(error.NativeStage1ChunkRunOutOfRange, S1.validateChunk(src_over, 64));
    const empty_run = try chunkWords(a, &.{.{ .dst = 0, .src = 0, .words = 0 }}, &data);
    defer a.free(empty_run);
    try testing.expectError(error.NativeStage1ChunkRunOutOfRange, S1.validateChunk(empty_run, 64));
    var bad = [_]u32{ 0, 0 };
    try testing.expectError(error.NativeStage1ChunkFormat, S1.chunkRuns(&bad)); // no runs
    bad = .{ 1, 7 };
    try testing.expectError(error.NativeStage1ChunkFormat, S1.chunkRuns(&bad)); // reserved word set
    var short = [_]u32{ 2, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.NativeStage1ChunkFormat, S1.chunkRuns(&short)); // table truncated
}

test "check spec: at most 8 zero words and 4 equal pairs of equal nonzero length" {
    var words: [16]u32 = @splat(0);
    const one = api.DeviceBuffer{ .ptr = &words, .words = 1 };
    var c = S1.CheckSpec{ .check = @intFromEnum(G.Check.root_match) };
    for (0..8) |_| try c.mustBeZero(one);
    try testing.expectError(error.NativeStage1CheckShape, c.mustBeZero(one));
    const eight = api.DeviceBuffer{ .ptr = &words, .words = 8 };
    for (0..4) |_| try c.mustEqual(eight, eight);
    try testing.expectError(error.NativeStage1CheckShape, c.mustEqual(eight, eight));
    for (0..4) |_| try c.mustMatch(eight, &.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try testing.expectError(error.NativeStage1CheckShape, c.mustMatch(eight, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }));
    try testing.expectEqual(@as(u32, 8), c.consts[3].words);
    try testing.expectEqual(@as(u32, 8), c.consts[3].values[7]);
    var d = S1.CheckSpec{ .check = @intFromEnum(G.Check.binding_authority) };
    try testing.expectError(error.NativeStage1CheckShape, d.mustMatch(eight, &.{1})); // length mismatch
    const seventeen = [_]u32{0} ** 17;
    try testing.expectError(error.NativeStage1CheckShape, d.mustMatch(.{ .ptr = &words, .words = 16 }, seventeen[0..16 + 1]));
    try testing.expectError(error.NativeStage1CheckShape, d.mustEqual(eight, one));
    try testing.expectError(error.NativeStage1CheckShape, d.mustEqual(.{ .ptr = &words, .words = 0 }, .{ .ptr = &words, .words = 0 }));
    try testing.expectError(error.NativeStage1CheckShape, d.mustBeZero(.{ .ptr = &words, .words = 0 }));
    // Every native Stage-1 check id sits in the native range the kernel accepts.
    for ([_]G.Check{ .witness_status, .binding_authority, .root_match }) |k| try testing.expectEqual(@as(u16, 0x02), @intFromEnum(k) >> 8);
}

test "registry protocol: misses fail closed, request words once, chunks in order, release drops" {
    const a = testing.allocator;
    var r = S1.Registry.init(a);
    defer r.deinit();
    const key: G.ClassKey = @splat(7);
    try testing.expectError(error.GpuNativeClassNotWarmed, r.classOf(1 << 20));
    const words = S1.RequestWords{ .seed = @splat(1), .prefix = @splat(2), .publics = &.{} };
    try testing.expectError(error.GpuNativeClassNotWarmed, r.setRequest(1, 0, key, words));
    // A class entry without a host plan is enough for the protocol checks
    // (removed before deinit: the registry would destroy it).
    var fake: S1.Class = undefined;
    try r.classes.put(a, key, &fake);
    defer _ = r.classes.swapRemove(key);
    try r.setRequest(1, 0, key, words);
    try testing.expectError(error.NativeStage1RequestWordsTwice, r.setRequest(1, 0, key, words));
    var layout: G.RequestLayout = undefined;
    const ctx = G.RequestContext{ .request = 1, .layout = &layout, .exchange = .{ .segments = 1, .claims_per_segment = 2, .devices = 1 }, .peer = undefined, .classes = undefined, .segments = &.{}, .generation = 1 };
    const data = [_]u32{ 9, 9 };
    const ch = try chunkWords(a, &.{.{ .dst = 0, .src = 0, .words = 2 }}, &data);
    defer a.free(ch);
    try testing.expectError(error.GpuNativeCaptureGeometryMismatch, r.chunk(&ctx, .{ .segment = 0, .sequence = 1, .first_row = 0, .rows = 1, .last = false, .words = ch }));
    try r.chunk(&ctx, .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 1, .last = false, .words = ch });
    try r.chunk(&ctx, .{ .segment = 0, .sequence = 1, .first_row = 1, .rows = 1, .last = true, .words = ch });
    var bad = [_]u32{ 0, 0 };
    try testing.expectError(error.NativeStage1ChunkFormat, r.chunk(&ctx, .{ .segment = 0, .sequence = 2, .first_row = 2, .rows = 1, .last = true, .words = &bad }));
    // A segment fed by chunks cannot also take device columns, and vice versa.
    const cols = [_][*]const u32{@ptrCast(&data)};
    try testing.expectError(error.NativeStage1WitnessTwice, r.setDeviceWitness(1, 0, &cols));
    try r.setDeviceWitness(1, 1, &cols);
    try testing.expectError(error.NativeStage1WitnessTwice, r.chunk(&ctx, .{ .segment = 1, .sequence = 0, .first_row = 0, .rows = 1, .last = true, .words = ch }));
    // Stage 1 without bound symbols fails closed before touching the class.
    try testing.expectError(error.NativeStage1SymbolsNotBound, r.stage1(&ctx, 0, 0));
    try testing.expectEqual(@as(f32, -1), r.gpuMs(1, 0));
    r.release(1);
    try testing.expectEqual(@as(usize, 0), r.requests.count());
    // Sealed: no new class may register on the request path.
    r.seal();
    var plan: @import("native_gkr.zig").Plan = undefined;
    try testing.expectError(error.GpuNativeClassBuildOnRequestPath, r.register(.{ .key = key, .gkr = &plan, .instances = &.{}, .fixed_shapes = &.{}, .fixed_host = &.{}, .fixed_root = @splat(0), .main_shapes = &.{}, .beta = 2 }, 1));
}

test "registry: one rows value maps to one class" {
    var r = S1.Registry.init(testing.allocator);
    defer r.deinit();
    var plan: @import("native_gkr.zig").Plan = undefined;
    const spec = S1.Spec{ .key = @splat(1), .gkr = &plan, .instances = &.{}, .fixed_shapes = &.{}, .fixed_host = &.{}, .fixed_root = @splat(0), .main_shapes = &.{}, .beta = 2 };
    try r.register(spec, 1 << 21);
    try r.register(spec, 1 << 21);
    var other = spec;
    other.key = @splat(2);
    try testing.expectError(error.GpuNativeClassKeyMismatch, r.register(other, 1 << 21));
    try testing.expectEqualSlices(u8, &spec.key, &(try r.classOf(1 << 21)));
}

test "registry: a registered class refuses to warm without a device count; install needs every device warmed" {
    var r = S1.Registry.init(testing.allocator);
    defer r.deinit();
    var plan: @import("native_gkr.zig").Plan = undefined;
    try r.register(.{ .key = @splat(3), .gkr = &plan, .instances = &.{}, .fixed_shapes = &.{}, .fixed_host = &.{}, .fixed_root = @splat(0), .main_shapes = &.{}, .beta = 2 }, 1 << 20);
    var cache = G.ClassCache.init(testing.allocator);
    defer cache.deinit();
    const h = r.hooks();
    try testing.expectError(error.NativeStage1DevicesNotBound, h.warm(h.ctx, &cache));
}

test "native factory routes Stage 1 to a bound registry; unbound stays fail-closed" {
    var reg = S1.Registry.init(testing.allocator);
    defer reg.deinit();
    var n = ND.Native{ .stage1_hooks = reg.hooks() };
    const f = n.factory();
    try testing.expectError(error.GpuNativeClassNotWarmed, f.vtable.class_of(f.ctx, 0, 3));
    var cache = G.ClassCache.init(testing.allocator);
    defer cache.deinit();
    try f.vtable.warm(f.ctx, &cache); // no registered class: nothing to warm
    try testing.expectEqual(@as(usize, 0), cache.count());
    const info = G.Installed{ .devices = 1 };
    try testing.expectError(error.NativeStage1WorkersNotBound, f.vtable.installed.?(f.ctx, &cache, &info));
}
