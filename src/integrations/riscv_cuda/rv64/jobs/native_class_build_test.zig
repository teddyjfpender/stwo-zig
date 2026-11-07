//! Host tests of the install-time class builder (native_class_build.zig):
//! patch-table derivation, fingerprint comparison, class resolution by
//! (block, segment, rows) and the shape-hook routing. Real-block parity (the
//! classes built from real captures vs the legacy per-segment ones) is
//! rv64_m8_class_build_parity_main.zig on the pod.
const std = @import("std");
const testing = std.testing;
const NCB = @import("native_class_build.zig");
const S2 = @import("native_device_stage2.zig");
const ND = @import("native_device.zig");
const G = @import("gpu_native.zig");
const JP = @import("../joined_parameters.zig");

test "class build: patch tables route every parameter slot to its device source" {
    const a = testing.allocator;
    // Role 0 at table offset 40: public (cpu_steps), shared (ram+2), semantic
    // (local+1), a claims slot (never patched); role 1 at 200: public first_id.
    const r0 = [_]u32{ JP.cpu_steps, JP.ram + 2, JP.local + 1, JP.claims };
    const r1 = [_]u32{JP.first_id};
    const hc = [_]NCB.HcRun{.{ .dst = 500, .first = S2.semantic_felts, .felts = 3 }};
    var set = try NCB.patchSet(a, &.{ .{ .slots = &r0, .base = 40 }, .{ .slots = &r1, .base = 200 } }, &hc);
    defer set.deinit(a);
    try testing.expectEqualSlices(u32, &.{ 40, 200 }, set.public.dst);
    try testing.expectEqualSlices(u32, &.{ JP.cpu_steps, JP.first_id }, set.public.index);
    try testing.expectEqualSlices(u32, &.{48}, set.shared.dst);
    try testing.expectEqualSlices(u32, &.{2}, set.shared.index);
    // semantic: the namespace felt, then the hc rows after the namespace felts.
    try testing.expectEqualSlices(u32, &.{ 56, 500, 508, 516 }, set.semantic.dst);
    try testing.expectEqualSlices(u32, &.{ 1, S2.semantic_felts, S2.semantic_felts + 1, S2.semantic_felts + 2 }, set.semantic.index);
    // In bounds of the sources and a 600-word target; out of a 510-word one.
    try set.check(8 * (S2.semantic_felts + 3), 600);
    try testing.expectError(error.NativeStage2PatchTable, set.check(8 * (S2.semantic_felts + 3), 510));
    try testing.expectError(error.NativeStage2PatchTable, set.check(8 * S2.semantic_felts, 600));
    const mask = try NCB.maskOf(a, set);
    defer a.free(mask);
    try testing.expectEqualSlices(u32, &.{ 40, 48, 56, 200, 500, 508, 516 }, mask);
}

fn field(name: []const u8, class: bool, byte: u8) NCB.Field {
    return .{ .name = name, .class = class, .digest = @splat(byte) };
}

test "class build: fingerprint compares class fields only and keys on them" {
    const a = testing.allocator;
    var x = NCB.Fingerprint{ .a = a };
    defer x.deinit();
    var y = NCB.Fingerprint{ .a = a };
    defer y.deinit();
    for ([_]NCB.Field{ field("s1.a", true, 1), field("s1.request.p", false, 2), field("s2.b", true, 3) }) |f| try x.fields.append(a, f);
    for ([_]NCB.Field{ field("s1.a", true, 1), field("s1.request.p", false, 9), field("s2.b", true, 3) }) |f| try y.fields.append(a, f);
    var out: [4]NCB.Mismatch = undefined;
    // A per-request difference is not a class difference, and not in the key.
    try testing.expectEqual(@as(usize, 0), try NCB.compare(&x, &y, &out));
    try testing.expectEqualSlices(u8, &x.key(), &y.key());
    y.fields.items[2].digest[0] ^= 1;
    try testing.expectEqual(@as(usize, 1), try NCB.compare(&x, &y, &out));
    try testing.expectEqualStrings("s2.b", out[0].name);
    try testing.expect(!std.mem.eql(u8, &x.key(), &y.key()));
    // A Stage-1-only fingerprint compares as a prefix.
    var s1 = NCB.Fingerprint{ .a = a };
    defer s1.deinit();
    try s1.fields.append(a, field("s1.a", true, 1));
    try testing.expectEqual(@as(usize, 0), try NCB.compare(&x, &s1, &out));
    s1.fields.items[0].name = "s1.other";
    try testing.expectError(error.GnShapeFingerprintShape, NCB.compare(&x, &s1, &out));
    try testing.expectError(error.GnShapeFingerprintShape, NCB.compare(&s1, &x, &out));
}

test "class build: keys of one class (stage-1 fixed region, stage-2 framing, registry token)" {
    var key: G.ClassKey = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    const fk = NCB.Class.framingKey(key);
    try testing.expect(!std.mem.eql(u8, &fk, &key));
    try testing.expectEqualSlices(u8, &fk, &NCB.Class.framingKey(key));
    // native_device_stage1 Class.fixed_key formula.
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-n1-fixed-v1");
    h.update(&key);
    var cl: NCB.Class = undefined;
    cl.key = key;
    try testing.expectEqualSlices(u8, &h.finalResult(), &cl.fixedKey());
    // The token never collides with a real row count (< 2^63).
    try testing.expect(NCB.rowsToken(key) >= @as(u64, 1) << 63);
}

fn testBuilder(a: std.mem.Allocator) NCB.Builder {
    return .{ .a = a, .env = undefined };
}
fn addBlock(b: *NCB.Builder, block: u64, keys: []const G.ClassKey, rows: []const u64) !void {
    try b.blocks.append(b.a, .{ .block = block, .keys = try b.a.dupe(G.ClassKey, keys), .rows = try b.a.dupe(u64, rows), .build_ns = 0, .miss = false });
}

test "class build: class_of by (block, segment, rows); the row-only form fails closed when ambiguous" {
    const a = testing.allocator;
    var b = testBuilder(a);
    defer b.deinit();
    const ka: G.ClassKey = @splat(0xa);
    const kb: G.ClassKey = @splat(0xb);
    const kc: G.ClassKey = @splat(0xc);
    // Two blocks; both have 2^20-row segments 0 and 1 with DIFFERENT classes
    // (equal rows, different FIXED/bridges): the bench15 case.
    try addBlock(&b, 100, &.{ ka, kb }, &.{ 1 << 20, 1 << 20 });
    try addBlock(&b, 200, &.{ kc, kb }, &.{ 1 << 20, 1 << 20 });
    try testing.expectEqualSlices(u8, &ka, &try b.classOf(100, 0, 1 << 20));
    try testing.expectEqualSlices(u8, &kc, &try b.classOf(200, 0, 1 << 20));
    try testing.expectEqualSlices(u8, &kb, &try b.classOf(null, 1, 1 << 20));
    try testing.expectError(error.GnShapeClassAmbiguous, b.classOf(null, 0, 1 << 20));
    try testing.expectError(error.GpuNativeClassNotWarmed, b.classOf(100, 0, 1 << 19));
    try testing.expectError(error.GpuNativeClassNotWarmed, b.classOf(300, 0, 1 << 20));
    try testing.expectError(error.GpuNativeClassNotWarmed, b.classOf(100, 2, 1 << 20));
    // Through the native factory vtable (shape-hook registration).
    var n = ND.Native{ .shape_hooks = b.hooks() };
    const f = n.factory();
    try testing.expectEqualSlices(u8, &kc, &try f.vtable.class_of_block.?(f.ctx, 200, 0, 1 << 20));
    try testing.expectError(error.GnShapeClassAmbiguous, f.vtable.class_of(f.ctx, 0, 1 << 20));
}

test "class build: legacy-side builders are analysed" {
    // Bodies used only by the pod parity harness (no host fixture here).
    _ = &NCB.stage1FromNumerical;
    _ = &NCB.inputsFromWorker;
    _ = &NCB.buildFromInventory;
    _ = &NCB.Inventory.init;
}

const NComp = @import("native_composition.zig");

/// A host-only Class shell with just what registration reads (framing
/// fields + replica links); never deinit'd through Class.deinit.
fn shellClass(a: std.mem.Allocator, key: G.ClassKey, plan: *NComp.Plan) NCB.Class {
    var cl: NCB.Class = undefined;
    cl.a = a;
    cl.key = key;
    cl.replicas = &.{};
    cl.proto = null;
    cl.s1_registered = false;
    cl.s2_registered = 0;
    cl.framing = .{ .a = a, .key = NCB.Class.framingKey(key), .claim_count = 0, .slots = &.{}, .inter = undefined, .composition = plan, .pcs = undefined, .program = .{ .a = a, .words = &.{}, .max_encoded_bytes = 0, .pcs_words = 0 }, .fixed_root = @splat(0), .fixed_key = @splat(0), .fixed_host = &.{}, .fixed_offsets = &.{}, .fixed_words = 0, .main_offsets = &.{}, .main_words = 0, .bind_plan = undefined, .global_patches = &.{}, .comp_patches = .{} };
    return cl;
}

test "class build: registration registers prototype + every replica once, and is retry-idempotent" {
    const a = testing.allocator;
    var f = S2.Factory{ .a = a, .sym = undefined, .identity = @splat(0) };
    defer f.deinit();
    var plans: [3]NComp.Plan = undefined;
    for (&plans) |*p| p.table = &.{};
    const key: G.ClassKey = @splat(0x42);
    var proto = shellClass(a, key, &plans[0]);
    var r1 = shellClass(a, key, &plans[1]);
    var r2 = shellClass(a, key, &plans[2]);
    r1.proto = &proto;
    r2.proto = &proto;
    var reps = [_]*NCB.Class{ &r1, &r2 };
    proto.replicas = &reps;
    try testing.expectEqual(@as(usize, 3), proto.framingInstances());
    var b = NCB.Builder{ .a = a, .env = undefined, .factory = &f, .framing_instances = 3 };
    defer b.deinit();
    try b.registerClassForTest(&proto);
    try b.registerClassForTest(&proto); // retry: nothing registered twice
    const pool = f.classes.get(NCB.Class.framingKey(key)).?;
    try testing.expectEqual(@as(usize, 3), pool.instances.items.len);
    // Exclusive leases hand out three DIFFERENT instances, each with its own
    // composition plan (no shared per-job Stage-2 state), then fail closed.
    const x = try f.acquire(&proto.framing.?);
    const y = try f.acquire(&proto.framing.?);
    const z = try f.acquire(&proto.framing.?);
    try testing.expect(x != y and y != z and x != z);
    try testing.expect(x.composition != y.composition and y.composition != z.composition and x.composition != z.composition);
    try testing.expectError(error.NativeStage2FramingBusy, f.acquire(&proto.framing.?));
}
