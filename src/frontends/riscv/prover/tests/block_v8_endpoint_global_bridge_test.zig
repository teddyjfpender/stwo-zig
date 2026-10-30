const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const K = @import("../block_v8_ram_endpoint_kernel_v1.zig");
const T = @import("../block_v7_memory_trace_v1.zig");
const B = @import("../block_v8_endpoint_global_bridge_component_v1.zig");
const Scope = @import("../block_v8_endpoint_global_bridge_scope_v1.zig");
const Proof = @import("../block_v8_endpoint_global_bridge_proof_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Old = @import("../block_v5_word_pcs_v1.zig").For(Cpu, @import("../block_v8_ram_endpoint_component_v1.zig").Spec);
const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
fn matrix(a: std.mem.Allocator, policy: K.Policy, n: u32) !T.Matrix {
    const log = @max(@as(u32, 4), std.math.log2_int_ceil(u32, n));
    var result = try T.Matrix.init(a, log, 25, 1 << 20);
    errdefer result.deinit();
    for (0..n) |i| {
        result.set(0, i, core.fields.m31.M31.one());
        result.set(1, i, if (i == 0) core.fields.m31.M31.one() else core.fields.m31.M31.zero());
        const address: u32 = 16 + 4 * @as(u32, @intCast(i));
        const row = try K.constructWithPrevious(.{ .address = address, .initial = @intCast(i), .final = @intCast(i + 1), .last_clock = @intCast(i + 1) }, if (i == 0) null else address - 4, policy);
        for (row, 0..) |value, column| result.set(column + 2, i, try value.tryIntoM31());
    }
    return result;
}
test "late endpoint bridge reuses distinct source roots and freshly verifies after source release" {
    const a = std.testing.allocator;
    const policy0 = K.Policy{ .source_ordinal = 0, .max_local_clock = 64 };
    const policy1 = K.Policy{ .source_ordinal = 1, .max_local_clock = 128 };
    var m0 = try matrix(a, policy0, 2);
    var m1 = try matrix(a, policy1, 3);
    var f0 = try Old.commit(a, m0.columns[0..2], m0.columns[2..], .{}, config, true);
    var f1 = try Old.commit(a, m1.columns[0..2], m1.columns[2..], .{}, config, true);
    var producers_live = true;
    defer if (producers_live) {
        f0.deinit(a);
        f1.deinit(a);
        m0.deinit();
        m1.deinit();
    };
    const sources = [_]Scope.Source{
        .{ .local_identity = @splat(1), .local_epoch = @splat(2), .endpoint_root = f0.roots[1], .endpoint_count = 2, .policy = policy0 },
        .{ .local_identity = @splat(3), .local_epoch = @splat(4), .endpoint_root = f1.roots[1], .endpoint_count = 3, .policy = policy1 },
    };
    const global = try E.Entry.init(.memory_joint, 0, @splat(5), &.{ @splat(6), @splat(7) });
    var scope = try Scope.Owned.init(a, @splat(8), config, &sources, global);
    defer scope.deinit();
    const drawn = try scope.epoch.draw(a);
    var expected = core.fields.qm31.QM31.zero();
    for ([_]T.Matrix{ m0, m1 }, [_]K.Policy{ policy0, policy1 }) |m, p| for (0..m.size()) |i| {
        expected = expected.add(try B.term(core.fields.qm31.QM31, p, drawn.memory.transition, core.fields.qm31.QM31.fromBase(m.get(0, i)), m.row(23, 2, i)).fraction());
    };
    var proof = try Proof.produceConditional(a, scope, &.{ .{ .endpoints = m0, .tree = &f0.scheme.trees.items[1], .tree_allocator = a }, .{ .endpoints = m1, .tree = &f1.scheme.trees.items[1], .tree_allocator = a } }, .{});
    defer proof.deinit();
    f0.deinit(a);
    f1.deinit(a);
    m0.deinit();
    m1.deinit();
    producers_live = false;
    try std.testing.expectEqualDeep(expected, try Proof.verifyConditional(a, scope, &proof.stark, proof.claims, .{}));
    // Compensated physical claims still change the transcript, even though
    // their aggregate remains the same. No aggregate-only absorption.
    var changed = [2]core.fields.qm31.QM31{ proof.claims[0].add(core.fields.qm31.QM31.one()), proof.claims[1].sub(core.fields.qm31.QM31.one()) };
    const first = try scope.afterClaims(drawn, proof.claims);
    const second = try scope.afterClaims(drawn, &changed);
    try std.testing.expect(!std.meta.eql(first.digestBytes(), second.digestBytes()));
    var changed_sources = sources;
    changed_sources[0].endpoint_root[0] ^= 1;
    var changed_scope = try Scope.Owned.init(a, @splat(8), config, &changed_sources, global);
    defer changed_scope.deinit();
    try std.testing.expectError(error.UntrustedEndpointBridgeProof, Proof.verifyConditional(a, changed_scope, &proof.stark, proof.claims, .{}));
    changed_sources = sources;
    changed_sources[0].policy.source_ordinal = 1;
    try std.testing.expectError(error.InvalidEndpointBridgeOrder, Scope.Owned.init(a, @splat(8), config, &changed_sources, global));
}
test "bridge geometry is receiver derived and no zero count proof is admitted" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidEndpointBridgeGeometry, B.prefix(a, 0, 4, 1 << 20));
    try std.testing.expectError(error.InvalidEndpointBridgeGeometry, B.prefix(a, 17, 4, 1 << 20));
    var fixed = try B.prefix(a, 17, 5, 1 << 20);
    defer fixed.deinit();
    for (0..32) |i| try std.testing.expectEqual(@as(u32, @intFromBool(i < 17)), fixed.get(0, i).toU32());
}
test "bridge batches retain one global epoch without rounding the real source count" {
    const a = std.testing.allocator;
    var sources: [129]Scope.Source = undefined;
    for (&sources, 0..) |*source, i| source.* = .{ .local_identity = @splat(1), .local_epoch = @splat(2), .endpoint_root = @splat(3), .endpoint_count = 1, .policy = .{ .source_ordinal = @intCast(i), .max_local_clock = 64 } };
    const global = try E.Entry.init(.window_memory_joint, 0, @splat(5), &.{ @splat(6), @splat(7) });
    var scope = try Scope.Owned.init(a, @splat(8), config, &sources, global);
    defer scope.deinit();
    var first = try scope.batch(a, 0, 127);
    defer first.deinit();
    var last = try scope.batch(a, 127, 2);
    defer last.deinit();
    try std.testing.expectEqual(@as(usize, 127), first.sources.len);
    try std.testing.expectEqual(@as(usize, 2), last.sources.len);
    try std.testing.expectEqualDeep(scope.epoch, first.epoch);
    try std.testing.expectEqualDeep(scope.epoch, last.epoch);
    try std.testing.expectEqualDeep(scope.entries, last.entries);
    try std.testing.expectEqual(@as(u32, 127), last.sources[0].policy.source_ordinal);
    try std.testing.expectEqual(@as(u32, 129), last.roster_count);
    try std.testing.expectError(error.InvalidEndpointBridgeBatch, last.batch(a, 0, 1));
    try std.testing.expectError(error.InvalidEndpointBridgeBatch, scope.batch(a, 128, 2));
}
