//! Source-only geometry cost: no guest execution or DAG/math witness replay.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const W = @import("worker.zig");
const Full = @import("statement.zig");
const View = @import("leaf_test.zig").View;
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const G = @import("../pure_p2_gkr_template.zig");
const Skeleton = @import("../pure_p2_trace_skeleton.zig");
fn source(a: std.mem.Allocator, key: *const W.Key, span: W.Span) !V.common.PoseidonContext {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const expected = try key.expected(span, 0);
    const shape = try Full.geometry(scratch, key, span);
    const values = try Skeleton.init(scratch, &shape);
    const instances = try (try key.geometry(span)).instances();
    const lengths = try scratch.alloc(u8, try G.countFor(&instances));
    @memset(lengths, 4); // Explicit candidate worker policy, before transcript mix.
    var proof = try G.skeletonFor(scratch, &instances, lengths);
    const zero_root = @import("../pure_p2_native.zig").hashWords(&.{});
    const view = View{ .key = key, .span = span, .expected = expected, .manifest = zero_root, .main = zero_root, .receipt = zero_root, .claims = .{ V.common.O.zero(), V.common.O.zero() }, .local = &proof, .shape = &shape, .values = &values };
    var scope = @import("../native_omul/scope.zig").begin();
    defer scope.deinit();
    return view.build(a, true);
}
test "Miller local GKR source class1023 cost without math replay" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 8 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var key = try W.Key.init(a, .op_target_b4_q72_p0_fold4_v1, 15, 15);
    defer key.deinit();
    var one = try source(a, &key, .{ .calls = 1023, .first_id = 1 });
    defer one.deinit();
    const raw = try one.rawCounts();
    const rows = try one.census(false);
    const mul_rows = try std.math.ceilPowerOfTwo(usize, @max(16, one.native_mul_calls.items.len));
    const NativeRow = @import("../native_omul/row.zig");
    const total = rows.total_trace_cells + mul_rows * (NativeRow.FIXED + NativeRow.MAIN + NativeRow.INTER);
    std.debug.print("OP_MILLER_GKR_SOURCE_CLASS calls=1023 frontier_log=15 arithmetic_log=15 raw={any} native_om={d} six_component_cells={d} source_only=true execution=false math_replay=false\n", .{ raw, one.native_mul_calls.items.len, total });
    // Request identity must not specialize immutable topology inside a class.
    var two = try source(a, &key, .{ .calls = 1022, .first_id = 17 });
    defer two.deinit();
    try std.testing.expectEqualSlices(usize, &raw, &(try two.rawCounts()));
    try std.testing.expectEqual(one.native_mul_calls.items.len, two.native_mul_calls.items.len);
    const source_fixed = one.base.circuit;
    const other_fixed = two.base.circuit;
    try std.testing.expectEqualDeep(source_fixed.eq.items, other_fixed.eq.items);
    try std.testing.expectEqualDeep(source_fixed.add.items, other_fixed.add.items);
    try std.testing.expectEqualDeep(source_fixed.sub.items, other_fixed.sub.items);
    try std.testing.expectEqualDeep(source_fixed.mul.items, other_fixed.mul.items);
    try std.testing.expectEqualDeep(source_fixed.pointwise_mul.items, other_fixed.pointwise_mul.items);
    try std.testing.expectEqualDeep(source_fixed.m31_to_u32.items, other_fixed.m31_to_u32.items);
    try std.testing.expectEqualDeep(source_fixed.output.items, other_fixed.output.items);
    try std.testing.expectEqual(source_fixed.n_vars, other_fixed.n_vars);
    try std.testing.expectEqualDeep(one.native_mul_calls.items, two.native_mul_calls.items);
    try std.testing.expectEqualDeep(one.calls.items, two.calls.items);
    try std.testing.expectEqualSlices(u32, one.usage.?.counts, two.usage.?.counts);
    var old_arena = std.heap.ArenaAllocator.init(a);
    defer old_arena.deinit();
    const old_a = old_arena.allocator();
    const old_shape = try @import("../pure_p2_tower_statement.zig").geometry(old_a, &key.base);
    const old_values = try Skeleton.init(old_a, &old_shape);
    const span = W.Span{ .calls = 1023, .first_id = 1 };
    const root = @import("../pure_p2_native.zig").hashWords(&.{});
    const old_view = @import("../pure_p2_tower_leaf_test.zig").View{ .key = &key.base, .span = span, .expected = try key.base.expected(span, 0), .manifest = root, .main = root, .claims = @splat(V.common.O.zero()), .shape = &old_shape, .values = &old_values };
    var old_scope = @import("../native_omul/scope.zig").begin();
    defer old_scope.deinit();
    var old = try old_view.build(a, true);
    defer old.deinit();
    const old_census = try old.census(false);
    const old_mul_rows = try std.math.ceilPowerOfTwo(usize, @max(16, old.native_mul_calls.items.len));
    const old_cells = old_census.total_trace_cells + old_mul_rows * (NativeRow.FIXED + NativeRow.MAIN + NativeRow.INTER);
    try std.testing.expect(total < old_cells);
    std.debug.print("OP_MILLER_GKR_SOURCE_COMPARE classic_raw={any} classic_native_om={d} classic_six_cells={d} candidate_six_cells={d} source_only=true proving_speedup_claim=false\n", .{ try old.rawCounts(), old.native_mul_calls.items.len, old_cells, total });
}
