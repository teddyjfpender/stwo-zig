//! Original fixed-column oracles only. No proof/capture/success token exists.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Ports = @import("../recursion/air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig");
const Rows = @import("../recursion/air/block_v5_recursive_fixed_port_rows_v1.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Projection = @import("../recursion/air/blake3_projection_links.zig");
const Links = @import("../recursion/air/blake3_query_links.zig");
const Arena = @import("../recursion/air/stable_graph_arena_v1.zig");
const Assembly = @import("../recursion/block_v5_recursive_parent_fixed_assembly_v1.zig");
const Fusion = @import("../recursion/air/arithmetic_fusion_rows.zig");
const Graph = @import("../recursion/air/composition_circuit.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
fn queryFixture() [5]Links.Query {
    var queries: [5]Links.Query = undefined;
    for (&queries, 0..) |*query, i| {
        query.* = .{ .source = .{ .circuit = 1, .wire = @intCast(i) } };
        for (&query.bits, 0..) |*bit, j| {
            bit.deep = @intCast(i * 31 + j);
            bit.fri = @intCast(i * 31 + j);
        }
    }
    return queries;
}
fn projectionAllocation(a: std.mem.Allocator) !void {
    var arena = try Arena.Owned.init(a);
    defer arena.deinit();
    const queries = queryFixture();
    const fixed = try Ports.ProjectionFixed.init(&arena, 6, &.{ 1, 4, 4, 6 }, &queries);
    try fixed.rows.finish();
}
test "recursive fixed roster: original full projection fixed-column parity and endpoints" {
    var arena = try Arena.Owned.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const queries = queryFixture();
    for ([_]u32{ 6, 31 }, [_][]const u32{ &.{ 1, 4, 4, 6 }, &.{ 1, 16, 31, 31 } }) |lifting, logs| {
        const limit = (@as(usize, 1) << @intCast(lifting)) - 1;
        const raw = [_]usize{ 0, 1, 2, limit - 1, limit };
        const original = try Projection.build(a, lifting, logs, &raw, &queries);
        const fixed = try Ports.ProjectionFixed.init(&arena, lifting, logs, &queries);
        try std.testing.expectEqualDeep(original.ports, fixed.ports);
        try std.testing.expectEqualSlices([31]u32, original.bit_reads, fixed.bit_reads);
        inline for (.{ 11, 7 }, .{ original.fixed_packed, original.fixed_routed }) |slot, rows| {
            const tails = try fixed.rows.metadata(slot);
            try std.testing.expectEqual(rows.len, tails.len);
            for (rows, tails) |row, tail| try std.testing.expectEqualDeep(Storage.compactFixed(Storage.Airs[slot], row), tail);
            // Exact original projection and scatter, including all padding.
            var expected: std.ArrayList(@import("stwo_prover_engine").pcs.ColumnEvaluation) = .empty;
            var actual: std.ArrayList(@import("stwo_prover_engine").pcs.ColumnEvaluation) = .empty;
            const log = try @import("../recursion/air/blake3_direct_cohort_columns_v1.zig").rowLog(rows.len);
            try @import("../recursion/air/blake3_row_columns.zig").project(Storage.Airs[slot], a, rows, log, 0, &expected);
            try fixed.rows.project(slot, a, &actual);
            try std.testing.expectEqual(expected.items.len, actual.items.len);
            for (expected.items, actual.items) |left, right| {
                try std.testing.expectEqual(left.log_size, right.log_size);
                try std.testing.expectEqualSlices(M, left.values, right.values);
            }
        }
    }
    try std.testing.expectError(error.InvalidProjectionLink, Ports.ProjectionFixed.init(&arena, 6, &.{7}, &queries));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, projectionAllocation, .{});
}
const nodes = [_]Graph.Node{
    .{ .op = .input }, .{ .op = .input }, .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } }, .{ .op = .{ .neg = 2 } }, .{ .op = .{ .add = .{ .lhs = 2, .rhs = 3 } } },
};
const values = [_]Q{ Q.fromBase(M.fromCanonical(3)), Q.fromBase(M.fromCanonical(7)), Q.fromBase(M.fromCanonical(21)), Q.fromBase(M.fromCanonical(21)).neg(), Q.zero() };
fn arithmeticAllocation(a: std.mem.Allocator, g: Graph.CircuitGraph) !void {
    var fixed = try Assembly.Arithmetic.init(a, .{ g, g, g });
    defer fixed.deinit();
    try fixed.validate();
}
test "recursive fixed roster: original fused arithmetic complete fixed tails and cleanup" {
    const a = std.testing.allocator;
    // Independently sealed mathematical IR fixture, not verifier admission.
    const g = try Graph.CircuitGraph.authenticate(&nodes, &.{4}, Graph.computeGraphDigest(&nodes, &.{4}));
    var fixed = try Assembly.Arithmetic.init(a, .{ g, g, g });
    defer fixed.deinit();
    var evaluations: [6]@import("../recursion/air/verifier_arithmetic_lowering.zig").Evaluation = undefined;
    for (&evaluations) |*evaluation| evaluation.* = .{ .circuit_identity = g.identity_digest, .values = &values };
    var original = try Fusion.materialize(a, &fixed.plan, fixed.reference, .{ .lanes = &evaluations }, .segment_leaf);
    defer original.deinit();
    inline for (.{ 18, 3, 4, 5 }, .{ original.opening, original.multiply, original.inverse, original.linear }, 0..) |slot, rows, i| {
        try std.testing.expectEqual(rows.len, fixed.fused.fixed[i].len);
        for (rows, fixed.fused.fixed[i]) |row, tail| try std.testing.expectEqualDeep(Storage.compactFixed(Storage.Airs[slot], row), tail);
    }
    try std.testing.expectEqual(original.dot4_matches, fixed.fused.dot4_matches);
    try std.testing.expectEqual(original.fma_matches, fixed.fused.fma_matches);
    try std.testing.checkAllAllocationFailures(a, arithmeticAllocation, .{g});
}
fn rowsAllocation(a: std.mem.Allocator) !void {
    var rows = try Rows.ForSlots(.{12}).init(a, .{1});
    defer rows.deinit();
    try std.testing.expectError(error.RecursiveFixedPortCountMismatch, rows.finish());
    try rows.appendLogicalFixed(12, try @import("../recursion/air/scalar_wire_source.zig").logicalRow(1502, 7, 3, M.zero()));
    try rows.finish();
    try std.testing.expectError(error.RecursiveFixedPortCountMismatch, rows.append(12, @splat(M.zero())));
}
test "recursive fixed roster: count admission rollback and original allocator release" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, rowsAllocation, .{});
    const budget = try Budget.create(std.testing.allocator, 1 << 20);
    var rows = try Rows.ForSlots(.{12}).init(budget.allocator(), .{1});
    budget.destroy();
    // Owner lease keeps heap accounting and allocator alive through final free.
    try rows.appendLogicalFixed(12, try @import("../recursion/air/scalar_wire_source.zig").logicalRow(1502, 1, 2, M.zero()));
    try rows.finish();
    rows.deinit();
    try std.testing.expectError(error.InvalidTraceShape, Rows.ForSlots(.{12}).init(std.testing.allocator, .{(1 << 24) + 1}));
}
test "recursive fixed roster: G partition exact original geometry at physical boundaries" {
    const P = @import("../recursion/air/blake3_g_partition.zig");
    for ([_]usize{ 0, 1, 1 << 20, (1 << 20) + 1, (1 << 22) + 3, 1 << 24 }) |count| {
        const shape = try P.geometry(count);
        var total: usize = 0;
        for (shape.counts, shape.logs) |active, log| {
            total += active;
            try std.testing.expect(active <= @as(usize, 1) << @intCast(log));
        }
        try std.testing.expectEqual(count, total);
        if (count <= 1 << 20) try std.testing.expectEqual(@as(usize, 0), shape.counts[1]);
    }
}

test "recursive fixed roster: stable arithmetic plan outlives original budget owner" {
    const g = try Graph.CircuitGraph.authenticate(&nodes, &.{4}, Graph.computeGraphDigest(&nodes, &.{4}));
    const budget = try Budget.create(std.testing.allocator, 8 << 20);
    var fixed = Assembly.Arithmetic.init(budget.allocator(), .{ g, g, g }) catch |failure| {
        budget.destroy();
        return failure;
    };
    budget.destroy();
    defer fixed.deinit();
    try fixed.validate();
}
