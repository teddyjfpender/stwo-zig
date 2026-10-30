const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Reuse = @import("../block_v7_union_fixed_reuse_v1.zig");
const S = core.proof_suites.Blake3;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;

test "v7 fixed reuse owns descriptors and leases distinct source budgets" {
    try scenario(std.testing.allocator);
}
test "v7 fixed reuse allocation failures release every acquired lease" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, scenario, .{});
}
fn scenario(a: std.mem.Allocator) !void {
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(a, 8 << 20);
    var budget_live = true;
    defer if (budget_live) budget.destroy();
    const b = budget.allocator();
    var first = try Scheme.init(a, config);
    var first_live = true;
    defer if (first_live) first.deinit(a);
    var second = try Scheme.init(b, config);
    var second_live = true;
    defer if (second_live) second.deinit(b);
    var merged = try Scheme.init(a, config);
    defer merged.deinit(a);
    var control = try Scheme.init(a, config);
    defer control.deinit(a);
    var values0: [8]M = undefined;
    var values1: [16]M = undefined;
    for (&values0, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * i + 9));
    for (&values1, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 7 + 2));
    const columns = [_]Column{ .{ .log_size = 3, .values = &values0 }, .{ .log_size = 4, .values = &values1 } };
    var ignored = S.Channel{};
    try first.commitBorrowedStreaming(a, columns[0..1], 8, &ignored);
    try second.commitBorrowedStreaming(b, columns[1..2], 8, &ignored);
    try control.commitBorrowedStreaming(a, &columns, 8, &ignored);
    const sources = [_]Reuse.Source{
        .{ .allocator = a, .scheme = &first, .expected_root = first.trees.items[0].root(), .raw_logs = &.{3} },
        .{ .allocator = b, .scheme = &second, .expected_root = second.trees.items[0].root(), .raw_logs = &.{4} },
    };
    var bad = sources;
    bad[0].expected_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedUnionFixedReuseRoot, Reuse.tryAppend(std.testing.failing_allocator, &merged, &bad, &ignored));
    bad = sources;
    bad[1].raw_logs = &.{3};
    try std.testing.expectError(error.UntrustedUnionFixedReuseGeometry, Reuse.tryAppend(std.testing.failing_allocator, &merged, &bad, &ignored));
    var wrong = config;
    wrong.pow_bits = 1;
    merged.config = wrong;
    try std.testing.expectError(error.UntrustedUnionFixedReuseConfig, Reuse.tryAppend(std.testing.failing_allocator, &merged, &sources, &ignored));
    merged.config = config;
    const saved_coefficients = second.trees.items[0].coefficients;
    second.trees.items[0].coefficients = null;
    try std.testing.expect(!try Reuse.tryAppend(std.testing.failing_allocator, &merged, &sources, &ignored));
    second.trees.items[0].coefficients = saved_coefficients;
    const saved_column = second.trees.items[0].columns[0];
    second.trees.items[0].columns[0].values = &.{};
    second.trees.items[0].columns[0].coefficient_values = saved_coefficients.?[0].coefficients();
    try std.testing.expect(!try Reuse.tryAppend(std.testing.failing_allocator, &merged, &sources, &ignored));
    second.trees.items[0].columns[0] = saved_column;
    merged.compact_polynomial_storage = true;
    try std.testing.expect(!try Reuse.tryAppend(std.testing.failing_allocator, &merged, &sources, &ignored));
    merged.compact_polynomial_storage = false;
    try std.testing.expect(try Reuse.tryAppend(a, &merged, &sources, &ignored));
    try std.testing.expectEqualDeep(control.trees.items[0].root(), merged.trees.items[0].root());
    // Release both producers and the explicit child-budget root before reads.
    first.deinit(a);
    first_live = false;
    second.deinit(b);
    second_live = false;
    budget.destroy();
    budget_live = false;
    const retained = merged.trees.items[0];
    try std.testing.expect(retained.borrowed_column_values);
    for (retained.columns, control.trees.items[0].columns) |actual, expected| try std.testing.expectEqualSlices(M, expected.values, actual.values);
    for (retained.coefficients.?, control.trees.items[0].coefficients.?) |actual, expected| {
        try std.testing.expect(!actual.owns_coeffs);
        try std.testing.expectEqualSlices(M, expected.coefficients(), actual.coefficients());
    }
    const refs = [_][]const M{ retained.columns[0].values, retained.columns[1].values };
    var opening = try retained.commitment.decommit(a, &.{ 0, 3, 9 }, &refs);
    defer opening.deinit(a);
}

test "v7 fixed reuse preserves ordered multi-source rosters and rejects reshaped columns" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var values: [16]M = undefined;
    for (&values, 0..) |*v, i| v.* = M.fromU64(i * i + 31);
    var first = try Scheme.init(a, config);
    defer first.deinit(a);
    var second = try Scheme.init(a, config);
    defer second.deinit(a);
    var ignored = S.Channel{};
    const source_columns = [_]Column{ .{ .log_size = 3, .values = values[0..8] }, .{ .log_size = 4, .values = &values } };
    try first.commitBorrowedStreaming(a, source_columns[0..1], 8, &ignored);
    try second.commitBorrowedStreaming(a, source_columns[1..2], 8, &ignored);
    // Variable source count is the multi-window path: no five-source tuple or
    // padded absent provider is allowed to change fixed-column placement.
    for ([_]usize{ 1, 4, 11 }) |count| {
        const sources = try a.alloc(Reuse.Source, count);
        defer a.free(sources);
        const columns = try a.alloc(Column, count);
        defer a.free(columns);
        for (sources, columns, 0..) |*source, *column, i| {
            const use_first = i % 2 == 0;
            const scheme = if (use_first) &first else &second;
            source.* = .{ .allocator = a, .scheme = scheme, .expected_root = scheme.trees.items[0].root(), .raw_logs = if (use_first) &.{3} else &.{4} };
            column.* = source_columns[i % 2];
        }
        var merged = try Scheme.init(a, config);
        defer merged.deinit(a);
        var control = try Scheme.init(a, config);
        defer control.deinit(a);
        try control.commitBorrowedStreaming(a, columns, 8, &ignored);
        try std.testing.expect(try Reuse.tryAppend(a, &merged, sources, &ignored));
        try std.testing.expectEqualDeep(control.trees.items[0].root(), merged.trees.items[0].root());
        for (merged.trees.items[0].columns, control.trees.items[0].columns) |actual, expected| {
            try std.testing.expectEqualSlices(M, expected.values, actual.values);
        }
        // Every source must keep the exact independently admitted column log.
        var empty = try Scheme.init(a, config);
        defer empty.deinit(a);
        sources[0].raw_logs = &.{ 3, 3 };
        try std.testing.expectError(error.UntrustedUnionFixedReuseGeometry, Reuse.tryAppend(std.testing.failing_allocator, &empty, sources, &ignored));
    }
}
