//! Conservative materialized first-round PCS residency, independently derived
//! from raw column logs. This is not a full proof peak or a measured allocation.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Storage = @import("block_v7_input_storage_v1.zig");

/// Producer-only physical storage selection. Never serialized into a proof,
/// epoch, key or verifier admission. Original merged fixed storage stays resident.
pub const ProducerStorage = struct {
    memory_inputs: Storage.Policy = .resident,
    memory_interaction: Storage.Policy = .resident,
    pub fn validate(self: ProducerStorage) !void {
        try self.memory_inputs.validate();
        try self.memory_interaction.validate();
    }
};
pub const Estimate = struct {
    columns: u64 = 0,
    lde_bytes: u64 = 0,
    coefficient_bytes: u64 = 0,
    merkle_bytes: u64 = 0,
    descriptor_bytes: u64 = 0,
    total_bytes: u64 = 0,
    pub fn addTree(self: *Estimate, raw_logs: []const u32, blowup: u32) !void {
        return self.addTreeWithStorage(raw_logs, blowup, .resident);
    }
    /// Retained PCS only: transient commit LDEs, source rows, quotient and FRI
    /// are excluded and must remain charged to the outer hard allocator cap.
    pub fn addTreeWithStorage(self: *Estimate, raw_logs: []const u32, blowup: u32, storage: Storage.Policy) !void {
        try storage.validate();
        if (blowup > 8 or raw_logs.len > 1 << 20) return error.InvalidMultiUnionResidency;
        var maximum: u32 = 0;
        for (raw_logs) |raw| {
            const extended = try std.math.add(u32, raw, blowup);
            if (extended > 30) return error.InvalidMultiUnionResidency;
            maximum = @max(maximum, extended);
            if (!try storage.selected(raw)) self.lde_bytes = try std.math.add(u64, self.lde_bytes, try std.math.mul(u64, @as(u64, 1) << @intCast(extended), 4));
            self.coefficient_bytes = try std.math.add(u64, self.coefficient_bytes, try std.math.mul(u64, @as(u64, 1) << @intCast(raw), 4));
        }
        self.columns = try std.math.add(u64, self.columns, raw_logs.len);
        const hashes = (@as(u64, 1) << @intCast(maximum + 1)) - 1;
        self.merkle_bytes = try std.math.add(u64, self.merkle_bytes, try std.math.mul(u64, hashes, 32));
        const per_column = @sizeOf(Engine.pcs.ColumnEvaluation) + @sizeOf(Engine.poly.circle.CircleCoefficients);
        const descriptors = try std.math.add(u64, try std.math.mul(u64, raw_logs.len, per_column), try std.math.mul(u64, maximum + 1, @sizeOf([][32]u8)));
        self.descriptor_bytes = try std.math.add(u64, self.descriptor_bytes, descriptors);
        self.total_bytes = try std.math.add(u64, try std.math.add(u64, self.lde_bytes, self.coefficient_bytes), try std.math.add(u64, self.merkle_bytes, self.descriptor_bytes));
    }
    pub fn require(self: Estimate, limit: usize) !void {
        if (limit == 0) return error.InvalidMultiUnionRetainedLimit;
        if (self.total_bytes > limit) return error.MultiUnionRetainedPCSExceedsBudget;
    }
};

/// Physical resource admission, not polynomial authentication. The eventual
/// original STARK authenticates coefficients/roots. This check prevents a
/// declared compact policy from discounting a still-resident LDE allocation.
pub fn requireTreeStorage(raw_logs: []const u32, blowup: u32, storage: Storage.Policy, tree: anytype) !void {
    try storage.validate();
    if (tree.columns.len != raw_logs.len) return error.UntrustedMultiUnionPhysicalStorage;
    const coefficients = tree.coefficients orelse return error.UntrustedMultiUnionPhysicalStorage;
    if (coefficients.len != raw_logs.len) return error.UntrustedMultiUnionPhysicalStorage;
    for (tree.columns, coefficients, raw_logs) |column, coefficient, raw| {
        const extended = try std.math.add(u32, raw, blowup);
        if (extended > 30 or column.log_size != extended or coefficient.logSize() != raw) return error.UntrustedMultiUnionPhysicalStorage;
        column.validateRetained() catch return error.UntrustedMultiUnionPhysicalStorage;
        if (try storage.selected(raw)) {
            const values = column.coefficient_values orelse return error.UntrustedMultiUnionPhysicalStorage;
            const owned = coefficient.coefficients();
            if (!tree.compact_polynomials or column.values.len != 0 or values.len != owned.len or values.ptr != owned.ptr) return error.UntrustedMultiUnionPhysicalStorage;
        } else if (column.values.len != @as(usize, 1) << @intCast(extended)) return error.UntrustedMultiUnionPhysicalStorage;
    }
}

test "producer residency omits only selected LDEs and keeps coefficients and Merkle" {
    var resident: Estimate = .{};
    try resident.addTree(&.{ 2, 3, 22 }, 1);
    var compact: Estimate = .{};
    try compact.addTreeWithStorage(&.{ 2, 3, 22 }, 1, .{ .coefficients = .{ .minimum_trace_log = 3 } });
    try std.testing.expectEqual(@as(u64, 8 * 4), compact.lde_bytes);
    try std.testing.expectEqual(resident.coefficient_bytes, compact.coefficient_bytes);
    try std.testing.expectEqual(resident.merkle_bytes, compact.merkle_bytes);
    try std.testing.expectEqual(resident.descriptor_bytes, compact.descriptor_bytes);
    try std.testing.expectEqual(@as(u64, (16 + (1 << 23)) * 4), resident.total_bytes - compact.total_bytes);
    try compact.require(@intCast(compact.total_bytes));
    try std.testing.expectError(error.MultiUnionRetainedPCSExceedsBudget, resident.require(@intCast(compact.total_bytes)));
    try std.testing.expectError(error.InvalidV7InputStorage, compact.addTreeWithStorage(&.{22}, 1, .{ .coefficients = .{ .minimum_trace_log = 0 } }));
    try std.testing.expectError(error.InvalidMultiUnionResidency, compact.addTreeWithStorage(&.{30}, 1, .{ .coefficients = .{} }));
}

test "producer physical storage cannot discount resident columns or duplicate coefficient ownership" {
    const M = @import("stwo_core").fields.m31.M31;
    const Coeff = Engine.poly.circle.CircleCoefficients;
    var values: [8]M = @splat(M.zero());
    var coefficients: [4]M = @splat(M.zero());
    var other: [4]M = @splat(M.zero());
    var columns = [_]Engine.pcs.ColumnEvaluation{.{ .log_size = 3, .values = &values }};
    var owned = [_]Coeff{try Coeff.initOwned(&coefficients)};
    const Tree = struct { columns: []Engine.pcs.ColumnEvaluation, coefficients: ?[]Coeff, compact_polynomials: bool };
    var tree = Tree{ .columns = &columns, .coefficients = &owned, .compact_polynomials = false };
    const selected: Storage.Policy = .{ .coefficients = .{ .minimum_trace_log = 2 } };
    try requireTreeStorage(&.{2}, 1, .resident, tree);
    try std.testing.expectError(error.UntrustedMultiUnionPhysicalStorage, requireTreeStorage(&.{2}, 1, selected, tree));
    columns[0].values = &.{};
    columns[0].coefficient_values = &coefficients;
    tree.compact_polynomials = true;
    try requireTreeStorage(&.{2}, 1, selected, tree);
    try std.testing.expectError(error.UntrustedMultiUnionPhysicalStorage, requireTreeStorage(&.{2}, 1, .resident, tree));
    columns[0].coefficient_values = &other;
    try std.testing.expectError(error.UntrustedMultiUnionPhysicalStorage, requireTreeStorage(&.{2}, 1, selected, tree));
    columns[0].coefficient_values = &coefficients;
    try std.testing.expectError(error.UntrustedMultiUnionPhysicalStorage, requireTreeStorage(&.{1}, 1, selected, tree));
    tree.coefficients = null;
    try std.testing.expectError(error.UntrustedMultiUnionPhysicalStorage, requireTreeStorage(&.{2}, 1, selected, tree));
}
