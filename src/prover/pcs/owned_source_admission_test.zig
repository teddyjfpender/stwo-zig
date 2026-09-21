//! Allocation-failure coverage for the complete owned source -> PCS tree move.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const Column = @import("commitment_tree.zig").ColumnEvaluation;
const Retention = @import("columns/storage.zig").CoefficientRetentionPolicy;
const poly = @import("../poly/circle/poly.zig");
const work = @import("stwo_prover_api").work_profile;
const blake = core.vcs_lifted.blake2_merkle;
const Channel = core.channel.blake2s.Blake2sChannel;

// The ownership policy matches an adopting device backend. Arithmetic and
// Merkle hashing remain the actual scalar production implementations.
pub const Backend = struct {
    pub const adopts_source_trace_arena = true;
    pub const combined_base_in_place = false;
    pub const combined_commit_min_columns = 0;
    pub const resident_column_arena_alignment = std.mem.Alignment.fromByteUnits(64);

    pub fn MerkleTree(comptime H: type) type {
        return @import("../vcs_lifted/prover.zig").MerkleProverLifted(H);
    }
    pub fn commitMerkle(comptime H: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(H) {
        return MerkleTree(H).commit(allocator, columns);
    }
    pub fn interpolateAndEvaluateCircleBuffers(
        allocator: std.mem.Allocator,
        source_values: []const []const M31,
        base_values: []const []M31,
        extended_values: []const []M31,
        transform_buffer: []M31,
        extended_start: usize,
        extended_stride: usize,
        base_domain: anytype,
        base_twiddles: anytype,
        extended_domain: anytype,
        extended_twiddles: anytype,
    ) !work.M31CircleLdeExecution {
        _ = allocator;
        _ = transform_buffer;
        _ = extended_start;
        _ = extended_stride;
        for (source_values, base_values, extended_values) |source, base, extended| {
            if (source.ptr != base.ptr) @memcpy(base, source);
            var base_batch = [_][]M31{base};
            try poly.interpolateBuffersWithTwiddles(&base_batch, base_domain, base_twiddles);
            @memcpy(extended[0..base.len], base);
            @memset(extended[base.len..], M31.zero());
            var extended_batch = [_][]M31{extended};
            try poly.evaluateBuffersWithTwiddles(&extended_batch, extended_domain, extended_twiddles);
        }
        return .{
            .interpolation = .{ .log_size = base_domain.logSize(), .column_count = @intCast(source_values.len), .batch_count = @intCast(source_values.len) },
            .forward = .{ .log_size = extended_domain.logSize(), .column_count = @intCast(source_values.len), .skipped_layers = 0 },
        };
    }
};
const Scheme = @import("scheme.zig").CommitmentSchemeProver(Backend, blake.Blake2sMerkleHasher, blake.Blake2sMerkleChannel);
const logs = [_]u32{ 3, 4, 3, 5, 4, 3 };
const config: core.pcs.PcsConfig = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };

fn ownedColumns(allocator: std.mem.Allocator) ![]Column {
    const result = try allocator.alloc(Column, logs.len);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column.values);
        allocator.free(result);
    }
    for (logs, result, 0..) |log, *column, index| {
        const values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log));
        column.* = .{ .log_size = log, .values = values };
        initialized += 1;
        for (values, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(1 + index * 73 + row * row));
    }
    return result;
}

fn commitFixture(allocator: std.mem.Allocator, use_packing: bool, retention: Retention) !Scheme {
    var scheme = try Scheme.init(allocator, config);
    errdefer scheme.deinit(allocator);
    try std.testing.expect(!scheme.pack_owned_source_by_log);
    scheme.pack_owned_source_by_log = use_packing;
    scheme.coefficient_retention_policy = retention;
    var channel = Channel{};
    // The normal first nonconstant commit may spawn a deferred worker. A
    // tiny real constant first tree keeps this ownership/OOM fixture entirely
    // synchronous without changing production policy or fabricating a tree.
    const first = try allocator.alloc(Column, 1);
    const constant = allocator.alloc(M31, 8) catch |err| {
        allocator.free(first);
        return err;
    };
    @memset(constant, M31.one());
    first[0] = .{ .log_size = 3, .values = constant };
    try scheme.commitOwned(allocator, first, &channel);
    try std.testing.expectEqual(@as(usize, 1), scheme.trees.items.len);
    // Force the target tree's final ownership handoff to allocate too, so
    // allocation injection covers append failure after successful preparation.
    const exact_trees = try allocator.dupe(@TypeOf(scheme.trees.items[0]), scheme.trees.items);
    scheme.trees.deinit(allocator);
    scheme.trees = @TypeOf(scheme.trees).fromOwnedSlice(exact_trees);
    const columns = try ownedColumns(allocator);
    // commitOwned consumes the input even if preparation, Merkle allocation,
    // or final tree-list append fails. Caller cleanup would be a double free.
    try scheme.commitOwned(allocator, columns, &channel);
    try std.testing.expectEqual(@as(usize, 2), scheme.trees.items.len);
    try std.testing.expect(scheme.pending_commit == null);
    return scheme;
}

fn allocationCase(allocator: std.mem.Allocator, use_packing: bool, retention: Retention) !void {
    var scheme = try commitFixture(allocator, use_packing, retention);
    defer scheme.deinit(allocator);
    try std.testing.expectEqual(retention == .always, scheme.trees.items[1].coefficients != null);
}

test "PCS owned source admission releases every partial ownership stage on allocation failure" {
    for ([_]Retention{ .always, .never }) |retention| {
        try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{ false, retention });
        try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{ true, retention });
    }
}

test "PCS owned source admission preserves real FFT Merkle roots and adopts aligned coefficients" {
    const allocator = std.testing.allocator;
    var original = try commitFixture(allocator, false, .always);
    defer original.deinit(allocator);
    var packed_scheme = try commitFixture(allocator, true, .always);
    defer packed_scheme.deinit(allocator);
    const before = &original.trees.items[1];
    const after = &packed_scheme.trees.items[1];
    try std.testing.expectEqualDeep(before.root(), after.root());
    const backing = after.coefficient_backing_buffers.?;
    try std.testing.expectEqual(@as(usize, 1), backing.len);
    const start = @intFromPtr(backing[0].ptr);
    const end = start + backing[0].len * @sizeOf(M31);
    var seen = [_]bool{false} ** @bitSizeOf(usize);
    for (before.columns, after.columns, before.coefficients.?, after.coefficients.?, logs) |left, right, left_coeff, right_coeff, log| {
        try std.testing.expectEqual(left.log_size, right.log_size);
        try std.testing.expectEqualSlices(M31, left.values, right.values);
        try std.testing.expectEqualSlices(M31, left_coeff.coefficients(), right_coeff.coefficients());
        const address = @intFromPtr(right_coeff.coefficients().ptr);
        try std.testing.expect(address >= start and address + right_coeff.coefficients().len * @sizeOf(M31) <= end);
        if (!seen[log]) {
            try std.testing.expectEqual(@as(usize, 0), address % 64);
            seen[log] = true;
        }
    }
}

test "PCS owned source admission never retention preserves LDE roots without coefficients" {
    const allocator = std.testing.allocator;
    var original = try commitFixture(allocator, false, .never);
    defer original.deinit(allocator);
    var packed_scheme = try commitFixture(allocator, true, .never);
    defer packed_scheme.deinit(allocator);
    const before = &original.trees.items[1];
    const after = &packed_scheme.trees.items[1];
    try std.testing.expectEqualDeep(before.root(), after.root());
    try std.testing.expect(before.coefficients == null and after.coefficients == null);
    try std.testing.expect(before.coefficient_backing_buffers == null and after.coefficient_backing_buffers == null);
    try std.testing.expectEqual(Backend.resident_column_arena_alignment, after.column_backing_alignment);
    for (before.columns, after.columns) |left, right| {
        try std.testing.expectEqual(left.log_size, right.log_size);
        try std.testing.expectEqualSlices(M31, left.values, right.values);
    }
}
