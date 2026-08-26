//! Owned PCS columns and their lifted Merkle commitment.
//!
//! This module owns column and coefficient lifetimes for one commitment tree.
//! Scheme orchestration, FRI integration, and transcript policy live elsewhere.

const std = @import("std");
const backend_merkle = @import("stwo_backend_contracts").merkle_ops;
const work_profile = @import("stwo_prover_api").work_profile;
const m31 = @import("stwo_core").fields.m31;
const prover_circle = @import("../poly/circle/mod.zig");
const vcs_lifted_prover = @import("../vcs_lifted/prover.zig");
const quotient_ops = @import("quotient_ops.zig");

const M31 = m31.M31;
const WorkRecorder = work_profile.Recorder(true);

pub const ColumnEvaluation = quotient_ops.ColumnEvaluation;

/// Optional backend-owned lifetime hook that runs after all host backing
/// allocations for a commitment have actually been returned to the allocator.
/// Treat this value as move-only.
pub const BackingTeardownToken = struct {
    context: ?*anyopaque,
    value: u64,
    release_fn: *const fn (?*anyopaque, u64) void,

    pub fn init(
        context: ?*anyopaque,
        value: u64,
        release_fn: *const fn (?*anyopaque, u64) void,
    ) BackingTeardownToken {
        return .{ .context = context, .value = value, .release_fn = release_fn };
    }

    pub fn deinit(self: *BackingTeardownToken) void {
        const context = self.context;
        const value = self.value;
        const release_fn = self.release_fn;
        self.* = undefined;
        release_fn(context, value);
    }
};

const HostMerkleBackend = struct {
    pub const reuses_constant_merkle_parents = true;

    pub fn MerkleTree(comptime H: type) type {
        return vcs_lifted_prover.MerkleProverLifted(H);
    }

    pub fn commitMerkle(
        comptime H: type,
        allocator: std.mem.Allocator,
        columns: []const []const M31,
    ) !MerkleTree(H) {
        return MerkleTree(H).commit(allocator, columns);
    }
};

pub fn CommitmentTreeProver(comptime H: type) type {
    return CommitmentTreeProverForBackend(HostMerkleBackend, H);
}

pub fn CommitmentTreeProverForBackend(comptime B: type, comptime H: type) type {
    comptime backend_merkle.assertMerkleOps(B, H);
    return struct {
        columns: []ColumnEvaluation,
        coefficients: ?[]prover_circle.CircleCoefficients,
        column_backing_buffers: ?[][]M31 = null,
        coefficient_backing_buffers: ?[][]M31 = null,
        backing_teardown: ?BackingTeardownToken = null,
        commitment: B.MerkleTree(H),

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            columns: []const ColumnEvaluation,
        ) !Self {
            const owned_columns = try cloneColumnsOwned(allocator, columns);
            errdefer freeOwnedColumns(allocator, owned_columns);
            return initOwnedWithCoefficients(allocator, owned_columns, null);
        }

        pub fn initOwned(
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
        ) !Self {
            return initOwnedWithCoefficients(allocator, owned_columns, null);
        }

        pub fn initOwnedWithCoefficients(
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            owned_coefficients: ?[]prover_circle.CircleCoefficients,
        ) !Self {
            return initOwnedWithBacking(
                allocator,
                owned_columns,
                owned_coefficients,
                null,
                null,
            );
        }

        pub fn initOwnedWithBacking(
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            owned_coefficients: ?[]prover_circle.CircleCoefficients,
            column_backing_buffers: ?[][]M31,
            coefficient_backing_buffers: ?[][]M31,
        ) !Self {
            return initOwnedWithBackingAndWorkRecorder(
                allocator,
                owned_columns,
                owned_coefficients,
                column_backing_buffers,
                coefficient_backing_buffers,
                null,
            );
        }

        pub fn initOwnedWithBackingAndWorkRecorder(
            allocator: std.mem.Allocator,
            owned_columns: []ColumnEvaluation,
            owned_coefficients: ?[]prover_circle.CircleCoefficients,
            column_backing_buffers: ?[][]M31,
            coefficient_backing_buffers: ?[][]M31,
            work_recorder: ?*WorkRecorder,
        ) !Self {
            for (owned_columns) |column| try column.validate();
            if (owned_coefficients) |coeffs| {
                if (coeffs.len != owned_columns.len) return error.ShapeMismatch;
            }

            const column_refs = try allocator.alloc([]const M31, owned_columns.len);
            defer allocator.free(column_refs);
            for (owned_columns, 0..) |column, i| {
                column_refs[i] = column.values;
            }

            var commitment = if (comptime @hasDecl(B, "commitMerkleWithBacking"))
                if (column_backing_buffers) |buffers|
                    try B.commitMerkleWithBacking(H, allocator, column_refs, buffers)
                else
                    try B.commitMerkle(H, allocator, column_refs)
            else
                try B.commitMerkle(H, allocator, column_refs);
            errdefer commitment.deinit(allocator);
            recordMerkleWork(B, work_recorder, column_refs);

            return .{
                .columns = owned_columns,
                .coefficients = owned_coefficients,
                .column_backing_buffers = column_backing_buffers,
                .coefficient_backing_buffers = coefficient_backing_buffers,
                .commitment = commitment,
            };
        }

        /// Adopts a backend commitment that was built in the same execution
        /// epoch as column preparation. All supplied storage becomes owned by
        /// the returned tree exactly as in `initOwnedWithBacking`.
        pub fn initPrecommitted(
            owned_columns: []ColumnEvaluation,
            owned_coefficients: ?[]prover_circle.CircleCoefficients,
            column_backing_buffers: ?[][]M31,
            coefficient_backing_buffers: ?[][]M31,
            commitment: B.MerkleTree(H),
        ) Self {
            return initPrecommittedWithTeardown(
                owned_columns,
                owned_coefficients,
                column_backing_buffers,
                coefficient_backing_buffers,
                commitment,
                null,
            );
        }

        pub fn initPrecommittedWithTeardown(
            owned_columns: []ColumnEvaluation,
            owned_coefficients: ?[]prover_circle.CircleCoefficients,
            column_backing_buffers: ?[][]M31,
            coefficient_backing_buffers: ?[][]M31,
            commitment: B.MerkleTree(H),
            backing_teardown: ?BackingTeardownToken,
        ) Self {
            std.debug.assert(owned_coefficients == null or owned_coefficients.?.len == owned_columns.len);
            return .{
                .columns = owned_columns,
                .coefficients = owned_coefficients,
                .column_backing_buffers = column_backing_buffers,
                .coefficient_backing_buffers = coefficient_backing_buffers,
                .backing_teardown = backing_teardown,
                .commitment = commitment,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            // A backend commitment may retain a no-copy view of the committed
            // column arena. Release that view before returning its host
            // backing to the allocator.
            self.commitment.deinit(allocator);
            if (self.column_backing_buffers) |buffers| {
                allocator.free(self.columns);
                for (buffers) |buffer| allocator.free(buffer);
                allocator.free(buffers);
            } else {
                freeOwnedColumns(allocator, self.columns);
            }
            if (self.coefficients) |coeffs| {
                for (coeffs) |*coeff| coeff.deinit(allocator);
                allocator.free(coeffs);
            }
            if (self.coefficient_backing_buffers) |buffers| {
                for (buffers) |buffer| allocator.free(buffer);
                allocator.free(buffers);
            }
            if (self.backing_teardown) |*token| token.deinit();
            self.* = undefined;
        }

        pub fn root(self: Self) H.Hash {
            return self.commitment.root();
        }

        pub fn columnLogSizes(self: Self, allocator: std.mem.Allocator) ![]u32 {
            const out = try allocator.alloc(u32, self.columns.len);
            for (self.columns, 0..) |column, i| out[i] = column.log_size;
            return out;
        }

        pub fn decommit(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
        ) !vcs_lifted_prover.MerkleProverLifted(H).DecommitmentResult {
            const QueryOrder = struct {
                positions: []const usize,

                fn lessThan(context: @This(), lhs: usize, rhs: usize) bool {
                    const lhs_position = context.positions[lhs];
                    const rhs_position = context.positions[rhs];
                    return lhs_position < rhs_position or
                        (lhs_position == rhs_position and lhs < rhs);
                }
            };
            const order = try allocator.alloc(usize, query_positions.len);
            defer allocator.free(order);
            for (order, 0..) |*index, i| index.* = i;
            std.sort.heap(usize, order, QueryOrder{ .positions = query_positions }, QueryOrder.lessThan);

            const sorted_positions = try allocator.alloc(usize, query_positions.len);
            defer allocator.free(sorted_positions);
            for (order, 0..) |original_index, sorted_index| {
                sorted_positions[sorted_index] = query_positions[original_index];
            }

            const column_refs = try allocator.alloc([]const M31, self.columns.len);
            defer allocator.free(column_refs);
            for (self.columns, 0..) |column, i| {
                column_refs[i] = column.values;
            }
            var result = try self.commitment.decommit(allocator, sorted_positions, column_refs);
            errdefer result.deinit(allocator);

            const reordered = try allocator.alloc([]M31, result.queried_values.len);
            var initialized: usize = 0;
            errdefer {
                for (reordered[0..initialized]) |column| allocator.free(column);
                allocator.free(reordered);
            }
            for (result.queried_values, 0..) |sorted_values, column_index| {
                const values = try allocator.alloc(M31, sorted_values.len);
                for (order, 0..) |original_index, sorted_index| {
                    values[original_index] = sorted_values[sorted_index];
                }
                reordered[column_index] = values;
                initialized += 1;
            }
            for (result.queried_values) |column| allocator.free(column);
            allocator.free(result.queried_values);
            result.queried_values = reordered;
            return result;
        }

        fn cloneColumnsOwned(
            allocator: std.mem.Allocator,
            columns: []const ColumnEvaluation,
        ) ![]ColumnEvaluation {
            const owned = try allocator.alloc(ColumnEvaluation, columns.len);
            errdefer allocator.free(owned);

            var initialized: usize = 0;
            errdefer {
                for (owned[0..initialized]) |column| allocator.free(column.values);
            }

            for (columns, 0..) |column, i| {
                owned[i] = .{
                    .log_size = column.log_size,
                    .values = try allocator.dupe(M31, column.values),
                };
                initialized += 1;
            }

            return owned;
        }

        fn freeOwnedColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
            for (columns) |column| allocator.free(column.values);
            allocator.free(columns);
        }
    };
}

fn recordMerkleWork(
    comptime B: type,
    recorder: ?*WorkRecorder,
    columns: []const []const M31,
) void {
    const active = recorder orelse return;
    if (comptime !@hasDecl(B, "reuses_constant_merkle_parents")) {
        active.markIncomplete();
        return;
    }
    var leaf_count: usize = 1;
    var all_constant = columns.len != 0;
    for (columns) |column| {
        leaf_count = @max(leaf_count, column.len);
        if (column.len == 0) {
            all_constant = false;
            continue;
        }
        const first = column[0];
        for (column[1..]) |value| {
            if (!value.eql(first)) {
                all_constant = false;
                break;
            }
        }
    }
    const encoded_leaf_count = std.math.cast(u64, leaf_count) orelse
        return active.markIncomplete();
    const count = work_profile.logicalMerkleCompressions(
        encoded_leaf_count,
        all_constant and B.reuses_constant_merkle_parents,
    ) catch return active.markIncomplete();
    active.recordCompletedDelta(.{
        .site = .commitment_tree_merkle,
        .producer = .commitment_tree_merkle,
        .source_mask = work_profile.SourceMask.one(.merkle_compressions),
        .counters = .{ .merkle_compressions = count },
    }) catch active.markIncomplete();
    // work-profile-complete:commitment-tree-merkle
}

test "Merkle work records every ordinary internal node at its exact site" {
    const Backend = struct {
        pub const reuses_constant_merkle_parents = false;
    };
    const values = [_]M31{
        M31.fromCanonical(0),
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
    };
    const columns = [_][]const M31{values[0..]};
    var recorder: WorkRecorder = .{};

    recordMerkleWork(Backend, &recorder, columns[0..]);

    try std.testing.expectEqual(@as(u64, 7), recorder.counters.merkle_compressions);
    try std.testing.expectEqual(@as(u64, 1), recorder.record_count);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.commitment_tree_merkle)],
    );
    try std.testing.expect(!recorder.legacy_site_coverage);
    try std.testing.expect(!recorder.incomplete);
}

test "Merkle work counts one reused constant parent per layer" {
    const Backend = struct {
        pub const reuses_constant_merkle_parents = true;
    };
    const values = [_]M31{M31.fromCanonical(11)} ** 8;
    const columns = [_][]const M31{values[0..]};
    var recorder: WorkRecorder = .{};

    recordMerkleWork(Backend, &recorder, columns[0..]);

    try std.testing.expectEqual(@as(u64, 3), recorder.counters.merkle_compressions);
    try std.testing.expectEqual(@as(u64, 1), recorder.record_count);
    try std.testing.expect(!recorder.incomplete);
}

test "Merkle work does not claim constant reuse for an ordinary backend" {
    const Backend = struct {
        pub const reuses_constant_merkle_parents = false;
    };
    const values = [_]M31{M31.fromCanonical(11)} ** 8;
    const columns = [_][]const M31{values[0..]};
    var recorder: WorkRecorder = .{};

    recordMerkleWork(Backend, &recorder, columns[0..]);

    try std.testing.expectEqual(@as(u64, 7), recorder.counters.merkle_compressions);
    try std.testing.expectEqual(@as(u64, 1), recorder.record_count);
    try std.testing.expect(!recorder.incomplete);
}

test "Merkle work fails closed when backend reuse semantics are unknown" {
    const UnsupportedBackend = struct {};
    const values = [_]M31{M31.one()} ** 8;
    const columns = [_][]const M31{values[0..]};
    var recorder: WorkRecorder = .{};

    recordMerkleWork(UnsupportedBackend, &recorder, columns[0..]);

    try std.testing.expect(recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 0), recorder.record_count);
    try std.testing.expectEqual(
        work_profile.Authority.unavailable,
        (try recorder.snapshot()).authority,
    );
}

test "Merkle work fails closed for a non-binary leaf shape" {
    const Backend = struct {
        pub const reuses_constant_merkle_parents = false;
    };
    const values = [_]M31{ M31.zero(), M31.one(), M31.zero() };
    const columns = [_][]const M31{values[0..]};
    var recorder: WorkRecorder = .{};

    recordMerkleWork(Backend, &recorder, columns[0..]);

    try std.testing.expect(recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 0), recorder.record_count);
}

test "backing teardown token releases exactly once" {
    const Context = struct { calls: u32 = 0, released: u64 = 0 };
    const Counter = struct {
        fn release(context: ?*anyopaque, value: u64) void {
            const counter: *Context = @ptrCast(@alignCast(context.?));
            counter.calls += 1;
            counter.released += value;
        }
    };
    var context: Context = .{};
    var token = BackingTeardownToken.init(&context, 7, Counter.release);
    token.deinit();
    try std.testing.expectEqual(@as(u32, 1), context.calls);
    try std.testing.expectEqual(@as(u64, 7), context.released);
}
