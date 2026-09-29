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

/// One owning allocation, possibly borrowed by several column descriptors.
pub const ColumnBacking = struct {
    values: []M31,
    alignment: std.mem.Alignment,
    pub fn deinit(self: ColumnBacking, allocator: std.mem.Allocator) void {
        if (self.values.len != 0)
            allocator.rawFree(std.mem.sliceAsBytes(self.values), self.alignment, @returnAddress());
    }
};

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

/// Moves independently owned LDE buffers to explicit retained storage. Consumes
/// the input on success and failure. Copy/free one column at a time, so the
/// temporary duplicate is bounded by the largest column, not the whole tree.
pub fn relocateOwnedColumns(
    allocator: std.mem.Allocator,
    retained_allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
) ![]ColumnEvaluation {
    defer {
        for (columns) |column| if (column.values.len != 0) allocator.free(column.values);
        allocator.free(columns);
    }
    const result = try allocator.alloc(ColumnEvaluation, columns.len);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| retained_allocator.free(column.values);
        allocator.free(result);
    }
    for (columns, result) |*source, *destination| {
        const values = try retained_allocator.dupe(M31, source.values);
        destination.* = .{ .log_size = source.log_size, .values = values };
        initialized += 1;
        allocator.free(source.values);
        source.values = &.{};
    }
    return result;
}

pub fn freeRetainedColumns(
    allocator: std.mem.Allocator,
    retained_allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
) void {
    for (columns) |column| if (column.values.len != 0) retained_allocator.free(column.values);
    allocator.free(columns);
}

/// The host reference Merkle backend behind `CommitmentTreeProver(H)`; its
/// column preparation takes the portable interpolate-then-extend path.
pub const HostMerkleBackend = struct {
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
        /// Value buffers only; outer descriptors remain on the caller allocator.
        retained_column_allocator: ?std.mem.Allocator = null,
        coefficients: ?[]prover_circle.CircleCoefficients,
        column_backing_buffers: ?[][]M31 = null,
        streaming_column_backings: ?[]ColumnBacking = null,
        column_backing_alignment: std.mem.Alignment = .of(M31),
        coefficient_backing_buffers: ?[][]M31 = null,
        coefficient_backing_alignment: std.mem.Alignment = .of(M31),
        backing_teardown: ?BackingTeardownToken = null,
        commitment: B.MerkleTree(H),
        shared_owner: ?*SharedOwner = null,
        compact_polynomials: bool = false,

        const Self = @This();
        const SharedOwner = struct {
            allocator: std.mem.Allocator,
            tree: Self,
            references: std.atomic.Value(usize),
        };

        /// Promote an exclusively owned tree to shared immutable storage.
        /// Failure preserves ownership. All copies must use retainShared; raw
        /// struct copies remain moves. Backend payload reads must be thread-safe
        /// before leases may be used concurrently, and the owner allocator must
        /// support the thread performing the final release.
        pub fn share(self: *Self, allocator: std.mem.Allocator) !void {
            if (self.shared_owner != null) return;
            const owner = try allocator.create(SharedOwner);
            owner.* = .{ .allocator = allocator, .tree = self.*, .references = .init(1) };
            self.shared_owner = owner;
        }

        /// The source lease must remain live throughout acquisition.
        pub fn retainShared(self: *const Self) Self {
            const owner = self.shared_owner orelse @panic("commitment tree is not shared");
            const previous = owner.references.fetchAdd(1, .monotonic);
            if (previous >= std.math.maxInt(usize) / 2) @panic("too many commitment leases");
            var result = owner.tree;
            result.shared_owner = owner;
            return result;
        }

        /// Drop the full LDE after hashing, retaining the native polynomial.
        /// Host backing arenas are detached selectively; tiny columns stay
        /// materialized. Backend aliases and shared owners cannot be invalidated.
        pub fn compactPolynomialStorage(self: *Self, allocator: std.mem.Allocator, minimum_log_size: u32) !void {
            if (self.compact_polynomials or self.columns.len == 0) return;
            if (comptime B.MerkleTree(H) != vcs_lifted_prover.MerkleProverLifted(H)) return error.UnsupportedCompactPolynomialStorage;
            if (self.shared_owner != null or self.backing_teardown != null)
                return error.UnsupportedCompactPolynomialStorage;
            const coefficients = self.coefficients orelse return error.MissingCompactCoefficients;
            if (coefficients.len != self.columns.len) return error.ShapeMismatch;
            for (self.columns, coefficients) |column, coefficient| {
                try column.validate();
                if (coefficient.logSize() > column.log_size) return error.ShapeMismatch;
            }
            const backed = self.column_backing_buffers != null or self.streaming_column_backings != null;
            if (backed and self.retained_column_allocator != null) return error.UnsupportedCompactPolynomialStorage;
            const small = try allocator.alloc([]const M31, self.columns.len);
            defer allocator.free(small);
            @memset(small, &.{});
            errdefer for (small) |values| allocator.free(values);
            if (backed) for (self.columns, small) |column, *copy| {
                if (column.log_size < minimum_log_size) copy.* = try allocator.dupe(M31, column.values);
            };
            for (self.columns, coefficients, small) |*column, coefficient, copy| {
                if (column.log_size < minimum_log_size) {
                    if (backed) column.values = copy;
                    continue;
                }
                // Tiny columns remain directly readable for ordinary table AIRs.
                if (!backed) (self.retained_column_allocator orelse allocator).free(column.values);
                column.values = &.{};
                column.coefficient_values = coefficient.coefficients();
            }
            if (self.streaming_column_backings) |backings| {
                for (backings) |backing| backing.deinit(allocator);
                allocator.free(backings);
                self.streaming_column_backings = null;
            }
            if (self.column_backing_buffers) |buffers| {
                @import("backed_columns.zig").freeBuffers(allocator, buffers, self.column_backing_alignment);
                self.column_backing_buffers = null;
            }
            self.compact_polynomials = true;
        }

        /// Sampling may discard its coefficient view, but shared storage stays
        /// alive for later proofs. Other allocations remain with the tree owner.
        pub fn releaseCoefficients(self: *Self, allocator: std.mem.Allocator) void {
            if (self.compact_polynomials) return;
            if (self.coefficients) |coefficients| {
                if (self.shared_owner == null) {
                    for (coefficients) |*coefficient| coefficient.deinit(allocator);
                    allocator.free(coefficients);
                    if (self.coefficient_backing_buffers) |buffers| {
                        @import("backed_columns.zig").freeBuffers(allocator, buffers, self.coefficient_backing_alignment);
                        self.coefficient_backing_buffers = null;
                    }
                }
                self.coefficients = null;
            }
        }

        /// Transfers a complete prepared owner on success, including the
        /// allocation metadata needed when releasing resident backing.
        pub fn initPrepared(allocator: std.mem.Allocator, prepared: anytype, recorder: ?*WorkRecorder) !Self {
            var tree = try initOwnedWithBackingAndWorkRecorder(
                allocator,
                prepared.columns,
                prepared.coefficients,
                prepared.column_backing_buffers,
                prepared.coefficient_backing_buffers,
                recorder,
            );
            tree.column_backing_alignment = prepared.column_backing_alignment;
            if (@hasField(@TypeOf(prepared.*), "coefficient_backing_alignment")) tree.coefficient_backing_alignment = prepared.coefficient_backing_alignment;
            return tree;
        }

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

            const HostTree = vcs_lifted_prover.MerkleProverLifted(H);
            const can_adopt_cached = B.MerkleTree(H) == HostTree or @hasDecl(B, "adoptHostMerkle");
            const loaded: ?HostTree = if (comptime can_adopt_cached)
                @import("merkle_cached_tree.zig").loadColumns(H, allocator, column_refs)
            else
                null;
            var commitment = if (loaded) |cached| blk: {
                if (comptime B.MerkleTree(H) == HostTree) break :blk cached;
                if (comptime @hasDecl(B, "adoptCachedMerkle"))
                    break :blk try B.adoptCachedMerkle(H, allocator, column_refs, column_backing_buffers, cached);
                break :blk B.adoptHostMerkle(H, cached);
            } else if (comptime @hasDecl(B, "commitMerkleWithBacking"))
                if (column_backing_buffers) |buffers|
                    try B.commitMerkleWithBacking(H, allocator, column_refs, buffers)
                else
                    try B.commitMerkle(H, allocator, column_refs)
            else
                try B.commitMerkle(H, allocator, column_refs);
            errdefer commitment.deinit(allocator);
            if (loaded == null) {
                if (comptime @hasDecl(B, "adoptCompactedMerkle")) {
                    if (@import("merkle_cached_tree.zig").captureAndStoreReader(
                        H,
                        allocator,
                        column_refs,
                        commitment,
                    )) |upper| {
                        const reduced = try B.adoptCompactedMerkle(
                            H,
                            allocator,
                            column_refs,
                            column_backing_buffers,
                            upper,
                        );
                        commitment.deinit(allocator);
                        commitment = reduced;
                    }
                } else {
                    @import("merkle_cached_tree.zig").storeReader(H, allocator, column_refs, commitment);
                }
                recordMerkleWork(B, work_recorder, column_refs);
            } else if (work_recorder) |active| {
                active.recordCompletedDelta(.{
                    .site = .commitment_tree_merkle,
                    .producer = .commitment_tree_merkle,
                    .source_mask = @import("stwo_prover_api").work_profile.SourceMask.one(.merkle_compressions),
                    .counters = .{},
                }) catch active.markIncomplete();
            }
            if (comptime @hasDecl(B.MerkleTree(H), "compactForQueries")) commitment.compactForQueries();

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
            var retained_commitment = commitment;
            if (comptime @hasDecl(B.MerkleTree(H), "compactForQueries")) retained_commitment.compactForQueries();
            return .{
                .columns = owned_columns,
                .coefficients = owned_coefficients,
                .column_backing_buffers = column_backing_buffers,
                .coefficient_backing_buffers = coefficient_backing_buffers,
                .backing_teardown = backing_teardown,
                .commitment = retained_commitment,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.shared_owner) |owner| {
                self.* = undefined;
                if (owner.references.fetchSub(1, .acq_rel) == 1) {
                    const original_allocator = owner.allocator;
                    const budget = @import("../host_budget_allocator.zig").SharedHostBudget.fromAllocator(original_allocator);
                    if (budget) |retained| _ = retained.retain();
                    defer if (budget) |retained| retained.destroy();
                    owner.tree.deinit(original_allocator);
                    original_allocator.destroy(owner);
                }
                return;
            }
            // A resident commitment can hold the final budget lease after its
            // caller releases the root owner. Keep the allocator alive while
            // destroying that view and then returning all host backing.
            const budget = @import("../host_budget_allocator.zig").SharedHostBudget.fromAllocator(allocator);
            if (budget) |retained| _ = retained.retain();
            defer if (budget) |retained| retained.destroy();
            // A backend commitment may retain a no-copy view of the committed
            // column arena. Release that view before returning its host
            // backing to the allocator.
            self.commitment.deinit(allocator);
            if (self.streaming_column_backings) |backings| {
                allocator.free(self.columns);
                for (backings) |backing| backing.deinit(allocator);
                allocator.free(backings);
            } else if (self.column_backing_buffers) |buffers| {
                allocator.free(self.columns);
                @import("backed_columns.zig").freeBuffers(allocator, buffers, self.column_backing_alignment);
            } else {
                freeRetainedColumns(allocator, self.retained_column_allocator orelse allocator, self.columns);
            }
            if (self.coefficients) |coeffs| {
                for (coeffs) |*coeff| coeff.deinit(allocator);
                allocator.free(coeffs);
            }
            if (self.coefficient_backing_buffers) |buffers| {
                @import("backed_columns.zig").freeBuffers(allocator, buffers, self.coefficient_backing_alignment);
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
            var result = if (self.compact_polynomials and self.columns.len != 0) blk: {
                if (comptime @hasField(B.MerkleTree(H), "layers"))
                    break :blk try @import("coefficient_opening.zig").decommit(H, allocator, self, sorted_positions)
                else if (comptime @hasDecl(B.MerkleTree(H), "coefficientOpeningCommitment")) {
                    const borrowed = .{ .columns = self.columns, .commitment = try self.commitment.coefficientOpeningCommitment() };
                    break :blk try @import("coefficient_opening.zig").decommitForBackend(B, H, allocator, borrowed, sorted_positions);
                } else return error.UnsupportedCompactPolynomialStorage;
            } else try self.commitment.decommit(allocator, sorted_positions, column_refs);
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
