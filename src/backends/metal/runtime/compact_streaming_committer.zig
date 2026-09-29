//! Incremental native commitment that never retains a complete LDE matrix.
//! A single terminal block is copied because callers retire each input batch.
const std = @import("std");
const prover = @import("stwo_prover_engine");
const M31 = @import("stwo_core").fields.m31.M31;
const shared = @import("../shared_runtime.zig");
const leaf_stream = @import("blake2_leaf_stream.zig");

pub fn Committer(comptime H: type) type {
    return struct {
        allocator: std.mem.Allocator,
        stream: ?leaf_stream.Stream(H) = null,
        pending: [16][]M31 = undefined,
        pending_count: usize = 0,
        planned_columns: ?usize = null,
        received_columns: usize = 0,
        initialized: bool = false,
        leaf_log_size: u32 = 0,
        failed: bool = false,
        const Self = @This();
        const Tree = prover.vcs_lifted.prover.MerkleProverLifted(H);

        pub fn init(a: std.mem.Allocator) Self {
            return .{ .allocator = a };
        }
        pub fn deinit(self: *Self) void {
            self.clearPending();
            if (self.stream) |*stream| {
                stream.deinit();
                shared.releaseResidentResource();
            }
            self.* = undefined;
        }
        fn clearPending(self: *Self) void {
            for (self.pending[0..self.pending_count]) |column| self.allocator.free(column);
            self.pending_count = 0;
        }
        fn ensureStream(self: *Self) !void {
            if (self.stream != null) return;
            var lease = try shared.acquire();
            defer lease.deinit();
            self.stream = try leaf_stream.Stream(H).init(self.allocator, lease.runtime);
            // Resource custody protects the runtime without holding a recursive
            // read lock across other backend operations or shutdown requests.
            shared.retainResidentResource();
        }
        pub fn compactLiftedTailStart(_: []const Tree.ColumnRef) ?usize {
            return null;
        }
        /// A complete shape lets terminal blocks be consumed while their
        /// caller-owned LDE backing is still live. Unplanned streaming retains
        /// the existing single-block carry contract.
        pub fn planColumnCount(self: *Self, count: usize) !void {
            if (self.failed or self.initialized or self.planned_columns != null)
                return error.InvalidIncrementalCommitmentPlan;
            self.planned_columns = count;
        }
        pub fn addColumns(self: *Self, refs: []const Tree.ColumnRef) !void {
            return self.addColumnsWithBacking(refs, &.{});
        }
        pub fn addColumnsWithBacking(self: *Self, refs: []const Tree.ColumnRef, backing: ?[][]M31) !void {
            if (self.failed) return error.IncrementalCommitmentFailed;
            errdefer self.failed = true;
            const received = try std.math.add(usize, self.received_columns, refs.len);
            if (self.planned_columns) |count| if (received > count)
                return error.InvalidIncrementalCommitmentPlan;
            var last = self.leaf_log_size;
            for (refs) |reference| {
                if (reference.log_size == 0 or reference.log_size >= 31 or reference.log_size < last or
                    reference.values.len != @as(usize, 1) << @intCast(reference.log_size)) return error.InvalidColumnSize;
                last = reference.log_size;
            }
            if (refs.len == 0) return;
            try self.ensureStream();
            const owners = backing orelse &.{};
            const views = try self.allocator.alloc([]const M31, owners.len);
            defer self.allocator.free(views);
            for (owners, views) |owner, *view| view.* = owner;
            var offset: usize = 0;
            while (offset < refs.len) {
                if (self.pending_count == 16) {
                    var columns: [16][]const M31 = undefined;
                    for (self.pending, &columns) |value, *column| column.* = value;
                    try self.stream.?.pushBlock(&columns, false, &.{});
                    self.clearPending();
                }
                // With a complete plan, an exact sixteen-column boundary no
                // longer needs copying just to discover its final-block flag.
                const available = @min(refs.len - offset, 16);
                const terminal = if (self.planned_columns) |count|
                    self.received_columns + offset + available == count
                else
                    false;
                const known_nonterminal = available == 16 and (refs.len - offset > 16 or
                    (self.planned_columns != null and !terminal));
                if (self.pending_count == 0 and (known_nonterminal or terminal)) {
                    var columns: [16][]const M31 = undefined;
                    for (refs[offset..][0..available], columns[0..available]) |reference, *column| column.* = reference.values;
                    try self.stream.?.pushBlock(columns[0..available], terminal, views);
                    offset += available;
                    continue;
                }
                self.pending[self.pending_count] = try self.allocator.dupe(M31, refs[offset].values);
                self.pending_count += 1;
                offset += 1;
            }
            self.initialized = true;
            self.leaf_log_size = last;
            self.received_columns = received;
        }
        /// Consume the committer on success; leave errors owned for deinit.
        pub fn finalize(self: *Self) !Tree {
            if (self.failed) return error.IncrementalCommitmentFailed;
            errdefer self.failed = true;
            if (self.planned_columns) |count| if (self.received_columns != count)
                return error.IncompleteIncrementalCommitmentPlan;
            if (!self.initialized) {
                var host = Tree.StreamingCommitter.init(self.allocator);
                errdefer host.deinit();
                const result = try host.finalize();
                self.deinit();
                return result;
            }
            if (!self.stream.?.final_block) {
                var columns: [16][]const M31 = undefined;
                for (self.pending[0..self.pending_count], columns[0..self.pending_count]) |value, *column| column.* = value;
                try self.stream.?.pushBlock(columns[0..self.pending_count], true, &.{});
                self.clearPending();
            }
            var result = try self.stream.?.finish(if (self.leaf_log_size >= 20) 4 else 0);
            result.compactForQueries();
            self.deinit();
            return result;
        }
        pub fn finalizeLiftedTail(self: *Self, refs: []const Tree.ColumnRef) !Tree {
            try self.addColumns(refs);
            return self.finalize();
        }
    };
}
