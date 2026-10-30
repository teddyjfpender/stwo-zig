//! Original parent preprocessed commitment from independently compiled fixed
//! rows/context. MAIN columns and a proof capture are neither needed nor used.
//! This PCS primitive does not authenticate its caller's family/statement.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Projection = @import("air/blake3_row_columns.zig");
const Protocol = @import("blake3_execution_parent_protocol.zig");
const Suite = @import("blake3_engine_protocol.zig");

/// Preserve the original exact physical cohort sizes, including already
/// partitioned joined children. Never silently repartition received metadata.
pub fn rowLogs(fixed: Storage.FixedTuple(false)) ![Storage.Airs.len]u32 {
    var logs: [Storage.Airs.len]u32 = undefined;
    inline for (0..Storage.Airs.len) |slot| {
        if (fixed[slot].len > @as(usize, 1) << 30) return error.InvalidBlake3ParentGeometry;
        logs[slot] = if (fixed[slot].len <= 1) 1 else std.math.log2_int_ceil(usize, fixed[slot].len);
    }
    return logs;
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, Suite.Hasher, Suite.MerkleChannel);
        /// An owned, in-process commitment to independently reconstructed rows.
        /// This is not a serialized key cache or an admission authority.
        pub const Committed = struct {
            allocator: std.mem.Allocator,
            key: Protocol.Key,
            tree: Scheme.CommittedTree,
            row_counts: [Storage.Airs.len]usize,
            row_digests: [Storage.Airs.len][32]u8,
            pub fn deinit(self: *@This()) void {
                self.tree.deinit(self.allocator);
                self.* = undefined;
            }
        };
        /// Family-owned assembly must independently reconstruct every fixed
        /// cell, external schedule and context before admitting this result.
        /// Inputs are immutable and borrowed only for this synchronous call.
        pub fn derive(a: std.mem.Allocator, fixed: Storage.FixedTuple(false), context: Protocol.Context, profile: Protocol.Profile) !Protocol.Key {
            return deriveInternal(false, a, fixed, context, profile);
        }
        /// Retain the actual tree so proving can consume this same commitment.
        /// Live rows must still match these independent fixed rows exactly.
        pub fn deriveCommitted(a: std.mem.Allocator, fixed: Storage.FixedTuple(false), context: Protocol.Context, profile: Protocol.Profile) !Committed {
            return deriveInternal(true, a, fixed, context, profile);
        }
        fn deriveInternal(comptime retain: bool, a: std.mem.Allocator, fixed: Storage.FixedTuple(false), context: Protocol.Context, profile: Protocol.Profile) !(if (retain) Committed else Protocol.Key) {
            const config = profile.config();
            const logs = try rowLogs(fixed);
            // Reject invalid context framing before allocating commitment data.
            _ = try Protocol.contextIdentity(context);
            var columns: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            defer {
                for (columns.items) |column| a.free(column.values);
                columns.deinit(a);
            }
            inline for (Storage.Airs, 0..) |Air, slot| try Projection.projectFixed(Air, a, fixed[slot], logs[slot], &columns);
            for ([_]@import("../air/lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8 }) |kind| try Projection.tablePreprocessed(a, kind, &columns);
            var scheme = try engine.pcs.CommitmentSchemeProver(Backend, Suite.Hasher, Suite.MerkleChannel).init(a, config);
            defer scheme.deinit(a);
            // Keep the same root with compact polynomial storage when supported.
            // No MAIN witness or request transcript is retained here.
            if (retain and Backend.MerkleTree(Suite.Hasher) == engine.vcs_lifted.prover.MerkleProverLifted(Suite.Hasher) and !std.process.hasEnvVarConstant("STWO_RISCV_MATERIALIZED_POLYNOMIALS"))
                scheme.setCompactPolynomialStorage(20)
            else
                scheme.setCoefficientRetentionPolicy(.never);
            var channel = Suite.Channel{};
            try scheme.commitOwnedStreamingWithRecorder(a, try columns.toOwnedSlice(a), @import("../prover/blake3_coefficient_retention.zig").streamingBatchColumns(), null, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 1) return error.InvalidBlake3ParentRoot;
            const key = Protocol.Key{ .profile = profile, .config = config, .context = context, .log_sizes = logs, .preprocessed_root = roots.items[0] };
            _ = try key.identity();
            if (!retain) return key;
            var counts: [Storage.Airs.len]usize = undefined;
            var digests: [Storage.Airs.len][32]u8 = undefined;
            inline for (0..Storage.Airs.len) |i| {
                counts[i] = fixed[i].len;
                digests[i] = @import("blake3_parent_fixed_row_guard_v1.zig").fixedDigest(fixed[i]);
            }
            try scheme.trees.items[0].share(a);
            return .{ .allocator = a, .key = key, .tree = scheme.trees.pop().?, .row_counts = counts, .row_digests = digests };
        }
    };
}
