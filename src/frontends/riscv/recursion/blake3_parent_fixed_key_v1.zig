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
        /// Family-owned assembly must independently reconstruct every fixed
        /// cell, external schedule and context before admitting this result.
        /// Inputs are immutable and borrowed only for this synchronous call.
        pub fn derive(a: std.mem.Allocator, fixed: Storage.FixedTuple(false), context: Protocol.Context, profile: Protocol.Profile) !Protocol.Key {
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
            // This is the ONE original streaming fixed-commitment body. Only
            // the root is retained; coefficients and MAIN epochs are absent.
            scheme.setCoefficientRetentionPolicy(.never);
            var channel = Suite.Channel{};
            try scheme.commitOwnedStreamingWithRecorder(a, try columns.toOwnedSlice(a), @import("../prover/blake3_coefficient_retention.zig").streamingBatchColumns(), null, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 1) return error.InvalidBlake3ParentRoot;
            const key = Protocol.Key{ .profile = profile, .config = config, .context = context, .log_sizes = logs, .preprocessed_root = roots.items[0] };
            _ = try key.identity();
            return key;
        }
    };
}
