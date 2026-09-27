//! Explicit execution-parent proof API. The caller derives and pins the key
//! from admitted preparation; received artifacts never choose their own key.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = @import("blake3_engine_protocol.zig");
const rows = @import("air/blake3_native_parent_rows.zig");
const columns = @import("air/blake3_row_columns.zig");
pub const protocol = @import("blake3_execution_parent_protocol.zig");
pub const spans = @import("blake3_execution_span.zig");
pub const public_io = @import("blake3_public_io.zig");
pub const pipeline = @import("blake3_tree_pipeline.zig");
pub const tree = @import("blake3_execution_tree.zig");
pub const aggregation = @import("blake3_execution_aggregate.zig");
pub const preparation = @import("blake3_execution_parent_preparation.zig");
pub const artifact = @import("blake3_native_parent_artifact.zig");
pub const codec = @import("blake3_native_parent_codec.zig");
pub const verify = @import("blake3_native_parent_verifier.zig").verify;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Backend, protocol);
        pub fn deriveKey(a: std.mem.Allocator, prepared: *const preparation.Prepared) !protocol.Key {
            return deriveKeyWithProfile(a, prepared, .diagnostic_q8_pow0);
        }
        /// A parent's profile does not upgrade the security of admitted children.
        /// The caller must qualify and admit the complete chain independently.
        pub fn deriveKeyWithProfile(a: std.mem.Allocator, prepared: *const preparation.Prepared, profile: protocol.Profile) !protocol.Key {
            const config = profile.config();
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            var logs: [rows.Airs.len]u32 = undefined;
            var pp: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            inline for (rows.Airs, 0..) |Air, i| {
                logs[i] = if (prepared.rows.fixed[i].len <= 1) 1 else std.math.log2_int_ceil(usize, prepared.rows.fixed[i].len);
                try columns.project(Air, temp, prepared.rows.fixed[i], logs[i], 0, &pp);
            }
            for ([_]@import("../air/lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8 }) |kind| try columns.tablePreprocessed(temp, kind, &pp);
            var scheme = try engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel).init(a, config);
            defer scheme.deinit(a);
            var channel = suite.Channel{};
            try scheme.commit(a, pp.items, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 1) return error.InvalidBlake3ParentRoot;
            const key = protocol.Key{ .profile = profile, .config = config, .context = prepared.context, .log_sizes = logs, .preprocessed_root = roots.items[0] };
            _ = try key.identity();
            return key;
        }
    };
}
