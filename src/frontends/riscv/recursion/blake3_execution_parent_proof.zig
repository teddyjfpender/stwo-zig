//! Explicit execution-parent proof API. The caller derives and pins the key
//! from admitted preparation; received artifacts never choose their own key.
const std = @import("std");
const engine = @import("stwo_prover_engine");
pub const protocol = @import("blake3_execution_parent_protocol.zig");
pub const spans = @import("blake3_execution_span.zig");
pub const public_io = @import("blake3_public_io.zig");
pub const pipeline = @import("blake3_tree_pipeline.zig");
pub const execution_pipeline = @import("blake3_execution_parent_pipeline.zig");
pub const tree = @import("blake3_execution_tree.zig");
pub const aggregation = @import("blake3_execution_aggregate.zig");
pub const exact_root = @import("blake3_exact_root_aggregate.zig");
pub const preparation = @import("blake3_execution_parent_preparation.zig");
pub const artifact = @import("blake3_native_parent_artifact.zig");
pub const codec = @import("blake3_native_parent_codec.zig");
pub const verify = @import("blake3_native_parent_verifier.zig").verify;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Backend, protocol);
        /// Independently compiled complete family fixed rows use the same
        /// original commitment body. Caller family admission remains required.
        pub const deriveKeyFromFixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Backend).derive;
        /// Finalizes bounded G partitions in place before binding the key.
        /// The finalized preparation can then be consumed by a proving worker.
        pub fn deriveKey(a: std.mem.Allocator, prepared: *preparation.Prepared) !protocol.Key {
            return deriveKeyWithProfile(a, prepared, .diagnostic_q8_pow0);
        }
        /// Reuses the caller's persistent pool during independent key derivation.
        /// Requires no current scoped binding. The binding ends before callers
        /// create a worker with its own pool.
        pub fn deriveKeyWithProfileAndPool(a: std.mem.Allocator, prepared: *preparation.Prepared, profile: protocol.Profile, pool: *engine.work_pool.WorkPool) !protocol.Key {
            var binding = try engine.work_pool.ScopedPoolBinding.init(pool);
            defer binding.deinit();
            return deriveKeyWithProfile(a, prepared, profile);
        }
        /// A parent's profile does not upgrade the security of admitted children.
        /// The caller must qualify and admit the complete chain independently.
        pub fn deriveKeyWithProfile(a: std.mem.Allocator, prepared: *preparation.Prepared, profile: protocol.Profile) !protocol.Key {
            try prepared.rows.partitionHashRows();
            return @import("blake3_parent_fixed_key_v1.zig").ForBackend(Backend).derive(a, prepared.rows.fixed, prepared.context, profile);
        }
    };
}
