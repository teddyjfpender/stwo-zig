//! Full original PAGE verifier equations. Expected key/schedule derive from
//! independent original admission and verifier rows, never artifact self-hashes.
const std = @import("std");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Parent = @import("blake3_execution_parent_proof.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Bus = @import("block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    const Protocol = @import("block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
    const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    return struct {
        pub const OpenEquation = struct {
            allocation_owner: ?*Budget,
            equation: @import("blake3_native_parent_verifier.zig").Verified,
            public_values: Bus.Values,
            pub const complete_source_authority = false;
            pub const complete_block_authority = false;
            pub fn deinit(self: *OpenEquation) void {
                const owner = self.allocation_owner;
                self.public_values.deinit();
                self.equation.deinit();
                self.* = undefined;
                if (owner) |value| value.destroy();
            }
        };
        pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, expected_key_id: [32]u8, schedule: []const Bus.Wire, admitted: *const Admission.Prepared, proposed: Bus.Claims) !OpenEquation {
            if (!std.meta.eql(key.config, admitted.config) or !std.meta.eql(key.context.child_config, admitted.config)) return error.SourcePageRecursiveSecurityMismatch;
            const owner = Budget.fromAllocator(a);
            if (owner) |value| _ = value.retain();
            errdefer if (owner) |value| value.destroy();
            var values = try Bus.Values.init(a, admitted, proposed);
            errdefer values.deinit();
            const authority = try Protocol.Admission.init(key, expected_key_id, schedule, values);
            var owned = try Parent.codec.decode(a, bytes, &authority);
            var equation = try Parent.verify(&owned, &authority);
            errdefer equation.deinit();
            try equation.validate(&authority, expected_key_id);
            return .{ .allocation_owner = owner, .equation = equation, .public_values = values };
        }
    };
}
