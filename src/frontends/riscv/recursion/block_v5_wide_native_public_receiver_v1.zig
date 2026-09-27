//! Actual new-parent fresh CPU verification under independently reconstructed
//! original policy and B5WP fields. Source normalization grants no authority.
const std = @import("std");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Original = @import("block_v5_wide_original_child_source_v1.zig");
const Public = @import("block_v5_wide_native_public_values_v1.zig");
const Grammar = @import("block_v5_reusable_wide_native_public_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub fn ForSubtype(comptime subtype: Coverage.Subtype) type {
    const O = Original.ForSubtype(subtype);
    const P = Public.ForSubtype(subtype);
    const Protocol = Grammar.ForSubtype(subtype);
    return struct {
        pub const Policy = struct {
            original: O.Policy,
            key: Protocol.Key,
            expected_id: [32]u8,
            schedule: []const Grammar.Wire,
            original_limits: Original.Limits = .{},
            public_limits: Public.Limits = .{},
            max_proof_bytes: usize = 512 << 20,
        };
        /// Heap stable because Values borrows Source. Independent original
        /// Prepared/key/schedule storage must outlive this scoped receipt.
        pub const Fresh = struct {
            allocator: std.mem.Allocator,
            policy: Policy,
            source: O.Source,
            public: P.Values,
            equation: @import("blake3_native_parent_verifier.zig").Verified,
            pub const complete_block_authority = false;
            pub const complete_source_authority = false;
            pub fn authority(self: *const Fresh) !Protocol.Admission {
                if (self.public.source != &self.source or !std.meta.eql(self.source.policy, self.policy.original) or self.public.max_cells != self.policy.public_limits.max_cells) return error.UnpairedWideNativePublicSource;
                return Protocol.Admission.init(self.policy.key, self.policy.expected_id, self.policy.schedule, &self.public);
            }
            pub fn validate(self: *const Fresh) !void {
                const admitted = try self.authority();
                try self.equation.validate(&admitted, self.policy.expected_id);
            }
            pub fn deinit(self: *Fresh) void {
                const a = self.allocator;
                const owner = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.fromAllocator(a);
                if (owner) |value| _ = value.retain();
                self.equation.deinit();
                self.public.deinit();
                self.source.deinit();
                a.destroy(self);
                if (owner) |value| value.destroy();
            }
        };
        /// The original child proof verification is constrained inside this
        /// actual new parent. Final standalone verification rederives its
        /// exact original inputs, raw fields, public schedule and trusted key;
        /// it never consumes a host original-proof acceptance token.
        pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
            if (policy.max_proof_bytes == 0 or bytes.len == 0 or bytes.len > policy.max_proof_bytes) return error.WideNativeParentResourceLimit;
            const fresh = try a.create(Fresh);
            errdefer a.destroy(fresh);
            fresh.allocator = a;
            fresh.policy = policy;
            fresh.source = try O.Source.init(a, policy.original, policy.original_limits);
            errdefer fresh.source.deinit();
            fresh.public = try P.Values.init(a, &fresh.source, policy.public_limits);
            errdefer fresh.public.deinit();
            const admitted = try fresh.authority();
            var proof = try Parent.codec.decode(a, bytes, &admitted);
            fresh.equation = try Parent.verify(&proof, &admitted);
            errdefer fresh.equation.deinit();
            try fresh.validate();
            return fresh;
        }
    };
}
