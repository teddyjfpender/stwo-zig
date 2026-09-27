//! Standalone fresh receiver reconstructs the complete independent public job
//! and original typed policies; no original host-verification token is needed.
const std = @import("std");
const Parent = @import("blake3_execution_parent_proof.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub fn ForModules(comptime Public: type, comptime Protocol: type, comptime Bus: type) type {
    return struct {
        pub const Policy = struct { public: Public.Policy, key: Protocol.Key, expected_id: [32]u8, schedule: []const Bus.Wire, public_limits: Public.Limits = .{}, max_proof_bytes: usize = 512 << 20 };
        pub const Fresh = struct {
            allocator: std.mem.Allocator,
            policy: Policy,
            public: Public.Owner,
            equation: @import("blake3_native_parent_verifier.zig").Verified,
            pub const complete_source_authority = false;
            pub const complete_block_authority = false;
            pub fn authority(self: *const Fresh) !Protocol.Admission {
                if (!std.meta.eql(self.public.policy, self.policy.public) or !std.meta.eql(self.public.limits, self.policy.public_limits)) return error.UnpairedWidePublicPolicy;
                return Protocol.Admission.init(self.policy.key, self.policy.expected_id, self.policy.schedule, .{ .public = &self.public });
            }
            pub fn validate(self: *const Fresh) !void {
                const admission = try self.authority();
                try self.equation.validate(&admission, self.policy.expected_id);
            }
            pub fn deinit(self: *Fresh) void {
                const a = self.allocator;
                const lease = Budget.fromAllocator(a);
                if (lease) |owner| _ = owner.retain();
                self.equation.deinit();
                self.public.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
        pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
            if (policy.max_proof_bytes == 0 or bytes.len == 0 or bytes.len > policy.max_proof_bytes) return error.WidePublicResourceLimit;
            const fresh = try a.create(Fresh);
            errdefer a.destroy(fresh);
            fresh.allocator = a;
            fresh.policy = policy;
            fresh.public = try Public.init(a, policy.public, policy.public_limits);
            errdefer fresh.public.deinit();
            const admission = try fresh.authority();
            var proof = try Parent.codec.decode(a, bytes, &admission);
            fresh.equation = try Parent.verify(&proof, &admission);
            errdefer fresh.equation.deinit();
            try fresh.validate();
            return fresh;
        }
    };
}
