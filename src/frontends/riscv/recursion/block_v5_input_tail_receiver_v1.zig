//! Genuine standalone full-tail verifier. Keys and the cached expected-input
//! owner are independently supplied; proof files cannot choose public CVs.
const std = @import("std");
const Public = @import("block_v5_input_tail_public_v1.zig");
const Protocol = @import("block_v5_input_tail_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Policy = struct { public: *Public.Owned, expected_input: Public.Pin, key: Protocol.Key, expected_id: [32]u8, max_proof_bytes: usize = 512 << 20 };
pub const Fresh = struct {
    allocator: std.mem.Allocator,
    budget: ?*Budget,
    policy: Policy,
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn authority(self: *const Fresh) !Protocol.Admission {
        return Protocol.Admission.init(self.policy.key, self.policy.expected_id, self.policy.public, self.policy.expected_input);
    }
    pub fn validate(self: *const Fresh) !void {
        const admitted = try self.authority();
        try self.equation.validate(&admitted, self.policy.expected_id);
    }
    pub fn deinit(self: *Fresh) void {
        const a = self.allocator;
        const lease = self.budget;
        self.equation.deinit();
        self.policy.public.deinit();
        a.destroy(self);
        if (lease) |owner| owner.destroy();
    }
};
pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
    if (bytes.len == 0 or policy.max_proof_bytes == 0 or bytes.len > policy.max_proof_bytes) return error.InputTailResourceLimit;
    const admitted = try Protocol.Admission.init(policy.key, policy.expected_id, policy.public, policy.expected_input);
    const budget = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
    errdefer if (budget) |owner| owner.destroy();
    const retained = policy.public.retain();
    errdefer retained.deinit();
    const fresh = try a.create(Fresh);
    errdefer a.destroy(fresh);
    fresh.allocator = a;
    fresh.budget = budget;
    fresh.policy = policy;
    var proof = try Parent.codec.decode(a, bytes, &admitted);
    fresh.equation = try Parent.verify(&proof, &admitted);
    errdefer fresh.equation.deinit();
    try fresh.validate();
    return fresh;
}
