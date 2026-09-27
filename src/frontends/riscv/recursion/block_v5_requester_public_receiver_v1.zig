//! Genuine original Parent verifier. Key/id/schedule must come from independent
//! original setup reconstruction; none is selected by an envelope or manifest.
const std = @import("std");
const Public = @import("block_v5_requester_public_compensation_v1.zig");
const Bus = @import("block_v5_requester_public_bus_v1.zig");
const Protocol = @import("block_v5_requester_public_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Policy = struct { public: *const Public.Owner, key: Protocol.Key, expected_id: [32]u8, wires: []const Bus.Wire, max_proof_bytes: usize = 512 << 20 };
pub const Fresh = struct {
    a: std.mem.Allocator,
    lease: ?*Budget,
    policy: Policy,
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    pub const complete_block_authority = false;
    pub fn authority(self: *const Fresh) !Protocol.Admission {
        return Protocol.Admission.init(self.policy.key, self.policy.expected_id, self.policy.wires, .{ .public = self.policy.public });
    }
    pub fn validate(self: *const Fresh) !void {
        const admitted = try self.authority();
        try self.equation.validate(&admitted, admitted.expected_id);
    }
    pub fn deinit(self: *Fresh) void {
        const a = self.a;
        const lease = self.lease;
        self.equation.deinit();
        a.destroy(self);
        if (lease) |budget| budget.destroy();
    }
};
/// Public owner and its independently paired compact public metadata must
/// outlive Fresh. The earlier requester capture is needed only by preparation;
/// stable catalogue metadata may survive it. No envelope selects setup here.
pub fn verify(a: std.mem.Allocator, bytes: []const u8, policy: Policy) !*Fresh {
    if (policy.max_proof_bytes == 0 or bytes.len == 0 or bytes.len > policy.max_proof_bytes) return error.RequesterPublicResourceLimit;
    const authority = try Protocol.Admission.init(policy.key, policy.expected_id, policy.wires, .{ .public = policy.public });
    const lease = if (Budget.fromAllocator(a)) |budget| budget.retain() else null;
    errdefer if (lease) |budget| budget.destroy();
    const self = try a.create(Fresh);
    errdefer a.destroy(self);
    var proof = try Parent.codec.decode(a, bytes, &authority);
    var equation = try Parent.verify(&proof, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, authority.expected_id);
    self.* = .{ .a = a, .lease = lease, .policy = policy, .equation = equation };
    return self;
}
