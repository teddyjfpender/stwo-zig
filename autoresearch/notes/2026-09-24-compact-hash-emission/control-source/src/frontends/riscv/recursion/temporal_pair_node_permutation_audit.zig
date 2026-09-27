//! Test-only dynamic accounting for temporal pair-node scalar Poseidon calls.
//!
//! Production builds expose an empty support namespace and compile the
//! observation branch away. Both the authority hasher and the public test
//! seam share this owner, so instrumentation cannot diverge across shards.

const builtin = @import("builtin");

pub const RuntimePermutationAuditV2 = struct {
    hash_invocations: usize = 0,
    scalar_poseidon_permutations: usize = 0,
};

threadlocal var active: ?*RuntimePermutationAuditV2 = null;

pub const test_support = if (builtin.is_test) struct {
    pub const PermutationAudit = RuntimePermutationAuditV2;
    pub const Error = error{
        AuditAlreadyActive,
        AuditNotActive,
    };

    pub fn begin(audit: *PermutationAudit) @This().Error!void {
        if (active != null) return error.AuditAlreadyActive;
        audit.* = .{};
        active = audit;
    }

    pub fn finish(audit: *PermutationAudit) @This().Error!PermutationAudit {
        if (active != audit) return error.AuditNotActive;
        active = null;
        return audit.*;
    }

    pub fn cancel(audit: *PermutationAudit) void {
        if (active == audit) active = null;
    }
} else struct {};

pub inline fn recordScalarPoseidonInvocations(permutations: usize) void {
    if (comptime builtin.is_test) {
        if (active) |audit| {
            audit.hash_invocations += 1;
            audit.scalar_poseidon_permutations += permutations;
        }
    }
}
