//! Original caller-fused verifier with exact auxiliary singleton namespaces.
const std = @import("std");
const Fixed = @import("block_v6_caller_fused_fixed_roster_v1.zig");
const Admission = @import("../prover/block_v5_caller_fused_recursive_admission_v1.zig");
const Aux = @import("block_v6_auxiliary_direct_public_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Policy = struct {
    pub const family: Aux.Family = .caller_fused;
    pub const Original = Fixed.Owned;
    pub const Admitted = Admission.Prepared;
    pub const Claims = Admission.Fused.ClaimFrames;
    pub const Limits = Fixed.Limits;
    pub fn deriveOriginal(a: std.mem.Allocator, admitted: *const Admitted, expected: [32]u8, claims: Claims, capacity: u32, profile: Base.Profile, limits: Limits) !Original {
        try admitted.validate(expected);
        return Original.derive(a, admitted, claims, capacity, profile, limits);
    }
    pub fn index(admitted: *const Admitted) u32 {
        return admitted.binding.execution_index;
    }
};
pub const Owned = @import("block_v6_auxiliary_fixed_singleton_v1.zig").ForPolicy(Policy).Owned;
