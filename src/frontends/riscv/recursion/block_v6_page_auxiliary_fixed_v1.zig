//! Capture-free PAGE fixed setup with both exact auxiliary/mixed namespaces.
const std = @import("std");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Fixed = @import("block_v5_memory_source_page_recursive_fixed_roster_v1.zig");
const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig");
const Aux = @import("block_v6_auxiliary_direct_public_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Policy = struct {
        pub const family: Aux.Family = if (kind == .raw) .source_raw else .source_fold;
        pub const Original = Fixed.ForKind(kind).Owned;
        pub const Admitted = Admission.ForKind(kind).Prepared;
        pub const Claims = Semantic.Claims;
        pub const Limits = Fixed.Limits;
        pub fn deriveOriginal(a: std.mem.Allocator, admitted: *const Admitted, expected: [32]u8, claims: Claims, capacity: u32, profile: Base.Profile, limits: Limits) !Original {
            return Original.derive(a, admitted, expected, claims, capacity, profile, limits);
        }
        pub fn index(admitted: *const Admitted) u32 {
            return if (kind == .raw) admitted.pin.raw.page.index else admitted.pin.page.index;
        }
    };
    return @import("block_v6_auxiliary_fixed_singleton_v1.zig").ForPolicy(Policy);
}
