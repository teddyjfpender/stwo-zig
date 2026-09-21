//! Explicit retained-campaign admission. Wire V4 remains bounded to 210 leaves;
//! selecting a different execution is never inferred from an untrusted artifact.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");

pub const VERSION: u16 = 1;
pub const SelectionV1 = enum {
    legacy_210,
    authenticated_v1,

    pub fn parse(value: []const u8) !SelectionV1 {
        if (std.mem.eql(u8, value, "legacy-210")) return .legacy_210;
        if (std.mem.eql(u8, value, "authenticated-v1")) return .authenticated_v1;
        return error.UnsupportedIncrementalCampaignGeometryV1;
    }

    /// Count and budget must come from the authenticated retained source request.
    pub fn validate(self: SelectionV1, segment_count: u32, step_budget: usize) !void {
        if (self == .legacy_210 and segment_count != publication.CANONICAL_SEGMENT_COUNT)
            return error.CanonicalIncrementalSegmentCountRequired;
        if (segment_count < 2 or segment_count > publication.MAX_SEGMENT_COUNT or
            step_budget == 0 or step_budget > frontend.recursion.segment_leaf_local_authority_v3.MAX_LEAF_CYCLES)
            return error.InvalidIncrementalCampaignGeometryV1;
    }
};

test "versioned retained campaign admits 61 leaves and smaller budgets without changing legacy 210" {
    try SelectionV1.legacy_210.validate(210, 4194304);
    try std.testing.expectError(error.CanonicalIncrementalSegmentCountRequired, SelectionV1.legacy_210.validate(61, 4194304));
    try SelectionV1.authenticated_v1.validate(61, 4194304);
    try SelectionV1.authenticated_v1.validate(121, 2097152);
    try SelectionV1.authenticated_v1.validate(210, 4194304);
    try std.testing.expectError(error.InvalidIncrementalCampaignGeometryV1, SelectionV1.authenticated_v1.validate(211, 2097152));
    try std.testing.expectError(error.InvalidIncrementalCampaignGeometryV1, SelectionV1.authenticated_v1.validate(61, 0));
    try std.testing.expectError(error.InvalidIncrementalCampaignGeometryV1, SelectionV1.authenticated_v1.validate(61, 1 << 25));
    try std.testing.expectError(error.UnsupportedIncrementalCampaignGeometryV1, SelectionV1.parse("authenticated-v2"));
}
