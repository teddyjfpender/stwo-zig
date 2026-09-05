//! Authenticated child-only recursion-wire boundary for the common fold.
//!
//! Unlike the temporal parent, the common fold has no row-11 statement lane:
//! its two verifier-rerecorded child graphs are the complete live arithmetic
//! input.  This process-local check permits that exact source shape without
//! fabricating a shared lane or weakening the ordinary source policy.

const std = @import("std");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const SERIALIZABLE_AUTHORITY = false;

pub fn validateAuthenticatedChildOnly(source: anytype) !void {
    if (source.shared_arithmetic != null)
        return error.CommonFoldSourceAuthorityMismatch;
    const expected = try source.pair.live.authenticatedCompositionLanes();
    for (source.children, expected) |child, expected_lane| {
        const actual = child.composition orelse
            return error.MissingCompositionAuthority;
        try actual.validate();
        try expected_lane.validate();
        if (!std.meta.eql(actual, expected_lane))
            return error.CommonFoldSourceAuthorityMismatch;
    }

    const rows = source.arithmetic_rows orelse
        return error.MissingCompositionAuthority;
    try rows.validate(source.children, null);
    var binary_public_terms: usize = 0;
    for (rows.plan.public_terms) |term| {
        if (term.active_in == .binary) binary_public_terms += 1;
    }
    if (binary_public_terms == 0)
        return error.CommonFoldSourceAuthorityMismatch;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or SERIALIZABLE_AUTHORITY)
        @compileError("common-fold wire-boundary authority contract drifted");
}
