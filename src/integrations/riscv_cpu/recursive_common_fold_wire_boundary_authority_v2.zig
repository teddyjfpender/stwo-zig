//! Authenticated arithmetic boundary for the common fold.
//! Both child composition graphs and the owned statement-fold lane are checked
//! against the same live source before any public wire terms are admitted.

const std = @import("std");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const SERIALIZABLE_AUTHORITY = false;

pub fn validateAuthenticated(source: anytype) !void {
    const shared = source.shared_arithmetic orelse return error.CommonFoldSourceAuthorityMismatch;
    if (!std.meta.eql(shared, try source.pair.statement.sharedInput())) return error.CommonFoldSourceAuthorityMismatch;
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
    try rows.validate(source.children, shared);
    var binary_public_terms: usize = 0;
    for (rows.plan.public_terms) |term| {
        if (term.active_in == .binary) binary_public_terms += 1;
    }
    if (binary_public_terms == 0)
        return error.CommonFoldSourceAuthorityMismatch;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 2 or SERIALIZABLE_AUTHORITY)
        @compileError("common-fold wire-boundary authority contract drifted");
}
