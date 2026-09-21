//! Canonical SegmentV2 leaf typed AIR roster shared by verifier and backend
//! catalog export. Rows 34 and 35 remain separately admitted native providers.
const universal_catalog = @import("universal_catalog.zig");
const boundary = @import("../segment_leaf_outer_air_v2.zig");
const public_air = @import("segment_public_outer_air_v2.zig");
const manifest_mod = @import("segment_outer_manifest_contract_v2.zig");

pub const Entry = struct { Air: type, row: manifest_mod.ComponentKey, requires_location: bool = false };
// Reuse the universal roster, replacing only the admitted V2 overrides. Each
// adapter authenticates its geometry against the canonical V2 typed catalog.
pub const LOGICAL_ROWS = rows: {
    var result: [manifest_mod.COMPONENT_COUNT - 2]Entry = undefined;
    for (universal_catalog.LOGICAL_ROWS, 0..) |entry, index| result[index] = .{
        .Air = switch (index) {
            11 => boundary.StatementSemanticsV2,
            12 => public_air.PublicationHeader,
            13 => public_air.NativePublicSums,
            14 => public_air.PublicationSeal,
            15 => public_air.StatementBoundary,
            16 => public_air.NativeChallenges,
            17 => public_air.ControlRelay,
            else => entry.Air,
        },
        .row = @enumFromInt(@intFromEnum(entry.row)),
        .requires_location = entry.requires_location,
    };
    result[34] = .{ .Air = boundary.Statement, .row = .statement_source_v2 };
    result[35] = .{ .Air = boundary.PublicLogUp, .row = .public_logup_source_v2 };
    result[36] = .{ .Air = @import("segment_publication_input_provider_v2.zig"), .row = .segment_publication_input_provider_v2 };
    break :rows result;
};
