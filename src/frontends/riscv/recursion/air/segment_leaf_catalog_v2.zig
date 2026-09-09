//! Canonical SegmentV2 leaf typed AIR roster shared by verifier and backend
//! catalog export. Rows 34 and 35 remain separately admitted native providers.
const recursion = @import("../mod.zig");
const air = @import("mod.zig");
const manifest_mod = @import("segment_outer_adapter_manifest_v2.zig");

pub const Entry = struct { Air: type, row: manifest_mod.ComponentKey, requires_location: bool = false };
// Reuse the universal roster, replacing only the admitted V2 overrides. Each
// adapter authenticates its geometry against the canonical V2 typed catalog.
pub const LOGICAL_ROWS = rows: {
    var result: [manifest_mod.COMPONENT_COUNT - 2]Entry = undefined;
    for (air.universal_catalog.LOGICAL_ROWS, 0..) |entry, index| result[index] = .{
        .Air = switch (index) {
            11 => recursion.segment_statement_outer_source_v2.Air,
            12 => air.segment_public_outer_air_v2.PublicationHeader,
            13 => air.segment_public_outer_air_v2.NativePublicSums,
            14 => air.segment_public_outer_air_v2.PublicationSeal,
            15 => air.segment_public_outer_air_v2.StatementBoundary,
            16 => air.segment_public_outer_air_v2.NativeChallenges,
            17 => air.segment_public_outer_air_v2.ControlRelay,
            else => entry.Air,
        },
        .row = @enumFromInt(@intFromEnum(entry.row)),
        .requires_location = entry.requires_location,
    };
    result[34] = .{ .Air = recursion.segment_leaf_outer_air_v2.Statement, .row = .statement_source_v2 };
    result[35] = .{ .Air = recursion.segment_leaf_outer_air_v2.PublicLogUp, .row = .public_logup_source_v2 };
    result[36] = .{ .Air = air.segment_publication_input_provider_v2, .row = .segment_publication_input_provider_v2 };
    break :rows result;
};
