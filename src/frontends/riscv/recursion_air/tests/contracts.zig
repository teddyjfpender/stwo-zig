//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: logical transcript and routing types" {
    try std.testing.expect(api.transcript.payload.Definition == @import("../transcript_payload.zig").Definition);
    try std.testing.expect(api.statement.publication.RootCoordinate == @import("../statement_publication.zig").RootCoordinate);
}
