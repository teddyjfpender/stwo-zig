//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: precompile calls and geometry" {
    try std.testing.expect(api.air.sha256_compression_rows.Call == @import("../air/sha256_compression_rows.zig").Call);
    try std.testing.expect(api.air.sha256_compression_rows.Geometry == @import("../air/sha256_compression_rows.zig").Geometry);
}
