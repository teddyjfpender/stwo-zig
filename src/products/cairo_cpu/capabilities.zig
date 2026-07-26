//! Machine-readable capability surface for the Cairo CPU/SIMD product.

const std = @import("std");
const identity = @import("identity.zig");
const profile = @import("profile.zig");

pub fn write(writer: anytype) !void {
    try std.json.Stringify.value(.{
        .schema_version = @as(u32, 1),
        .product = identity.value(),
        .backend_availability = .{
            .cpu = true,
            .simd = true,
        },
        .frontend = .{
            .name = "stwo-cairo",
            .input_schema = "official-prover-input-json",
            .commands = &[_][]const u8{"prove"},
        },
        .channels = &[_][]const u8{"blake2s"},
        .proof_formats = &[_][]const u8{ "json", "cairo-serde", "binary" },
        .profiles = profile.supported_profiles[0..],
        .verification = .{
            .zig = true,
            .official_rust_release_gate = true,
        },
    }, .{}, writer);
}

test "Cairo CPU capabilities expose no GPU backend" {
    var storage: [8192]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try write(&output);
    const encoded = output.buffered();
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"cpu\":true") != null);
    inline for (.{ "\"metal\"", "\"cuda\"" }) |forbidden|
        try std.testing.expect(std.mem.indexOf(u8, encoded, forbidden) == null);
}
