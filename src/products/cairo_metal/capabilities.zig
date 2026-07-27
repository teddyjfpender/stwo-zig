//! Machine-readable capability surface for the Cairo Metal product.

const std = @import("std");
const cairo_product = @import("cairo_product");
const identity = @import("identity.zig");

pub fn write(writer: anytype) !void {
    try std.json.Stringify.value(.{
        .schema_version = @as(u32, 1),
        .product = identity.value(),
        .backend_availability = .{ .metal = true },
        .frontend = .{
            .name = "stwo-cairo",
            .input_schema = "official-prover-input-json",
            .commands = &[_][]const u8{ "prove", "run-and-prove" },
            .program_types = &[_][]const u8{ "json", "executable" },
            .execution_layout = "all_cairo_stwo",
        },
        .channels = &[_][]const u8{"blake2s"},
        .proof_formats = &[_][]const u8{ "json", "cairo-serde", "binary" },
        .profiles = cairo_product.profile.supported_profiles[0..],
        .runtime_modes = &[_][]const u8{"authenticated-aot"},
        .stage_placement = .{
            .execution = "cairo-vm-sidecar",
            .witness = "host",
            .air_constraint_evaluation = "host-simd",
            .commitment_lde_quotient_fri = "metal",
        },
        .verification = .{
            .zig = true,
            .official_rust_release_gate = false,
        },
    }, .{}, writer);
}

test "Cairo Metal capabilities report hybrid stage placement" {
    var storage: [8192]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try write(&output);
    const encoded = output.buffered();
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"metal\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"cpu\":true") == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"air_constraint_evaluation\":\"host-simd\"",
    ) != null);
}
