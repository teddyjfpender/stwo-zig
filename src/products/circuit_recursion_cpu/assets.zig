//! Authenticated circuit AIR assets shared by leaf, fold, and batch sessions.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");

const projection_bytes = @embedFile("circuit_air_projection");
const air_programs_bytes = @embedFile("circuit_air_programs");
const projection_sha256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09";

pub fn authenticatedAirPrograms() ![]const u8 {
    try authenticate(air_programs_bytes, circuit_cpu.air.bundle_sha256);
    return air_programs_bytes;
}

pub const Air = struct {
    projection: circuit.air_eval.projection.Projection,

    pub fn init(gpa: std.mem.Allocator) !Air {
        try authenticate(projection_bytes, projection_sha256);
        return .{ .projection = try circuit.air_eval.projection.parse(gpa, projection_bytes) };
    }

    pub fn deinit(self: *Air) void {
        self.projection.deinit();
    }

    pub fn circuitTable(self: *const Air, gpa: std.mem.Allocator) !circuit.air_eval.component_table.Table {
        return circuit.air_eval.circuit_components.build(gpa, &self.projection);
    }

    pub fn cairoTable(self: *const Air, gpa: std.mem.Allocator) !circuit.air_eval.component_table.Table {
        return circuit.air_eval.cairo_components.build(gpa, &self.projection);
    }
};

pub fn airBundle(gpa: std.mem.Allocator) !circuit_cpu.air.Bundle {
    return circuit_cpu.air.parse(gpa, try authenticatedAirPrograms());
}

pub fn authenticate(bytes: []const u8, comptime expected: *const [64]u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected)) return error.EmbeddedAssetDigestMismatch;
}

test "embedded assets are authenticated" {
    var air = try Air.init(std.testing.allocator);
    defer air.deinit();
    const programs = try authenticatedAirPrograms();
    try std.testing.expect(programs.len > 0);
}
