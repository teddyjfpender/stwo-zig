//! Historical targets for the provisional CUDA Blake v1 protocol.

const std = @import("std");
const geometry = @import("geometry.zig");

pub const Target = struct {
    statement: geometry.LegacyStatement,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};

pub const clean_m5_functional = [_]Target{
    .{
        .statement = .{ .log_n_rows = 10, .n_rounds = 10 },
        .proof_bytes = 97_973,
        .proof_sha256 = digest(
            "4153acd6e32a98b9d240730062f7fa35e2e31eca915f01c179337f04d409cbd2",
        ),
    },
    .{
        .statement = .{ .log_n_rows = 12, .n_rounds = 10 },
        .proof_bytes = 107_867,
        .proof_sha256 = digest(
            "c614a48bd0678839d904f3d9b0d6396653422cc5044f8e71b9b8f3512f42308b",
        ),
    },
};

pub fn checkCpuOracle(
    _: std.mem.Allocator,
    _: Target,
) !void {
    return error.UnsupportedExactBlakeProtocol;
}

fn digest(comptime text: []const u8) [32]u8 {
    var output: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, text) catch
        @compileError("invalid Blake parity target digest");
    return output;
}

test "Blake parity targets increase trace size with fixed width" {
    try std.testing.expectEqual(
        @as(usize, 2),
        clean_m5_functional.len,
    );
    try std.testing.expect(
        clean_m5_functional[0].statement.log_n_rows <
            clean_m5_functional[1].statement.log_n_rows,
    );
    try std.testing.expect(
        clean_m5_functional[0].proof_bytes <
            clean_m5_functional[1].proof_bytes,
    );
}

test "legacy Blake targets cannot claim exact CPU parity" {
    for (clean_m5_functional) |target| {
        try std.testing.expectError(
            error.UnsupportedExactBlakeProtocol,
            checkCpuOracle(std.testing.allocator, target),
        );
    }
}
