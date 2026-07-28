//! Frozen Native CPU proof identities for CUDA Plonk release gates.

const std = @import("std");
const cpu_plonk = @import("stwo_native_examples").plonk_logup;
const proof_wire = @import("stwo_proof_wire");

pub const Target = struct {
    log_n_rows: u32,
    canonical_bytes: usize,
    canonical_sha256: [32]u8,
};

pub const targets = [_]Target{
    .{
        .log_n_rows = 14,
        .canonical_bytes = 54_542,
        .canonical_sha256 = digest(
            "e2a69add9f86f85fb5ec1eb706a448400de2676607f19738767afae331e1b8d3",
        ),
    },
    .{
        .log_n_rows = 16,
        .canonical_bytes = 65_527,
        .canonical_sha256 = digest(
            "5f6b7d4f8e033ca46f1c5c7a3f1071c90a2b5b8df1bf1c0656e89588253f006f",
        ),
    },
};

fn digest(comptime encoded: *const [64]u8) [32]u8 {
    var output: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, encoded) catch unreachable;
    return output;
}

test "Plonk CPU oracle retains both frozen CUDA targets" {
    const allocator = std.testing.allocator;
    for (targets) |target| {
        try verify(allocator, target);
    }
}

pub fn verify(
    allocator: std.mem.Allocator,
    target: Target,
) !void {
    var output = try cpu_plonk.prove(
        allocator,
        @import("stwo_core").pcs.PcsConfig.default(),
        .{ .log_n_rows = target.log_n_rows },
    );
    defer output.proof.deinit(allocator);
    const canonical = try proof_wire.encodeProofBytes(
        allocator,
        output.proof,
    );
    defer allocator.free(canonical);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical, &actual, .{});
    try std.testing.expectEqual(target.canonical_bytes, canonical.len);
    try std.testing.expectEqualSlices(
        u8,
        &target.canonical_sha256,
        &actual,
    );
}
