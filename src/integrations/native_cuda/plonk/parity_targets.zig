//! Frozen Native CPU proof identities for CUDA Plonk release gates.

const std = @import("std");
const cpu_plonk = @import("stwo_native_examples").plonk;
const proof_wire = @import("stwo_proof_wire");

pub const Target = struct {
    log_n_rows: u32,
    canonical_bytes: usize,
    canonical_sha256: [32]u8,
};

pub const targets = [_]Target{
    .{
        .log_n_rows = 14,
        .canonical_bytes = 45_200,
        .canonical_sha256 = digest(
            "d63a2c92846148edc075fbb46fe63f5cf0fc6fe05ae1d5d54d09bda33b69dbaf",
        ),
    },
    .{
        .log_n_rows = 16,
        .canonical_bytes = 55_401,
        .canonical_sha256 = digest(
            "cfb36bf17fb3526bf1bdd9401fb885fd91ca46b9982fee1ca5fad33a1d574b72",
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
}
