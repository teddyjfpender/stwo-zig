//! Frozen Native CPU targets for final CUDA/Rust Poseidon parity gates.

const std = @import("std");
const cpu_poseidon = @import("stwo_native_examples").poseidon;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("stwo_proof_wire");

pub const Target = struct {
    statement: cpu_poseidon.Statement,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};

pub const clean_m5_functional = [_]Target{
    .{
        .statement = .{ .log_n_instances = 10 },
        .proof_bytes = 115_317,
        .proof_sha256 = digest(
            "f9a36e9a0f3450832974c58b46b447d1212d1559329013f160511c730b0329b3",
        ),
    },
    .{
        .statement = .{ .log_n_instances = 13 },
        .proof_bytes = 131_420,
        .proof_sha256 = digest(
            "37daf8a992c796b0a38a883df51035fcdd59c60e2df90df51c5812b8e903a1fc",
        ),
    },
};

pub fn checkCpuOracle(
    allocator: std.mem.Allocator,
    target: Target,
) !void {
    const protocol = pcs.PcsConfig.default();
    var output = try cpu_poseidon.prove(
        allocator,
        protocol,
        target.statement,
    );
    var proof_live = true;
    defer if (proof_live) output.proof.deinit(allocator);

    const encoded = try proof_wire.encodeProofBytes(
        allocator,
        output.proof,
    );
    defer allocator.free(encoded);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &actual, .{});
    if (encoded.len != target.proof_bytes or
        !std.mem.eql(u8, &actual, &target.proof_sha256))
    {
        const actual_hex = std.fmt.bytesToHex(actual, .lower);
        std.debug.print(
            "Poseidon parity target drift: bytes={d}, sha256={s}\n",
            .{ encoded.len, &actual_hex },
        );
        return error.ParityTargetMismatch;
    }

    proof_live = false;
    try cpu_poseidon.verify(
        allocator,
        protocol,
        output.statement,
        output.proof,
    );
}

fn digest(comptime text: []const u8) [32]u8 {
    var output: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, text) catch
        @compileError("invalid Poseidon parity target digest");
    return output;
}

test "Poseidon parity targets increase trace size with fixed width" {
    try std.testing.expectEqual(
        @as(usize, 2),
        clean_m5_functional.len,
    );
    try std.testing.expect(
        clean_m5_functional[0].statement.log_n_instances <
            clean_m5_functional[1].statement.log_n_instances,
    );
    try std.testing.expect(
        clean_m5_functional[0].proof_bytes <
            clean_m5_functional[1].proof_bytes,
    );
}

test "Poseidon Native CPU parity targets remain exact and verified" {
    for (clean_m5_functional) |target| {
        try checkCpuOracle(std.testing.allocator, target);
    }
}
