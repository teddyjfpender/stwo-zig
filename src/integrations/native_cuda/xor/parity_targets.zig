//! Frozen clean-M5 CPU targets for final CUDA/Rust parity gates.

const std = @import("std");
const cpu_xor = @import("stwo_native_examples").xor;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("stwo_proof_wire");

pub const Target = struct {
    statement: cpu_xor.Statement,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};

pub const clean_m5_functional = [_]Target{
    .{
        .statement = .{ .log_size = 14, .log_step = 2, .offset = 3 },
        .proof_bytes = 54_565,
        .proof_sha256 = digest(
            "f2399d3b372d1b6dfa757b3a795f2d4615b3203796ce2f44147bc8e79bdc93df",
        ),
    },
    .{
        .statement = .{ .log_size = 16, .log_step = 2, .offset = 3 },
        .proof_bytes = 59_774,
        .proof_sha256 = digest(
            "3b7ab569122afb34cc6d4bb1d4844b1fc13606bcd5539d29b053578e8a22749b",
        ),
    },
};

pub fn checkCpuOracle(
    allocator: std.mem.Allocator,
    target: Target,
) !void {
    const protocol = pcs.PcsConfig.default();
    var output = try cpu_xor.prove(
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
            "XOR parity target drift: bytes={d}, sha256={s}\n",
            .{ encoded.len, &actual_hex },
        );
        return error.ParityTargetMismatch;
    }

    proof_live = false;
    try cpu_xor.verify(
        allocator,
        protocol,
        target.statement,
        output.proof,
    );
}

fn digest(comptime text: []const u8) [32]u8 {
    var output: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&output, text) catch
        @compileError("invalid XOR parity target digest");
    return output;
}

test "XOR parity targets cover increasing public trace sizes" {
    try std.testing.expectEqual(@as(usize, 2), clean_m5_functional.len);
    try std.testing.expect(
        clean_m5_functional[0].statement.log_size <
            clean_m5_functional[1].statement.log_size,
    );
    try std.testing.expect(
        clean_m5_functional[0].proof_bytes <
            clean_m5_functional[1].proof_bytes,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &clean_m5_functional[0].proof_sha256,
        &clean_m5_functional[1].proof_sha256,
    ));
}

test "XOR clean-M5 CPU parity targets remain exact and verified" {
    for (clean_m5_functional) |target| {
        try checkCpuOracle(std.testing.allocator, target);
    }
}
