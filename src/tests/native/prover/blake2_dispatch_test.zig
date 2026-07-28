const std = @import("std");
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const fri = @import("stwo_core").fri;
const pcs = @import("stwo_core").pcs;
const proof_wire = @import("stwo_proof_wire");
const wide_fibonacci = @import("stwo_native_examples").wide_fibonacci;

const DispatchProof = struct {
    bytes: []u8,
    counts: @TypeOf(blake2_hash.testCompressionCounts()),

    fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn proveWithMode(
    allocator: std.mem.Allocator,
    mode: blake2_hash.BackendMode,
    config: pcs.PcsConfig,
    statement: wide_fibonacci.Statement,
) !DispatchProof {
    blake2_hash.setBackendMode(mode);
    blake2_hash.resetTestCompressionCounts();

    var output = try wide_fibonacci.prove(allocator, config, statement);
    var proof_owned = true;
    errdefer if (proof_owned) output.proof.deinit(allocator);
    const bytes = try proof_wire.encodeProofBytes(allocator, output.proof);
    errdefer allocator.free(bytes);

    proof_owned = false;
    try wide_fibonacci.verify(allocator, config, output.statement, output.proof);

    return .{
        .bytes = bytes,
        .counts = blake2_hash.testCompressionCounts(),
    };
}

test "native proof: Blake scalar and SIMD paths are byte-identical and mode-complete" {
    const allocator = std.testing.allocator;
    const previous = blake2_hash.getBackendMode();
    defer blake2_hash.setBackendMode(previous);

    const config = pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
    const statement = wide_fibonacci.Statement{ .log_n_rows = 5, .sequence_len = 8 };

    var scalar = try proveWithMode(allocator, .scalar, config, statement);
    defer scalar.deinit(allocator);
    try std.testing.expect(scalar.counts.scalar > 0);
    try std.testing.expectEqual(@as(u64, 0), scalar.counts.simd);
    try std.testing.expectEqual(@as(u64, 0), scalar.counts.parallel_simd_4);

    var simd = try proveWithMode(allocator, .simd, config, statement);
    defer simd.deinit(allocator);
    try std.testing.expectEqualSlices(u8, scalar.bytes, simd.bytes);
    if (blake2_hash.supportsSimdBackend()) {
        try std.testing.expect(simd.counts.simd > 0);
        try std.testing.expect(simd.counts.parallel_simd_4 > 0);
    } else {
        try std.testing.expect(simd.counts.scalar > 0);
        try std.testing.expectEqual(@as(u64, 0), simd.counts.parallel_simd_4);
    }
}
