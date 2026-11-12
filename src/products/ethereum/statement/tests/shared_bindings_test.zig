const std = @import("std");
const cpu = @import("stwo_riscv_cpu_integration");
const legacy_cpu = @import("legacy_riscv_cpu_integration");
const rv = @import("stwo_riscv_rv64");
const rv32 = @import("stwo_riscv_rv32");
const frontend = @import("stwo_riscv_frontend");

test "shared binding: native schema matches the existing chain authority" {
    const C = cpu.rv64_native_schema;
    const family: C.Family = .cpu_first;
    try std.testing.expectEqual(@as(u32, 4), C.RUNGS);
    try std.testing.expectEqual(cpu.rv64_gkr_chain.UNCLASSED, cpu.rv64_gkr_chain.cpuRungFor(.m6_v2_strict, family, @splat(0)));
    try std.testing.expectEqual(try cpu.rv64_gkr_chain.versionIdentity(.m5_chain_v1), C.versionIdentity(C.RUNGS));
}

test "shared binding: native rungs retain the legacy table identity" {
    const rungs = cpu.rv64_native_rungs;
    try std.testing.expect(rungs.Entry == legacy_cpu.rv64_ethereum_canon_rungs.Entry);
    try std.testing.expect(rungs.TruthEntry == legacy_cpu.rv64_ethereum_canon_rungs.TruthEntry);
    for (rungs.CPU) |entry| {
        const family: cpu.rv64_native_schema.Family = entry.family;
        try std.testing.expectEqual(@as(u32, 0), cpu.rv64_gkr_chain.cpuRungFor(.m6_v2_strict, family, entry.rungs[0]));
    }
}

test "shared binding: curve arithmetic retains packet tags and field operations" {
    try std.testing.expect(rv.machine.Cpu == frontend.rv64.machine.Cpu);
    const arithmetic = rv.service_calls.curves.arithmetic;
    try std.testing.expectEqual(arithmetic.BN254_G1_ADD_TAG, rv.service_calls.curves.tag(.bn254_g1_add));
    try std.testing.expectEqual(arithmetic.BLS12_381_G1_DOUBLE_TAG, rv.service_calls.curves.tag(.bls12_381_g1_double));
    const inverse = arithmetic.invMod(u256, 3, arithmetic.BN254_P);
    try std.testing.expectEqual(@as(u512, 1), (@as(u512, inverse) * 3) % arithmetic.BN254_P);
    try std.testing.expectEqual(@as(u384, 5), arithmetic.mod384(1, 2, 3, 11));
}

test "shared binding: artifact owner retains framing and rejection precedence" {
    try std.testing.expect(rv32.execution.trace.TraceRow == frontend.runner.trace.TraceRow);
    const native = rv32.prover;
    const Artifact = frontend.prover_mod.blake3_profile_artifact.ForOwner(struct {
        pub const profile = frontend.runner.segment_session.ExecutionProfile.rv32im_zkvm_v1;
        pub const extended = false;
        pub const count_recovery_calls = false;
        pub const manifest = native.blake3_execution_manifest;
        pub const codec = native.blake3_execution_codec;
        pub const proof_api = native.blake3_execution_proof;
        pub const magic = "B3RVART1";
    });
    try std.testing.expectEqualStrings("B3RVART1", Artifact.MAGIC);
    try std.testing.expectEqual(@as(usize, 28), Artifact.HEADER_BYTES);
    try std.testing.expectError(error.TruncatedExecutionArtifact, Artifact.split("", .{}));
    try std.testing.expectError(error.ExecutionArtifactTooLarge, Artifact.split("x", .{ .max_bytes = 0 }));
    var raw = [_]u8{0} ** 28;
    @memcpy(raw[0..8], Artifact.MAGIC);
    std.mem.writeInt(u32, raw[8..12], 1, .little);
    try std.testing.expectError(error.InvalidExecutionArtifactLength, Artifact.split(&raw, .{}));
    raw[0] ^= 1;
    try std.testing.expectError(error.InvalidExecutionArtifactVersion, Artifact.split(&raw, .{}));
}
