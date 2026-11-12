const std = @import("std");
const artifacts = @import("blake3_profile_artifact.zig");
const Profile = @import("stwo_riscv_isa").execution_profile.ExecutionProfile;

test "full-width artifact framing preserves profile domains and rejection precedence" {
    inline for ([_]Profile{ .rv32im_zkvm_v1, .rv32im_zkvm_poseidon2_v1, .rv32im_zkvm_ethereum_v1, .rv32im_zkvm_ethereum_sha_v1 }, [_][]const u8{ "B3RVART1", "B3PVART1", "B3EVART1", "B3SVART1" }) |profile, magic| {
        const A = artifacts.ForExecutionProfile(profile);
        try std.testing.expectEqualStrings(magic, A.MAGIC);
        try std.testing.expectEqual(@as(usize, 28), A.HEADER_BYTES);
        try std.testing.expectError(error.TruncatedExecutionArtifact, A.split("", .{}));
        var raw = [_]u8{0} ** 28;
        @memcpy(raw[0..8], magic);
        std.mem.writeInt(u32, raw[8..12], 1, .little);
        try std.testing.expectError(error.InvalidExecutionArtifactLength, A.split(&raw, .{}));
        raw[0] ^= 1;
        try std.testing.expectError(error.InvalidExecutionArtifactVersion, A.split(&raw, .{}));
        try std.testing.expectError(error.ExecutionArtifactTooLarge, A.split(raw[0..1], .{ .max_bytes = 0 }));
    }
    try std.testing.expect(artifacts.ForProfile(false) == artifacts.ForExecutionProfile(.rv32im_zkvm_v1));
    try std.testing.expect(artifacts.ForProfile(true) == artifacts.ForExecutionProfile(.rv32im_zkvm_ethereum_v1));
}
