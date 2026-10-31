//! Explicit semantic profiles. V1 remains the qualified binary-only control.
pub const Profile = enum(u32) { binary_v1 = 1, alu_binary_v2 = 2 };
pub fn mainCount(profile: Profile) usize {
    return if (profile == .binary_v1) 44 else 46;
}
pub fn romCount(profile: Profile) usize {
    return if (profile == .binary_v1) 16 else 23;
}
pub const immediate = 44;
pub const branch = 45;
pub const MAX_MAIN = 46;
pub const MAX_ROM = 23;

/// Receiver-selected semantic/clock policy, independent of program and counts.
/// Program bytes and concrete geometry have their own authority identities.
pub fn identity(profile: Profile) [32]u8 {
    const std = @import("std");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(switch (profile) {
        .binary_v1 => "stwo-rv64/word16-cpu/binary-v1/REG6-reset0-clocks24/FUNCTION13-global-ids",
        .alu_binary_v2 => "stwo-rv64/word16-cpu/alu-binary-v2/REG6-reset0-clocks24/ROM23-two-branch-edges/FUNCTION13-global-ids/U16-canonical",
    });
    if (profile == .alu_binary_v2) hash.update(&@import("../word16_v1/alu_encoding.zig").identity());
    return hash.finalResult();
}
