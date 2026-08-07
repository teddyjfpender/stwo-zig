//! Versioned machine profiles admitted by the RISC-V frontend.
//!
//! The base profile remains the exact Sail-refined RV32IM machine.  The
//! Poseidon2 profile is a zkVM extension and must be selected explicitly by
//! executable admission metadata before its CUSTOM-0 instruction is decoded.

const std = @import("std");
const base_profile = @import("profile.zig");

pub const base_name = base_profile.name;
pub const poseidon2_name = "rv32im-zkvm-poseidon2-v1";
pub const poseidon2_capability = "stwo.poseidon2-m31.permute-in-place@1";

pub const poseidon2_capability_bit: u64 = 1;
pub const poseidon2_abi_version: u16 = 1;

/// Canonical ELF admission-note envelope shared by readers and future emitters.
/// The descriptor remains a byte protocol; this is deliberately not a packed
/// native struct.
pub const admission = struct {
    pub const section_name = ".note.stwo.zkvm";
    pub const note_name = "STWO\x00";
    pub const note_type: u32 = 1;
    pub const descriptor_size: usize = 56;
    pub const descriptor_magic = "STWZKVM\x00";
    pub const schema_version: u16 = 1;
};

/// SHA-256 of the canonical typed program
/// `riscv.poseidon2_m31.permute.v1`.
pub const poseidon2_semantic_digest = [32]u8{
    0x9e, 0x8c, 0x3b, 0x5a, 0xcc, 0xdc, 0x2b, 0xe3,
    0x1c, 0xf8, 0xca, 0x12, 0x8b, 0x5b, 0x27, 0xc8,
    0x76, 0x13, 0xf6, 0x91, 0xee, 0x8f, 0xd2, 0x5e,
    0x03, 0x1f, 0x42, 0x86, 0xce, 0xac, 0x81, 0xed,
};

/// Protocol identity selected before execution begins.
///
/// Numeric values are the ELF admission-note profile IDs.  They are explicit
/// wire values, not enum ordinals that may be reordered freely.
pub const ExecutionProfile = enum(u16) {
    rv32im_zkvm_v1 = 0,
    rv32im_zkvm_poseidon2_v1 = 1,

    pub fn name(self: ExecutionProfile) []const u8 {
        return switch (self) {
            .rv32im_zkvm_v1 => base_name,
            .rv32im_zkvm_poseidon2_v1 => poseidon2_name,
        };
    }

    pub fn requiredCapabilities(self: ExecutionProfile) u64 {
        return switch (self) {
            .rv32im_zkvm_v1 => 0,
            .rv32im_zkvm_poseidon2_v1 => poseidon2_capability_bit,
        };
    }
};

test "execution profile wire IDs, names, and semantic identity are pinned" {
    try std.testing.expectEqual(@as(u16, 0), @intFromEnum(ExecutionProfile.rv32im_zkvm_v1));
    try std.testing.expectEqual(@as(u16, 1), @intFromEnum(ExecutionProfile.rv32im_zkvm_poseidon2_v1));
    try std.testing.expectEqualStrings(base_profile.name, ExecutionProfile.rv32im_zkvm_v1.name());
    try std.testing.expectEqualStrings(poseidon2_name, ExecutionProfile.rv32im_zkvm_poseidon2_v1.name());
    try std.testing.expectEqualStrings(
        "stwo.poseidon2-m31.permute-in-place@1",
        poseidon2_capability,
    );
    try std.testing.expectEqualStrings(".note.stwo.zkvm", admission.section_name);
    try std.testing.expectEqualSlices(u8, "STWO\x00", admission.note_name);
    try std.testing.expectEqual(@as(u32, 1), admission.note_type);
    try std.testing.expectEqual(@as(usize, 56), admission.descriptor_size);
    try std.testing.expectEqualSlices(u8, "STWZKVM\x00", admission.descriptor_magic);
    try std.testing.expectEqual(@as(u16, 1), admission.schema_version);
    try std.testing.expectEqual(@as(u16, 1), poseidon2_abi_version);
    try std.testing.expectEqual(@as(u64, 0), ExecutionProfile.rv32im_zkvm_v1.requiredCapabilities());
    try std.testing.expectEqual(poseidon2_capability_bit, ExecutionProfile.rv32im_zkvm_poseidon2_v1.requiredCapabilities());
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x9e, 0x8c, 0x3b, 0x5a, 0xcc, 0xdc, 0x2b, 0xe3,
        0x1c, 0xf8, 0xca, 0x12, 0x8b, 0x5b, 0x27, 0xc8,
        0x76, 0x13, 0xf6, 0x91, 0xee, 0x8f, 0xd2, 0x5e,
        0x03, 0x1f, 0x42, 0x86, 0xce, 0xac, 0x81, 0xed,
    }, &poseidon2_semantic_digest);
}
