//! Profile-aware decoding for the zkVM-owned CUSTOM-0 opcode space.
//!
//! This module is intentionally separate from the Sail-refined base decoder.
//! A base-profile decoder never admits these words, and extension instructions
//! never enter the base runner's decoded-instruction cache.

const std = @import("std");
const base_decode = @import("decode.zig");
const execution_profile = @import("execution_profile.zig");

pub const ExecutionProfile = execution_profile.ExecutionProfile;

pub const major_opcode: u7 = 0x0b;
pub const poseidon2_funct7: u7 = 1;
pub const poseidon2_fixed_word: u32 =
    (@as(u32, poseidon2_funct7) << 25) | @as(u32, major_opcode);

pub const Opcode = enum {
    poseidon2_m31_permute_in_place_v1,
};

pub const Decoded = struct {
    opcode: Opcode,
    rs1: u5,
};

pub const DecodeError = error{
    IllegalInstruction,
    RequiredCapabilityUnavailable,
    InvalidPrecompileEncoding,
};

/// Encode `stwo.p2perm.m31.v1 rs1` exactly as fixed by the guest ABI.
pub inline fn encodePoseidon2(rs1: u5) u32 {
    return poseidon2_fixed_word | (@as(u32, rs1) << 15);
}

/// Decode only the zkVM-owned CUSTOM-0 opcode space under `profile`.
///
/// Non-CUSTOM-0 words are outside this decoder.  The base profile rejects the
/// entire major opcode, and the extension compares the complete word after
/// extracting the sole variable field; reserved encodings cannot alias v1.
pub inline fn decode(profile: ExecutionProfile, word: u32) DecodeError!Decoded {
    if (@as(u7, @truncate(word)) != major_opcode)
        return error.IllegalInstruction;
    if (profile != .rv32im_zkvm_poseidon2_v1)
        return error.RequiredCapabilityUnavailable;

    const rs1: u5 = @truncate(word >> 15);
    if (word != encodePoseidon2(rs1))
        return error.InvalidPrecompileEncoding;

    return .{
        .opcode = .poseidon2_m31_permute_in_place_v1,
        .rs1 = rs1,
    };
}

test "Poseidon2 CUSTOM-0 admits exactly the 32 rs1 encodings in the extension profile" {
    try std.testing.expectEqual(@as(u32, 0x0200_000b), encodePoseidon2(0));
    try std.testing.expectEqual(@as(u32, 0x020f_800b), encodePoseidon2(31));
    for (0..32) |register_index| {
        const rs1: u5 = @intCast(register_index);
        const word = encodePoseidon2(rs1);
        const decoded = try decode(.rv32im_zkvm_poseidon2_v1, word);
        try std.testing.expectEqual(Opcode.poseidon2_m31_permute_in_place_v1, decoded.opcode);
        try std.testing.expectEqual(rs1, decoded.rs1);

        // The existing RV32IM profile and canonical decoder remain byte-for-byte
        // closed over the whole CUSTOM-0 family.
        try std.testing.expectError(
            error.RequiredCapabilityUnavailable,
            decode(.rv32im_zkvm_v1, word),
        );
        try std.testing.expectError(
            error.IllegalInstruction,
            base_decode.DecodedInst.decode(word),
        );
    }
}

test "Poseidon2 CUSTOM-0 compares every fixed encoding bit" {
    const canonical = encodePoseidon2(17);
    const rs1_mask: u32 = 0x000f_8000;
    for (0..32) |bit_index| {
        const bit = @as(u32, 1) << @intCast(bit_index);
        if (bit & rs1_mask != 0) continue;
        const mutated = canonical ^ bit;
        if (bit_index < 7) {
            try std.testing.expectError(
                error.IllegalInstruction,
                decode(.rv32im_zkvm_poseidon2_v1, mutated),
            );
        } else {
            try std.testing.expectError(
                error.InvalidPrecompileEncoding,
                decode(.rv32im_zkvm_poseidon2_v1, mutated),
            );
        }
    }
}

test "CUSTOM-0 decoder does not claim ordinary RV32IM words" {
    try std.testing.expectError(
        error.IllegalInstruction,
        decode(.rv32im_zkvm_poseidon2_v1, 0x0010_0093),
    );
}
