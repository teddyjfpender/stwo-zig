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
pub const keccakf_funct7: u7 = 2;
pub const secp256k1_recover_funct7: u7 = 3;
pub const poseidon2_fixed_word: u32 =
    (@as(u32, poseidon2_funct7) << 25) | @as(u32, major_opcode);
pub const keccakf_fixed_word: u32 =
    (@as(u32, keccakf_funct7) << 25) | @as(u32, major_opcode);
pub const secp256k1_recover_fixed_word: u32 =
    (@as(u32, secp256k1_recover_funct7) << 25) | @as(u32, major_opcode);

pub const Opcode = enum {
    poseidon2_m31_permute_in_place_v1,
    keccakf_1600_permute_in_place_v1,
    secp256k1_recover_signer_v1,
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

/// Encode `stwo.keccakf.1600.v1 rs1` exactly as fixed by the guest ABI.
pub inline fn encodeKeccakf(rs1: u5) u32 {
    return keccakf_fixed_word | (@as(u32, rs1) << 15);
}

/// Encode `stwo.secp256k1.recover.v1 rs1` exactly as fixed by the guest ABI.
pub inline fn encodeSecp256k1Recover(rs1: u5) u32 {
    return secp256k1_recover_fixed_word | (@as(u32, rs1) << 15);
}

/// Decode only the zkVM-owned CUSTOM-0 opcode space under `profile`.
///
/// Non-CUSTOM-0 words are outside this decoder.  The base profile rejects the
/// entire major opcode, and the extension compares the complete word after
/// extracting the sole variable field; reserved encodings cannot alias v1.
pub inline fn decode(profile: ExecutionProfile, word: u32) DecodeError!Decoded {
    if (@as(u7, @truncate(word)) != major_opcode)
        return error.IllegalInstruction;
    const rs1: u5 = @truncate(word >> 15);
    return switch (profile) {
        .rv32im_zkvm_v1 => error.RequiredCapabilityUnavailable,
        .rv32im_zkvm_poseidon2_v1 => if (word == encodePoseidon2(rs1))
            .{ .opcode = .poseidon2_m31_permute_in_place_v1, .rs1 = rs1 }
        else
            error.InvalidPrecompileEncoding,
        .rv32im_zkvm_keccakf_v1 => if (word == encodeKeccakf(rs1))
            .{ .opcode = .keccakf_1600_permute_in_place_v1, .rs1 = rs1 }
        else
            error.InvalidPrecompileEncoding,
        .rv32im_zkvm_ethereum_v1 => if (word == encodeKeccakf(rs1))
            .{ .opcode = .keccakf_1600_permute_in_place_v1, .rs1 = rs1 }
        else if (word == encodeSecp256k1Recover(rs1))
            .{ .opcode = .secp256k1_recover_signer_v1, .rs1 = rs1 }
        else
            error.InvalidPrecompileEncoding,
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

test "Keccak-f encoding is exact and admitted only by its profile" {
    for (0..32) |register_index| {
        const rs1: u5 = @intCast(register_index);
        const word = encodeKeccakf(rs1);
        const admitted = try decode(.rv32im_zkvm_keccakf_v1, word);
        try std.testing.expectEqual(Opcode.keccakf_1600_permute_in_place_v1, admitted.opcode);
        try std.testing.expectEqual(rs1, admitted.rs1);
        try std.testing.expectError(
            error.InvalidPrecompileEncoding,
            decode(.rv32im_zkvm_poseidon2_v1, word),
        );
        try std.testing.expectError(
            error.RequiredCapabilityUnavailable,
            decode(.rv32im_zkvm_v1, word),
        );
        try std.testing.expectError(error.IllegalInstruction, base_decode.DecodedInst.decode(word));
    }

    const canonical = encodeKeccakf(7);
    const rs1_mask: u32 = 0x000f_8000;
    for (0..32) |bit_index| {
        const bit_mask = @as(u32, 1) << @intCast(bit_index);
        if (bit_mask & rs1_mask != 0) continue;
        const mutated = canonical ^ bit_mask;
        if (bit_index < 7) {
            try std.testing.expectError(
                error.IllegalInstruction,
                decode(.rv32im_zkvm_keccakf_v1, mutated),
            );
        } else {
            try std.testing.expectError(
                error.InvalidPrecompileEncoding,
                decode(.rv32im_zkvm_keccakf_v1, mutated),
            );
        }
    }
}

test "Ethereum profile combines unchanged Keccak-f and exact signer recovery" {
    for (0..32) |register_index| {
        const rs1: u5 = @intCast(register_index);
        const keccak = try decode(.rv32im_zkvm_ethereum_v1, encodeKeccakf(rs1));
        try std.testing.expectEqual(Opcode.keccakf_1600_permute_in_place_v1, keccak.opcode);
        try std.testing.expectEqual(rs1, keccak.rs1);

        const recover_word = encodeSecp256k1Recover(rs1);
        const recover = try decode(.rv32im_zkvm_ethereum_v1, recover_word);
        try std.testing.expectEqual(Opcode.secp256k1_recover_signer_v1, recover.opcode);
        try std.testing.expectEqual(rs1, recover.rs1);
        try std.testing.expectError(
            error.RequiredCapabilityUnavailable,
            decode(.rv32im_zkvm_v1, recover_word),
        );
        try std.testing.expectError(
            error.InvalidPrecompileEncoding,
            decode(.rv32im_zkvm_poseidon2_v1, recover_word),
        );
        try std.testing.expectError(
            error.InvalidPrecompileEncoding,
            decode(.rv32im_zkvm_keccakf_v1, recover_word),
        );
    }

    const canonical = encodeSecp256k1Recover(11);
    const rs1_mask: u32 = 0x000f_8000;
    for (0..32) |bit_index| {
        const bit_mask = @as(u32, 1) << @intCast(bit_index);
        if (bit_mask & rs1_mask != 0) continue;
        const mutated = canonical ^ bit_mask;
        if (mutated == encodeKeccakf(11)) {
            const decoded = try decode(.rv32im_zkvm_ethereum_v1, mutated);
            try std.testing.expectEqual(
                Opcode.keccakf_1600_permute_in_place_v1,
                decoded.opcode,
            );
            continue;
        }
        if (bit_index < 7) {
            try std.testing.expectError(
                error.IllegalInstruction,
                decode(.rv32im_zkvm_ethereum_v1, mutated),
            );
        } else {
            try std.testing.expectError(
                error.InvalidPrecompileEncoding,
                decode(.rv32im_zkvm_ethereum_v1, mutated),
            );
        }
    }
}
