//! Fixed-register CUSTOM-0 ABI proposed for word-granular bulk memcpy.
//!
//! The instruction reads the ordinary C ABI argument registers directly:
//! a0=destination, a1=source, a2=length.  All 32 instruction bits are fixed,
//! which avoids a descriptor-memory round trip and makes the declared-program
//! tuple unambiguous.  The decoder is intentionally not wired into the live
//! Ethereum profile while the caller/interaction proof remains incomplete.

const std = @import("std");

pub const production_active = false;
pub const major_opcode: u7 = 0x0b;
pub const funct7: u7 = 4;
pub const destination_register: u5 = 10; // a0
pub const source_register: u5 = 11; // a1
pub const length_register: u5 = 12; // a2
pub const proof_opcode_id: u32 = 48;

pub const fixed_word: u32 =
    (@as(u32, funct7) << 25) |
    (@as(u32, length_register) << 20) |
    (@as(u32, source_register) << 15) |
    (@as(u32, destination_register) << 7) |
    @as(u32, major_opcode);

pub const Decoded = struct {
    destination_register: u5,
    source_register: u5,
    length_register: u5,
};

pub fn decode(word: u32) error{InvalidBulkMemcpyEncoding}!Decoded {
    if (word != fixed_word) return error.InvalidBulkMemcpyEncoding;
    return .{
        .destination_register = destination_register,
        .source_register = source_register,
        .length_register = length_register,
    };
}

pub fn programTuple(pc: u32) [5]u32 {
    return .{
        pc,
        proof_opcode_id,
        destination_register,
        source_register,
        length_register,
    };
}

test "bulk memcpy candidate fixes every instruction bit and C ABI register" {
    try std.testing.expectEqual(@as(u32, 0x08c5_850b), fixed_word);
    try std.testing.expectEqual(
        Decoded{
            .destination_register = 10,
            .source_register = 11,
            .length_register = 12,
        },
        try decode(fixed_word),
    );
    for (0..32) |bit| try std.testing.expectError(
        error.InvalidBulkMemcpyEncoding,
        decode(fixed_word ^ (@as(u32, 1) << @intCast(bit))),
    );
    try std.testing.expectEqualDeep(
        [_]u32{ 0x1000, 48, 10, 11, 12 },
        programTuple(0x1000),
    );
}
