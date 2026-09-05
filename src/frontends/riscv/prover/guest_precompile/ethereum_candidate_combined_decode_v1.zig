//! Declared-program decoder for the ordered two-member candidate registry.

const program_decode = @import("../../air/program/decode.zig");
const authority_mod =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");

pub const production_active = false;

pub const DeclaredDecodeAuthority = struct {
    authority: authority_mod.Authority,

    pub fn init(authority: authority_mod.Authority) !DeclaredDecodeAuthority {
        try authority.validate();
        return .{ .authority = authority };
    }

    pub fn validate(self: DeclaredDecodeAuthority) !void {
        try self.authority.validate();
    }

    pub fn decodeFetchedWord(
        self: DeclaredDecodeAuthority,
        word: u32,
    ) !program_decode.ProgramValues {
        try self.validate();
        if (word == self.authority.bulk_memcpy.bulk_memcpy.fixed_word) {
            const decoded = try self.authority.bulk_memcpy.bulk_memcpy.decode(word);
            return .{
                self.authority.bulk_memcpy.bulk_memcpy.allocation.proof_opcode_id,
                decoded.destination_register,
                decoded.source_register,
                decoded.length_register,
            };
        }
        if (word == self.authority.stack_swap.stack_swap.fixed_word) {
            const decoded = try self.authority.stack_swap.stack_swap.decode(word);
            return .{
                self.authority.stack_swap.stack_swap.allocation.proof_opcode_id,
                decoded.destination_register,
                decoded.lhs_pointer_register,
                decoded.rhs_pointer_register,
            };
        }
        return program_decode.decodeProgramWordForProfile(
            authority_mod.base_profile,
            word,
        );
    }

    pub fn decodeDeclaredWord(
        self: DeclaredDecodeAuthority,
        word: u32,
    ) !program_decode.ProgramValues {
        if (word == self.authority.bulk_memcpy.bulk_memcpy.fixed_word or
            word == self.authority.stack_swap.stack_swap.fixed_word)
        {
            return self.decodeFetchedWord(word);
        }
        try self.validate();
        return program_decode.decodeDeclaredProgramWordForProfile(
            authority_mod.base_profile,
            word,
        );
    }

    pub fn isDeclaredPadding(
        _: DeclaredDecodeAuthority,
        word: u32,
    ) bool {
        return program_decode.isDeclaredPaddingForProfile(
            authority_mod.base_profile,
            word,
        );
    }
};

comptime {
    if (production_active or authority_mod.production_active)
        @compileError("combined candidate decoder became active");
}

test "combined decoder admits both private words and delegates Ethereum" {
    const std = @import("std");
    const custom0 = @import("../../isa/custom0.zig");
    var digest = [_]u8{0} ** 32;
    digest[0] = 1;
    const authority = try authority_mod.Authority.create(digest);
    const decoder = try DeclaredDecodeAuthority.init(authority);
    try std.testing.expectEqualDeep(
        program_decode.ProgramValues{ 48, 10, 11, 12 },
        try decoder.decodeFetchedWord(authority.bulk_memcpy.bulk_memcpy.fixed_word),
    );
    try std.testing.expectEqualDeep(
        program_decode.ProgramValues{ 49, 0, 10, 11 },
        try decoder.decodeFetchedWord(authority.stack_swap.stack_swap.fixed_word),
    );
    const keccak = custom0.encodeKeccakf(5);
    try std.testing.expectEqualDeep(
        try program_decode.decodeProgramWordForProfile(authority_mod.base_profile, keccak),
        try decoder.decodeFetchedWord(keccak),
    );
}
