//! Closed declared-program decoder for Ethereum plus private U256 SWAP.
//!
//! Ordinary/Keccak/recovery/padding semantics delegate to the frozen Ethereum
//! decoder. Exactly one additional CUSTOM-0 word is admitted from the private
//! registry authority; every other encoding remains rejected.

const std = @import("std");

const program_decode = @import("../../air/program/decode.zig");
const custom0 = @import("../../isa/custom0.zig");
const authority_mod = @import("../../isa/ethereum_stack_swap_candidate_v1.zig");
const private_registry = @import("../../isa/stack_swap_private_registry_v1.zig");

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
        if (word == self.authority.stack_swap.fixed_word) {
            const decoded = try self.authority.stack_swap.decode(word);
            return .{
                self.authority.stack_swap.allocation.proof_opcode_id,
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
        try self.validate();
        if (word == self.authority.stack_swap.fixed_word)
            return self.decodeFetchedWord(word);
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
    if (production_active or authority_mod.production_active or
        private_registry.allocated_funct7 == custom0.keccakf_funct7 or
        private_registry.allocated_funct7 == custom0.secp256k1_recover_funct7)
    {
        @compileError("Ethereum+SWAP declared decoder authority drifted");
    }
}
