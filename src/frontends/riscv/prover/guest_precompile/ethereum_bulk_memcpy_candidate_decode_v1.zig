//! Candidate-only declared-program decoder for private bulk memcpy.
//!
//! Ordinary instructions retain the canonical base decoder. Exactly the one
//! registry-bound CUSTOM-0 word maps to proof opcode 48; every other CUSTOM-0
//! encoding fails closed.

const bulk = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const private_registry = @import("../../isa/bulk_memcpy_private_registry_v1.zig");
const program_decode = @import("../../air/program/decode.zig");

pub const production_active = false;

pub const DeclaredDecodeAuthority = struct {
    authority: private_registry.Authority,

    pub fn init(
        authority: private_registry.Authority,
    ) !DeclaredDecodeAuthority {
        try private_registry.validateAuthority(authority);
        return .{ .authority = authority };
    }

    pub fn validate(self: DeclaredDecodeAuthority) !void {
        try private_registry.validateAuthority(self.authority);
    }

    pub fn decodeFetchedWord(
        self: DeclaredDecodeAuthority,
        word: u32,
    ) !program_decode.ProgramValues {
        try self.validate();
        if (@as(u7, @truncate(word)) != bulk.major_opcode)
            return program_decode.decodeProgramWord(word);
        _ = try self.authority.decode(word);
        return .{
            self.authority.allocation.proof_opcode_id,
            bulk.destination_register,
            bulk.source_register,
            bulk.length_register,
        };
    }

    pub fn decodeDeclaredWord(
        self: DeclaredDecodeAuthority,
        word: u32,
    ) !program_decode.ProgramValues {
        return self.decodeFetchedWord(word);
    }

    pub fn isDeclaredPadding(_: DeclaredDecodeAuthority, _: u32) bool {
        return false;
    }
};

comptime {
    if (production_active or bulk.production_active or
        private_registry.production_active or bulk.proof_opcode_id != 48)
    {
        @compileError("bulk-memcpy candidate decode became production-active");
    }
}

test "bulk memcpy declared decoder is exact and fail closed" {
    const decoder = try DeclaredDecodeAuthority.init(
        try private_registry.authority(),
    );
    try @import("std").testing.expectEqualDeep(
        program_decode.ProgramValues{ 48, 10, 11, 12 },
        try decoder.decodeFetchedWord(bulk.fixed_word),
    );
    try @import("std").testing.expectError(
        error.InvalidBulkMemcpyEncoding,
        decoder.decodeFetchedWord(bulk.fixed_word ^ (@as(u32, 1) << 25)),
    );
}
