//! Exact architectural and zkVM environment profile refined by the AIR.

const std = @import("std");

pub const name = "rv32im-zkvm-v1";
pub const xlen: u8 = 32;
pub const instruction_alignment: u8 = 4;
pub const address_bits: u8 = 32;
pub const register_count: u8 = 32;

/// The inherited sparse program commitment has 2^30 byte-addressed leaves.
/// A committed instruction occupies four consecutive leaves, so its aligned
/// word address is at most `2^30 - 4`.
pub const program_commitment_address_bits: u8 = 30;
pub const program_commitment_size: u32 =
    @as(u32, 1) << program_commitment_address_bits;
pub const max_program_word_address: u32 =
    program_commitment_size - instruction_alignment;

pub const ProgramAddressError = error{
    MisalignedProgramWord,
    ProgramAddressOutOfRange,
};

pub const Extension = enum {
    i,
    m,
};

pub const extensions = [_]Extension{ .i, .m };

pub const MisalignedAccess = enum {
    reject_before_retirement,
};

pub const TrapModel = enum {
    /// The proof language contains successful architectural retirements only.
    /// A trap-capable input is rejected before a witness can be committed.
    successful_retirements_only,
};

pub const SystemBoundary = enum {
    /// ECALL and EBREAK are host-control events, never proof rows. Strict
    /// release execution rejects them; hosted developer execution may handle
    /// them outside the architectural trace.
    host_control_not_retired,
};

pub const Completion = enum {
    /// The linker-defined halt flag and an unretired self-loop sentinel are
    /// the only completion mechanisms in the proof-bearing environment.
    halt_flag_or_unretired_sentinel,
};

pub const Environment = struct {
    misaligned_access: MisalignedAccess = .reject_before_retirement,
    traps: TrapModel = .successful_retirements_only,
    system: SystemBoundary = .host_control_not_retired,
    completion: Completion = .halt_flag_or_unretired_sentinel,
};

pub const environment = Environment{};

pub fn isInstructionAligned(pc: u32) bool {
    return pc & (instruction_alignment - 1) == 0;
}

pub fn requireInstructionAligned(pc: u32) error{InstructionAddressMisaligned}!void {
    if (!isInstructionAligned(pc)) return error.InstructionAddressMisaligned;
}

/// Validate the protocol-level program commitment address. This is narrower
/// than RV32's architectural address space because the compatibility Merkle
/// layout has a fixed 30-level leaf domain.
pub fn requireProgramWordAddress(address: u32) ProgramAddressError!void {
    if (!isInstructionAligned(address)) return error.MisalignedProgramWord;
    if (address > max_program_word_address) return error.ProgramAddressOutOfRange;
}

pub fn requireDataAligned(address: u32, width_bytes: u8) error{LoadStoreAddressMisaligned}!void {
    if (width_bytes == 0 or !std.math.isPowerOfTwo(width_bytes))
        unreachable;
    if (address & (width_bytes - 1) != 0)
        return error.LoadStoreAddressMisaligned;
}

test "RV32IM zkVM profile fixes alignment and extension surface" {
    try std.testing.expectEqual(@as(u8, 32), xlen);
    try std.testing.expectEqualSlices(Extension, &.{ .i, .m }, &extensions);
    try requireInstructionAligned(0x1000);
    try std.testing.expectError(
        error.InstructionAddressMisaligned,
        requireInstructionAligned(0x1002),
    );
    try requireProgramWordAddress(max_program_word_address);
    try std.testing.expectError(
        error.MisalignedProgramWord,
        requireProgramWordAddress(0x1002),
    );
    try std.testing.expectError(
        error.ProgramAddressOutOfRange,
        requireProgramWordAddress(program_commitment_size),
    );
    try requireDataAligned(0x2002, 2);
    try std.testing.expectError(
        error.LoadStoreAddressMisaligned,
        requireDataAligned(0x2002, 4),
    );
}
