//! Exact proof-level A/B acceptance for typed SHIFTS_REG witness authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

const BODY = [_]u32{
    0x8000_02b7, // LUI  x5, 0x80000
    0xfff0_0313, // ADDI x6, x0, -1 (low five bits = 31)
    0x0010_0393, // ADDI x7, x0, 1
    encodeShiftReg(.left, 8, 5, 7), // ordinary left shift
    encodeShiftReg(.logical_right, 9, 5, 6), // logical high-bit shift
    encodeShiftReg(.arithmetic_right, 10, 5, 6), // arithmetic sign fill
    encodeShiftReg(.left, 5, 5, 7), // rd == rs1 alias
    encodeShiftReg(.logical_right, 0, 5, 7), // x0 architectural discard
    encodeShiftReg(.arithmetic_right, 11, 0, 7), // x0 source
};

test "typed SHIFTS_REG generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 11,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 6), try guest.familyRowCount(.shifts_reg));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_shifts_reg_authority,
    );
    std.debug.print(
        "\n  typed SHIFTS_REG authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
    try guest.requireSailAgreement("typed SHIFTS_REG authority proof guest");
}

const Direction = enum { left, logical_right, arithmetic_right };

fn encodeShiftReg(
    comptime direction: Direction,
    comptime rd: u5,
    comptime rs1: u5,
    comptime rs2: u5,
) u32 {
    const funct3: u32 = switch (direction) {
        .left => 1,
        .logical_right, .arithmetic_right => 5,
    };
    const funct7: u32 = switch (direction) {
        .left, .logical_right => 0,
        .arithmetic_right => 0x20,
    };
    return (funct7 << 25) |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, rd) << 7) |
        0x33;
}
