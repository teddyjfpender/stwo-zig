//! Exact proof-level A/B acceptance for typed SHIFTS_IMM witness authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

const BODY = [_]u32{
    0x8000_02b7, // LUI  x5, 0x80000
    encodeShiftImm(.left, 6, 5, 0), // zero-shift boundary
    encodeShiftImm(.logical_right, 7, 5, 31), // logical high-bit shift
    encodeShiftImm(.arithmetic_right, 8, 5, 31), // arithmetic sign fill
    encodeShiftImm(.left, 5, 5, 8), // rd == rs1 alias and limb boundary
    encodeShiftImm(.logical_right, 0, 5, 7), // x0 architectural discard
    encodeShiftImm(.arithmetic_right, 9, 0, 1), // x0 source
};

test "typed SHIFTS_IMM generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 6), try guest.familyRowCount(.shifts_imm));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_shifts_imm_authority,
    );
    std.debug.print(
        "\n  typed SHIFTS_IMM authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
    try guest.requireSailAgreement("typed SHIFTS_IMM authority proof guest");
}

const Direction = enum { left, logical_right, arithmetic_right };

fn encodeShiftImm(
    comptime direction: Direction,
    comptime rd: u5,
    comptime rs1: u5,
    comptime amount: u5,
) u32 {
    const funct3: u32 = switch (direction) {
        .left => 1,
        .logical_right, .arithmetic_right => 5,
    };
    const immediate: u32 = @as(u32, amount) | switch (direction) {
        .left, .logical_right => 0,
        .arithmetic_right => 0x400,
    };
    return (immediate << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, rd) << 7) |
        0x13;
}
