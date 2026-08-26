//! Exact proof-level A/B acceptance for typed RV32 high-word multiply authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

const BODY = [_]u32{
    0x8000_02b7, // LUI  x5, 0x80000
    0xfff0_0313, // ADDI x6, x0, -1
    0x0010_0393, // ADDI x7, x0, 1
    encodeMulHigh(.signed_signed, 8, 5, 6), // negative * negative
    encodeMulHigh(.signed_unsigned, 9, 5, 6), // negative * maximal unsigned
    encodeMulHigh(.unsigned_unsigned, 10, 5, 6), // high-bit unsigned operands
    encodeMulHigh(.signed_signed, 5, 5, 5), // rd == rs1 == rs2 alias chain
    encodeMulHigh(.signed_unsigned, 0, 5, 6), // x0 architectural discard
    encodeMulHigh(.unsigned_unsigned, 11, 0, 6), // x0 source operand
};

test "typed MULH generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 11,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 6), try guest.familyRowCount(.mulh));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_mulh_authority,
    );
    std.debug.print(
        "\n  typed MULH authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
}

const ProductKind = enum {
    signed_signed,
    signed_unsigned,
    unsigned_unsigned,
};

fn encodeMulHigh(
    comptime kind: ProductKind,
    comptime rd: u5,
    comptime rs1: u5,
    comptime rs2: u5,
) u32 {
    const funct3: u32 = switch (kind) {
        .signed_signed => 1,
        .signed_unsigned => 2,
        .unsigned_unsigned => 3,
    };
    return (0x01 << 25) |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, rd) << 7) |
        0x33;
}
