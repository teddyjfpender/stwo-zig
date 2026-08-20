//! Serial proof-level A/B acceptance for typed RV32 `MUL` witness authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

const BODY = [_]u32{
    0x8000_02b7, // LUI  x5, 0x80000
    0xfff0_0313, // ADDI x6, x0, -1
    encodeMul(7, 5, 6), // ordinary high-carry operands
    encodeMul(5, 5, 5), // rd == rs1 alias
    encodeMul(0, 5, 6), // x0 architectural discard
    encodeMul(9, 0, 6), // x0 source operand
};

test "typed MUL generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 4), try guest.familyRowCount(.mul));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_mul_authority,
    );
    std.debug.print(
        "\n  typed MUL authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
}

fn encodeMul(comptime rd: u5, comptime rs1: u5, comptime rs2: u5) u32 {
    return (0x01 << 25) |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (@as(u32, rd) << 7) |
        0x33;
}
