//! Exact proof-level A/B acceptance for typed LT_REG witness authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

const BODY = [_]u32{
    0x8000_02b7, // LUI  x5, 0x80000
    0xfff0_0313, // ADDI x6, x0, -1
    encodeLtReg(.signed, 7, 5, 6), // negative x5 < -1
    encodeLtReg(.unsigned, 8, 5, 6), // high-bit x5 < 0xffff_ffff
    encodeLtReg(.signed, 5, 5, 6), // rd == rs1 alias
    encodeLtReg(.unsigned, 0, 5, 6), // x0 architectural discard
    encodeLtReg(.signed, 9, 0, 5), // x0 source against negative rhs
};

test "typed LT_REG generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 5), try guest.familyRowCount(.lt_reg));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_lt_reg_authority,
    );
    std.debug.print(
        "\n  typed LT_REG authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
    try guest.requireSailAgreement("typed LT_REG authority proof guest");
}

const Comparison = enum { signed, unsigned };

fn encodeLtReg(
    comptime comparison: Comparison,
    comptime rd: u5,
    comptime rs1: u5,
    comptime rs2: u5,
) u32 {
    const funct3: u32 = switch (comparison) {
        .signed => 2,
        .unsigned => 3,
    };
    return (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, rd) << 7) |
        0x33;
}
