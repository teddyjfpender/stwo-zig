//! Exact proof-level A/B acceptance for typed LT_IMM witness authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

const BODY = [_]u32{
    0x8000_02b7, // LUI   x5, 0x80000
    encodeLtImm(.signed, 6, 5, 0), // negative x5 < 0
    encodeLtImm(.unsigned, 7, 5, -1), // high-bit x5 < 0xffff_ffff
    encodeLtImm(.signed, 5, 5, -2048), // rd == rs1 alias
    encodeLtImm(.unsigned, 0, 5, 2047), // x0 architectural discard
    encodeLtImm(.signed, 9, 0, 1), // x0 source and positive boundary
};

test "typed LT_IMM generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 5), try guest.familyRowCount(.lt_imm));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_lt_imm_authority,
    );
    std.debug.print(
        "\n  typed LT_IMM authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
    try guest.requireSailAgreement("typed LT_IMM authority proof guest");
}

const Comparison = enum { signed, unsigned };

fn encodeLtImm(
    comptime comparison: Comparison,
    comptime rd: u5,
    comptime rs1: u5,
    comptime immediate: i12,
) u32 {
    const immediate_bits: u12 = @bitCast(immediate);
    const funct3: u32 = switch (comparison) {
        .signed => 2,
        .unsigned => 3,
    };
    return (@as(u32, immediate_bits) << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, rd) << 7) |
        0x13;
}
