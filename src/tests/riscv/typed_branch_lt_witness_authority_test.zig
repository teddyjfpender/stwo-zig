//! Exact proof-level A/B acceptance for typed BRANCH_LT witness authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

// Every branch converges at the following branch: a true comparison skips its
// inert ADDI while a false comparison executes it. This exercises physical
// taken and fallthrough targets without making later coverage path-dependent.
const BODY = [_]u32{
    0x8000_02b7, // LUI  x5, 0x80000: signed minimum, unsigned high bit
    0xfff0_0313, // ADDI x6, x0, -1: signed -1, unsigned maximum
    encodeBranch(.blt, 5, 6, 8), // signed true
    0x0000_0013,
    encodeBranch(.blt, 6, 5, 8), // signed false
    0x0000_0013,
    encodeBranch(.bltu, 5, 6, 8), // unsigned true
    0x0000_0013,
    encodeBranch(.bltu, 6, 5, 8), // unsigned false
    0x0000_0013,
    encodeBranch(.bge, 6, 5, 8), // signed true
    0x0000_0013,
    encodeBranch(.bge, 5, 6, 8), // signed false
    0x0000_0013,
    encodeBranch(.bgeu, 6, 5, 8), // unsigned true
    0x0000_0013,
    encodeBranch(.bgeu, 5, 6, 8), // unsigned false
    0x0000_0013,
    encodeBranch(.bge, 0, 0, 8), // equality true through x0 aliases
    0x0000_0013,
    encodeBranch(.blt, 0, 0, 8), // equality false through x0 aliases
    0x0000_0013,
    0x02a0_0493, // ADDI x9, x0, 42
};

test "typed BRANCH_LT generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 10), try guest.familyRowCount(.branch_lt));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_branch_lt_authority,
    );
    std.debug.print(
        "\n  typed BRANCH_LT authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
    try guest.requireSailAgreement("typed BRANCH_LT authority proof guest");
}

const Comparison = enum { blt, bge, bltu, bgeu };

fn encodeBranch(
    comptime comparison: Comparison,
    comptime rs1: u5,
    comptime rs2: u5,
    comptime offset: i32,
) u32 {
    comptime {
        if (offset < -4096 or offset > 4094 or (offset & 1) != 0)
            @compileError("branch offset is outside the RV32 B-immediate domain");
    }
    const funct3: u32 = switch (comparison) {
        .blt => 4,
        .bge => 5,
        .bltu => 6,
        .bgeu => 7,
    };
    const immediate: u32 = @bitCast(offset);
    return (((immediate >> 12) & 1) << 31) |
        (((immediate >> 5) & 0x3f) << 25) |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (((immediate >> 1) & 0xf) << 8) |
        (((immediate >> 11) & 1) << 7) |
        0x63;
}
