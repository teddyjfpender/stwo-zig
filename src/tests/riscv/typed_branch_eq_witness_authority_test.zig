//! Exact proof-level A/B acceptance for typed RV32 BEQ/BNE authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

// Execution order is 0,1,2,5,6,7,4,5,6,7,8,9. It covers BEQ/BNE,
// equality/inequality, forward/backward targets, physical fallthrough, and a
// logically taken branch whose +4 target is fallthrough-equivalent.
const BODY = [_]u32{
    0x0000_0137, // LUI  x2, 0
    0x0010_0193, // ADDI x3, x0, 1
    encodeBranch(.bne, 2, 3, 12), // unequal: forward taken to word 5
    0x0000_0013, // skipped NOP
    0x0010_0113, // ADDI x2, x0, 1; reached by the backward branch
    encodeBranch(.beq, 2, 3, 4), // unequal on both visits: not taken
    0x0000_0193, // ADDI x3, x0, 0
    encodeBranch(.beq, 2, 3, -12), // first equal/taken, second unequal/not-taken
    encodeBranch(.bne, 2, 3, 4), // taken with fallthrough-equivalent target
    0x02a0_0493, // ADDI x9, x0, 42
};

test "typed BRANCH_EQ generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 9,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 6), try guest.familyRowCount(.branch_eq));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_branch_eq_authority,
    );
    std.debug.print(
        "\n  typed BRANCH_EQ authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
    try guest.requireSailAgreement("typed BRANCH_EQ authority proof guest");
}

const Comparison = enum { beq, bne };

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
        .beq => 0,
        .bne => 1,
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
