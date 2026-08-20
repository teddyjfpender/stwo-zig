//! Serial proof-level acceptance for typed load/store witness authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

// Signed byte/halfword paths plus the fixture's prologue LW and epilogue SW
// rows. The row-level corpus separately covers all eight opcodes and offsets.
const BODY = [_]u32{
    0x001F_F337, // LUI x6, 0x001ff
    0xF800_0393, // ADDI x7, x0, -128
    0x0073_0023, // SB x7, 0(x6)
    0x0003_0503, // LB x10, 0(x6)
    0x0000_8437, // LUI x8, 0x8
    0x0083_1223, // SH x8, 4(x6)
    0x0043_1583, // LH x11, 4(x6)
};

test "typed load/store generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 10,
    });
    defer guest.deinit();
    try std.testing.expect((try guest.familyRowCount(.load_store)) >= 7);

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_load_store_authority,
    );
    std.debug.print(
        "\n  typed load/store authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
}
