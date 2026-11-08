//! Serial proof-level acceptance for typed DIV/REM witness authority.

const std = @import("std");
const committed = @import("committed_forgery_harness.zig");
const authority = @import("typed_witness_authority_test_support.zig");

/// `x6 = 100`, `x7 = 3`, followed by DIV, DIVU, REM, and REMU.
const BODY = [_]u32{
    0x0640_0313,
    0x0030_0393,
    0x0273_4533,
    0x0273_55B3,
    0x0273_6633,
    0x0273_76B3,
};

test "typed DIV generated and legacy authorities produce identical proofs" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 10,
    });
    defer guest.deinit();
    try std.testing.expectEqual(@as(usize, 4), try guest.familyRowCount(.div));

    const evidence = try authority.compare(
        allocator,
        &guest,
        .legacy_div_authority,
    );
    std.debug.print(
        "\n  typed DIV authority proof: bytes={d} sha256={s} " ++
            "transcript={s} draws={d}\n",
        .{
            evidence.proof_bytes,
            &std.fmt.bytesToHex(evidence.proof_sha256, .lower),
            &std.fmt.bytesToHex(evidence.transcript_digest, .lower),
            evidence.transcript_draws,
        },
    );
}
