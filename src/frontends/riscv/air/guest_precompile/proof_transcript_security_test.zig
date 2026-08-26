//! Soundness regression for detailed profile-claim Fiat--Shamir binding.

const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const subject = @import("proof_transcript.zig");
const support = @import("proof_transcript_test.zig");

test "profile transcript binds compensating detailed batch mutations before composition" {
    const allocator = std.testing.allocator;
    const fixture = try support.Fixture.init(2);
    var claim = try support.OwnedInteractionClaim.init(
        allocator,
        &fixture.core,
        &fixture.extension,
    );
    defer claim.deinit(allocator);

    var original = Blake2sChannel{};
    try subject.mixInteractionClaim(
        &original,
        &fixture.core,
        &fixture.extension,
        &claim.claim,
        claim.detailed(),
    );
    const original_alpha = try original.drawSecureFelts(allocator, 1);
    defer allocator.free(original_alpha);

    const delta = QM31.fromU32Unchecked(7, 11, 13, 17);
    claim.caller[0] = claim.caller[0].add(delta);
    claim.caller[1] = claim.caller[1].add(delta.neg());

    var changed = Blake2sChannel{};
    try subject.mixInteractionClaim(
        &changed,
        &fixture.core,
        &fixture.extension,
        &claim.claim,
        claim.detailed(),
    );
    const changed_alpha = try changed.drawSecureFelts(allocator, 1);
    defer allocator.free(changed_alpha);

    try std.testing.expect(!original_alpha[0].eql(changed_alpha[0]));
    try std.testing.expect(!std.mem.eql(
        u8,
        &original.digestBytes(),
        &changed.digestBytes(),
    ));
}
