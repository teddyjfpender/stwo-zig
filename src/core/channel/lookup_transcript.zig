//! Transcript steps shared by AIR provers built on the Stwo LogUp framework:
//! the channel salt, the lookup-element draw, and the claimed-sum mix.
//!
//! The Cairo prover (stwo-cairo `prover.rs`) and the circuit prover
//! (`crates/circuit_prover/src/prover.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) perform these three steps with
//! the same encoding; frontends call them here rather than re-deriving them.

const std = @import("std");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

/// The `(z, alpha)` pair every relation of a common-lookup-elements AIR is
/// built from (`CommonLookupElements::draw`: two secure felts, z first).
pub const LookupElements = struct {
    z: QM31,
    alpha: QM31,
};

/// `channel.mix_felts(&[channel_salt.into()])`: the salt is reduced modulo P
/// (`M31::from(u32)`) and mixed as one QM31 with zero upper coordinates.
pub fn mixChannelSalt(channel: anytype, channel_salt: u32) void {
    channel.mixFelts(&[_]QM31{QM31.fromBase(M31.fromU64(channel_salt))});
}

pub fn drawLookupElements(allocator: std.mem.Allocator, channel: anytype) !LookupElements {
    const values = try channel.drawSecureFelts(allocator, 2);
    defer allocator.free(values);
    return .{ .z = values[0], .alpha = values[1] };
}

/// `interaction_claim.mix_into`: every component's claimed sum, in component
/// order, as one `mix_felts`.
pub fn mixInteractionClaim(channel: anytype, claimed_sums: []const QM31) void {
    channel.mixFelts(claimed_sums);
}

const blake2s = @import("blake2s.zig");

test "lookup transcript: salt reduces modulo P like M31::from(u32)" {
    var reduced = blake2s.Blake2sM31Channel{};
    mixChannelSalt(&reduced, m31.Modulus + 5);
    var expected = blake2s.Blake2sM31Channel{};
    expected.mixFelts(&.{QM31.fromU32Unchecked(5, 0, 0, 0)});
    try std.testing.expectEqualSlices(u8, &expected.digestBytes(), &reduced.digestBytes());
}

test "lookup transcript: lookup elements are the next two secure felts" {
    const allocator = std.testing.allocator;
    var channel = blake2s.Blake2sM31Channel{};
    channel.mixU64(7);
    var reference = channel;
    const elements = try drawLookupElements(allocator, &channel);
    const expected = try reference.drawSecureFelts(allocator, 2);
    defer allocator.free(expected);
    try std.testing.expect(elements.z.eql(expected[0]));
    try std.testing.expect(elements.alpha.eql(expected[1]));
    try std.testing.expectEqualSlices(u8, &reference.digestBytes(), &channel.digestBytes());
}
