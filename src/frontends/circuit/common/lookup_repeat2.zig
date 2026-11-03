//! Candidate outer-circuit lookup profile. Construction primitives only: no
//! existing receiver or registry admits this profile until both AIR lanes,
//! decoder geometry and recursive verification are qualified together.
const std = @import("std");
const core = @import("stwo_core");
const List = @import("component_list.zig");
const Q = core.fields.qm31.QM31;
const Transcript = core.channel.lookup_transcript;
pub const Elements = Transcript.LookupElements;
pub const Claims = List.PerComponent(Q);
pub const lookup_repetitions = 2;
pub const queries = 108;
pub const fri_pow_bits = 20;
pub const interaction_pow_bits = 20;
pub const receiver_qualified = false;
pub const domain = "stwo/circuit/lookup-repeat2/q108-p20-fold4/candidate-v1";

pub fn targetPcs(trace_log: u32) !core.pcs.config_v2.PcsConfigV2 {
    if (trace_log < 5 or trace_log > 26) return error.InvalidRepeat2Geometry;
    return core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(try core.pcs.config_v2.FriConfigV2.init(fri_pow_bits, 0, 1, queries, 4), trace_log);
}
/// Registry identity differs even for an identical topology and MAIN root.
/// This digest is not a verifier key and cannot establish receiver authority.
pub fn registryIdentity(topology: [32]u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(&topology);
    return hash.finalResult();
}
pub fn requireProductionReceiver() !void {
    return error.UnqualifiedRepeat2CircuitReceiver;
}
/// Caller has mixed this profile's identity and committed the sole MAIN tree.
/// Both pairs are receiver-derived; producer-supplied pairs are not authority.
pub fn draw(a: std.mem.Allocator, channel: anytype) ![2]Elements {
    var next = channel.*;
    const first = try Transcript.drawLookupElements(a, &next);
    const second = try Transcript.drawLookupElements(a, &next);
    if (first.z.eql(second.z) and first.alpha.eql(second.alpha)) return error.ReusedLookupChallenge;
    channel.* = next;
    return .{ first, second };
}
pub fn mixClaims(channel: anytype, claims: [2]Claims) void {
    var flat: [2 * List.N_COMPONENTS]Q = undefined;
    @memcpy(flat[0..List.N_COMPONENTS], &claims[0].toArray());
    @memcpy(flat[List.N_COMPONENTS..], &claims[1].toArray());
    Transcript.mixInteractionClaim(channel, &flat);
}
test "repeat2 target identity transcript and admission are distinct from legacy" {
    const C = core.channel.blake2s.Blake2sM31Channel;
    var channel = C{};
    channel.mixU32s(&.{ 17, 29 }); // stand-in for an already bound MAIN digest
    var reference = channel;
    const actual = try draw(std.testing.allocator, &channel);
    const first = try Transcript.drawLookupElements(std.testing.allocator, &reference);
    const second = try Transcript.drawLookupElements(std.testing.allocator, &reference);
    try std.testing.expect(actual[0].z.eql(first.z) and actual[1].alpha.eql(second.alpha));
    try std.testing.expectEqualSlices(u8, &reference.digestBytes(), &channel.digestBytes());
    try std.testing.expect(!std.mem.eql(u8, &registryIdentity(@splat(0)), &registryIdentity(@splat(1))));
    const config = try targetPcs(20);
    try std.testing.expectEqual(@as(u32, 108), config.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 20), config.fri_config.pow_bits);
    try std.testing.expectError(error.UnqualifiedRepeat2CircuitReceiver, requireProductionReceiver());
    try std.testing.expectError(error.InvalidRepeat2Geometry, targetPcs(27));
}

test "repeat2 draw is failure atomic and claimed sums bind both lanes" {
    const C = core.channel.blake2s.Blake2sM31Channel;
    var channel = C{};
    channel.mixU32s(&.{ 17, 29 });
    const initial = channel.digestBytes();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    try std.testing.expectError(error.OutOfMemory, draw(failing.allocator(), &channel));
    try std.testing.expectEqualSlices(u8, &initial, &channel.digestBytes());
    _ = try draw(std.testing.allocator, &channel);
    var reference = channel;
    var claims: [2]Claims = .{ Claims.fromArray(@splat(Q.zero())), Claims.fromArray(@splat(Q.zero())) };
    mixClaims(&channel, claims);
    claims[1].eq = Q.one();
    mixClaims(&reference, claims);
    try std.testing.expect(!std.mem.eql(u8, &channel.digestBytes(), &reference.digestBytes()));
}
