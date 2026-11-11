//! New OP pure-P2 physical/GKR/manifest suite; no production admission.
const std = @import("std");
const core = @import("stwo_core");
pub const Profile = @import("op_profile.zig").Profile;
pub const W = @import("../word16_global_execution/services/poseidon2_native/worker_protocol.zig").W;
fn externalId(channel: *W.Channel, id: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, id[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn begin(profile: Profile, expected: anytype, key_identity: [32]u8, fixed: W.H.Hash) W.Channel {
    var channel = W.Channel.init();
    profile.config().mixInto(&channel);
    channel.mixU32s(&.{ 0x4f505739, 1, 9, @intFromEnum(expected.kind), expected.ordinal });
    externalId(&channel, profile.identity());
    externalId(&channel, expected.statement);
    externalId(&channel, key_identity);
    channel.mixRoot(fixed);
    return channel;
}
pub fn mixManifestAndClaims(channel: *W.Channel, manifest: W.H.Hash, claims: []const core.fields.om31.OM31) void {
    channel.mixU32s(&.{ 0x4f505739, 2, 9, @intCast(claims.len) });
    channel.mixRoot(manifest);
    channel.mixFelts(claims);
}
