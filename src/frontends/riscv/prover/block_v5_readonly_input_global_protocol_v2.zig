//! Versioned shared classifier/read challenges for a sealed provider roster.
//! This protocol alone grants no provider, source or block proof authority.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Original = @import("block_v5_readonly_input_protocol_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
pub const VERSION: u32 = 2;
pub const TAG: u32 = 0x42354947; // B5IG
pub const Challenges = Original.Challenges;
/// The group is the final implicit tuple cell. Shifting z retains the original
/// classifier AIR arity while preventing cancellation across source groups.
pub fn forGroup(challenges: Challenges, group_id: u32) !Challenges {
    if (group_id >= core.fields.m31.Modulus) return error.InvalidGlobalReadonlyGroup;
    var result = challenges;
    const group = M.fromCanonical(group_id);
    result.classification.z = result.classification.z.sub(result.classification.alpha_powers[4].mul(result.classification.alpha).mulM31(group));
    result.read.z = result.read.z.sub(result.read.alpha_powers[3].mul(result.read.alpha).mulM31(group));
    return result;
}
pub const Epoch = struct {
    plan_digest: [32]u8,
    /// Independent versioned roster of source+provider+range fixed/main roots.
    roster_digest: [32]u8,
    pub fn require(self: Epoch, sealed: anytype) !void {
        if (std.mem.allEqual(u8, &self.plan_digest, 0) or std.mem.allEqual(u8, &self.roster_digest, 0) or
            !std.meta.eql(self.roster_digest, sealed.readonly_roster_digest)) return error.UntrustedGlobalReadonlyEpoch;
    }
};
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/readonly-global-providers/v2\x00");
    hash.update(&Original.abiId());
    hash.update("sharedWord52;globalClassRead2;sealedPlan+source/provider/range-roster;sourceclaims-open;no-per-source-counter-array;source-counter-schema-u32;histogram1-or-ordered-interval-stream2;stream-selection+kind+index+group+u64expected+ordered-u64ordinal/count;providerLE16+u64prefix+boolean-carry;fixed10/main18/inter44/equations48;range9-per-physical-row;nonzero-fragments;topcarry0;groupmass<p;class/read-last-tuple-group-shift;independent-source-shard-census\x00");
    return hash.finalResult();
}
pub fn mixSuffix(channel: anytype, plan: anytype, roster: anytype) void {
    channel.mixU32s(&.{ TAG, VERSION });
    channel.mixRoot(abiId());
    channel.mixRoot(plan);
    channel.mixRoot(roster);
}
pub fn drawFromChannel(a: std.mem.Allocator, channel: anytype, plan: anytype, roster: anytype) !Challenges {
    const word = try Word.Challenges.drawFromChannel(a, channel);
    mixSuffix(channel, plan, roster);
    const values = try channel.drawSecureFelts(a, 4);
    defer a.free(values);
    return .{ .word = word, .classification = .init(values[0], values[1]), .read = .init(values[2], values[3]) };
}
pub fn draw(a: std.mem.Allocator, sealed: anytype, epoch: Epoch) !Challenges {
    try epoch.require(sealed);
    var channel = sealed.sharedChannel();
    return drawFromChannel(a, &channel, epoch.plan_digest, epoch.roster_digest);
}
