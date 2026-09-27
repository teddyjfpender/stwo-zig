const std = @import("std");
const core = @import("stwo_core");
const Elements = @import("../air/relation_challenges.zig").RelationElements;
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const M = core.fields.m31.M31;
pub const TAG: u32 = 0x42354952; // B5IR
pub const VERSION: u32 = 1;
pub const Claim = struct {
    source_sum: core.fields.qm31.QM31,
    mutable_sum: core.fields.qm31.QM31,
    classification_sum: core.fields.qm31.QM31,
    read_sum: core.fields.qm31.QM31,
    readonly_count: u64,
};
pub const Challenges = struct {
    word: Word.Challenges,
    classification: Elements(5),
    read: Elements(4),
    pub fn draw(a: std.mem.Allocator, sealed: anytype, plan: [32]u8, source_identity: [32]u8, roots: [2][32]u8) !Challenges {
        var channel = sealed.sharedChannel();
        return drawFromChannel(a, &channel, plan, source_identity, roots);
    }
    pub fn drawFromChannel(a: std.mem.Allocator, channel: anytype, plan: anytype, source_identity: anytype, roots: anytype) !Challenges {
        const word = try Word.Challenges.drawFromChannel(a, channel);
        return drawSuffix(a, channel, word, plan, source_identity, roots);
    }
    /// Shared exact B5IR suffix; typed recorder wrappers may supply original
    /// public root coordinates without changing framing or draw order.
    pub fn drawSuffix(a: std.mem.Allocator, channel: anytype, word: Word.Challenges, plan: anytype, source_identity: anytype, roots: anytype) !Challenges {
        mixSuffix(channel, plan, source_identity, roots);
        const values = try channel.drawSecureFelts(a, 4);
        defer a.free(values);
        return .{ .word = word, .classification = .init(values[0], values[1]), .read = .init(values[2], values[3]) };
    }
};
/// Value-free statement and live challenge replay share these exact six mixes.
pub fn mixSuffix(channel: anytype, plan: anytype, source_identity: anytype, roots: anytype) void {
    channel.mixU32s(&.{ TAG, VERSION });
    channel.mixRoot(abiId());
    channel.mixRoot(plan);
    channel.mixRoot(source_identity);
    for (roots) |root| channel.mixRoot(root);
}
pub fn intervalTuple(interval: Plan.Interval) [5]M {
    return .{ M.fromCanonical(interval.lower), M.fromCanonical(interval.upper), M.fromCanonical(@intFromBool(interval.readonly)), M.fromCanonical(interval.value & 65535), M.fromCanonical(interval.value >> 16) };
}
pub fn inputTuple(address: u32, value: u32) [4]M {
    return .{ M.fromCanonical(address & 65535), M.fromCanonical(address >> 16), M.fromCanonical(value & 65535), M.fromCanonical(value >> 16) };
}
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/readonly-input-classifier/v1\x00");
    hash.update(&Word.abiId());
    hash.update("space1;aligned-byte-u32;clockLE16x4;valueLE16x2;word-index30;membership-gap30x2;complete-public-interval-partition;readonly-singletons-derived-from-input\x00");
    hash.update("main103;fixed-active-exact-census;interaction20;equations205;all-current-main;previous-interaction-only;degree3;source,mutable,classifier,read,count;no-register-or-clock-width-truncation\x00");
    return hash.finalResult();
}
