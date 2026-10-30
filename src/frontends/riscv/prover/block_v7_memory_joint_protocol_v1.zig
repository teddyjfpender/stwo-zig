//! Distinct joint-original proof identity, complete physical claims and typed
//! open relation. No function in this module authenticates a proof by itself.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const suite = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const Layout = @import("block_v7_memory_joint_layout_v1.zig");
const Air = @import("block_v7_memory_joint_air_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
pub const VERSION: u32 = 2;
pub const TAG: u32 = 0x42374d4a;
pub const Open = @import("block_v7_memory_source_v1.zig").Open;
pub fn firstChannel(policy: Policy, layout: *const Layout.Layout) !suite.Channel {
    var ch = suite.Channel{};
    ch.mixU32s(&.{ TAG, VERSION, 1, Layout.TREE_COUNT, Layout.SPLIT });
    ch.mixRoot(try policy.digest());
    ch.mixRoot(layout.digest);
    return ch;
}
pub fn entry(policy: Policy, layout: *const Layout.Layout, roots: [2][32]u8) !E.Entry {
    var ch = try firstChannel(policy, layout);
    ch.mixU32s(&.{ TAG, VERSION, 2 });
    return E.Entry.init(.memory_joint, 0, ch.digestBytes(), &roots);
}
pub fn requireEpoch(policy: Policy, epoch: E.Epoch, roster: []const E.Entry, pin: E.Entry) !void {
    if (pin.family != .memory_joint or pin.index != 0 or epoch.counts[@intFromEnum(E.Family.memory_joint)] != 1 or !std.meta.eql(epoch.statement, try policy.digest()) or !std.meta.eql(epoch.config, policy.config)) return error.InvalidV7JointEpoch;
    for ([_]E.Family{ .ram, .interval, .range16, .terminal }) |family| if (epoch.counts[@intFromEnum(family)] != 0) return error.MixedV7MemoryLayouts;
    try epoch.requireEntry(roster, pin);
}
pub fn proofChannel(drawn: E.Drawn, pin: E.Entry, layout: *const Layout.Layout, claims: Air.Claims) !suite.Channel {
    var ch = drawn.channel;
    try recordAfterChallenges(&ch, pin, layout, claims);
    return ch;
}
/// One framing grammar for native execution, public statement extraction and
/// independently compiled recursive transcript routing.
pub fn recordAfterChallenges(ch: anytype, pin: E.Entry, layout: *const Layout.Layout, claims: Air.Claims) !void {
    if (claims.ram.len + 3 != layout.parts.len) return error.InvalidV7JointClaims;
    ch.mixU32s(&.{ TAG, VERSION, 3, layout.claims });
    ch.mixU32s(&.{ @intFromEnum(pin.family), pin.index, pin.root_count });
    ch.mixRoot(pin.identity);
    for (pin.roots[0..pin.root_count]) |root| ch.mixRoot(root);
    for (claims.ram, layout.parts[0..claims.ram.len]) |item, part| try mix(ch, part, &item.sums);
    try mix(ch, layout.parts[claims.ram.len], &claims.interval);
    try mix(ch, layout.parts[claims.ram.len + 1], &claims.range16);
    try mix(ch, layout.parts[claims.ram.len + 2], &claims.terminal);
}
fn mix(ch: anytype, part: Layout.Part, sums: []const Q) !void {
    if (sums.len != part.claim_count) return error.InvalidV7JointClaims;
    ch.mixU32s(&.{ @intFromEnum(part.family), part.index, part.claim_offset, part.claim_count });
    for (sums) |sum| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidV7MemoryClaims;
        ch.mixFelts(&.{sum});
    }
}
/// Original independent bus and integer-count equations over already verified
/// physical claims. Transition remains OPEN for actual execution/caller closure.
pub const closeVerifiedClaims = @import("block_v7_memory_claim_closure_v1.zig").close;
