//! Distinct joint-original proof identity, complete physical claims and typed
//! open relation. No function in this module authenticates a proof by itself.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const suite = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const Layout = @import("block_v7_window_memory_joint_layout_v1.zig");
const Air = @import("block_v7_window_memory_joint_air_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x4237574a;
pub const Open = @import("block_v7_memory_source_v1.zig").Open;
pub fn firstChannel(policy: Policy, layout: *const Layout.Layout) !suite.Channel {
    if (policy.window == null) return error.InvalidV7MemoryPolicyMode;
    var ch = suite.Channel{};
    ch.mixU32s(&.{ TAG, VERSION, 1, Layout.TREE_COUNT, Layout.SPLIT });
    ch.mixRoot(try policy.digest());
    ch.mixRoot(layout.digest);
    return ch;
}
pub fn entry(policy: Policy, layout: *const Layout.Layout, roots: [2][32]u8) !E.Entry {
    var ch = try firstChannel(policy, layout);
    ch.mixU32s(&.{ TAG, VERSION, 2 });
    return E.Entry.init(.window_memory_joint, 0, ch.digestBytes(), &roots);
}
pub fn requireEpoch(policy: Policy, epoch: E.Epoch, roster: []const E.Entry, pin: E.Entry) !void {
    if (pin.family != .window_memory_joint or pin.index != 0 or epoch.counts[@intFromEnum(E.Family.window_memory_joint)] != 1 or !std.meta.eql(epoch.statement, try policy.digest()) or !std.meta.eql(epoch.config, policy.config)) return error.InvalidV7JointEpoch;
    for ([_]E.Family{ .ram, .interval, .range16, .terminal, .memory_joint }) |family| if (epoch.counts[@intFromEnum(family)] != 0) return error.MixedV7MemoryLayouts;
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
    if (claims.ram.len + 2 != layout.parts.len) return error.InvalidV7JointClaims;
    ch.mixU32s(&.{ TAG, VERSION, 3, layout.claims });
    ch.mixU32s(&.{ @intFromEnum(pin.family), pin.index, pin.root_count });
    ch.mixRoot(pin.identity);
    for (pin.roots[0..pin.root_count]) |root| ch.mixRoot(root);
    for (claims.ram, layout.parts[0..claims.ram.len]) |item, part| try mix(ch, part, &item.sums);
    try mix(ch, layout.parts[claims.ram.len], &claims.interval);
    try mix(ch, layout.parts[claims.ram.len + 1], &claims.range16);
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
pub fn closeVerifiedClaims(policy: Policy, delta: @FieldType(@import("block_v5_word_memory_protocol_v1.zig").Challenges, "initial"), claims: Air.Claims) !Open {
    const window = policy.window orelse return error.InvalidV7MemoryPolicyMode;
    try policy.validate();
    if (claims.ram.len == 0) return error.InvalidV7JointClaims;
    var transition = Q.zero();
    var link = Q.zero();
    var initialization = claims.interval[0];
    var range = claims.range16[0];
    var state_delta = Q.zero();
    var first_count: u64 = 0;
    var range_count: u64 = 0;
    for (claims.ram) |item| {
        for (item.sums) |sum| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidV7MemoryClaims;
        transition = transition.add(item.sums[0]);
        link = link.add(item.sums[1]);
        initialization = initialization.add(item.sums[2]);
        for (item.sums[3..27]) |sum| range = range.add(sum);
        state_delta = state_delta.add(item.sums[29]).add(item.sums[30]);
        const f = try T.natural(item.sums[27]);
        const r = try T.natural(item.sums[28]);
        if (f > item.geometry.events or r > @as(u64, item.geometry.events) * 24) return error.InvalidV7MemoryCensus;
        first_count = try std.math.add(u64, first_count, f);
        range_count = try std.math.add(u64, range_count, r);
    }
    if (!link.isZero() or !initialization.isZero() or !range.isZero() or first_count != try T.natural(claims.interval[1]) or range_count != try T.natural(claims.range16[1])) return error.UnclosedV7MemoryRelations;
    if (!state_delta.eql(try window.delta(delta))) return error.UnclosedV7WindowState;
    return .{ .transition = transition, .event_count = claims.ram[0].geometry.total_events };
}
