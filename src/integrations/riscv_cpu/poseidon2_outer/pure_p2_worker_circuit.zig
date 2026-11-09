//! Exact circuit counterpart of the OP native worker framing.
const std = @import("std");
const C = @import("full_p2_common.zig");
const F = @import("full_p2_frame.zig");
const B = @import("stwo_circuit_frontend").builder;
pub const Binding = struct { identity: [32]u8, root: [36]u8, profile: @import("op_profile.zig").Profile };
fn mixId(ctx: *C.Context, channel: *C.Channel, id: [32]u8) !void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, id[4 * i ..][0..4], .little);
    try channel.mixConstU32s(ctx, &words);
}
pub fn mixBegin(ctx: *C.Context, channel: *C.Channel, ordinal: F.Word, statement: F.Digest, fixed: C.Hash, binding: Binding) !void {
    try channel.mixConfig(ctx, binding.profile.config());
    const prefix = [_]F.Word{ try B.wrappers.constU32(C.Q, ctx, 0x4f505739), try B.wrappers.constU32(C.Q, ctx, 1), try B.wrappers.constU32(C.Q, ctx, 9), try B.wrappers.constU32(C.Q, ctx, 0), ordinal };
    try channel.mixU32s(ctx, &prefix);
    try mixId(ctx, channel, binding.profile.identity());
    try channel.mixU32s(ctx, &statement);
    try mixId(ctx, channel, binding.identity);
    try channel.mixRoot(ctx, fixed);
}
pub fn mixManifestAndClaims(ctx: *C.Context, channel: *C.Channel, manifest: C.Hash, claims: []const C.F) !void {
    try channel.mixConstU32s(ctx, &.{ 0x4f505739, 2, 9, @intCast(claims.len) });
    try channel.mixRoot(ctx, manifest);
    try channel.mixFelts(ctx, claims);
}
