//! Eight-word rejection and M31 reduction for the exact native BLAKE3 channel.
//! Output wire coordinates are (M31 value,0,0,0), not packed word bytes.
//! A surrounding transcript scheduler must authenticate draw order and retries.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const Id = lang.types.ValueId;
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 71;
pub const PREPROCESSED_COLUMN_COUNT = 15;
pub const LOGICAL_INPUT_COUNT = 86;
pub const DIRECT_CONSTRAINT_COUNT = 47;
pub const RELATION_EVENT_COUNT = 33;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 17;
pub const INTERACTION_COLUMN_COUNT = 68;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = .{ 0x14, 0x88, 0x3e, 0xc7, 0x35, 0x14, 0x44, 0x75, 0xa7, 0x11, 0x9b, 0xee, 0x94, 0xbb, 0x05, 0xfc, 0xe6, 0xb7, 0x39, 0xe4, 0x44, 0xb6, 0xfd, 0xd5, 0x68, 0xd8, 0xa0, 0xab, 0xb9, 0x36, 0x2b, 0x5e };
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct { source_circuit: u32, source_first: u32, destination_circuit: u32, destination_first: u32, uses: [8]u32, status_wire: u32, status_uses: u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3ChallengeBlock;
    }
};
pub fn computeSemanticDigest(a: std.mem.Allocator) ![32]u8 {
    var d = try buildRaw(a);
    defer d.deinit();
    return (try lang.digest.computeIdentity(&d.arena)).bytes;
}
pub fn build(a: std.mem.Allocator) !Definition {
    var d = try buildRaw(a);
    errdefer d.deinit();
    try d.validate();
    return d;
}
fn buildRaw(a: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(a);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var ids: [LOGICAL_INPUT_COUNT]Id = undefined;
    for (&ids, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_challenge.value_{d}", .{i}), if (i < 64 and i % 8 < 4) .byte else .felt, span);
    }
    const zero = try constant(&arena, 0);
    const c254 = try constant(&arena, 254);
    const c255 = try constant(&arena, 255);
    const c765 = try constant(&arena, 765);
    const enable = ids[71];
    const accept = ids[70];
    for (0..8) |i| {
        const w = ids[i * 8 ..][0..8];
        const lo = try arena.sub(w[0], try arena.mul(enable, c254, span), span);
        const hi = try arena.sub(w[0], try arena.mul(enable, c255, span), span);
        try root(&arena, i * 5, try arena.sub(w[4], try arena.mul(lo, hi, span), span));
        var d = try arena.add(w[4], try arena.mul(enable, c765, span), span);
        for (w[1..4]) |byte| d = try arena.sub(d, byte, span);
        const invalid = try arena.sub(enable, w[6], span);
        try root(&arena, i * 5 + 1, try arena.sub(try arena.mul(d, w[5], span), w[6], span));
        try root(&arena, i * 5 + 2, try arena.mul(d, invalid, span));
        var reduced = w[0];
        for (1..4) |j| reduced = try arena.add(reduced, try arena.mul(w[j], try constant(&arena, @as(u32, 1) << @as(u5, @intCast(8 * j))), span), span);
        try root(&arena, i * 5 + 3, try arena.mul(w[6], try arena.sub(w[7], reduced, span), span));
        try root(&arena, i * 5 + 4, try arena.mul(invalid, w[7], span));
        const offset = try constant(&arena, @intCast(i));
        _ = try effects.appendGroup(4, &arena, .{
            .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[72], try arena.add(ids[73], offset, span) } ++ w[0..4].*), .weight = enable },
            .{ .domain = .range_check_8_8, .role = .request, .values = &.{ w[0], w[1] }, .weight = enable },
            .{ .domain = .range_check_8_8, .role = .request, .values = &.{ w[2], w[3] }, .weight = enable },
            .{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[74], try arena.add(ids[75], offset, span), w[7], zero, zero, zero }, .weight = try arena.mul(ids[76 + i], accept, span) },
        }, span);
    }
    var prior = ids[6];
    for (0..7) |i| {
        try root(&arena, 40 + i, try arena.sub(ids[64 + i], try arena.mul(prior, ids[(i + 1) * 8 + 6], span), span));
        prior = ids[64 + i];
    }
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[74], ids[84], accept, zero, zero, zero }, .weight = ids[85] }}, span);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*event, i| event.* = @enumFromInt(i);
    return .{ .arena = arena, .events = events };
}
fn constant(arena: *lang.ir.Arena, value: u32) !Id {
    return arena.constantField(value, lang.source.SourceSpan.generated());
}
fn root(arena: *lang.ir.Arena, index: usize, value: Id) !void {
    var buf: [48]u8 = undefined;
    _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_challenge.constraint_{d}", .{index}), value, null, .semantic, lang.source.SourceSpan.generated());
}
pub fn fixedRow(s: Schedule) !Row {
    const p = core.fields.m31.Modulus;
    if (s.source_circuit >= p or s.destination_circuit >= p or s.source_circuit == s.destination_circuit or s.source_first > p - 8 or s.destination_first > p - 8 or s.status_wire >= p or (s.status_wire >= s.destination_first and s.status_wire < s.destination_first + 8)) return error.InvalidBlake3ChallengeBlock;
    var row: Row = @splat(M31.zero());
    row[71..76].* = .{ M31.one(), M31.fromCanonical(s.source_circuit), M31.fromCanonical(s.source_first), M31.fromCanonical(s.destination_circuit), M31.fromCanonical(s.destination_first) };
    for (row[76..84], s.uses) |*field, use| {
        if (use >= p) return error.InvalidBlake3ChallengeBlock;
        field.* = M31.fromCanonical(use);
    }
    if (s.status_uses >= p) return error.InvalidBlake3ChallengeBlock;
    row[84] = M31.fromCanonical(s.status_wire);
    row[85] = M31.fromCanonical(s.status_uses);
    return row;
}
pub fn logicalRow(s: Schedule, words: [8]u32) !Row {
    var row = try fixedRow(s);
    for (words, 0..) |word, i| {
        const w = row[i * 8 ..][0..8];
        for (w[0..4], 0..) |*byte, j| byte.* = M31.fromCanonical((word >> @as(u5, @intCast(j * 8))) & 255);
        const b0: i64 = w[0].toU32();
        const product: u32 = @intCast((b0 - 254) * (b0 - 255));
        const d = M31.fromCanonical(product + 765 - w[1].toU32() - w[2].toU32() - w[3].toU32());
        w[4] = M31.fromCanonical(product);
        w[5] = if (d.isZero()) M31.zero() else try d.inv();
        w[6] = if (d.isZero()) M31.zero() else M31.one();
        w[7] = core.channel.blake3.sampleWord(word) orelse M31.zero();
    }
    var prior = row[6];
    for (0..7) |i| {
        prior = prior.mul(row[(i + 1) * 8 + 6]);
        row[64 + i] = prior;
    }
    return row;
}
