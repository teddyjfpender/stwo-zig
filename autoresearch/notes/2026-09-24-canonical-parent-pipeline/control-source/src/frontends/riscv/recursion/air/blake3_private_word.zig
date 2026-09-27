//! Bounded private digest words. Authentication is supplied by a hash path to
//! its public root, not by a claim that the sibling has a known preimage.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 4;
pub const PREPROCESSED_COLUMN_COUNT = 4;
pub const LOGICAL_INPUT_COUNT = 8;
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 2;
pub const INTERACTION_COLUMN_COUNT = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "8dbfba49958aac1df9478d41f2aa812e764eecd3921b4124e81b3733a27e99db") catch @compileError("invalid BLAKE3 private word digest");
    break :blk out;
};
pub const Row = [8]M31;
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [3]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != 0 or self.arena.effectsView().len != 3) return error.InvalidBlake3PrivateWord;
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
    var ids: [8]Id = undefined;
    for (&ids, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_private_word.value_{d}", .{i}), if (i < 4) .byte else .felt, span);
    }
    const events = try effects.appendGroup(3, &arena, .{
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[5], ids[6] } ++ ids[0..4].*), .weight = ids[7] },
        .{ .domain = .range_check_8_8, .role = .request, .values = &.{ ids[0], ids[1] }, .weight = ids[4] },
        .{ .domain = .range_check_8_8, .role = .request, .values = &.{ ids[2], ids[3] }, .weight = ids[4] },
    }, span);
    return .{ .arena = arena, .events = events };
}
pub fn logicalRow(circuit: u32, wire: u32, uses: u32, word: u32) !Row {
    if (circuit >= core.fields.m31.Modulus or wire >= core.fields.m31.Modulus or uses == 0 or uses >= core.fields.m31.Modulus) return error.InvalidBlake3PrivateWord;
    var row: Row = undefined;
    for (row[0..4], 0..) |*byte, i| byte.* = M31.fromCanonical((word >> @as(u5, @intCast(i * 8))) & 255);
    row[4..8].* = .{ M31.one(), M31.fromCanonical(circuit), M31.fromCanonical(wire), M31.fromCanonical(uses) };
    return row;
}
