//! Fixed affine byte routing with authenticated source and destination words.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const Id = lang.types.ValueId;
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 12;
pub const PREPROCESSED_COLUMN_COUNT = 45;
pub const LOGICAL_INPUT_COUNT = 57;
pub const DIRECT_CONSTRAINT_COUNT = 4;
pub const RELATION_EVENT_COUNT = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 2;
pub const INTERACTION_COLUMN_COUNT = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "5deae0f0745922a26429f79804263c6c365d7ce4a8c4f418c72d31b3a42ba178") catch @compileError("invalid BLAKE3 byte route digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Endpoint = struct { circuit: u32, wire: u32 };
pub const Byte = union(enum) { constant: u8, source: struct { word: u1, byte: u2 } };
pub const Schedule = struct { sources: [2]?Endpoint, destination: Endpoint, uses: u32, bytes: [4]Byte };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [3]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != 4 or self.arena.effectsView().len != 3) return error.InvalidBlake3ByteRoute;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_route.value_{d}", .{i}), .felt, span);
    }
    for (0..4) |i| {
        var sum = ids[21 + i];
        for (0..8) |j| sum = try arena.add(sum, try arena.mul(ids[j], ids[25 + i * 8 + j], span), span);
        var buf: [48]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_route.byte_{d}", .{i}), try arena.sub(ids[8 + i], sum, span), null, .semantic, span);
    }
    const events = try effects.appendGroup(3, &arena, .{
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[14], ids[15] } ++ ids[0..4].*), .weight = ids[12] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[16], ids[17] } ++ ids[4..8].*), .weight = ids[13] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[18], ids[19] } ++ ids[8..12].*), .weight = ids[20] },
    }, span);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    var row: Row = @splat(M31.zero());
    for (s.sources, 0..) |maybe, i| if (maybe) |endpoint| {
        row[12 + i] = M31.one();
        row[14 + 2 * i] = try field(endpoint.circuit);
        row[15 + 2 * i] = try field(endpoint.wire);
    };
    row[18] = try field(s.destination.circuit);
    row[19] = try field(s.destination.wire);
    row[20] = try field(s.uses);
    if (s.uses == 0) return error.InvalidBlake3ByteRoute;
    for (s.bytes, 0..) |byte, i| switch (byte) {
        .constant => |value| row[21 + i] = M31.fromCanonical(value),
        .source => |source| {
            if (s.sources[source.word] == null) return error.InvalidBlake3ByteRoute;
            row[25 + i * 8 + @as(usize, source.word) * 4 + source.byte] = M31.one();
        },
    };
    return row;
}
pub fn logicalRow(s: Schedule, words: [2]u32) !Row {
    var row = try fixedRow(s);
    for (words, 0..) |word, i| for (0..4) |j| {
        row[i * 4 + j] = M31.fromCanonical((word >> @as(u5, @intCast(j * 8))) & 255);
    };
    for (s.bytes, 0..) |byte, i| row[8 + i] = switch (byte) {
        .constant => |value| M31.fromCanonical(value),
        .source => |source| row[@as(usize, source.word) * 4 + source.byte],
    };
    return row;
}
fn field(value: u32) !M31 {
    if (value >= core.fields.m31.Modulus) return error.InvalidBlake3ByteRoute;
    return M31.fromCanonical(value);
}
