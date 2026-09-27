//! Lossless private-word copy from an authenticated caller into a hash graph.
//! Fixed schedules are verifier-owned; this component cannot authenticate a
//! caller by itself. Caller emissions must balance its source consumption.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 4;
pub const PREPROCESSED_COLUMN_COUNT = 10;
pub const LOGICAL_INPUT_COUNT = 14;
pub const DIRECT_CONSTRAINT_COUNT = 4;
pub const RELATION_EVENT_COUNT = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 1;
pub const INTERACTION_COLUMN_COUNT = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "1de95d16ebc1bf0a3eec04a2ae2fd423e4a3609d18ef1aa63096d609738dc4da") catch @compileError("invalid BLAKE3 input bridge digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct {
    source_circuit: u32,
    source_wire: u32,
    hash_circuit: u32,
    hash_wire: u32,
    uses: u32,
    byte_count: u3 = 4,
};
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [2]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != 4 or self.arena.effectsView().len != 2) return error.InvalidBlake3InputBridge;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_input.value_{d}", .{i}), .felt, span);
    }
    for (0..4) |i| {
        var buf: [48]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_input.unused_byte_{d}", .{i}), try arena.mul(ids[i], ids[10 + i], span), null, .semantic, span);
    }
    const events = try effects.appendGroup(2, &arena, .{
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[5], ids[6] } ++ ids[0..4].*), .weight = ids[4] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[7], ids[8] } ++ ids[0..4].*), .weight = ids[9] },
    }, span);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(schedule: Schedule) !Row {
    if (schedule.byte_count == 0 or schedule.byte_count > 4 or schedule.uses == 0) return error.InvalidBlake3InputBridge;
    var row: Row = @splat(M31.zero());
    const fixed = [6]u32{ 1, schedule.source_circuit, schedule.source_wire, schedule.hash_circuit, schedule.hash_wire, schedule.uses };
    for (row[4..10], fixed) |*field, word| {
        if (word >= core.fields.m31.Modulus) return error.InvalidBlake3InputBridge;
        field.* = M31.fromCanonical(word);
    }
    for (row[10..14], 0..) |*field, i| field.* = if (i >= schedule.byte_count) M31.one() else M31.zero();
    return row;
}
pub fn logicalRow(schedule: Schedule, word: u32) !Row {
    var row = try fixedRow(schedule);
    for (row[0..4], 0..) |*field, i| field.* = M31.fromCanonical((word >> @as(u5, @intCast(i * 8))) & 255);
    // Deliberately do not mask unused bytes: malformed caller words must fail
    // the typed constraints rather than silently change their source value.
    return row;
}
