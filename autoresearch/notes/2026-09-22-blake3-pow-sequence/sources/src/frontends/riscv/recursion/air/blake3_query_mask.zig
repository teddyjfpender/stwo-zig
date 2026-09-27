//! Raw query masking with bounded bytes; no field reduction or rejection.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 8;
pub const PREPROCESSED_COLUMN_COUNT = 10;
pub const LOGICAL_INPUT_COUNT = 18;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 6;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 3;
pub const INTERACTION_COLUMN_COUNT = 12;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "e0820aaef9e85ecc3c61f993e547a2f2399d7f5a36b50952c3f739029ba8a183") catch @compileError("invalid query mask digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct { source_circuit: u32, source_wire: u32, destination_circuit: u32, destination_wire: u32, uses: u32, log_domain_size: u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != 0 or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3QueryMask;
    }
};
pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var d = try buildRaw(allocator);
    defer d.deinit();
    return (try lang.digest.computeIdentity(&d.arena)).bytes;
}
pub fn build(allocator: std.mem.Allocator) !Definition {
    var d = try buildRaw(allocator);
    errdefer d.deinit();
    try d.validate();
    return d;
}
fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var main: [8]Id = undefined;
    var pp: [10]Id = undefined;
    for (&main, 0..) |*id, i| {
        var buf: [40]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_query_mask.byte_{d}", .{i}), .byte, span);
    }
    for (&pp, 0..) |*id, i| {
        var buf: [40]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_query_mask.fixed_{d}", .{i}), if (i < 6) .felt else .byte, span);
    }
    const operation = try arena.constantUnsigned(.{ .bounded_uint = .{ .bits = 2, .representation = .canonical_field } }, 0, span);
    for (0..4) |i| _ = try effects.appendGroup(1, &arena, .{.{ .domain = .bitwise, .role = .request, .values = &.{ main[i], pp[6 + i], main[4 + i], operation }, .weight = pp[0] }}, span);
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[2] } ++ main[0..4].*), .weight = pp[0] }}, span);
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[3], pp[4] } ++ main[4..8].*), .weight = pp[5] }}, span);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*id, i| id.* = @enumFromInt(i);
    return .{ .arena = arena, .events = events };
}
pub fn logicalRow(schedule: Schedule, input: u32) !Row {
    if (schedule.log_domain_size > 31) return error.InvalidBlake3QueryMask;
    return logicalLowBitsRow(schedule, input);
}
/// Explicit low-bit predicate supports width 32 for PoW; query constructors do not.
pub fn logicalLowBitsRow(schedule: Schedule, input: u32) !Row {
    var row = try fixedLowBitsRow(schedule);
    const mask = try lowMask(schedule.log_domain_size);
    for ([2]u32{ input, input & mask }, 0..) |word, i| for (0..4) |j| {
        row[i * 4 + j] = M31.fromCanonical((word >> @as(u5, @intCast(j * 8))) & 255);
    };
    return row;
}
pub fn fixedRow(schedule: Schedule) !Row {
    if (schedule.log_domain_size > 31) return error.InvalidBlake3QueryMask;
    return fixedLowBitsRow(schedule);
}
pub fn fixedLowBitsRow(schedule: Schedule) !Row {
    const mask = try lowMask(schedule.log_domain_size);
    if (schedule.source_circuit == schedule.destination_circuit) return error.InvalidBlake3QueryMask;
    var row: Row = @splat(M31.zero());
    const pp = [6]u32{ 1, schedule.source_circuit, schedule.source_wire, schedule.destination_circuit, schedule.destination_wire, schedule.uses };
    for (row[8..14], pp) |*field, word| {
        if (word >= core.fields.m31.Modulus) return error.InvalidBlake3QueryMask;
        field.* = M31.fromCanonical(word);
    }
    for (row[14..18], 0..) |*field, i| field.* = M31.fromCanonical((mask >> @as(u5, @intCast(8 * i))) & 255);
    return row;
}

fn lowMask(bits: u32) !u32 {
    if (bits > 32) return error.InvalidBlake3QueryMask;
    return if (bits == 32) std.math.maxInt(u32) else (@as(u32, 1) << @as(u5, @intCast(bits))) - 1;
}
