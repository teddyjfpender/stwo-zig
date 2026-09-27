//! First-accepted secure draw selection; a checked base-counter join is separate.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 12;
pub const PREPROCESSED_COLUMN_COUNT = 22;
pub const LOGICAL_INPUT_COUNT = 34;
pub const DIRECT_CONSTRAINT_COUNT = 4;
pub const RELATION_EVENT_COUNT = 20;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 10;
pub const INTERACTION_COLUMN_COUNT = 40;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "bc7f9f9df841aae93d1cff37cd8a107c584d8ba40856075ff995b08206b449f5") catch @compileError("invalid retry control digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Endpoint = @import("blake3_byte_route.zig").Endpoint;
pub const Caller = @import("blake3_frame_route.zig").Caller;
pub const Schedule = struct { pending: Endpoint, status: Endpoint, next_pending: Endpoint, next_uses: u32 = 1, values: Caller, destination: Caller, count_wire: u32, ordinal: u32, words: u4 = 8 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3RetryControl;
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
    var ids: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
    for (&ids, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_retry_control.value_{d}", .{i}), .felt, span);
    }
    const roots = [_]lang.types.ValueId{
        try arena.mul(ids[0], try arena.sub(ids[0], ids[12], span), span),
        try arena.mul(ids[1], try arena.sub(ids[1], ids[12], span), span),
        try arena.sub(ids[2], try arena.mul(ids[0], ids[1], span), span),
        try arena.sub(ids[3], try arena.sub(ids[0], ids[2], span), span),
    };
    for (roots, 0..) |root, i| {
        var buf: [48]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_retry_control.check_{d}", .{i}), root, null, .semantic, span);
    }
    const zero = try arena.constantField(0, span);
    _ = try effects.appendGroup(3, &arena, .{
        .{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[13], ids[14], ids[0], zero, zero, zero }, .weight = ids[12] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[15], ids[16], ids[1], zero, zero, zero }, .weight = ids[12] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[17], ids[18], ids[3], zero, zero, zero }, .weight = ids[19] },
    }, span);
    for (0..8) |i| {
        const offset = try arena.constantField(@intCast(i), span);
        _ = try effects.appendGroup(2, &arena, .{
            .{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[20], try arena.add(ids[21], offset, span), ids[4 + i], zero, zero, zero }, .weight = try arena.mul(ids[24 + i], ids[1], span) },
            .{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[22], try arena.add(ids[23], offset, span), ids[4 + i], zero, zero, zero }, .weight = try arena.mul(ids[24 + i], ids[2], span) },
        }, span);
    }
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[22], ids[32], ids[33], zero, zero, zero }, .weight = ids[2] }}, span);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*event, i| event.* = @enumFromInt(i);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    const p = core.fields.m31.Modulus;
    if ((s.words != 4 and s.words != 8) or s.ordinal == 0 or s.next_uses == 0 or s.values.first_wire > p - 8 or s.destination.first_wire > p - 8 or s.destination.circuit == s.values.circuit or (s.count_wire >= s.destination.first_wire and s.count_wire < s.destination.first_wire + 8) or std.meta.eql(s.pending, s.next_pending)) return error.InvalidBlake3RetryControl;
    var row: Row = @splat(M31.zero());
    const fields = [_]u32{ 1, s.pending.circuit, s.pending.wire, s.status.circuit, s.status.wire, s.next_pending.circuit, s.next_pending.wire, s.next_uses, s.values.circuit, s.values.first_wire, s.destination.circuit, s.destination.first_wire };
    for (row[12..24], fields) |*out, value| {
        if (value >= p) return error.InvalidBlake3RetryControl;
        out.* = M31.fromCanonical(value);
    }
    for (row[24..32], 0..) |*out, i| out.* = M31.fromCanonical(@intFromBool(i < s.words));
    if (s.count_wire >= p or s.ordinal >= p) return error.InvalidBlake3RetryControl;
    row[32] = M31.fromCanonical(s.count_wire);
    row[33] = M31.fromCanonical(s.ordinal);
    return row;
}
pub fn logicalRow(s: Schedule, pending: u1, accept: u1, values: [8]M31) !Row {
    var row = try fixedRow(s);
    row[0] = M31.fromCanonical(pending);
    row[1] = M31.fromCanonical(accept);
    row[2] = M31.fromCanonical(pending & accept);
    row[3] = M31.fromCanonical(pending - (pending & accept));
    for (values) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidBlake3RetryControl;
    row[4..12].* = values;
    return row;
}
