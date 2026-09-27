//! Typed memory boundary: exact legacy word/clock tuple to four byte wires.
//! Verifier-owned schedules bind address, clock and byte destinations. Production
//! root/path admission must bind those addresses to the corresponding leaf paths.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 4;
pub const PREPROCESSED_COLUMN_COUNT = 10;
pub const LOGICAL_INPUT_COUNT = 14;
/// Address is verifier-owned, aligned, and bounded to 30 bits by fixedRow.
pub const FIXED_ADDRESS_INPUTS: []const usize = &.{5};
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 7;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 4;
pub const INTERACTION_COLUMN_COUNT = 16;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, "33f5035f2ca070d0895d9d8ad08f208c1b985308c59cc92339015d08daacb0df") catch @compileError("invalid memory boundary digest");
    break :blk bytes;
};
pub const Row = [LOGICAL_INPUT_COUNT]M;
pub const Direction = enum { initial, final };
pub const Schedule = struct { address: u32, clock: u32, direction: Direction, circuit: u32, first_wire: u32, uses: [4]u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void { self.arena.deinit(); }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST)) return error.InvalidMemoryBoundaryIdentity;
    }
};
pub fn build(a: std.mem.Allocator) !Definition {
    var result = try buildRaw(a);
    errdefer result.deinit();
    try result.validate();
    return result;
}
pub fn computeSemanticDigest(a: std.mem.Allocator) ![32]u8 {
    var result = try buildRaw(a);
    defer result.deinit();
    return (try lang.digest.computeIdentity(&result.arena)).bytes;
}
fn buildRaw(a: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(a);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var ids: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
    for (&ids, 0..) |*id, i| {
        var buffer: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buffer, "blake3_memory_boundary.value_{d}", .{i}), if (i < 4) .byte else if (i == 5) .address else if (i == 6) .clock else .felt, span);
    }
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    events[0] = (try effects.appendGroup(1, &arena, .{.{ .domain = .memory_access, .role = .emit, .values = &(.{ one, ids[5], ids[6] } ++ ids[0..4].*), .weight = ids[7] }}, span))[0];
    for (0..2) |i| events[1 + i] = (try effects.appendGroup(1, &arena, .{.{ .domain = .range_check_8_8, .role = .request, .values = ids[i * 2 ..][0..2], .weight = ids[4] }}, span))[0];
    for (0..4) |i| events[3 + i] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[8], try arena.add(ids[9], try arena.constantField(@intCast(i), span), span), ids[i], zero, zero, zero }, .weight = ids[10 + i] }}, span))[0];
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    const p = core.fields.m31.Modulus;
    if (s.address >= (1 << 30) or s.address & 3 != 0 or s.clock >= p or s.circuit >= p or s.first_wire > p - 4) return error.InvalidMemoryBoundarySchedule;
    var row: Row = @splat(M.zero());
    row[4..10].* = .{ M.one(), M.fromCanonical(s.address), M.fromCanonical(s.clock), if (s.direction == .initial) M.one() else M.one().neg(), M.fromCanonical(s.circuit), M.fromCanonical(s.first_wire) };
    for (row[10..14], s.uses) |*value, uses| {
        if (uses == 0 or uses >= p) return error.InvalidMemoryBoundarySchedule;
        value.* = M.fromCanonical(uses);
    }
    return row;
}
pub fn logicalRow(s: Schedule, bytes: [4]u8) !Row {
    var row = try fixedRow(s);
    for (row[0..4], bytes) |*value, byte| value.* = M.fromCanonical(byte);
    return row;
}
