//! Canonical decoded program tuple to four scalar hash-source wires.
//! Address and multiplicity are verifier-owned scheduling inputs. Canonical
//! field-to-byte encoding and Merkle paths authenticate the four field values.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 4;
pub const PREPROCESSED_COLUMN_COUNT = 4;
pub const LOGICAL_INPUT_COUNT = 8;
pub const FIXED_ADDRESS_INPUTS: []const usize = &.{5};
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 5;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 3;
pub const INTERACTION_COLUMN_COUNT = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, "9c210270e637dc55090e0f06e16e4127bc58e3acd0d04c436a67b5fe0c9fdd16") catch @compileError("invalid program boundary digest");
    break :blk bytes;
};
pub const Row = [LOGICAL_INPUT_COUNT]M;
pub const Schedule = struct { address: u32, multiplicity: u32, circuit: u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST)) return error.InvalidProgramBoundaryIdentity;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buffer, "blake3_program_boundary.value_{d}", .{i}), if (i == 5) .pc else .felt, span);
    }
    const zero = try arena.constantField(0, span);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    events[0] = (try effects.appendGroup(1, &arena, .{.{ .domain = .program_access, .role = .request, .values = &(.{ids[5]} ++ ids[0..4].*), .weight = ids[6] }}, span))[0];
    for (0..4) |i| events[i + 1] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[7], try arena.constantField(@intCast(i), span), ids[i], zero, zero, zero }, .weight = ids[4] }}, span))[0];
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    const p = core.fields.m31.Modulus;
    if (s.address >= (1 << 30) or s.address & 3 != 0 or s.multiplicity >= p or s.circuit >= p) return error.InvalidProgramBoundarySchedule;
    var row: Row = @splat(M.zero());
    // Registry requests negate their weight; a provider therefore supplies
    // negative multiplicity to retain the legacy positive program tuple.
    row[4..8].* = .{ M.one(), M.fromCanonical(s.address), M.fromCanonical(s.multiplicity).neg(), M.fromCanonical(s.circuit) };
    return row;
}
pub fn logicalRow(s: Schedule, values: [4]u32) !Row {
    var row = try fixedRow(s);
    for (row[0..4], values) |*field, value| {
        if (value >= core.fields.m31.Modulus) return error.NonCanonicalProgramField;
        field.* = M.fromCanonical(value);
    }
    return row;
}
