//! Fixed program-access provider for a complete, root-authenticated decoded ROM.
//! Callers must validate the v3 commitment plan before committing these columns.
//! Values, addresses and multiplicities all belong to verifier preprocessing.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 0;
pub const PREPROCESSED_COLUMN_COUNT = 6;
pub const LOGICAL_INPUT_COUNT = 6;
pub const FIXED_ADDRESS_INPUTS: []const usize = &.{4};
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT = 1;
pub const INTERACTION_COLUMN_COUNT = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, "ce40e3b88fb0410ceef6580541d83e8b97e5d0379a3d26f5dd8431ef95146cac") catch @compileError("invalid public program digest");
    break :blk bytes;
};
pub const Row = [LOGICAL_INPUT_COUNT]M;
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST)) return error.InvalidPublicProgramIdentity;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buffer, "blake3_public_program.value_{d}", .{i}), if (i == 4) .pc else .felt, span);
    }
    const events = try effects.appendGroup(1, &arena, .{.{ .domain = .program_access, .role = .request, .values = &(.{ids[4]} ++ ids[0..4].*), .weight = ids[5] }}, span);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(address: u32, multiplicity: u32, values: [4]u32) !Row {
    if (address >= (1 << 30) or address & 3 != 0 or multiplicity >= core.fields.m31.Modulus) return error.InvalidProgramBoundarySchedule;
    var row: Row = undefined;
    for (row[0..4], values) |*field, value| {
        if (value >= core.fields.m31.Modulus) return error.NonCanonicalProgramField;
        field.* = M.fromCanonical(value);
    }
    row[4] = M.fromCanonical(address);
    // Registry requests negate the weight; this supplies the program tuple.
    row[5] = M.fromCanonical(multiplicity).neg();
    return row;
}
