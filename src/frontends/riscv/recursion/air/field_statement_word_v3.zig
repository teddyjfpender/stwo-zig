//! Field-node statement bridge for the new common-fold profile.
//! Two transcript u16 limbs must encode one canonical M31 word. The body
//! word can then feed the existing statement/composition relation. Rows with
//! no statement output carry a full u32 nonce through two range-checked limbs.
//! This AIR
//! is not installed in the frozen universal roster or CSP profile.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;

pub const STABLE_NAME = "recursion.field_statement_word.v3";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 10;
pub const PREPROCESSED_COLUMN_COUNT: usize = 13;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 15;
pub const RELATION_EVENT_COUNT: usize = 6;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 3;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
// The verifier-owned statement mask already includes row activation.
// Its quadratic multiplicity keeps batched constraints within degree three.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const SEMANTIC_DIGEST_HEX = "60daab2d7f7db0786481597b30e9a282e1b9e8a3bf307a5e417998971083e208";
pub const SEMANTIC_DIGEST = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch @compileError("invalid field statement AIR digest");
    break :blk result;
};

pub const MAIN_COLUMN_NAMES = [_][]const u8{
    "field_statement.enabler",               "field_statement.value",
    "field_statement.low",                   "field_statement.high",
    "field_statement.low_byte_0",            "field_statement.low_byte_1",
    "field_statement.high_byte_0",           "field_statement.high_byte_1",
    "field_statement.canonical_gap_inverse", "field_statement.doubled_high_byte",
};
pub const PREPROCESSED_COLUMN_NAMES = [_][]const u8{
    "field_statement.row_mask",            "field_statement.verifier_id",
    "field_statement.sequence",            "field_statement.tag",
    "field_statement.arg_0",               "field_statement.arg_1",
    "field_statement.arg_2",               "field_statement.arg_3",
    "field_statement.payload_index",       "field_statement.scope",
    "field_statement.word_index",          "field_statement.statement_mask",
    "field_statement.statement_use_count",
};

pub const Definition = struct {
    arena: lang.ir.Arena,
    roots: [DIRECT_CONSTRAINT_COUNT]Id,
    constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidFieldStatementDefinition;
        for (self.constraints, self.roots, 0..) |constraint, root, index| {
            if (lang.types.idIndex(constraint) != index or
                (self.arena.constraint(constraint) orelse return error.InvalidFieldStatementDefinition).root != root)
                return error.InvalidFieldStatementDefinition;
        }
        for (self.events, 0..) |event, index| if (lang.types.idIndex(event) != index)
            return error.InvalidFieldStatementDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var definition = try buildRaw(allocator);
    defer definition.deinit();
    return (try lang.digest.computeIdentity(&definition.arena)).bytes;
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var main: [PHYSICAL_MAIN_COLUMN_COUNT]Id = undefined;
    for (&main, MAIN_COLUMN_NAMES, 0..) |*id, name, index|
        id.* = try arena.input(name, if (index == 0) .selector else if ((index >= 4 and index <= 7) or index == 9) .byte else .felt, span);
    var pp: [PREPROCESSED_COLUMN_COUNT]Id = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*id, name, index|
        id.* = try arena.input(name, if (index == 0 or index == 11) .selector else .felt, span);
    const one = try arena.constantField(1, span);
    const two = try arena.constantField(2, span);
    const byte_base = try arena.constantField(256, span);
    const limb_base = try arena.constantField(65536, span);
    const max_low = try arena.constantField(65535, span);
    const max_high = try arena.constantField(32767, span);
    const inactive = try arena.sub(one, pp[0], span);
    var roots: [DIRECT_CONSTRAINT_COUNT]Id = undefined;
    roots[0] = try arena.sub(main[0], pp[0], span);
    for (main[1..], 1..) |value, index| roots[index] = try arena.mul(inactive, value, span);
    const low = try arena.add(main[4], try arena.mul(byte_base, main[5], span), span);
    const high = try arena.add(main[6], try arena.mul(byte_base, main[7], span), span);
    roots[10] = try arena.mul(pp[0], try arena.sub(main[2], low, span), span);
    roots[11] = try arena.mul(pp[0], try arena.sub(main[3], high, span), span);
    const value = try arena.add(main[2], try arena.mul(limb_base, main[3], span), span);
    roots[12] = try arena.mul(pp[0], try arena.sub(main[1], value, span), span);
    // Published field words require a 15-bit high limb and exclude the
    // modulus alias. Nonce rows have no statement output and retain all
    // 32 bits; their two payload limbs still receive full byte range checks.
    const gap = try arena.add(try arena.sub(max_low, main[2], span), try arena.sub(max_high, main[3], span), span);
    roots[13] = try arena.mul(pp[11], try arena.sub(try arena.mul(gap, main[8], span), one, span), span);
    roots[14] = try arena.mul(pp[0], try arena.sub(main[9], try arena.mul(pp[11], try arena.mul(two, main[7], span), span), span), span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        var buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&buffer, "field_statement.constraint_{d}", .{index});
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }
    const low_payload = pp[1..8].* ++ .{ pp[8], main[2] };
    const high_payload = pp[1..8].* ++ .{ try arena.add(pp[8], one, span), main[3] };
    const statement = .{ pp[9], pp[10], main[1] };
    const output_weight = try arena.mul(pp[11], pp[12], span);
    const events = try effects.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_transcript_payload_word, .role = .emit, .values = &low_payload, .weight = pp[0] },
        .{ .domain = .recursion_transcript_payload_word, .role = .emit, .values = &high_payload, .weight = pp[0] },
        .{ .domain = .recursion_statement_word, .role = .emit, .values = &statement, .weight = output_weight },
        .{ .domain = .range_check_8_8, .role = .request, .values = &.{ main[4], main[5] }, .weight = pp[0] },
        .{ .domain = .range_check_8_8, .role = .request, .values = &.{ main[6], main[7] }, .weight = pp[0] },
        .{ .domain = .range_check_8_8, .role = .request, .values = &.{ main[9], main[7] }, .weight = pp[0] },
    }, span);
    return .{ .arena = arena, .roots = roots, .constraints = constraints, .events = events };
}

/// Witness construction rejects noncanonical integers before field reduction.
pub fn mainRow(value: u32) ![PHYSICAL_MAIN_COLUMN_COUNT]M31 {
    if (value >= core.fields.m31.Modulus) return error.NonCanonicalFieldStatementWord;
    return wordRow(value, true);
}

/// A nonce is an unsigned 32-bit chunk, not a published M31 word.
pub fn nonceRow(value: u32) ![PHYSICAL_MAIN_COLUMN_COUNT]M31 {
    return wordRow(value, false);
}

fn wordRow(value: u32, canonical: bool) ![PHYSICAL_MAIN_COLUMN_COUNT]M31 {
    const low = value & 0xffff;
    const high = value >> 16;
    const inverse = if (canonical) try M31.fromCanonical((65535 - low) + (32767 - high)).inv() else M31.zero();
    return .{ M31.one(), M31.fromCanonical(value % core.fields.m31.Modulus), M31.fromCanonical(low), M31.fromCanonical(high), M31.fromCanonical(low & 255), M31.fromCanonical(low >> 8), M31.fromCanonical(high & 255), M31.fromCanonical(high >> 8), inverse, M31.fromCanonical(if (canonical) 2 * (high >> 8) else 0) };
}
