//! Candidate fixed-key Statement source for a log-10 SegmentV2 leaf.
//!
//! The sole preprocessed value is the verifier-owned logical row ordinal.
//! Wire/context/padding placement is proved from the public wire count using
//! bounded differences, rather than being compiled into leaf-specific fixed
//! columns. The public parameter must be bound to the authenticated child
//! geometry by the enclosing proof. This AIR is not a standalone proof.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const ir = @import("../../air/lang/ir.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const digest = @import("../../air/lang/digest.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");
const interaction = @import("relation_interaction.zig");
const boundary = @import("../segment_leaf_statement_contract_v2.zig");
const framework = @import("framework_interaction.zig");

pub const FORMAT_VERSION: u16 = 8;
pub const STABLE_NAME = "recursion.segment_leaf_v8.statement_source.direct";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const LOG_SIZE: u32 = 10;
pub const CAPACITY: usize = 1 << LOG_SIZE;
pub const MIN_WIRE_WORDS: u32 = 664;
pub const MAX_WIRE_WORDS: u32 = CAPACITY - boundary.CONTEXT_WORD_COUNT;
pub const DISTANCE_BITS: usize = 10;
pub const SHORT_BITS: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 4 + DISTANCE_BITS + 3 * SHORT_BITS;
pub const PREPROCESSED_COLUMN_COUNT: usize = 1;
pub const PARAMETER_COUNT: usize = 1;
pub const LOGICAL_INPUT_COUNT = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 10 + DISTANCE_BITS + 3 * SHORT_BITS + SHORT_BITS;
pub const RELATION_EVENT_COUNT: usize = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const SEMANTIC_DIGEST_HEX = "0597ef97e6d5961e4949258d81eca3b622611dc3b473cc850fcdc1b3e61aaec9";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var value: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&value, SEMANTIC_DIGEST_HEX) catch @compileError("invalid V8 Statement AIR digest");
    break :blk value;
};

const VALUE: usize = 0;
const WIRE: usize = 1;
const CONTEXT: usize = 2;
const EXTRA: usize = 3;
const DISTANCE: usize = 4;
const CONTEXT_COMPLEMENT: usize = DISTANCE + DISTANCE_BITS;
const WIRE_LOWER: usize = CONTEXT_COMPLEMENT + SHORT_BITS;
const WIRE_UPPER: usize = WIRE_LOWER + SHORT_BITS;

pub const MAIN_COLUMN_NAMES = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[VALUE] = STABLE_NAME ++ ".value";
    names[WIRE] = STABLE_NAME ++ ".wire";
    names[CONTEXT] = STABLE_NAME ++ ".context";
    names[EXTRA] = STABLE_NAME ++ ".extra";
    for (0..DISTANCE_BITS) |i| names[DISTANCE + i] = std.fmt.comptimePrint(STABLE_NAME ++ ".distance_bit_{d}", .{i});
    for (0..SHORT_BITS) |i| {
        names[CONTEXT_COMPLEMENT + i] = std.fmt.comptimePrint(STABLE_NAME ++ ".context_complement_bit_{d}", .{i});
        names[WIRE_LOWER + i] = std.fmt.comptimePrint(STABLE_NAME ++ ".wire_lower_bit_{d}", .{i});
        names[WIRE_UPPER + i] = std.fmt.comptimePrint(STABLE_NAME ++ ".wire_upper_bit_{d}", .{i});
    }
    break :blk names;
};
pub const PREPROCESSED_COLUMN_NAMES = [_][]const u8{STABLE_NAME ++ ".ordinal"};
pub const PARAMETER_NAMES = [_][]const u8{STABLE_NAME ++ ".wire_count"};

pub const Runtime = interaction.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Plan = Runtime.Plan;
pub const Row = Runtime.Row;

pub const Definition = struct {
    arena: ir.Arena,
    event: types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// The candidate's semantic digest is pinned, but production activation also
/// requires an enclosing proof to bind the public wire-count parameter.
pub fn build(allocator: std.mem.Allocator) !Definition {
    var definition = try buildRaw(allocator);
    errdefer definition.deinit();
    try validate_mod.validate(&definition.arena);
    const identity = try digest.computeIdentity(&definition.arena);
    if (definition.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or definition.arena.effectsView().len != RELATION_EVENT_COUNT or
        !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST))
        return error.InvalidDirectStatementV8;
    return definition;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) !digest.Digest {
    var definition = try buildRaw(allocator);
    defer definition.deinit();
    return (try digest.computeIdentity(&definition.arena)).bytes;
}

pub fn authenticate(definition: *const Definition) !Plan {
    try validate_mod.validate(&definition.arena);
    const identity = try digest.computeIdentity(&definition.arena);
    if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST)) return error.InvalidDirectStatementV8;
    return Runtime.authenticate(&definition.arena, SEMANTIC_DIGEST, .{definition.event});
}

/// Complete verifier-owned fixed column. The committed row permutation is
/// independent of leaf data and of the authenticated wire count.
pub fn writePreprocessed(column: []M31) !void {
    if (column.len != CAPACITY) return error.InvalidDirectStatementV8Columns;
    for (column) |value| if (!value.isZero()) return error.DirectStatementV8ColumnsNotFresh;
    for (0..CAPACITY) |ordinal| column[framework.committedRow(ordinal, LOG_SIZE)] = try fixedOrdinalRow(ordinal);
}

pub fn fixedOrdinalRow(ordinal: usize) !M31 {
    if (ordinal >= CAPACITY) return error.InvalidDirectStatementV8Ordinal;
    return M31.fromCanonical(@intCast(ordinal));
}

pub fn logicalRow(ordinal: usize, wire_count: u32, value: M31, extra: u32) !Row {
    if (ordinal >= CAPACITY or wire_count < MIN_WIRE_WORDS or wire_count > MAX_WIRE_WORDS or extra > 2)
        return error.InvalidDirectStatementV8Row;
    const active_end: u32 = wire_count + @as(u32, boundary.CONTEXT_WORD_COUNT);
    const wire: u32 = @intFromBool(ordinal < wire_count);
    const context: u32 = @intFromBool(ordinal >= wire_count and ordinal < active_end);
    if (extra != 0 and wire + context == 0) return error.InvalidDirectStatementV8Row;
    if (wire + context == 0 and !value.isZero()) return error.InvalidDirectStatementV8Row;
    var row: Row = @splat(M31.zero());
    row[VALUE] = value;
    row[WIRE] = M31.fromCanonical(wire);
    row[CONTEXT] = M31.fromCanonical(context);
    row[EXTRA] = M31.fromCanonical(extra);
    const distance: u32 = if (wire == 1) wire_count - 1 - @as(u32, @intCast(ordinal)) else if (context == 1) @as(u32, @intCast(ordinal)) - wire_count else @as(u32, @intCast(ordinal)) - active_end;
    setBits(&row, DISTANCE, DISTANCE_BITS, distance);
    if (context == 1) setBits(&row, CONTEXT_COMPLEMENT, SHORT_BITS, @as(u32, boundary.CONTEXT_WORD_COUNT - 1) - distance);
    setBits(&row, WIRE_LOWER, SHORT_BITS, wire_count - MIN_WIRE_WORDS);
    setBits(&row, WIRE_UPPER, SHORT_BITS, MAX_WIRE_WORDS - wire_count);
    row[PHYSICAL_MAIN_COLUMN_COUNT] = try fixedOrdinalRow(ordinal);
    row[PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT] = M31.fromCanonical(wire_count);
    return row;
}

fn setBits(row: *Row, offset: usize, count: usize, value: u32) void {
    for (0..count) |i| row[offset + i] = M31.fromCanonical((value >> @intCast(i)) & 1);
}

fn bits(arena: *ir.Arena, main: []const types.ValueId, offset: usize, count: usize, span: source.SourceSpan) !types.ValueId {
    var result = try arena.constantField(0, span);
    for (0..count) |i| {
        const scaled = try arena.mul(main[offset + i], try arena.constantField(@as(u32, 1) << @intCast(i), span), span);
        result = try arena.add(result, scaled, span);
    }
    return result;
}

fn assert(arena: *ir.Arena, name: []const u8, root: types.ValueId, span: source.SourceSpan) !void {
    _ = try arena.assertZero(name, root, null, .semantic, span);
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    var main: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&main, MAIN_COLUMN_NAMES, 0..) |*id, name, i| id.* = try arena.input(name, if (i == WIRE or i == CONTEXT or i >= DISTANCE) .selector else .felt, span);
    const ordinal = try arena.input(PREPROCESSED_COLUMN_NAMES[0], .felt, span);
    const wire_count = try arena.input(PARAMETER_NAMES[0], .felt, span);
    const one = try arena.constantField(1, span);
    const two = try arena.constantField(2, span);
    const active = try arena.add(main[WIRE], main[CONTEXT], span);
    const padding = try arena.sub(one, active, span);
    try assert(&arena, STABLE_NAME ++ ".wire_boolean", try arena.mul(main[WIRE], try arena.sub(main[WIRE], one, span), span), span);
    try assert(&arena, STABLE_NAME ++ ".context_boolean", try arena.mul(main[CONTEXT], try arena.sub(main[CONTEXT], one, span), span), span);
    try assert(&arena, STABLE_NAME ++ ".disjoint", try arena.mul(main[WIRE], main[CONTEXT], span), span);
    try assert(&arena, STABLE_NAME ++ ".extra_ternary", try arena.mul(main[EXTRA], try arena.mul(try arena.sub(main[EXTRA], one, span), try arena.sub(main[EXTRA], two, span), span), span), span);
    try assert(&arena, STABLE_NAME ++ ".inactive_extra_zero", try arena.mul(padding, main[EXTRA], span), span);
    try assert(&arena, STABLE_NAME ++ ".inactive_value_zero", try arena.mul(padding, main[VALUE], span), span);
    inline for (DISTANCE..PHYSICAL_MAIN_COLUMN_COUNT) |i| {
        const bit = main[i];
        try assert(&arena, std.fmt.comptimePrint(STABLE_NAME ++ ".bit_{d}", .{i}), try arena.mul(bit, try arena.sub(bit, one, span), span), span);
    }
    const distance = try bits(&arena, &main, DISTANCE, DISTANCE_BITS, span);
    const complement = try bits(&arena, &main, CONTEXT_COMPLEMENT, SHORT_BITS, span);
    const lower = try bits(&arena, &main, WIRE_LOWER, SHORT_BITS, span);
    const upper = try bits(&arena, &main, WIRE_UPPER, SHORT_BITS, span);
    const wire_delta = try arena.sub(try arena.sub(wire_count, one, span), ordinal, span);
    const context_delta = try arena.sub(ordinal, wire_count, span);
    const padding_delta = try arena.sub(context_delta, try arena.constantField(boundary.CONTEXT_WORD_COUNT, span), span);
    const wanted = try arena.add(try arena.add(try arena.mul(main[WIRE], wire_delta, span), try arena.mul(main[CONTEXT], context_delta, span), span), try arena.mul(padding, padding_delta, span), span);
    try assert(&arena, STABLE_NAME ++ ".ordered_distance", try arena.sub(distance, wanted, span), span);
    try assert(&arena, STABLE_NAME ++ ".context_end", try arena.mul(main[CONTEXT], try arena.sub(try arena.add(distance, complement, span), try arena.constantField(boundary.CONTEXT_WORD_COUNT - 1, span), span), span), span);
    inline for (CONTEXT_COMPLEMENT..WIRE_LOWER) |i| try assert(&arena, std.fmt.comptimePrint(STABLE_NAME ++ ".inactive_context_bit_{d}", .{i}), try arena.mul(try arena.sub(one, main[CONTEXT], span), main[i], span), span);
    try assert(&arena, STABLE_NAME ++ ".wire_lower_bound", try arena.sub(try arena.sub(wire_count, try arena.constantField(MIN_WIRE_WORDS, span), span), lower, span), span);
    try assert(&arena, STABLE_NAME ++ ".wire_upper_bound", try arena.sub(try arena.sub(try arena.constantField(MAX_WIRE_WORDS, span), wire_count, span), upper, span), span);
    const scope = try arena.add(try arena.mul(main[WIRE], try arena.constantField(boundary.WIRE_SCOPE, span), span), try arena.mul(main[CONTEXT], try arena.constantField(boundary.CONTEXT_SCOPE, span), span), span);
    const index = try arena.add(try arena.mul(main[WIRE], ordinal, span), try arena.mul(main[CONTEXT], context_delta, span), span);
    const weight = try arena.add(active, main[EXTRA], span);
    const event = try relation_effect.append(&arena, .{ .domain = .recursion_statement_word, .role = .emit, .values = &.{ scope, index, main[VALUE] }, .weight = weight }, span);
    return .{ .arena = arena, .event = event };
}
