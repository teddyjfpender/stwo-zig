//! Lane-specific typed AIR for Stark-V universal query-bits row 20.
//!
//! Each active transcript query is decomposed into its unique 31-bit M31
//! representation. The inverse constraint excludes the all-ones alias of
//! zero, while typed relations bind the raw draw, the complete bit vector,
//! and every individually consumed position bit.  The raw transcript word and
//! its lifting-domain position are deliberately distinct typed values: the
//! former retains all 31 authenticated bits, while verifier-owned projection
//! parameters zero bits outside the selected proof profile's domain.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.query_bits.v2";
pub const M31_BIT_COUNT: usize = 31;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 3 + M31_BIT_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: usize = 6 + M31_BIT_COUNT;
pub const PARAMETER_COUNT: usize = 3;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 5 + 2 * M31_BIT_COUNT;
pub const RELATION_EVENT_COUNT: usize = 2 + M31_BIT_COUNT;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 17;
pub const INTERACTION_COLUMN_COUNT: usize = 68;
// Projection masks are verifier-owned preprocessed scalars.  Moving them
// from V1's proof-global parameter array into each authenticated row permits
// distinct left/right lifting domains without adding a physical component.
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "d6099d3f2c4a494db37923a30799e40aa14216cd078a584307c86f5f542d3310";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion query-bits semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "4a22440431eb6980f4fc60720fecc49163aa5b88278b0bb70f86764ed85706cb";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.query_bits.enabler",
    "recursion.query_bits.word",
    "recursion.query_bits.canonical_inverse",
    "recursion.query_bits.bit_0",
    "recursion.query_bits.bit_1",
    "recursion.query_bits.bit_2",
    "recursion.query_bits.bit_3",
    "recursion.query_bits.bit_4",
    "recursion.query_bits.bit_5",
    "recursion.query_bits.bit_6",
    "recursion.query_bits.bit_7",
    "recursion.query_bits.bit_8",
    "recursion.query_bits.bit_9",
    "recursion.query_bits.bit_10",
    "recursion.query_bits.bit_11",
    "recursion.query_bits.bit_12",
    "recursion.query_bits.bit_13",
    "recursion.query_bits.bit_14",
    "recursion.query_bits.bit_15",
    "recursion.query_bits.bit_16",
    "recursion.query_bits.bit_17",
    "recursion.query_bits.bit_18",
    "recursion.query_bits.bit_19",
    "recursion.query_bits.bit_20",
    "recursion.query_bits.bit_21",
    "recursion.query_bits.bit_22",
    "recursion.query_bits.bit_23",
    "recursion.query_bits.bit_24",
    "recursion.query_bits.bit_25",
    "recursion.query_bits.bit_26",
    "recursion.query_bits.bit_27",
    "recursion.query_bits.bit_28",
    "recursion.query_bits.bit_29",
    "recursion.query_bits.bit_30",
};

pub const PREPROCESSED_COLUMN_NAMES = blk: {
    var names: [PREPROCESSED_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion_query_raw_row_mask";
    names[1] = "recursion_query_raw_segment_mask";
    names[2] = "recursion_query_raw_binary_mask";
    names[3] = "recursion_query_raw_verifier_id";
    names[4] = "recursion_query_raw_query";
    names[5] = "recursion_query_raw_use_count";
    for (0..M31_BIT_COUNT) |bit| names[6 + bit] = std.fmt.comptimePrint(
        "recursion_query_raw_position_bit_mask_{d}",
        .{bit},
    );
    break :blk names;
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.query_bits.param.segment_active",
    "recursion.query_bits.param.binary_active",
    "recursion.query_bits.param.raw_query_kind",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    word: types.ValueId,
    canonical_inverse: types.ValueId,
    bits: [M31_BIT_COUNT]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.word, self.canonical_inverse } ++ self.bits;
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    verifier_id: types.ValueId,
    query: types.ValueId,
    use_count: types.ValueId,
    position_bit_masks: [M31_BIT_COUNT]types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.query,
            self.use_count,
        } ++ self.position_bit_masks;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    raw_query_kind: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.binary_active, self.raw_query_kind };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidQueryBitsDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    projected_bits: [M31_BIT_COUNT]types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    weights: [RELATION_EVENT_COUNT]types.ValueId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const actual_identity = try digest.computeIdentity(&self.arena);
        if (actual_identity.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual_identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidQueryBitsDefinition;
        }
        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            .main,
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed,
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            .parameters,
        );
        var name_buffer: [96]u8 = undefined;
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidQueryBitsDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidQueryBitsDefinition;
            const expected_name = constraintName(index, &name_buffer) catch
                return error.InvalidQueryBitsDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidQueryBitsDefinition;
            }
        }
        try validateEvents(self);
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn identity(allocator: std.mem.Allocator) !digest.Identity {
    var result = try buildDefinition(allocator);
    defer result.deinit();
    return digest.computeIdentity(&result.arena);
}

fn buildDefinition(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();

    var main_values: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&main_values, MAIN_COLUMN_NAMES, 0..) |*value, name, index| {
        const ty: types.Type = if (index == 0)
            .selector
        else if (index >= 3)
            .bit
        else
            .felt;
        value.* = try arena.input(name, ty, span);
    }
    const main = MainColumns{
        .enabler = main_values[0],
        .word = main_values[1],
        .canonical_inverse = main_values[2],
        .bits = main_values[3..][0..M31_BIT_COUNT].*,
    };

    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(
            name,
            if (index <= 2 or index >= 6) .selector else .felt,
            span,
        );
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .verifier_id = preprocessed_values[3],
        .query = preprocessed_values[4],
        .use_count = preprocessed_values[5],
        .position_bit_masks = preprocessed_values[6..][0..M31_BIT_COUNT].*,
    };
    var parameter_values: [PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameter_values, PARAMETER_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(
            name,
            if (index == 2) .felt else .selector,
            span,
        );
    }
    const parameters = Parameters{
        .segment_active = parameter_values[0],
        .binary_active = parameter_values[1],
        .raw_query_kind = parameter_values[2],
    };

    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const inactive = try arena.sub(one, active, span);

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try arena.sub(main.enabler, active, span);
    roots[1] = try arena.mul(inactive, main.word, span);
    roots[2] = try arena.mul(inactive, main.canonical_inverse, span);
    for (main.bits, 0..) |bit, index| {
        roots[3 + 2 * index] = try arena.mul(
            bit,
            try arena.sub(one, bit, span),
            span,
        );
        roots[4 + 2 * index] = try arena.mul(inactive, bit, span);
    }

    var reconstructed = zero;
    var bit_sum = zero;
    for (main.bits, 0..) |bit, index| {
        const weight = try arena.constantField(@as(u32, 1) << @intCast(index), span);
        reconstructed = try arena.add(
            reconstructed,
            try arena.mul(weight, bit, span),
            span,
        );
        bit_sum = try arena.add(bit_sum, bit, span);
    }
    roots[3 + 2 * M31_BIT_COUNT] = try arena.sub(main.word, reconstructed, span);
    const thirty_one = try arena.constantField(M31_BIT_COUNT, span);
    roots[4 + 2 * M31_BIT_COUNT] = try arena.sub(
        try arena.mul(
            try arena.sub(try arena.mul(active, thirty_one, span), bit_sum, span),
            main.canonical_inverse,
            span,
        ),
        active,
        span,
    );

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [96]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        const name = try constraintName(index, &name_buffer);
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    var weights: [RELATION_EVENT_COUNT]types.ValueId = undefined;
    weights[0] = active;
    weights[1] = try arena.mul(active, preprocessed.use_count, span);
    const two = try arena.constantField(2, span);
    for (weights[2..]) |*weight| weight.* = try arena.mul(active, two, span);

    var bit_tuple: [2 + M31_BIT_COUNT]types.ValueId = undefined;
    bit_tuple[0] = preprocessed.verifier_id;
    bit_tuple[1] = preprocessed.query;
    @memcpy(bit_tuple[2..], &main.bits);
    var projected_bits: [M31_BIT_COUNT]types.ValueId = undefined;
    for (&projected_bits, main.bits, preprocessed.position_bit_masks) |
        *projected,
        bit,
        mask,
    | projected.* = try arena.mul(bit, mask, span);
    var bit_value_tuples: [M31_BIT_COUNT][4]types.ValueId = undefined;
    var event_specs: [RELATION_EVENT_COUNT]relation_effect.EventSpec = undefined;
    event_specs[0] = .{
        .domain = .recursion_verifier_randomness_word,
        .role = .consume,
        .values = &.{
            preprocessed.verifier_id,
            parameters.raw_query_kind,
            preprocessed.query,
            zero,
            main.word,
        },
        .weight = weights[0],
    };
    event_specs[1] = .{
        .domain = .recursion_query_bits,
        .role = .emit,
        .values = &bit_tuple,
        .weight = weights[1],
    };
    for (&bit_value_tuples, projected_bits, 0..) |*tuple, bit, index| {
        tuple.* = .{
            preprocessed.verifier_id,
            preprocessed.query,
            try arena.constantField(@intCast(index), span),
            bit,
        };
        event_specs[2 + index] = .{
            .domain = .recursion_query_bit_value,
            .role = .emit,
            .values = tuple,
            .weight = weights[2 + index],
        };
    }
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        event_specs,
        span,
    );

    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .projected_bits = projected_bits,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .events = events,
    };
}

const InputGroup = enum { main, preprocessed, parameters };

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    group: InputGroup,
) error{InvalidQueryBitsDefinition}!void {
    if (values.len != names.len) return error.InvalidQueryBitsDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidQueryBitsDefinition;
        const node = arena.node(value) orelse return error.InvalidQueryBitsDefinition;
        const expected_type: types.Type = switch (group) {
            .main => if (local_index == 0)
                .selector
            else if (local_index >= 3)
                .bit
            else
                .felt,
            .preprocessed => if (local_index <= 2 or local_index >= 6) .selector else .felt,
            .parameters => if (local_index == 2) .felt else .selector,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidQueryBitsDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidQueryBitsDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidQueryBitsDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidQueryBitsDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidQueryBitsDefinition}!void {
    var bit_tuple: [2 + M31_BIT_COUNT]types.ValueId = undefined;
    bit_tuple[0] = self.preprocessed.verifier_id;
    bit_tuple[1] = self.preprocessed.query;
    @memcpy(bit_tuple[2..], &self.main.bits);
    const zero = zeroValue(&self.arena) orelse return error.InvalidQueryBitsDefinition;
    const randomness = [_]types.ValueId{
        self.preprocessed.verifier_id,
        self.parameters.raw_query_kind,
        self.preprocessed.query,
        zero,
        self.main.word,
    };
    try validateEvent(self, 0, .recursion_verifier_randomness_word, .consume, &randomness);
    try validateEvent(self, 1, .recursion_query_bits, .emit, &bit_tuple);
    for (self.projected_bits, 0..) |bit, index| {
        const index_value = constantValue(&self.arena, index) orelse
            return error.InvalidQueryBitsDefinition;
        const tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.preprocessed.query,
            index_value,
            bit,
        };
        try validateEvent(self, 2 + index, .recursion_query_bit_value, .emit, &tuple);
    }
}

fn validateEvent(
    self: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
) error{InvalidQueryBitsDefinition}!void {
    const effect_id = self.events[index];
    if (types.idIndex(effect_id) != index) return error.InvalidQueryBitsDefinition;
    const item = self.arena.effect(effect_id) orelse return error.InvalidQueryBitsDefinition;
    const binding = item.binding orelse return error.InvalidQueryBitsDefinition;
    const schema = relation.get(domain);
    const values = self.arena.effectValues(effect_id) orelse
        return error.InvalidQueryBitsDefinition;
    if (item.kind != .component_call or item.liveness != self.weights[index] or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, expected_values))
    {
        return error.InvalidQueryBitsDefinition;
    }
}

fn constraintName(index: usize, buffer: *[96]u8) ![]const u8 {
    return switch (index) {
        0 => "recursion.query_bits.enabler_matches_active",
        1 => "recursion.query_bits.inactive_word_zero",
        2 => "recursion.query_bits.inactive_inverse_zero",
        3...(3 + 2 * M31_BIT_COUNT - 1) => if ((index - 3) % 2 == 0)
            std.fmt.bufPrint(buffer, "recursion.query_bits.bit_{d}_boolean", .{(index - 3) / 2})
        else
            std.fmt.bufPrint(buffer, "recursion.query_bits.bit_{d}_inactive_zero", .{(index - 4) / 2}),
        3 + 2 * M31_BIT_COUNT => "recursion.query_bits.reconstruct_word",
        4 + 2 * M31_BIT_COUNT => "recursion.query_bits.canonical_m31",
        else => error.InvalidConstraintIndex,
    };
}

fn zeroValue(arena: *const ir.Arena) ?types.ValueId {
    return constantValue(arena, 0);
}

fn constantValue(arena: *const ir.Arena, expected: u64) ?types.ValueId {
    for (arena.nodesView(), 0..) |node, index| switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| if (value == expected) return @enumFromInt(index),
            .unsigned => {},
        },
        else => {},
    };
    return null;
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
