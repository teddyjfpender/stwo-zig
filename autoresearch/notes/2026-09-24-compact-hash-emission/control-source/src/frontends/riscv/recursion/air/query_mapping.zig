//! Exact typed logical AIR for Stark-V universal query-mapping row 21.
//!
//! Verifier-owned weights map the canonical bit vector from row 20 into the
//! exact position and fold offset required by each trace, DEEP, and FRI use.
//! The proof may supply the resulting columns, but cannot select a route or
//! alter its weights.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.query_mapping.v1";
pub const M31_BIT_COUNT: usize = 31;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 3 + M31_BIT_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: usize = 7 + 2 * M31_BIT_COUNT;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 5 + M31_BIT_COUNT;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

// Filled from the independently computed typed-effect identity and pinned by
// the exactness gate. Updating this value requires an intentional IR change.
pub const SEMANTIC_DIGEST_HEX =
    "2aa730409d9411ea1a675513c81e72ac5d3f4b8875aa88d76788651075ed955c";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion query-mapping semantic digest",
);

pub const MAIN_COLUMN_NAMES = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.query_mapping.enabler";
    names[1] = "recursion.query_mapping.position";
    names[2] = "recursion.query_mapping.offset";
    for (0..M31_BIT_COUNT) |bit| {
        names[3 + bit] = std.fmt.comptimePrint(
            "recursion.query_mapping.bit_{d}",
            .{bit},
        );
    }
    break :blk names;
};

pub const PREPROCESSED_COLUMN_NAMES = blk: {
    var names: [PREPROCESSED_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion_query_mapping_row_mask";
    names[1] = "recursion_query_mapping_segment_mask";
    names[2] = "recursion_query_mapping_binary_mask";
    names[3] = "recursion_query_mapping_verifier_id";
    names[4] = "recursion_query_mapping_kind";
    names[5] = "recursion_query_mapping_item";
    names[6] = "recursion_query_mapping_query";
    for (0..M31_BIT_COUNT) |bit| {
        names[7 + bit] = std.fmt.comptimePrint(
            "recursion_query_mapping_position_weight_{d}",
            .{bit},
        );
        names[7 + M31_BIT_COUNT + bit] = std.fmt.comptimePrint(
            "recursion_query_mapping_offset_weight_{d}",
            .{bit},
        );
    }
    break :blk names;
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.query_mapping.param.segment_active",
    "recursion.query_mapping.param.binary_active",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    position: types.ValueId,
    offset: types.ValueId,
    bits: [M31_BIT_COUNT]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.position, self.offset } ++ self.bits;
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    verifier_id: types.ValueId,
    kind: types.ValueId,
    item: types.ValueId,
    query: types.ValueId,
    position_weights: [M31_BIT_COUNT]types.ValueId,
    offset_weights: [M31_BIT_COUNT]types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.kind,
            self.item,
            self.query,
        } ++ self.position_weights ++ self.offset_weights;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.binary_active };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidQueryMappingDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
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
            return error.InvalidQueryMappingDefinition;
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
                return error.InvalidQueryMappingDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidQueryMappingDefinition;
            const expected_name = constraintName(index, &name_buffer) catch
                return error.InvalidQueryMappingDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidQueryMappingDefinition;
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
        .position = main_values[1],
        .offset = main_values[2],
        .bits = main_values[3..][0..M31_BIT_COUNT].*,
    };

    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 2) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .verifier_id = preprocessed_values[3],
        .kind = preprocessed_values[4],
        .item = preprocessed_values[5],
        .query = preprocessed_values[6],
        .position_weights = preprocessed_values[7..][0..M31_BIT_COUNT].*,
        .offset_weights = preprocessed_values[7 + M31_BIT_COUNT ..][0..M31_BIT_COUNT].*,
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
    };

    const one = try arena.constantField(1, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const inactive = try arena.sub(one, active, span);

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try arena.sub(main.enabler, active, span);
    roots[1] = try arena.mul(inactive, main.position, span);
    roots[2] = try arena.mul(inactive, main.offset, span);
    for (main.bits, 0..) |bit, index| {
        roots[3 + index] = try arena.mul(inactive, bit, span);
    }

    const zero = try arena.constantField(0, span);
    var expected_position = zero;
    var expected_offset = zero;
    for (
        main.bits,
        preprocessed.position_weights,
        preprocessed.offset_weights,
    ) |bit, position_weight, offset_weight| {
        expected_position = try arena.add(
            expected_position,
            try arena.mul(bit, position_weight, span),
            span,
        );
        expected_offset = try arena.add(
            expected_offset,
            try arena.mul(bit, offset_weight, span),
            span,
        );
    }
    roots[3 + M31_BIT_COUNT] = try arena.sub(main.position, expected_position, span);
    roots[4 + M31_BIT_COUNT] = try arena.sub(main.offset, expected_offset, span);

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [96]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        const name = try constraintName(index, &name_buffer);
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const weights = [RELATION_EVENT_COUNT]types.ValueId{ active, active };
    var bit_tuple: [2 + M31_BIT_COUNT]types.ValueId = undefined;
    bit_tuple[0] = preprocessed.verifier_id;
    bit_tuple[1] = preprocessed.query;
    @memcpy(bit_tuple[2..], &main.bits);
    const position_tuple = [_]types.ValueId{
        preprocessed.verifier_id,
        preprocessed.kind,
        preprocessed.item,
        preprocessed.query,
        main.position,
        main.offset,
    };
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        .{
            .{
                .domain = .recursion_query_bits,
                .role = .consume,
                .values = &bit_tuple,
                .weight = weights[0],
            },
            .{
                .domain = .recursion_query_position,
                .role = .emit,
                .values = &position_tuple,
                .weight = weights[1],
            },
        },
        span,
    );

    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
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
) error{InvalidQueryMappingDefinition}!void {
    if (values.len != names.len) return error.InvalidQueryMappingDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidQueryMappingDefinition;
        const node = arena.node(value) orelse return error.InvalidQueryMappingDefinition;
        const expected_type: types.Type = switch (group) {
            .main => if (local_index == 0)
                .selector
            else if (local_index >= 3)
                .bit
            else
                .felt,
            .preprocessed => if (local_index <= 2) .selector else .felt,
            .parameters => .selector,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidQueryMappingDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidQueryMappingDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidQueryMappingDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidQueryMappingDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidQueryMappingDefinition}!void {
    var bit_tuple: [2 + M31_BIT_COUNT]types.ValueId = undefined;
    bit_tuple[0] = self.preprocessed.verifier_id;
    bit_tuple[1] = self.preprocessed.query;
    @memcpy(bit_tuple[2..], &self.main.bits);
    const position_tuple = [_]types.ValueId{
        self.preprocessed.verifier_id,
        self.preprocessed.kind,
        self.preprocessed.item,
        self.preprocessed.query,
        self.main.position,
        self.main.offset,
    };
    try validateEvent(self, 0, .recursion_query_bits, .consume, &bit_tuple);
    try validateEvent(self, 1, .recursion_query_position, .emit, &position_tuple);
}

fn validateEvent(
    self: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
) error{InvalidQueryMappingDefinition}!void {
    const effect_id = self.events[index];
    if (types.idIndex(effect_id) != index) return error.InvalidQueryMappingDefinition;
    const item = self.arena.effect(effect_id) orelse return error.InvalidQueryMappingDefinition;
    const binding = item.binding orelse return error.InvalidQueryMappingDefinition;
    const schema = relation.get(domain);
    const values = self.arena.effectValues(effect_id) orelse
        return error.InvalidQueryMappingDefinition;
    if (item.kind != .component_call or item.liveness != self.weights[index] or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, expected_values))
    {
        return error.InvalidQueryMappingDefinition;
    }
}

fn constraintName(index: usize, buffer: *[96]u8) ![]const u8 {
    return switch (index) {
        0 => "recursion.query_mapping.enabler_matches_active",
        1 => "recursion.query_mapping.inactive_position_zero",
        2 => "recursion.query_mapping.inactive_offset_zero",
        3...(3 + M31_BIT_COUNT - 1) => std.fmt.bufPrint(
            buffer,
            "recursion.query_mapping.bit_{d}_inactive_zero",
            .{index - 3},
        ),
        3 + M31_BIT_COUNT => "recursion.query_mapping.position_from_bits",
        4 + M31_BIT_COUNT => "recursion.query_mapping.offset_from_bits",
        else => error.InvalidConstraintIndex,
    };
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
