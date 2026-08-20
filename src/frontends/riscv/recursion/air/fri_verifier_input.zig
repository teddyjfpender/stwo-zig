//! Exact typed logical AIR for Stark-V universal FRI-verifier input row 29.
//!
//! Verifier-owned preprocessing assigns each fixed arithmetic-circuit input to
//! one semantic producer and one circuit node. Active lanes consume the exact
//! transcript/PCS/query/FRI source and emit its graph-derived wire use count.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.fri_verifier_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 20;
pub const PARAMETER_COUNT: usize = 8;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 3;
pub const RELATION_EVENT_COUNT: usize = 9;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 5;
pub const INTERACTION_COLUMN_COUNT: usize = 20;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
/// The local profiler conservatively assigns degree one to verifier-owned
/// preprocessing; Stark-V treats those columns as composition constants.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;

pub const SEMANTIC_DIGEST_HEX =
    "f9b3a280c2cc87860b00508e45a2d4939b706163fe3135d48180edcb95331aa7";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion FRI-verifier-input semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.fri_verifier_input.enabler",
    "recursion.fri_verifier_input.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_fri_verifier_input_row_mask",
    "recursion_fri_verifier_input_segment_mask",
    "recursion_fri_verifier_input_binary_mask",
    "recursion_fri_verifier_input_deep_answer_mask",
    "recursion_fri_verifier_input_authenticated_value_mask",
    "recursion_fri_verifier_input_alpha_mask",
    "recursion_fri_verifier_input_query_bit_mask",
    "recursion_fri_verifier_input_fri_position_mask",
    "recursion_fri_verifier_input_fri_offset_mask",
    "recursion_fri_verifier_input_last_position_mask",
    "recursion_fri_verifier_input_coefficient_mask",
    "recursion_fri_verifier_input_selector_mask",
    "recursion_fri_verifier_input_verifier_id",
    "recursion_fri_verifier_input_circuit_id",
    "recursion_fri_verifier_input_node_id",
    "recursion_fri_verifier_input_use_count",
    "recursion_fri_verifier_input_source_index_0",
    "recursion_fri_verifier_input_source_index_1",
    "recursion_fri_verifier_input_source_index_2",
    "recursion_fri_verifier_input_source_index_3",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.fri_verifier_input.param.segment_active",
    "recursion.fri_verifier_input.param.binary_active",
    "recursion.fri_verifier_input.param.fri_alpha_kind",
    "recursion.fri_verifier_input.param.fri_fold_kind",
    "recursion.fri_verifier_input.param.last_layer_kind",
    "recursion.fri_verifier_input.param.position_field",
    "recursion.fri_verifier_input.param.offset_field",
    "recursion.fri_verifier_input.param.coefficient_kind",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.fri_verifier_input.enabler_matches_row_mask",
    "recursion.fri_verifier_input.inactive_witness_is_zero",
    "recursion.fri_verifier_input.selector_matches_active_lane",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    value: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.value };
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    deep_answer_mask: types.ValueId,
    authenticated_value_mask: types.ValueId,
    alpha_mask: types.ValueId,
    query_bit_mask: types.ValueId,
    fri_position_mask: types.ValueId,
    fri_offset_mask: types.ValueId,
    last_position_mask: types.ValueId,
    coefficient_mask: types.ValueId,
    selector_mask: types.ValueId,
    verifier_id: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    use_count: types.ValueId,
    source_indices: [4]types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.deep_answer_mask,
            self.authenticated_value_mask,
            self.alpha_mask,
            self.query_bit_mask,
            self.fri_position_mask,
            self.fri_offset_mask,
            self.last_position_mask,
            self.coefficient_mask,
            self.selector_mask,
            self.verifier_id,
            self.circuit_id,
            self.node_id,
            self.use_count,
        } ++ self.source_indices;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    fri_alpha_kind: types.ValueId,
    fri_fold_kind: types.ValueId,
    last_layer_kind: types.ValueId,
    position_field: types.ValueId,
    offset_field: types.ValueId,
    coefficient_kind: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
            self.fri_alpha_kind,
            self.fri_fold_kind,
            self.last_layer_kind,
            self.position_field,
            self.offset_field,
            self.coefficient_kind,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidFriVerifierInputDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    witness_mask: types.ValueId,
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
        const identity_value = try digest.computeIdentity(&self.arena);
        if (identity_value.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &identity_value.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidFriVerifierInputDefinition;
        }
        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            &.{0},
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{ 0, 1 },
        );
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidFriVerifierInputDefinition;
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidFriVerifierInputDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidFriVerifierInputDefinition;
            if (item.root != root or item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidFriVerifierInputDefinition;
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
    for (&main_values, MAIN_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index == 0) .selector else .felt, span);
    const main = MainColumns{ .enabler = main_values[0], .value = main_values[1] };

    var pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index <= 11) .selector else .felt, span);
    const preprocessed = PreprocessedColumns{
        .row_mask = pp[0],
        .segment_mask = pp[1],
        .binary_mask = pp[2],
        .deep_answer_mask = pp[3],
        .authenticated_value_mask = pp[4],
        .alpha_mask = pp[5],
        .query_bit_mask = pp[6],
        .fri_position_mask = pp[7],
        .fri_offset_mask = pp[8],
        .last_position_mask = pp[9],
        .coefficient_mask = pp[10],
        .selector_mask = pp[11],
        .verifier_id = pp[12],
        .circuit_id = pp[13],
        .node_id = pp[14],
        .use_count = pp[15],
        .source_indices = pp[16..20].*,
    };

    var parameter_values: [PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameter_values, PARAMETER_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index <= 1) .selector else .felt, span);
    const parameters = Parameters{
        .segment_active = parameter_values[0],
        .binary_active = parameter_values[1],
        .fri_alpha_kind = parameter_values[2],
        .fri_fold_kind = parameter_values[3],
        .last_layer_kind = parameter_values[4],
        .position_field = parameter_values[5],
        .offset_field = parameter_values[6],
        .coefficient_kind = parameter_values[7],
    };

    const one = try arena.constantField(1, span);
    const zero = try arena.constantField(0, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const witness_mask = try arena.sub(preprocessed.row_mask, preprocessed.selector_mask, span);
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(
            try arena.mul(witness_mask, try arena.sub(one, active, span), span),
            main.value,
            span,
        ),
        try arena.mul(
            preprocessed.selector_mask,
            try arena.sub(main.value, active, span),
            span,
        ),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);

    const source_masks = .{
        preprocessed.deep_answer_mask,
        preprocessed.authenticated_value_mask,
        preprocessed.alpha_mask,
        preprocessed.query_bit_mask,
        preprocessed.fri_position_mask,
        preprocessed.fri_offset_mask,
        preprocessed.last_position_mask,
        preprocessed.coefficient_mask,
    };
    var weights: [RELATION_EVENT_COUNT]types.ValueId = undefined;
    inline for (source_masks, 0..) |mask, index|
        weights[index] = try arena.mul(active, mask, span);
    weights[8] = try arena.mul(active, preprocessed.use_count, span);

    const i = preprocessed.source_indices;
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_pcs_deep_answer_word, .role = .consume, .values = &.{ preprocessed.verifier_id, i[0], i[1], main.value }, .weight = weights[0] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .consume, .values = &.{ preprocessed.verifier_id, i[0], i[1], i[2], i[3], main.value }, .weight = weights[1] },
        .{ .domain = .recursion_verifier_randomness_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.fri_alpha_kind, i[0], i[1], main.value }, .weight = weights[2] },
        .{ .domain = .recursion_query_bit_value, .role = .consume, .values = &.{ preprocessed.verifier_id, i[0], i[1], main.value }, .weight = weights[3] },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.fri_fold_kind, i[0], i[1], parameters.position_field, main.value }, .weight = weights[4] },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.fri_fold_kind, i[0], i[1], parameters.offset_field, main.value }, .weight = weights[5] },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.last_layer_kind, zero, i[0], parameters.position_field, main.value }, .weight = weights[6] },
        .{ .domain = .recursion_verifier_input_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.coefficient_kind, i[0], i[1], main.value }, .weight = weights[7] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &.{ preprocessed.circuit_id, preprocessed.node_id, main.value, zero, zero, zero }, .weight = weights[8] },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .witness_mask = witness_mask,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .events = events,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidFriVerifierInputDefinition}!void {
    if (values.len != names.len) return error.InvalidFriVerifierInputDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidFriVerifierInputDefinition;
        const node = arena.node(value) orelse return error.InvalidFriVerifierInputDefinition;
        var expected_type: types.Type = .felt;
        for (selector_indices) |selector_index| if (selector_index == local_index) {
            expected_type = .selector;
            break;
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidFriVerifierInputDefinition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidFriVerifierInputDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidFriVerifierInputDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidFriVerifierInputDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidFriVerifierInputDefinition}!void {
    const Expected = struct { domain: relation.Domain, role: relation.Role };
    const expected = [_]Expected{
        .{ .domain = .recursion_pcs_deep_answer_word, .role = .consume },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .consume },
        .{ .domain = .recursion_verifier_randomness_word, .role = .consume },
        .{ .domain = .recursion_query_bit_value, .role = .consume },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .consume },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .consume },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .consume },
        .{ .domain = .recursion_verifier_input_word, .role = .consume },
        .{ .domain = .recursion_wire, .role = .emit },
    };
    for (self.events, self.weights, expected, 0..) |effect_id, weight, want, index| {
        if (types.idIndex(effect_id) != index)
            return error.InvalidFriVerifierInputDefinition;
        const item = self.arena.effect(effect_id) orelse
            return error.InvalidFriVerifierInputDefinition;
        const binding = item.binding orelse return error.InvalidFriVerifierInputDefinition;
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidFriVerifierInputDefinition;
        const schema = relation.get(want.domain);
        if (item.kind != .component_call or item.liveness != weight or
            item.access_ordinal != null or binding.schema != schema.id or
            binding.schema_version != schema.version or binding.role != want.role or
            values.len != schema.fields.len)
        {
            return error.InvalidFriVerifierInputDefinition;
        }
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
