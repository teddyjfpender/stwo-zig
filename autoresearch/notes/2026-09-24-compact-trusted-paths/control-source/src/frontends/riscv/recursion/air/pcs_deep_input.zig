//! Exact typed logical AIR for Stark-V universal PCS-DEEP boundary row 24.
//!
//! Verifier-owned preprocessing classifies every circuit input. Active lanes
//! consume each authenticated source, export the four-word DEEP answer, and
//! emit the input node's exact wire multiplicity from the same definition.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.pcs_deep_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 18;
pub const PARAMETER_COUNT: usize = 6;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 3;
pub const RELATION_EVENT_COUNT: usize = 8;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 4;
pub const INTERACTION_COLUMN_COUNT: usize = 16;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
/// The local profiler conservatively counts verifier-owned preprocessing as
/// degree one. Stark-V treats those columns as constants during composition.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;

pub const SEMANTIC_DIGEST_HEX =
    "97b4efa272c99994e842df9bfdee9faf372ce30b45e54bc49cbaa6882c8001dd";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion PCS-DEEP-input semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.pcs_deep_input.enabler",
    "recursion.pcs_deep_input.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_pcs_deep_input_row_mask",
    "recursion_pcs_deep_input_segment_mask",
    "recursion_pcs_deep_input_binary_mask",
    "recursion_pcs_deep_input_sampled_value_mask",
    "recursion_pcs_deep_input_queried_value_mask",
    "recursion_pcs_deep_input_oods_seed_mask",
    "recursion_pcs_deep_input_deep_randomness_mask",
    "recursion_pcs_deep_input_query_bit_mask",
    "recursion_pcs_deep_input_query_position_mask",
    "recursion_pcs_deep_input_answer_mask",
    "recursion_pcs_deep_input_selector_mask",
    "recursion_pcs_deep_input_verifier_id",
    "recursion_pcs_deep_input_circuit_id",
    "recursion_pcs_deep_input_node_id",
    "recursion_pcs_deep_input_use_count",
    "recursion_pcs_deep_input_source_index_0",
    "recursion_pcs_deep_input_source_index_1",
    "recursion_pcs_deep_input_source_index_2",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.pcs_deep_input.param.segment_active",
    "recursion.pcs_deep_input.param.binary_active",
    "recursion.pcs_deep_input.param.sampled_value_kind",
    "recursion.pcs_deep_input.param.oods_point_kind",
    "recursion.pcs_deep_input.param.deep_randomness_kind",
    "recursion.pcs_deep_input.param.deep_position_kind",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.pcs_deep_input.enabler_matches_row_mask",
    "recursion.pcs_deep_input.inactive_witness_is_zero",
    "recursion.pcs_deep_input.selector_matches_active_lane",
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
    sampled_value_mask: types.ValueId,
    queried_value_mask: types.ValueId,
    oods_seed_mask: types.ValueId,
    deep_randomness_mask: types.ValueId,
    query_bit_mask: types.ValueId,
    query_position_mask: types.ValueId,
    answer_mask: types.ValueId,
    selector_mask: types.ValueId,
    verifier_id: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    use_count: types.ValueId,
    source_index_0: types.ValueId,
    source_index_1: types.ValueId,
    source_index_2: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.sampled_value_mask,
            self.queried_value_mask,
            self.oods_seed_mask,
            self.deep_randomness_mask,
            self.query_bit_mask,
            self.query_position_mask,
            self.answer_mask,
            self.selector_mask,
            self.verifier_id,
            self.circuit_id,
            self.node_id,
            self.use_count,
            self.source_index_0,
            self.source_index_1,
            self.source_index_2,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    sampled_value_kind: types.ValueId,
    oods_point_kind: types.ValueId,
    deep_randomness_kind: types.ValueId,
    deep_position_kind: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
            self.sampled_value_kind,
            self.oods_point_kind,
            self.deep_randomness_kind,
            self.deep_position_kind,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidPcsDeepInputDefinition,
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
            return error.InvalidPcsDeepInputDefinition;
        }
        try validateInputGroup(&self.arena, &self.main.physical(), &MAIN_COLUMN_NAMES, 0, &.{0});
        try validateInputGroup(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
        );
        try validateInputGroup(
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
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidPcsDeepInputDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidPcsDeepInputDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidPcsDeepInputDefinition;
            }
        }
        const zero = zeroValue(&self.arena) orelse
            return error.InvalidPcsDeepInputDefinition;
        const tuples = [_][]const types.ValueId{
            &.{ self.preprocessed.verifier_id, self.parameters.sampled_value_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.preprocessed.source_index_2, self.main.value },
            &.{ self.preprocessed.verifier_id, self.parameters.oods_point_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.parameters.deep_randomness_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.parameters.deep_position_kind, zero, self.preprocessed.source_index_0, self.main.value, zero },
            &.{ self.preprocessed.verifier_id, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.circuit_id, self.preprocessed.node_id, self.main.value, zero, zero, zero },
        };
        const domains = [_]relation.Domain{
            .recursion_verifier_input_word,
            .recursion_trace_query_value,
            .recursion_verifier_randomness_word,
            .recursion_verifier_randomness_word,
            .recursion_query_bit_value,
            .recursion_query_position,
            .recursion_pcs_deep_answer_word,
            .recursion_wire,
        };
        const roles = [_]relation.Role{
            .consume, .consume, .consume, .consume, .consume, .consume, .emit, .emit,
        };
        for (self.events, self.weights, domains, roles, tuples, 0..) |
            effect_id,
            weight,
            domain,
            role,
            tuple,
            index,
        | {
            if (types.idIndex(effect_id) != index)
                return error.InvalidPcsDeepInputDefinition;
            const item = self.arena.effect(effect_id) orelse
                return error.InvalidPcsDeepInputDefinition;
            const binding = item.binding orelse
                return error.InvalidPcsDeepInputDefinition;
            const schema = relation.get(domain);
            const values = self.arena.effectValues(effect_id) orelse
                return error.InvalidPcsDeepInputDefinition;
            if (item.kind != .component_call or item.liveness != weight or
                item.access_ordinal != null or binding.schema != schema.id or
                binding.schema_version != schema.version or binding.role != role or
                !std.mem.eql(types.ValueId, values, tuple))
            {
                return error.InvalidPcsDeepInputDefinition;
            }
        }
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
    const main = MainColumns{
        .enabler = try arena.input(MAIN_COLUMN_NAMES[0], .selector, span),
        .value = try arena.input(MAIN_COLUMN_NAMES[1], .felt, span),
    };
    var pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 10) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = pp[0],
        .segment_mask = pp[1],
        .binary_mask = pp[2],
        .sampled_value_mask = pp[3],
        .queried_value_mask = pp[4],
        .oods_seed_mask = pp[5],
        .deep_randomness_mask = pp[6],
        .query_bit_mask = pp[7],
        .query_position_mask = pp[8],
        .answer_mask = pp[9],
        .selector_mask = pp[10],
        .verifier_id = pp[11],
        .circuit_id = pp[12],
        .node_id = pp[13],
        .use_count = pp[14],
        .source_index_0 = pp[15],
        .source_index_1 = pp[16],
        .source_index_2 = pp[17],
    };
    var parameters_values: [PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameters_values, PARAMETER_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 1) .selector else .felt, span);
    }
    const parameters = Parameters{
        .segment_active = parameters_values[0],
        .binary_active = parameters_values[1],
        .sampled_value_kind = parameters_values[2],
        .oods_point_kind = parameters_values[3],
        .deep_randomness_kind = parameters_values[4],
        .deep_position_kind = parameters_values[5],
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
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }
    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        try arena.mul(active, preprocessed.sampled_value_mask, span),
        try arena.mul(active, preprocessed.queried_value_mask, span),
        try arena.mul(active, preprocessed.oods_seed_mask, span),
        try arena.mul(active, preprocessed.deep_randomness_mask, span),
        try arena.mul(active, preprocessed.query_bit_mask, span),
        try arena.mul(active, preprocessed.query_position_mask, span),
        try arena.mul(active, preprocessed.answer_mask, span),
        try arena.mul(active, preprocessed.use_count, span),
    };
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_verifier_input_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.sampled_value_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[0] },
        .{ .domain = .recursion_trace_query_value, .role = .consume, .values = &.{ preprocessed.verifier_id, preprocessed.source_index_0, preprocessed.source_index_1, preprocessed.source_index_2, main.value }, .weight = weights[1] },
        .{ .domain = .recursion_verifier_randomness_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.oods_point_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[2] },
        .{ .domain = .recursion_verifier_randomness_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.deep_randomness_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[3] },
        .{ .domain = .recursion_query_bit_value, .role = .consume, .values = &.{ preprocessed.verifier_id, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[4] },
        .{ .domain = .recursion_query_position, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.deep_position_kind, zero, preprocessed.source_index_0, main.value, zero }, .weight = weights[5] },
        .{ .domain = .recursion_pcs_deep_answer_word, .role = .emit, .values = &.{ preprocessed.verifier_id, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[6] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &.{ preprocessed.circuit_id, preprocessed.node_id, main.value, zero, zero, zero }, .weight = weights[7] },
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

fn validateInputGroup(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidPcsDeepInputDefinition}!void {
    if (values.len != names.len) return error.InvalidPcsDeepInputDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidPcsDeepInputDefinition;
        const node = arena.node(value) orelse return error.InvalidPcsDeepInputDefinition;
        var expected_type: types.Type = .felt;
        for (selector_indices) |selector_index| if (selector_index == local_index) {
            expected_type = .selector;
            break;
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidPcsDeepInputDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidPcsDeepInputDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidPcsDeepInputDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidPcsDeepInputDefinition;
    }
}

fn zeroValue(arena: *const ir.Arena) ?types.ValueId {
    for (arena.nodesView(), 0..) |node, index| switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| if (value == 0) return @enumFromInt(index),
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
