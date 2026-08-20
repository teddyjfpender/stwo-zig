//! Exact typed logical AIR for Stark-V authority-spine row 18.
//!
//! One verifier-owned table closes VM and recursive composition-circuit inputs.
//! Fixed constants and designated outputs belong to the independently derived
//! arithmetic-lowering public boundary; counting them here as well would give
//! two producers for one wire tuple.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.vm_air_composition_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 22;
pub const PARAMETER_COUNT: usize = 9;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 7;
pub const RELATION_EVENT_COUNT: usize = 9;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 5;
pub const INTERACTION_COLUMN_COUNT: usize = 20;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "cdafd62830488c5c6a9043435dc30ba7da9990c944a27eeea659ccd4c6cfcb0e";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion VM AIR-composition-input semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "2171c3d23ca8db25381a347bdb6b84d56a2045a01868fb085b6599cf16e3b22e";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.vm_air_composition_input.enabler",
    "recursion.vm_air_composition_input.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_vm_air_composition_input_row_mask",
    "recursion_vm_air_composition_input_sampled_value_mask",
    "recursion_vm_air_composition_input_claimed_sum_mask",
    "recursion_vm_air_composition_input_challenge_mask",
    "recursion_vm_air_composition_input_composition_randomness_mask",
    "recursion_vm_air_composition_input_oods_point_mask",
    "recursion_vm_air_composition_input_selector_mask",
    "recursion_vm_air_composition_input_circuit_id",
    "recursion_vm_air_composition_input_node_id",
    "recursion_vm_air_composition_input_use_count",
    "recursion_vm_air_composition_input_source_index_0",
    "recursion_vm_air_composition_input_source_index_1",
    "recursion_circuit_anchor_row_mask",
    "recursion_circuit_input_segment_mask",
    "recursion_circuit_input_binary_mask",
    "recursion_circuit_parent_binary_selector_mask",
    "recursion_circuit_child_kind_selector_mask",
    "recursion_circuit_statement_word_mask",
    "recursion_circuit_input_verifier_id",
    "recursion_circuit_input_statement_scope",
    "recursion_circuit_input_recursion_claimed_sum_mask",
    "recursion_circuit_input_transcript_claimed_sum_mask",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.vm_air_composition_input.param.segment_active",
    "recursion.vm_air_composition_input.param.binary_active",
    "recursion.vm_air_composition_input.param.sampled_value_kind",
    "recursion.vm_air_composition_input.param.vm_claimed_sum_kind",
    "recursion.vm_air_composition_input.param.recursion_claimed_sum_kind",
    "recursion.vm_air_composition_input.param.challenge_scope",
    "recursion.vm_air_composition_input.param.composition_randomness_kind",
    "recursion.vm_air_composition_input.param.oods_point_kind",
    "recursion.vm_air_composition_input.param.transcript_claimed_sum_kind",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.vm_air_composition_input.enabler_matches_row_mask",
    "recursion.vm_air_composition_input.row_partition",
    "recursion.vm_air_composition_input.inactive_segment_input_zero",
    "recursion.vm_air_composition_input.inactive_binary_input_zero",
    "recursion.vm_air_composition_input.segment_selector_value",
    "recursion.vm_air_composition_input.parent_binary_selector_value",
    "recursion.vm_air_composition_input.anchor_value_zero",
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
    sampled_value_mask: types.ValueId,
    claimed_sum_mask: types.ValueId,
    challenge_mask: types.ValueId,
    composition_randomness_mask: types.ValueId,
    oods_point_mask: types.ValueId,
    selector_mask: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    use_count: types.ValueId,
    source_index_0: types.ValueId,
    source_index_1: types.ValueId,
    anchor_row_mask: types.ValueId,
    input_segment_mask: types.ValueId,
    input_binary_mask: types.ValueId,
    parent_binary_selector_mask: types.ValueId,
    child_kind_selector_mask: types.ValueId,
    statement_word_mask: types.ValueId,
    verifier_id: types.ValueId,
    statement_scope: types.ValueId,
    recursion_claimed_sum_mask: types.ValueId,
    transcript_claimed_sum_mask: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.sampled_value_mask,
            self.claimed_sum_mask,
            self.challenge_mask,
            self.composition_randomness_mask,
            self.oods_point_mask,
            self.selector_mask,
            self.circuit_id,
            self.node_id,
            self.use_count,
            self.source_index_0,
            self.source_index_1,
            self.anchor_row_mask,
            self.input_segment_mask,
            self.input_binary_mask,
            self.parent_binary_selector_mask,
            self.child_kind_selector_mask,
            self.statement_word_mask,
            self.verifier_id,
            self.statement_scope,
            self.recursion_claimed_sum_mask,
            self.transcript_claimed_sum_mask,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    sampled_value_kind: types.ValueId,
    vm_claimed_sum_kind: types.ValueId,
    recursion_claimed_sum_kind: types.ValueId,
    challenge_scope: types.ValueId,
    composition_randomness_kind: types.ValueId,
    oods_point_kind: types.ValueId,
    transcript_claimed_sum_kind: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
            self.sampled_value_kind,
            self.vm_claimed_sum_kind,
            self.recursion_claimed_sum_kind,
            self.challenge_scope,
            self.composition_randomness_kind,
            self.oods_point_kind,
            self.transcript_claimed_sum_kind,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidVmAirCompositionInputDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    input_mask: types.ValueId,
    input_active: types.ValueId,
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
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidVmAirCompositionInputDefinition;
        }
        try validateInputs(&self.arena, &self.main.physical(), &MAIN_COLUMN_NAMES, 0, &.{0});
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1, 2, 3, 4, 5, 6, 12, 13, 14, 15, 16, 17, 20, 21 },
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
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidVmAirCompositionInputDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidVmAirCompositionInputDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidVmAirCompositionInputDefinition;
            }
        }
        const zero = zeroValue(&self.arena) orelse
            return error.InvalidVmAirCompositionInputDefinition;
        const tuples = [_][]const types.ValueId{
            &.{ self.preprocessed.verifier_id, self.parameters.sampled_value_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.parameters.vm_claimed_sum_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.parameters.recursion_claimed_sum_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.parameters.challenge_scope, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.parameters.composition_randomness_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.verifier_id, self.parameters.oods_point_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{ self.preprocessed.statement_scope, self.preprocessed.source_index_0, self.main.value },
            &.{ self.preprocessed.circuit_id, self.preprocessed.node_id, self.main.value, zero, zero, zero },
            &.{ self.preprocessed.verifier_id, self.parameters.transcript_claimed_sum_kind, self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
        };
        const domains = [_]relation.Domain{
            .recursion_verifier_input_word,
            .recursion_verifier_input_word,
            .recursion_verifier_input_word,
            .recursion_relation_challenge_word,
            .recursion_verifier_randomness_word,
            .recursion_verifier_randomness_word,
            .recursion_statement_word,
            .recursion_wire,
            .recursion_verifier_input_word,
        };
        const roles = [_]relation.Role{
            .consume, .consume, .consume, .consume,
            .consume, .consume, .consume, .emit,
            .consume,
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
                return error.InvalidVmAirCompositionInputDefinition;
            const item = self.arena.effect(effect_id) orelse
                return error.InvalidVmAirCompositionInputDefinition;
            const binding = item.binding orelse
                return error.InvalidVmAirCompositionInputDefinition;
            const schema = relation.get(domain);
            const values = self.arena.effectValues(effect_id) orelse
                return error.InvalidVmAirCompositionInputDefinition;
            if (item.kind != .component_call or item.liveness != weight or
                item.access_ordinal != null or binding.schema != schema.id or
                binding.schema_version != schema.version or binding.role != role or
                !std.mem.eql(types.ValueId, values, tuple))
            {
                return error.InvalidVmAirCompositionInputDefinition;
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

/// Regeneration hook used by the digest-pinning test. It deliberately hashes
/// the raw arena before pinned-digest validation.
pub fn computeSemanticDigest(allocator: std.mem.Allocator) !digest.Digest {
    var definition = try buildDefinition(allocator);
    defer definition.deinit();
    return (try digest.computeIdentity(&definition.arena)).bytes;
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
        value.* = try arena.input(name, if (isPreprocessedSelector(index)) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = pp[0],
        .sampled_value_mask = pp[1],
        .claimed_sum_mask = pp[2],
        .challenge_mask = pp[3],
        .composition_randomness_mask = pp[4],
        .oods_point_mask = pp[5],
        .selector_mask = pp[6],
        .circuit_id = pp[7],
        .node_id = pp[8],
        .use_count = pp[9],
        .source_index_0 = pp[10],
        .source_index_1 = pp[11],
        .anchor_row_mask = pp[12],
        .input_segment_mask = pp[13],
        .input_binary_mask = pp[14],
        .parent_binary_selector_mask = pp[15],
        .child_kind_selector_mask = pp[16],
        .statement_word_mask = pp[17],
        .verifier_id = pp[18],
        .statement_scope = pp[19],
        .recursion_claimed_sum_mask = pp[20],
        .transcript_claimed_sum_mask = pp[21],
    };
    var parameter_values: [PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameter_values, PARAMETER_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 1) .selector else .felt, span);
    }
    const parameters = Parameters{
        .segment_active = parameter_values[0],
        .binary_active = parameter_values[1],
        .sampled_value_kind = parameter_values[2],
        .vm_claimed_sum_kind = parameter_values[3],
        .recursion_claimed_sum_kind = parameter_values[4],
        .challenge_scope = parameter_values[5],
        .composition_randomness_kind = parameter_values[6],
        .oods_point_kind = parameter_values[7],
        .transcript_claimed_sum_kind = parameter_values[8],
    };

    const input_mask = try addMany(&arena, &.{
        preprocessed.sampled_value_mask,
        preprocessed.claimed_sum_mask,
        preprocessed.challenge_mask,
        preprocessed.composition_randomness_mask,
        preprocessed.oods_point_mask,
        preprocessed.selector_mask,
        preprocessed.parent_binary_selector_mask,
        preprocessed.child_kind_selector_mask,
        preprocessed.statement_word_mask,
    }, span);
    const input_active = try arena.add(
        try arena.mul(preprocessed.input_segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.input_binary_mask, parameters.binary_active, span),
        span,
    );
    const one = try arena.constantField(1, span);
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.sub(try arena.sub(preprocessed.row_mask, input_mask, span), preprocessed.anchor_row_mask, span),
        try arena.mul(
            try arena.mul(preprocessed.input_segment_mask, try arena.sub(one, parameters.segment_active, span), span),
            main.value,
            span,
        ),
        try arena.mul(
            try arena.mul(preprocessed.input_binary_mask, try arena.sub(one, parameters.binary_active, span), span),
            main.value,
            span,
        ),
        try arena.mul(preprocessed.selector_mask, try arena.sub(main.value, parameters.segment_active, span), span),
        try arena.mul(preprocessed.parent_binary_selector_mask, try arena.sub(main.value, parameters.binary_active, span), span),
        try arena.mul(preprocessed.anchor_row_mask, main.value, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const vm_claimed_mask = try arena.sub(
        try arena.sub(
            preprocessed.claimed_sum_mask,
            preprocessed.recursion_claimed_sum_mask,
            span,
        ),
        preprocessed.transcript_claimed_sum_mask,
        span,
    );
    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        try arena.mul(input_active, preprocessed.sampled_value_mask, span),
        try arena.mul(input_active, vm_claimed_mask, span),
        try arena.mul(input_active, preprocessed.recursion_claimed_sum_mask, span),
        try arena.mul(input_active, preprocessed.challenge_mask, span),
        try arena.mul(input_active, preprocessed.composition_randomness_mask, span),
        try arena.mul(input_active, preprocessed.oods_point_mask, span),
        try arena.mul(input_active, preprocessed.statement_word_mask, span),
        try arena.mul(input_active, preprocessed.use_count, span),
        try arena.mul(
            input_active,
            preprocessed.transcript_claimed_sum_mask,
            span,
        ),
    };
    const zero = try arena.constantField(0, span);
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_verifier_input_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.sampled_value_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[0] },
        .{ .domain = .recursion_verifier_input_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.vm_claimed_sum_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[1] },
        .{ .domain = .recursion_verifier_input_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.recursion_claimed_sum_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[2] },
        .{ .domain = .recursion_relation_challenge_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.challenge_scope, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[3] },
        .{ .domain = .recursion_verifier_randomness_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.composition_randomness_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[4] },
        .{ .domain = .recursion_verifier_randomness_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.oods_point_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[5] },
        .{ .domain = .recursion_statement_word, .role = .consume, .values = &.{ preprocessed.statement_scope, preprocessed.source_index_0, main.value }, .weight = weights[6] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &.{ preprocessed.circuit_id, preprocessed.node_id, main.value, zero, zero, zero }, .weight = weights[7] },
        .{ .domain = .recursion_verifier_input_word, .role = .consume, .values = &.{ preprocessed.verifier_id, parameters.transcript_claimed_sum_kind, preprocessed.source_index_0, preprocessed.source_index_1, main.value }, .weight = weights[8] },
    }, span);

    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .input_mask = input_mask,
        .input_active = input_active,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .events = events,
    };
}

fn addMany(
    arena: *ir.Arena,
    values: []const types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    std.debug.assert(values.len != 0);
    var result = values[0];
    for (values[1..]) |value| result = try arena.add(result, value, span);
    return result;
}

fn isPreprocessedSelector(index: usize) bool {
    return switch (index) {
        0, 1, 2, 3, 4, 5, 6, 12, 13, 14, 15, 16, 17, 20, 21 => true,
        else => false,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidVmAirCompositionInputDefinition}!void {
    if (values.len != names.len)
        return error.InvalidVmAirCompositionInputDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidVmAirCompositionInputDefinition;
        const node = arena.node(value) orelse
            return error.InvalidVmAirCompositionInputDefinition;
        var expected_type: types.Type = .felt;
        for (selector_indices) |selector_index| if (selector_index == local_index) {
            expected_type = .selector;
            break;
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidVmAirCompositionInputDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidVmAirCompositionInputDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidVmAirCompositionInputDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidVmAirCompositionInputDefinition;
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
