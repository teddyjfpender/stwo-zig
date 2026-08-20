//! Exact typed logical AIR for Stark-V statement-semantics input row 11.
//!
//! Verifier-owned circuit-input metadata selects the active proof branch.
//! Scoped statement words are consumed, active raw integers are decomposed
//! through the shared `(8, 8)` table, and every input emits its exact wire-use
//! multiplicity into the universal statement circuit.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.statement_semantics_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 4;
pub const PREPROCESSED_COLUMN_COUNT: usize = 13;
pub const PARAMETER_COUNT: usize = 4;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 6;
pub const RELATION_EVENT_COUNT: usize = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
// The local conservative analyzer treats verifier parameters as degree-one
// logical inputs. STWO substitutes them as public constants, yielding the
// exact reference maximum above.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;

pub const SEMANTIC_DIGEST_HEX =
    "aa906906138f3a57b3c22618a716d8ba96ee60a472ab7a7b3c681ab6bd4ca602";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion statement-semantics-input semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "fd1042d79c1d98a75f513102dce78725bf1a27013e95c1af5068484277cd97a1";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.statement_semantics_input.enabler",
    "recursion.statement_semantics_input.value",
    "recursion.statement_semantics_input.low_byte",
    "recursion.statement_semantics_input.high_byte",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_statement_semantics_input_row_mask",
    "recursion_statement_semantics_input_statement_mask",
    "recursion_statement_semantics_input_selector_mask",
    "recursion_statement_semantics_input_private_mask",
    "recursion_statement_semantics_input_integer_mask",
    "recursion_statement_semantics_input_segment_active",
    "recursion_statement_semantics_input_binary_active",
    "recursion_statement_semantics_input_empty_active",
    "recursion_statement_semantics_input_circuit_id",
    "recursion_statement_semantics_input_node_id",
    "recursion_statement_semantics_input_use_count",
    "recursion_statement_semantics_input_scope",
    "recursion_statement_semantics_input_word_index",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.statement_semantics_input.param.segment_active",
    "recursion.statement_semantics_input.param.binary_active",
    "recursion.statement_semantics_input.param.empty_active",
    "recursion.statement_semantics_input.param.zero",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    value: types.ValueId,
    low_byte: types.ValueId,
    high_byte: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.value, self.low_byte, self.high_byte };
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    statement_mask: types.ValueId,
    selector_mask: types.ValueId,
    private_mask: types.ValueId,
    integer_mask: types.ValueId,
    segment_enabled: types.ValueId,
    binary_enabled: types.ValueId,
    empty_enabled: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    use_count: types.ValueId,
    statement_scope: types.ValueId,
    word_index: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.statement_mask,
            self.selector_mask,
            self.private_mask,
            self.integer_mask,
            self.segment_enabled,
            self.binary_enabled,
            self.empty_enabled,
            self.circuit_id,
            self.node_id,
            self.use_count,
            self.statement_scope,
            self.word_index,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    empty_active: types.ValueId,
    zero: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
            self.empty_active,
            self.zero,
        };
    }
};

pub const Events = struct {
    statement_word_consume: types.EffectId,
    wire_emit: types.EffectId,
    range_check_consume: types.EffectId,

    pub fn ordered(self: Events) [RELATION_EVENT_COUNT]types.EffectId {
        return .{
            self.statement_word_consume,
            self.wire_emit,
            self.range_check_consume,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidStatementSemanticsInputDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    active_statement: types.ValueId,
    active_integer: types.ValueId,
    wire_weight: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    events: Events,

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
            return error.InvalidStatementSemanticsInputDefinition;
        }

        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            &.{0},
            &.{ 2, 3 },
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1, 2, 3, 4, 5, 6, 7 },
            &.{},
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{ 0, 1, 2 },
            &.{},
        );
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            name,
            index,
        | {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidStatementSemanticsInputDefinition;
            const constraint = self.arena.constraint(constraint_id) orelse
                return error.InvalidStatementSemanticsInputDefinition;
            const actual_name = self.arena.name(constraint.name) orelse
                return error.InvalidStatementSemanticsInputDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic or
                !std.mem.eql(u8, actual_name, name))
            {
                return error.InvalidStatementSemanticsInputDefinition;
            }
        }

        const statement_tuple = [_]types.ValueId{
            self.preprocessed.statement_scope,
            self.preprocessed.word_index,
            self.main.value,
        };
        const wire_tuple = [_]types.ValueId{
            self.preprocessed.circuit_id,
            self.preprocessed.node_id,
            self.main.value,
            self.parameters.zero,
            self.parameters.zero,
            self.parameters.zero,
        };
        const range_tuple = [_]types.ValueId{ self.main.low_byte, self.main.high_byte };
        try validateEvent(self, 0, .recursion_statement_word, .consume, self.active_statement, &statement_tuple);
        try validateEvent(self, 1, .recursion_wire, .emit, self.wire_weight, &wire_tuple);
        try validateEvent(self, 2, .range_check_8_8, .request, self.active_integer, &range_tuple);
    }
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.statement_semantics_input.enabler_matches_row_mask",
    "recursion.statement_semantics_input.inactive_witness_zero",
    "recursion.statement_semantics_input.selector_value",
    "recursion.statement_semantics_input.integer_decomposition",
    "recursion.statement_semantics_input.inactive_low_byte_zero",
    "recursion.statement_semantics_input.inactive_high_byte_zero",
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn semanticIdentity(allocator: std.mem.Allocator) !digest.Identity {
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
        .low_byte = try arena.input(MAIN_COLUMN_NAMES[2], .byte, span),
        .high_byte = try arena.input(MAIN_COLUMN_NAMES[3], .byte, span),
    };
    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 7) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .statement_mask = preprocessed_values[1],
        .selector_mask = preprocessed_values[2],
        .private_mask = preprocessed_values[3],
        .integer_mask = preprocessed_values[4],
        .segment_enabled = preprocessed_values[5],
        .binary_enabled = preprocessed_values[6],
        .empty_enabled = preprocessed_values[7],
        .circuit_id = preprocessed_values[8],
        .node_id = preprocessed_values[9],
        .use_count = preprocessed_values[10],
        .statement_scope = preprocessed_values[11],
        .word_index = preprocessed_values[12],
    };
    var parameter_values: [PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameter_values, PARAMETER_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 2) .selector else .felt, span);
    }
    const parameters = Parameters{
        .segment_active = parameter_values[0],
        .binary_active = parameter_values[1],
        .empty_active = parameter_values[2],
        .zero = parameter_values[3],
    };

    const active = try arena.add(
        try arena.add(
            try arena.mul(preprocessed.segment_enabled, parameters.segment_active, span),
            try arena.mul(preprocessed.binary_enabled, parameters.binary_active, span),
            span,
        ),
        try arena.mul(preprocessed.empty_enabled, parameters.empty_active, span),
        span,
    );
    const active_statement = try arena.mul(preprocessed.statement_mask, active, span);
    const active_integer = try arena.mul(preprocessed.integer_mask, active, span);
    const witness_input = try arena.add(
        preprocessed.statement_mask,
        preprocessed.private_mask,
        span,
    );
    const one = try arena.constantField(1, span);
    const two_fifty_six = try arena.constantField(256, span);
    const inactive = try arena.sub(one, active, span);
    const inactive_integer = try arena.sub(one, active_integer, span);
    const reconstructed = try arena.add(
        main.low_byte,
        try arena.mul(main.high_byte, two_fifty_six, span),
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(try arena.mul(witness_input, inactive, span), main.value, span),
        try arena.mul(
            preprocessed.selector_mask,
            try arena.sub(main.value, active, span),
            span,
        ),
        try arena.mul(
            active_integer,
            try arena.sub(main.value, reconstructed, span),
            span,
        ),
        try arena.mul(inactive_integer, main.low_byte, span),
        try arena.mul(inactive_integer, main.high_byte, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const wire_weight = try arena.mul(preprocessed.row_mask, preprocessed.use_count, span);
    const statement_tuple = [_]types.ValueId{
        preprocessed.statement_scope,
        preprocessed.word_index,
        main.value,
    };
    const wire_tuple = [_]types.ValueId{
        preprocessed.circuit_id,
        preprocessed.node_id,
        main.value,
        parameters.zero,
        parameters.zero,
        parameters.zero,
    };
    const range_tuple = [_]types.ValueId{ main.low_byte, main.high_byte };
    const event_ids = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_statement_word,
            .role = .consume,
            .values = &statement_tuple,
            .weight = active_statement,
        },
        .{
            .domain = .recursion_wire,
            .role = .emit,
            .values = &wire_tuple,
            .weight = wire_weight,
        },
        .{
            .domain = .range_check_8_8,
            .role = .request,
            .values = &range_tuple,
            .weight = active_integer,
        },
    }, span);

    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .active_statement = active_statement,
        .active_integer = active_integer,
        .wire_weight = wire_weight,
        .roots = roots,
        .constraints = constraints,
        .events = .{
            .statement_word_consume = event_ids[0],
            .wire_emit = event_ids[1],
            .range_check_consume = event_ids[2],
        },
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
    byte_indices: []const usize,
) error{InvalidStatementSemanticsInputDefinition}!void {
    if (values.len != names.len)
        return error.InvalidStatementSemanticsInputDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidStatementSemanticsInputDefinition;
        const node = arena.node(value) orelse
            return error.InvalidStatementSemanticsInputDefinition;
        var ty: types.Type = .felt;
        for (selector_indices) |index| if (index == local_index) {
            ty = .selector;
            break;
        };
        for (byte_indices) |index| if (index == local_index) {
            ty = .byte;
            break;
        };
        if (!std.meta.eql(node.key.ty, ty))
            return error.InvalidStatementSemanticsInputDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidStatementSemanticsInputDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidStatementSemanticsInputDefinition;
        if (!std.mem.eql(u8, actual_name, name))
            return error.InvalidStatementSemanticsInputDefinition;
    }
}

fn validateEvent(
    definition: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    weight: types.ValueId,
    tuple: []const types.ValueId,
) error{InvalidStatementSemanticsInputDefinition}!void {
    const event_id = definition.events.ordered()[index];
    if (types.idIndex(event_id) != index)
        return error.InvalidStatementSemanticsInputDefinition;
    const effect = definition.arena.effect(event_id) orelse
        return error.InvalidStatementSemanticsInputDefinition;
    const binding = effect.binding orelse
        return error.InvalidStatementSemanticsInputDefinition;
    const schema = relation.get(domain);
    const values = definition.arena.effectValues(event_id) orelse
        return error.InvalidStatementSemanticsInputDefinition;
    if (effect.kind != .component_call or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        effect.liveness != weight or effect.access_ordinal != null or
        !std.mem.eql(types.ValueId, values, tuple))
    {
        return error.InvalidStatementSemanticsInputDefinition;
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
