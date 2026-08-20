//! Exact typed logical AIR for Stark-V universal statement-input row 10.
//!
//! One fixed row exists for each canonical statement word in the VM, left,
//! and right verifier lanes. The selected lane consumes the word authenticated
//! by the transcript and routes it into the statement-semantics scopes.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.statement_input.v2";
pub const CANONICAL_WORD_COUNT: usize = 412;
pub const STATEMENT_LANE_COUNT: usize = 4;
pub const SEGMENT_STATEMENT_SCOPE: u32 = 0;
pub const LEFT_STATEMENT_SCOPE: u32 = 1;
pub const RIGHT_STATEMENT_SCOPE: u32 = 2;
pub const PARENT_STATEMENT_SCOPE: u32 = 3;
pub const VM_CLAIM_STATEMENT_SCOPE: u32 = 4;
pub const STATEMENT_INPUT_KIND: u32 = 2;
pub const STATEMENT_INPUT_ITEM: u32 = 0;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 7;
pub const PARAMETER_COUNT: usize = 5;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 2;
pub const RELATION_EVENT_COUNT: usize = 4;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "10e8800f523409f20ab769032b6a59c4b135c4665779ac181879292678d0ba7c";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion statement-input semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "b317ff4e34903eff42d569e5f53058bac14ac08641c2e341f65294f26e237a48";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.statement_input.enabler",
    "recursion.statement_input.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_statement_input_row_mask",
    "recursion_statement_input_segment_mask",
    "recursion_statement_input_binary_mask",
    "recursion_statement_input_derived_parent_mask",
    "recursion_statement_input_verifier_id",
    "recursion_statement_input_scope",
    "recursion_statement_input_word_index",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.statement_input.param.segment_active",
    "recursion.statement_input.param.binary_active",
    "recursion.statement_input.param.input_kind",
    "recursion.statement_input.param.input_item",
    "recursion.statement_input.param.vm_claim_scope",
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
    derived_parent_mask: types.ValueId,
    verifier_id: types.ValueId,
    statement_scope: types.ValueId,
    word_index: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.derived_parent_mask,
            self.verifier_id,
            self.statement_scope,
            self.word_index,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    input_kind: types.ValueId,
    input_item: types.ValueId,
    vm_claim_scope: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
            self.input_kind,
            self.input_item,
            self.vm_claim_scope,
        };
    }
};

pub const Events = struct {
    input_word_consume: types.EffectId,
    scoped_statement_emit: types.EffectId,
    parent_statement_emit: types.EffectId,
    vm_claim_statement_emit: types.EffectId,

    pub fn ordered(self: Events) [RELATION_EVENT_COUNT]types.EffectId {
        return .{
            self.input_word_consume,
            self.scoped_statement_emit,
            self.parent_statement_emit,
            self.vm_claim_statement_emit,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidStatementInputDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    authenticated_input_active: types.ValueId,
    binary_lane_active: types.ValueId,
    derived_parent_lane_active: types.ValueId,
    segment_lane_active: types.ValueId,
    scoped_output_weight: types.ValueId,
    parent_output_weight: types.ValueId,
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
            return error.InvalidStatementInputDefinition;
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
            &.{ 0, 1, 2, 3 },
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
            name,
            index,
        | {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidStatementInputDefinition;
            const constraint = self.arena.constraint(constraint_id) orelse
                return error.InvalidStatementInputDefinition;
            const actual_name = self.arena.name(constraint.name) orelse
                return error.InvalidStatementInputDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic or
                !std.mem.eql(u8, actual_name, name))
            {
                return error.InvalidStatementInputDefinition;
            }
        }

        const input_tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.parameters.input_kind,
            self.parameters.input_item,
            self.preprocessed.word_index,
            self.main.value,
        };
        const scoped_tuple = [_]types.ValueId{
            self.preprocessed.statement_scope,
            self.preprocessed.word_index,
            self.main.value,
        };
        const vm_tuple = [_]types.ValueId{
            self.parameters.vm_claim_scope,
            self.preprocessed.word_index,
            self.main.value,
        };
        const parent_tuple = [_]types.ValueId{
            constantValue(&self.arena, PARENT_STATEMENT_SCOPE) orelse
                return error.InvalidStatementInputDefinition,
            self.preprocessed.word_index,
            self.main.value,
        };
        try validateEvent(self, 0, .recursion_verifier_input_word, .consume, self.authenticated_input_active, &input_tuple);
        try validateEvent(self, 1, .recursion_statement_word, .emit, self.scoped_output_weight, &scoped_tuple);
        try validateEvent(self, 2, .recursion_statement_word, .emit, self.parent_output_weight, &parent_tuple);
        try validateEvent(self, 3, .recursion_statement_word, .emit, self.segment_lane_active, &vm_tuple);
    }
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.statement_input.enabler_matches_row_mask",
    "recursion.statement_input.inactive_value_zero",
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

fn buildDefinition(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();

    const main = MainColumns{
        .enabler = try arena.input(MAIN_COLUMN_NAMES[0], .selector, span),
        .value = try arena.input(MAIN_COLUMN_NAMES[1], .felt, span),
    };
    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 3) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .derived_parent_mask = preprocessed_values[3],
        .verifier_id = preprocessed_values[4],
        .statement_scope = preprocessed_values[5],
        .word_index = preprocessed_values[6],
    };
    var parameter_values: [PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameter_values, PARAMETER_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 1) .selector else .felt, span);
    }
    const parameters = Parameters{
        .segment_active = parameter_values[0],
        .binary_active = parameter_values[1],
        .input_kind = parameter_values[2],
        .input_item = parameter_values[3],
        .vm_claim_scope = parameter_values[4],
    };

    const segment_lane_active = try arena.mul(
        preprocessed.segment_mask,
        parameters.segment_active,
        span,
    );
    const binary_lane_active = try arena.mul(
        preprocessed.binary_mask,
        parameters.binary_active,
        span,
    );
    const derived_parent_lane_active = try arena.mul(
        preprocessed.derived_parent_mask,
        parameters.binary_active,
        span,
    );
    const authenticated_input_active = try arena.add(
        segment_lane_active,
        binary_lane_active,
        span,
    );
    const active = try arena.add(
        authenticated_input_active,
        derived_parent_lane_active,
        span,
    );
    // A binary child word has two authenticated consumers: row 11 checks the
    // parent-statement fold and row 18 feeds the recursive composition graph.
    // Emitting multiplicity two here keeps that fan-out in the typed source
    // of truth rather than patching the global claim after evaluation.
    const scoped_output_weight = try arena.add(
        active,
        binary_lane_active,
        span,
    );
    // A segment leaf is also the parent statement of its one-leaf recursion
    // subtree. That is a distinct typed tuple, not multiplicity two on the
    // segment scope. In binary mode the derived parent lane emits PARENT while
    // deliberately making no verifier-input claim; row 11 owns the fold
    // constraints linking it to the authenticated LEFT and RIGHT words.
    const parent_output_weight = segment_lane_active;
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(
            try arena.sub(preprocessed.row_mask, active, span),
            main.value,
            span,
        ),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const input_tuple = [_]types.ValueId{
        preprocessed.verifier_id,
        parameters.input_kind,
        parameters.input_item,
        preprocessed.word_index,
        main.value,
    };
    const scoped_tuple = [_]types.ValueId{
        preprocessed.statement_scope,
        preprocessed.word_index,
        main.value,
    };
    const vm_tuple = [_]types.ValueId{
        parameters.vm_claim_scope,
        preprocessed.word_index,
        main.value,
    };
    const parent_scope = try arena.constantField(PARENT_STATEMENT_SCOPE, span);
    const parent_tuple = [_]types.ValueId{
        parent_scope,
        preprocessed.word_index,
        main.value,
    };
    const event_ids = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_verifier_input_word,
            .role = .consume,
            .values = &input_tuple,
            .weight = authenticated_input_active,
        },
        .{
            .domain = .recursion_statement_word,
            .role = .emit,
            .values = &scoped_tuple,
            .weight = scoped_output_weight,
        },
        .{
            .domain = .recursion_statement_word,
            .role = .emit,
            .values = &parent_tuple,
            .weight = parent_output_weight,
        },
        .{
            .domain = .recursion_statement_word,
            .role = .emit,
            .values = &vm_tuple,
            .weight = segment_lane_active,
        },
    }, span);

    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .authenticated_input_active = authenticated_input_active,
        .binary_lane_active = binary_lane_active,
        .derived_parent_lane_active = derived_parent_lane_active,
        .segment_lane_active = segment_lane_active,
        .scoped_output_weight = scoped_output_weight,
        .parent_output_weight = parent_output_weight,
        .roots = roots,
        .constraints = constraints,
        .events = .{
            .input_word_consume = event_ids[0],
            .scoped_statement_emit = event_ids[1],
            .parent_statement_emit = event_ids[2],
            .vm_claim_statement_emit = event_ids[3],
        },
    };
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

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidStatementInputDefinition}!void {
    if (values.len != names.len) return error.InvalidStatementInputDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidStatementInputDefinition;
        const node = arena.node(value) orelse return error.InvalidStatementInputDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        if (!std.meta.eql(node.key.ty, if (selector) types.Type.selector else .felt))
            return error.InvalidStatementInputDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidStatementInputDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidStatementInputDefinition;
        if (!std.mem.eql(u8, actual_name, name))
            return error.InvalidStatementInputDefinition;
    }
}

fn validateEvent(
    definition: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    weight: types.ValueId,
    tuple: []const types.ValueId,
) error{InvalidStatementInputDefinition}!void {
    const event_id = definition.events.ordered()[index];
    if (types.idIndex(event_id) != index)
        return error.InvalidStatementInputDefinition;
    const effect = definition.arena.effect(event_id) orelse
        return error.InvalidStatementInputDefinition;
    const binding = effect.binding orelse return error.InvalidStatementInputDefinition;
    const schema = relation.get(domain);
    const values = definition.arena.effectValues(event_id) orelse
        return error.InvalidStatementInputDefinition;
    if (effect.kind != .component_call or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        effect.liveness != weight or effect.access_ordinal != null or
        !std.mem.eql(types.ValueId, values, tuple))
    {
        return error.InvalidStatementInputDefinition;
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
