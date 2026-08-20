//! Exact typed logical AIR for Stark-V authority-spine row 16.
//!
//! Verifier-owned preprocessing assigns every arithmetic-circuit input to one
//! public claim word, claim byte, relation challenge, claimed-sum limb, or the
//! segment selector. Segment mode consumes each source and emits its exact
//! static wire multiplicity; all other modes force every value to zero.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.vm_public_logup_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 11;
pub const PROOF_KIND_PARAMETER_COUNT: usize = 5;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT +
    PROOF_KIND_PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 3;
pub const RELATION_EVENT_COUNT: usize = 5;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 3;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "2f77e5ff9912065565a006add094c6ff0f83e72b2ff60bf4c6c404244379f33f";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion VM public-LogUp input semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.vm_public_logup_input.enabler",
    "recursion.vm_public_logup_input.value",
};
pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_vm_public_logup_input_row_mask",
    "recursion_vm_public_logup_input_claim_word_mask",
    "recursion_vm_public_logup_input_claim_byte_mask",
    "recursion_vm_public_logup_input_challenge_mask",
    "recursion_vm_public_logup_input_claimed_sum_mask",
    "recursion_vm_public_logup_input_selector_mask",
    "recursion_vm_public_logup_input_circuit_id",
    "recursion_vm_public_logup_input_node_id",
    "recursion_vm_public_logup_input_use_count",
    "recursion_vm_public_logup_input_source_index_0",
    "recursion_vm_public_logup_input_source_index_1",
};
pub const PARAMETER_NAMES = [PROOF_KIND_PARAMETER_COUNT][]const u8{
    "recursion.vm_public_logup_input.param.segment_active",
    "recursion.vm_public_logup_input.param.claim_scope",
    "recursion.vm_public_logup_input.param.verifier_id",
    "recursion.vm_public_logup_input.param.challenge_scope",
    "recursion.vm_public_logup_input.param.claimed_sum_kind",
};
pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.vm_public_logup_input.enabler",
    "recursion.vm_public_logup_input.inactive_witness_zero",
    "recursion.vm_public_logup_input.selector",
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
    claim_word_mask: types.ValueId,
    claim_byte_mask: types.ValueId,
    challenge_mask: types.ValueId,
    claimed_sum_mask: types.ValueId,
    selector_mask: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    use_count: types.ValueId,
    source_index_0: types.ValueId,
    source_index_1: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.claim_word_mask,
            self.claim_byte_mask,
            self.challenge_mask,
            self.claimed_sum_mask,
            self.selector_mask,
            self.circuit_id,
            self.node_id,
            self.use_count,
            self.source_index_0,
            self.source_index_1,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    claim_scope: types.ValueId,
    verifier_id: types.ValueId,
    challenge_scope: types.ValueId,
    claimed_sum_kind: types.ValueId,

    pub fn physical(self: Parameters) [PROOF_KIND_PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.claim_scope,
            self.verifier_id,
            self.challenge_scope,
            self.claimed_sum_kind,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidVmPublicLogupInputDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
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
            return error.InvalidVmPublicLogupInputDefinition;
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
            &.{ 0, 1, 2, 3, 4, 5 },
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{0},
        );
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidVmPublicLogupInputDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidVmPublicLogupInputDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidVmPublicLogupInputDefinition;
            }
        }
        const zero = zeroValue(&self.arena) orelse
            return error.InvalidVmPublicLogupInputDefinition;
        const tuples = [_][]const types.ValueId{
            &.{ self.parameters.claim_scope, self.preprocessed.source_index_0, self.main.value },
            &.{ self.preprocessed.source_index_0, self.preprocessed.source_index_1, self.main.value },
            &.{
                self.parameters.verifier_id,
                self.parameters.challenge_scope,
                self.preprocessed.source_index_0,
                self.preprocessed.source_index_1,
                self.main.value,
            },
            &.{
                self.parameters.verifier_id,
                self.parameters.claimed_sum_kind,
                self.preprocessed.source_index_0,
                self.preprocessed.source_index_1,
                self.main.value,
            },
            &.{
                self.preprocessed.circuit_id,
                self.preprocessed.node_id,
                self.main.value,
                zero,
                zero,
                zero,
            },
        };
        const domains = [_]relation.Domain{
            .recursion_vm_public_claim_word,
            .recursion_vm_public_claim_byte,
            .recursion_relation_challenge_word,
            .recursion_verifier_input_word,
            .recursion_wire,
        };
        const roles = [_]relation.Role{
            .consume,
            .consume,
            .consume,
            .consume,
            .emit,
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
                return error.InvalidVmPublicLogupInputDefinition;
            const item = self.arena.effect(effect_id) orelse
                return error.InvalidVmPublicLogupInputDefinition;
            const binding = item.binding orelse
                return error.InvalidVmPublicLogupInputDefinition;
            const schema = relation.get(domain);
            const values = self.arena.effectValues(effect_id) orelse
                return error.InvalidVmPublicLogupInputDefinition;
            if (item.kind != .component_call or item.liveness != weight or
                item.access_ordinal != null or binding.schema != schema.id or
                binding.schema_version != schema.version or binding.role != role or
                !std.mem.eql(types.ValueId, values, tuple))
            {
                return error.InvalidVmPublicLogupInputDefinition;
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

fn buildDefinition(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const main = MainColumns{
        .enabler = try arena.input(MAIN_COLUMN_NAMES[0], .selector, span),
        .value = try arena.input(MAIN_COLUMN_NAMES[1], .felt, span),
    };
    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |
        *value,
        name,
        index,
    | value.* = try arena.input(name, if (index <= 5) .selector else .felt, span);
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .claim_word_mask = preprocessed_values[1],
        .claim_byte_mask = preprocessed_values[2],
        .challenge_mask = preprocessed_values[3],
        .claimed_sum_mask = preprocessed_values[4],
        .selector_mask = preprocessed_values[5],
        .circuit_id = preprocessed_values[6],
        .node_id = preprocessed_values[7],
        .use_count = preprocessed_values[8],
        .source_index_0 = preprocessed_values[9],
        .source_index_1 = preprocessed_values[10],
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .claim_scope = try arena.input(PARAMETER_NAMES[1], .felt, span),
        .verifier_id = try arena.input(PARAMETER_NAMES[2], .felt, span),
        .challenge_scope = try arena.input(PARAMETER_NAMES[3], .felt, span),
        .claimed_sum_kind = try arena.input(PARAMETER_NAMES[4], .felt, span),
    };
    const one = try arena.constantField(1, span);
    const witness_mask = try arena.sub(
        preprocessed.row_mask,
        preprocessed.selector_mask,
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(
            try arena.mul(
                witness_mask,
                try arena.sub(one, parameters.segment_active, span),
                span,
            ),
            main.value,
            span,
        ),
        try arena.mul(
            preprocessed.selector_mask,
            try arena.sub(main.value, parameters.segment_active, span),
            span,
        ),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);

    const claim_word_weight = try arena.mul(
        parameters.segment_active,
        preprocessed.claim_word_mask,
        span,
    );
    const claim_byte_weight = try arena.mul(
        parameters.segment_active,
        preprocessed.claim_byte_mask,
        span,
    );
    const challenge_weight = try arena.mul(
        parameters.segment_active,
        preprocessed.challenge_mask,
        span,
    );
    const claimed_sum_weight = try arena.mul(
        parameters.segment_active,
        preprocessed.claimed_sum_mask,
        span,
    );
    const wire_weight = try arena.mul(
        try arena.mul(parameters.segment_active, preprocessed.row_mask, span),
        preprocessed.use_count,
        span,
    );
    const zero = try arena.constantField(0, span);
    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        claim_word_weight,
        claim_byte_weight,
        challenge_weight,
        claimed_sum_weight,
        wire_weight,
    };
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_vm_public_claim_word,
            .role = .consume,
            .values = &.{ parameters.claim_scope, preprocessed.source_index_0, main.value },
            .weight = claim_word_weight,
        },
        .{
            .domain = .recursion_vm_public_claim_byte,
            .role = .consume,
            .values = &.{ preprocessed.source_index_0, preprocessed.source_index_1, main.value },
            .weight = claim_byte_weight,
        },
        .{
            .domain = .recursion_relation_challenge_word,
            .role = .consume,
            .values = &.{
                parameters.verifier_id,
                parameters.challenge_scope,
                preprocessed.source_index_0,
                preprocessed.source_index_1,
                main.value,
            },
            .weight = challenge_weight,
        },
        .{
            .domain = .recursion_verifier_input_word,
            .role = .consume,
            .values = &.{
                parameters.verifier_id,
                parameters.claimed_sum_kind,
                preprocessed.source_index_0,
                preprocessed.source_index_1,
                main.value,
            },
            .weight = claimed_sum_weight,
        },
        .{
            .domain = .recursion_wire,
            .role = .emit,
            .values = &.{
                preprocessed.circuit_id,
                preprocessed.node_id,
                main.value,
                zero,
                zero,
                zero,
            },
            .weight = wire_weight,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
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
) error{InvalidVmPublicLogupInputDefinition}!void {
    if (values.len != names.len)
        return error.InvalidVmPublicLogupInputDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidVmPublicLogupInputDefinition;
        const node = arena.node(value) orelse
            return error.InvalidVmPublicLogupInputDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        if (!std.meta.eql(
            node.key.ty,
            if (selector) types.Type.selector else .felt,
        )) return error.InvalidVmPublicLogupInputDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidVmPublicLogupInputDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidVmPublicLogupInputDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidVmPublicLogupInputDefinition;
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
