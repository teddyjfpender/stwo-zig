//! Exact typed logical AIR for Stark-V authority-spine row 15.
//!
//! A fixed circuit profile owns every input coordinate and use count. Segment
//! proofs consume public claim, statement, and I/O-digest words and emit their
//! exact arithmetic-wire multiplicities. Binary and empty proofs force every
//! witness-owned value to zero while the selector follows the public mode.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.vm_public_claim_semantics_input.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 11;
pub const PROOF_KIND_PARAMETER_COUNT: usize = 3;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT +
    PROOF_KIND_PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 3;
pub const RELATION_EVENT_COUNT: usize = 4;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "4346bde98717f9a2861c98971c0261720828b52ee79c953ec3aa68ccb1b7f748";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion VM claim-semantics input semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.vm_claim_semantics_input.enabler",
    "recursion.vm_claim_semantics_input.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_vm_claim_semantics_input_row_mask",
    "recursion_vm_claim_semantics_input_claim_mask",
    "recursion_vm_claim_semantics_input_statement_mask",
    "recursion_vm_claim_semantics_input_selector_mask",
    "recursion_vm_claim_semantics_input_private_mask",
    "recursion_vm_claim_semantics_input_io_digest_mask",
    "recursion_vm_claim_semantics_input_io_kind",
    "recursion_vm_claim_semantics_input_circuit_id",
    "recursion_vm_claim_semantics_input_node_id",
    "recursion_vm_claim_semantics_input_use_count",
    "recursion_vm_claim_semantics_input_word_index",
};

pub const PARAMETER_NAMES = [PROOF_KIND_PARAMETER_COUNT][]const u8{
    "recursion.vm_claim_semantics_input.param.segment_active",
    "recursion.vm_claim_semantics_input.param.claim_scope",
    "recursion.vm_claim_semantics_input.param.statement_scope",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.vm_claim_semantics_input.enabler",
    "recursion.vm_claim_semantics_input.inactive_witness_zero",
    "recursion.vm_claim_semantics_input.selector",
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
    claim_mask: types.ValueId,
    statement_mask: types.ValueId,
    selector_mask: types.ValueId,
    private_mask: types.ValueId,
    io_digest_mask: types.ValueId,
    io_kind: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    use_count: types.ValueId,
    word_index: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.claim_mask,
            self.statement_mask,
            self.selector_mask,
            self.private_mask,
            self.io_digest_mask,
            self.io_kind,
            self.circuit_id,
            self.node_id,
            self.use_count,
            self.word_index,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    claim_scope: types.ValueId,
    statement_scope: types.ValueId,

    pub fn physical(self: Parameters) [PROOF_KIND_PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.claim_scope, self.statement_scope };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidVmClaimSemanticsInputDefinition,
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
            return error.InvalidVmClaimSemanticsInputDefinition;
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
                return error.InvalidVmClaimSemanticsInputDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidVmClaimSemanticsInputDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidVmClaimSemanticsInputDefinition;
            }
        }
        const tuples = [_][]const types.ValueId{
            &.{ self.parameters.claim_scope, self.preprocessed.word_index, self.main.value },
            &.{ self.parameters.statement_scope, self.preprocessed.word_index, self.main.value },
            &.{ self.preprocessed.io_kind, self.preprocessed.word_index, self.main.value },
            &.{
                self.preprocessed.circuit_id,
                self.preprocessed.node_id,
                self.main.value,
                zeroValue(&self.arena) orelse
                    return error.InvalidVmClaimSemanticsInputDefinition,
                zeroValue(&self.arena) orelse
                    return error.InvalidVmClaimSemanticsInputDefinition,
                zeroValue(&self.arena) orelse
                    return error.InvalidVmClaimSemanticsInputDefinition,
            },
        };
        const domains = [_]relation.Domain{
            .recursion_vm_public_claim_word,
            .recursion_statement_word,
            .recursion_vm_public_io_digest,
            .recursion_wire,
        };
        const roles = [_]relation.Role{ .consume, .consume, .consume, .emit };
        for (self.events, self.weights, domains, roles, tuples, 0..) |
            effect_id,
            weight,
            domain,
            role,
            tuple,
            index,
        | {
            if (types.idIndex(effect_id) != index)
                return error.InvalidVmClaimSemanticsInputDefinition;
            const item = self.arena.effect(effect_id) orelse
                return error.InvalidVmClaimSemanticsInputDefinition;
            const binding = item.binding orelse
                return error.InvalidVmClaimSemanticsInputDefinition;
            const schema = relation.get(domain);
            const values = self.arena.effectValues(effect_id) orelse
                return error.InvalidVmClaimSemanticsInputDefinition;
            if (item.kind != .component_call or item.liveness != weight or
                item.access_ordinal != null or binding.schema != schema.id or
                binding.schema_version != schema.version or binding.role != role or
                !std.mem.eql(types.ValueId, values, tuple))
            {
                return error.InvalidVmClaimSemanticsInputDefinition;
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
        .claim_mask = preprocessed_values[1],
        .statement_mask = preprocessed_values[2],
        .selector_mask = preprocessed_values[3],
        .private_mask = preprocessed_values[4],
        .io_digest_mask = preprocessed_values[5],
        .io_kind = preprocessed_values[6],
        .circuit_id = preprocessed_values[7],
        .node_id = preprocessed_values[8],
        .use_count = preprocessed_values[9],
        .word_index = preprocessed_values[10],
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .claim_scope = try arena.input(PARAMETER_NAMES[1], .felt, span),
        .statement_scope = try arena.input(PARAMETER_NAMES[2], .felt, span),
    };
    const one = try arena.constantField(1, span);
    const witness_mask = try arena.add(
        try arena.add(preprocessed.claim_mask, preprocessed.statement_mask, span),
        try arena.add(preprocessed.private_mask, preprocessed.io_digest_mask, span),
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

    const claim_weight = try arena.mul(
        parameters.segment_active,
        preprocessed.claim_mask,
        span,
    );
    const statement_weight = try arena.mul(
        parameters.segment_active,
        preprocessed.statement_mask,
        span,
    );
    const digest_weight = try arena.mul(
        parameters.segment_active,
        preprocessed.io_digest_mask,
        span,
    );
    const wire_weight = try arena.mul(
        try arena.mul(parameters.segment_active, preprocessed.row_mask, span),
        preprocessed.use_count,
        span,
    );
    const zero = try arena.constantField(0, span);
    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        claim_weight,
        statement_weight,
        digest_weight,
        wire_weight,
    };
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_vm_public_claim_word,
            .role = .consume,
            .values = &.{ parameters.claim_scope, preprocessed.word_index, main.value },
            .weight = claim_weight,
        },
        .{
            .domain = .recursion_statement_word,
            .role = .consume,
            .values = &.{ parameters.statement_scope, preprocessed.word_index, main.value },
            .weight = statement_weight,
        },
        .{
            .domain = .recursion_vm_public_io_digest,
            .role = .consume,
            .values = &.{ preprocessed.io_kind, preprocessed.word_index, main.value },
            .weight = digest_weight,
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
) error{InvalidVmClaimSemanticsInputDefinition}!void {
    if (values.len != names.len)
        return error.InvalidVmClaimSemanticsInputDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidVmClaimSemanticsInputDefinition;
        const node = arena.node(value) orelse
            return error.InvalidVmClaimSemanticsInputDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        if (!std.meta.eql(
            node.key.ty,
            if (selector) types.Type.selector else .felt,
        )) return error.InvalidVmClaimSemanticsInputDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidVmClaimSemanticsInputDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidVmClaimSemanticsInputDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidVmClaimSemanticsInputDefinition;
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
