//! Field-native child-value router for the recursive Ethereum leaf wrapper.
//!
//! A row consumes at most one authenticated child source (the verified local
//! statement or transcript), or carries a verifier-derived hash result.  The
//! same committed value may feed two canonical hash-preimage positions and a
//! versioned verifier-input tuple.  This is the equality bridge needed to
//! derive the local statement authority/receipt and to retain Tree0 without
//! converting a native SHA-256 seal into field authority.

const std = @import("std");
const core = @import("stwo_core");

const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");
const relation_interaction = @import("relation_interaction.zig");

const M31 = core.fields.m31.M31;

pub const STABLE_NAME = "recursion.ethereum_leaf.child_field_router.v1";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 22;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 29;
pub const RELATION_EVENT_COUNT: usize = 5;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = RELATION_EVENT_COUNT;
pub const INTERACTION_COLUMN_COUNT: usize = 4 * INTERACTION_BATCH_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "fce384515d85ca9ac6a193f46eb0e9fa5f91553e53061800adeab8c7808d28b6";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid Ethereum child-field router semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.ethereum_leaf.child_field_router.value",
};

pub const PREPROCESSED_COLUMN_NAMES =
    [PREPROCESSED_COLUMN_COUNT][]const u8{
        "recursion_ethereum_leaf_child_router_active",
        "recursion_ethereum_leaf_child_router_statement_source_mask",
        "recursion_ethereum_leaf_child_router_verifier_source_mask",
        "recursion_ethereum_leaf_child_router_constant_source_mask",
        "recursion_ethereum_leaf_child_router_derived_source_mask",
        "recursion_ethereum_leaf_child_router_raw_a_sink_mask",
        "recursion_ethereum_leaf_child_router_raw_b_sink_mask",
        "recursion_ethereum_leaf_child_router_verifier_sink_mask",
        "recursion_ethereum_leaf_child_router_statement_scope",
        "recursion_ethereum_leaf_child_router_statement_index",
        "recursion_ethereum_leaf_child_router_source_verifier_kind",
        "recursion_ethereum_leaf_child_router_source_index_0",
        "recursion_ethereum_leaf_child_router_source_index_1",
        "recursion_ethereum_leaf_child_router_constant_value",
        "recursion_ethereum_leaf_child_router_raw_a_scope",
        "recursion_ethereum_leaf_child_router_raw_a_index",
        "recursion_ethereum_leaf_child_router_raw_b_scope",
        "recursion_ethereum_leaf_child_router_raw_b_index",
        "recursion_ethereum_leaf_child_router_sink_verifier_kind",
        "recursion_ethereum_leaf_child_router_sink_index_0",
        "recursion_ethereum_leaf_child_router_sink_index_1",
        "recursion_ethereum_leaf_child_router_sink_use_count",
    };

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.ethereum_leaf.child_router.active_boolean",
    "recursion.ethereum_leaf.child_router.statement_source_boolean",
    "recursion.ethereum_leaf.child_router.verifier_source_boolean",
    "recursion.ethereum_leaf.child_router.constant_source_boolean",
    "recursion.ethereum_leaf.child_router.derived_source_boolean",
    "recursion.ethereum_leaf.child_router.raw_a_sink_boolean",
    "recursion.ethereum_leaf.child_router.raw_b_sink_boolean",
    "recursion.ethereum_leaf.child_router.verifier_sink_boolean",
    "recursion.ethereum_leaf.child_router.source_partition",
    "recursion.ethereum_leaf.child_router.sink_union",
    "recursion.ethereum_leaf.child_router.derived_has_verifier_sink",
    "recursion.ethereum_leaf.child_router.inactive_statement_scope_zero",
    "recursion.ethereum_leaf.child_router.inactive_statement_index_zero",
    "recursion.ethereum_leaf.child_router.inactive_source_kind_zero",
    "recursion.ethereum_leaf.child_router.inactive_source_index_0_zero",
    "recursion.ethereum_leaf.child_router.inactive_source_index_1_zero",
    "recursion.ethereum_leaf.child_router.inactive_constant_zero",
    "recursion.ethereum_leaf.child_router.inactive_raw_a_scope_zero",
    "recursion.ethereum_leaf.child_router.inactive_raw_a_index_zero",
    "recursion.ethereum_leaf.child_router.inactive_raw_b_scope_zero",
    "recursion.ethereum_leaf.child_router.inactive_raw_b_index_zero",
    "recursion.ethereum_leaf.child_router.inactive_sink_kind_zero",
    "recursion.ethereum_leaf.child_router.inactive_sink_index_0_zero",
    "recursion.ethereum_leaf.child_router.inactive_sink_index_1_zero",
    "recursion.ethereum_leaf.child_router.inactive_sink_use_count_zero",
    "recursion.ethereum_leaf.child_router.inactive_value_zero",
    "recursion.ethereum_leaf.child_router.constant_value",
    "recursion.ethereum_leaf.child_router.unused_constant_zero",
    "recursion.ethereum_leaf.child_router.unused_sink_count_zero",
};

pub const MainColumns = struct {
    value: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.value};
    }
};

pub const PreprocessedColumns = struct {
    active: types.ValueId,
    statement_source_mask: types.ValueId,
    verifier_source_mask: types.ValueId,
    constant_source_mask: types.ValueId,
    derived_source_mask: types.ValueId,
    raw_a_sink_mask: types.ValueId,
    raw_b_sink_mask: types.ValueId,
    verifier_sink_mask: types.ValueId,
    statement_scope: types.ValueId,
    statement_index: types.ValueId,
    source_verifier_kind: types.ValueId,
    source_index_0: types.ValueId,
    source_index_1: types.ValueId,
    constant_value: types.ValueId,
    raw_a_scope: types.ValueId,
    raw_a_index: types.ValueId,
    raw_b_scope: types.ValueId,
    raw_b_index: types.ValueId,
    sink_verifier_kind: types.ValueId,
    sink_index_0: types.ValueId,
    sink_index_1: types.ValueId,
    sink_use_count: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.active,
            self.statement_source_mask,
            self.verifier_source_mask,
            self.constant_source_mask,
            self.derived_source_mask,
            self.raw_a_sink_mask,
            self.raw_b_sink_mask,
            self.verifier_sink_mask,
            self.statement_scope,
            self.statement_index,
            self.source_verifier_kind,
            self.source_index_0,
            self.source_index_1,
            self.constant_value,
            self.raw_a_scope,
            self.raw_a_index,
            self.raw_b_scope,
            self.raw_b_index,
            self.sink_verifier_kind,
            self.sink_index_0,
            self.sink_index_1,
            self.sink_use_count,
        };
    }
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try validate_mod.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
        {
            return error.InvalidEthereumChildFieldRouterDefinition;
        }
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidEthereumChildFieldRouterDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidEthereumChildFieldRouterDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidEthereumChildFieldRouterDefinition;
            }
        }
        try validateEvent(self, 0, .recursion_statement_word, .consume);
        try validateEvent(self, 1, .recursion_verifier_input_word, .consume);
        try validateEvent(self, 2, .recursion_vm_public_claim_word, .emit);
        try validateEvent(self, 3, .recursion_vm_public_claim_word, .emit);
        try validateEvent(self, 4, .recursion_verifier_input_word, .emit);
    }
};

pub const Runtime = relation_interaction.Runtime(
    LOGICAL_INPUT_COUNT,
    RELATION_EVENT_COUNT,
    LOOKUP_BATCH_SIZE,
);
pub const Plan = Runtime.Plan;
pub const Row = Runtime.Row;

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) !digest.Digest {
    var definition = try buildRaw(allocator);
    defer definition.deinit();
    return (try digest.computeIdentity(&definition.arena)).bytes;
}

pub fn authenticate(definition: *const Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(
        &definition.arena,
        SEMANTIC_DIGEST,
        definition.events,
    );
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const main = MainColumns{
        .value = try arena.input(MAIN_COLUMN_NAMES[0], .felt, span),
    };
    var pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(
            name,
            if (index <= 7) .selector else .felt,
            span,
        );
    }
    const preprocessed = PreprocessedColumns{
        .active = pp[0],
        .statement_source_mask = pp[1],
        .verifier_source_mask = pp[2],
        .constant_source_mask = pp[3],
        .derived_source_mask = pp[4],
        .raw_a_sink_mask = pp[5],
        .raw_b_sink_mask = pp[6],
        .verifier_sink_mask = pp[7],
        .statement_scope = pp[8],
        .statement_index = pp[9],
        .source_verifier_kind = pp[10],
        .source_index_0 = pp[11],
        .source_index_1 = pp[12],
        .constant_value = pp[13],
        .raw_a_scope = pp[14],
        .raw_a_index = pp[15],
        .raw_b_scope = pp[16],
        .raw_b_index = pp[17],
        .sink_verifier_kind = pp[18],
        .sink_index_0 = pp[19],
        .sink_index_1 = pp[20],
        .sink_use_count = pp[21],
    };
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const inactive = try arena.sub(one, preprocessed.active, span);
    const source_sum = try arena.add(
        try arena.add(
            preprocessed.statement_source_mask,
            preprocessed.verifier_source_mask,
            span,
        ),
        try arena.add(
            preprocessed.constant_source_mask,
            preprocessed.derived_source_mask,
            span,
        ),
        span,
    );
    const a_or_b = try arena.sub(
        try arena.add(
            preprocessed.raw_a_sink_mask,
            preprocessed.raw_b_sink_mask,
            span,
        ),
        try arena.mul(
            preprocessed.raw_a_sink_mask,
            preprocessed.raw_b_sink_mask,
            span,
        ),
        span,
    );
    const sink_union = try arena.sub(
        try arena.add(a_or_b, preprocessed.verifier_sink_mask, span),
        try arena.mul(a_or_b, preprocessed.verifier_sink_mask, span),
        span,
    );
    const inactive_values = [_]types.ValueId{
        preprocessed.statement_scope,
        preprocessed.statement_index,
        preprocessed.source_verifier_kind,
        preprocessed.source_index_0,
        preprocessed.source_index_1,
        preprocessed.constant_value,
        preprocessed.raw_a_scope,
        preprocessed.raw_a_index,
        preprocessed.raw_b_scope,
        preprocessed.raw_b_index,
        preprocessed.sink_verifier_kind,
        preprocessed.sink_index_0,
        preprocessed.sink_index_1,
        preprocessed.sink_use_count,
        main.value,
    };
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    const booleans = [_]types.ValueId{
        preprocessed.active,
        preprocessed.statement_source_mask,
        preprocessed.verifier_source_mask,
        preprocessed.constant_source_mask,
        preprocessed.derived_source_mask,
        preprocessed.raw_a_sink_mask,
        preprocessed.raw_b_sink_mask,
        preprocessed.verifier_sink_mask,
    };
    for (booleans, 0..) |value, index|
        roots[index] = try booleanRoot(&arena, value, one, span);
    roots[8] = try arena.sub(preprocessed.active, source_sum, span);
    roots[9] = try arena.sub(preprocessed.active, sink_union, span);
    roots[10] = try arena.mul(
        preprocessed.derived_source_mask,
        try arena.sub(one, preprocessed.verifier_sink_mask, span),
        span,
    );
    for (inactive_values, 0..) |value, index|
        roots[11 + index] = try arena.mul(inactive, value, span);
    roots[26] = try arena.mul(
        preprocessed.constant_source_mask,
        try arena.sub(main.value, preprocessed.constant_value, span),
        span,
    );
    roots[27] = try arena.mul(
        try arena.sub(one, preprocessed.constant_source_mask, span),
        preprocessed.constant_value,
        span,
    );
    roots[28] = try arena.mul(
        try arena.sub(one, preprocessed.verifier_sink_mask, span),
        preprocessed.sink_use_count,
        span,
    );
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }
    const statement_tuple = [_]types.ValueId{
        preprocessed.statement_scope,
        preprocessed.statement_index,
        main.value,
    };
    const source_verifier_tuple = [_]types.ValueId{
        zero,
        preprocessed.source_verifier_kind,
        preprocessed.source_index_0,
        preprocessed.source_index_1,
        main.value,
    };
    const raw_a_tuple = [_]types.ValueId{
        preprocessed.raw_a_scope,
        preprocessed.raw_a_index,
        main.value,
    };
    const raw_b_tuple = [_]types.ValueId{
        preprocessed.raw_b_scope,
        preprocessed.raw_b_index,
        main.value,
    };
    const sink_verifier_tuple = [_]types.ValueId{
        zero,
        preprocessed.sink_verifier_kind,
        preprocessed.sink_index_0,
        preprocessed.sink_index_1,
        main.value,
    };
    const verifier_sink_weight = try arena.mul(
        preprocessed.verifier_sink_mask,
        preprocessed.sink_use_count,
        span,
    );
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        .{
            .{
                .domain = .recursion_statement_word,
                .role = .consume,
                .values = &statement_tuple,
                .weight = preprocessed.statement_source_mask,
            },
            .{
                .domain = .recursion_verifier_input_word,
                .role = .consume,
                .values = &source_verifier_tuple,
                .weight = preprocessed.verifier_source_mask,
            },
            .{
                .domain = .recursion_vm_public_claim_word,
                .role = .emit,
                .values = &raw_a_tuple,
                .weight = preprocessed.raw_a_sink_mask,
            },
            .{
                .domain = .recursion_vm_public_claim_word,
                .role = .emit,
                .values = &raw_b_tuple,
                .weight = preprocessed.raw_b_sink_mask,
            },
            .{
                .domain = .recursion_verifier_input_word,
                .role = .emit,
                .values = &sink_verifier_tuple,
                .weight = verifier_sink_weight,
            },
        },
        span,
    );
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .roots = roots,
        .constraints = constraints,
        .events = events,
    };
}

fn booleanRoot(
    arena: *ir.Arena,
    value: types.ValueId,
    one: types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.mul(value, try arena.sub(value, one, span), span);
}

fn validateEvent(
    definition: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
) !void {
    const event = definition.arena.effect(definition.events[index]) orelse
        return error.InvalidEthereumChildFieldRouterDefinition;
    const binding = event.binding orelse
        return error.InvalidEthereumChildFieldRouterDefinition;
    const schema = relation.get(domain);
    if (types.idIndex(definition.events[index]) != index or
        event.kind != .component_call or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        event.access_ordinal != null)
    {
        return error.InvalidEthereumChildFieldRouterDefinition;
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    if (value.len != 2 * @sizeOf(digest.Digest)) @compileError(message);
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

pub fn logicalRow(value: M31, preprocessed: [PREPROCESSED_COLUMN_COUNT]u32) Row {
    var result: Row = undefined;
    result[0] = value;
    for (result[1..], preprocessed) |*target, word|
        target.* = M31.fromCanonical(word);
    return result;
}

comptime {
    if (relation.universalDescriptor(.recursion_statement_word).arity != 3 or
        relation.universalDescriptor(.recursion_vm_public_claim_word).arity != 3 or
        relation.universalDescriptor(.recursion_verifier_input_word).arity != 5)
    {
        @compileError("Ethereum child-field router relation ABI drifted");
    }
}
