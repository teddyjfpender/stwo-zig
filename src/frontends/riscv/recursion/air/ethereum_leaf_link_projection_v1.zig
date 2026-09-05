//! Field-native routing component for the recursive Ethereum leaf wrapper.
//!
//! Each active row has exactly one authenticated source: a MetadataV3 or
//! VerifiedLinkV3 preimage word, a child-verifier digest limb, or the fixed
//! zero used by the local-clock projection.  The same committed value is then
//! routed to the global statement or consumed from the verified local
//! SegmentV2 statement.  Link header and cross-object joins are therefore AIR
//! equalities, not native SHA custody checks.

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
const leaf_source = @import("ethereum_leaf_link_source_v1.zig");

const M31 = core.fields.m31.M31;

pub const STABLE_NAME = "recursion.ethereum_leaf_link.projection.v1";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 18;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 26;
pub const RELATION_EVENT_COUNT: usize = 5;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = RELATION_EVENT_COUNT;
pub const INTERACTION_COLUMN_COUNT: usize = 4 * INTERACTION_BATCH_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX =
    "b0f89d6b6ce7259421a98d03ba57f3ff075f696aa33a9aa1df1e839053662482";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid Ethereum leaf-link projection semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.ethereum_leaf_link.projection.value",
};

pub const PREPROCESSED_COLUMN_NAMES =
    [PREPROCESSED_COLUMN_COUNT][]const u8{
        "recursion_ethereum_leaf_link_projection_active",
        "recursion_ethereum_leaf_link_projection_raw_mask",
        "recursion_ethereum_leaf_link_projection_verifier_mask",
        "recursion_ethereum_leaf_link_projection_constant_source_mask",
        "recursion_ethereum_leaf_link_projection_global_statement_mask",
        "recursion_ethereum_leaf_link_projection_local_statement_mask",
        "recursion_ethereum_leaf_link_projection_expected_mask",
        "recursion_ethereum_leaf_link_projection_raw_scope",
        "recursion_ethereum_leaf_link_projection_raw_index",
        "recursion_ethereum_leaf_link_projection_raw_join_mask",
        "recursion_ethereum_leaf_link_projection_raw_join_scope",
        "recursion_ethereum_leaf_link_projection_raw_join_index",
        "recursion_ethereum_leaf_link_projection_verifier_kind",
        "recursion_ethereum_leaf_link_projection_verifier_index_0",
        "recursion_ethereum_leaf_link_projection_verifier_index_1",
        "recursion_ethereum_leaf_link_projection_statement_scope",
        "recursion_ethereum_leaf_link_projection_statement_index",
        "recursion_ethereum_leaf_link_projection_expected",
    };

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.ethereum_leaf_link.projection.active_boolean",
    "recursion.ethereum_leaf_link.projection.raw_boolean",
    "recursion.ethereum_leaf_link.projection.verifier_boolean",
    "recursion.ethereum_leaf_link.projection.constant_source_boolean",
    "recursion.ethereum_leaf_link.projection.global_statement_boolean",
    "recursion.ethereum_leaf_link.projection.local_statement_boolean",
    "recursion.ethereum_leaf_link.projection.expected_boolean",
    "recursion.ethereum_leaf_link.projection.raw_join_boolean",
    "recursion.ethereum_leaf_link.projection.source_partition",
    "recursion.ethereum_leaf_link.projection.raw_join_implies_active",
    "recursion.ethereum_leaf_link.projection.global_implies_active",
    "recursion.ethereum_leaf_link.projection.local_implies_active",
    "recursion.ethereum_leaf_link.projection.expected_implies_active",
    "recursion.ethereum_leaf_link.projection.inactive_raw_scope_zero",
    "recursion.ethereum_leaf_link.projection.inactive_raw_index_zero",
    "recursion.ethereum_leaf_link.projection.inactive_raw_join_scope_zero",
    "recursion.ethereum_leaf_link.projection.inactive_raw_join_index_zero",
    "recursion.ethereum_leaf_link.projection.inactive_verifier_kind_zero",
    "recursion.ethereum_leaf_link.projection.inactive_verifier_index_0_zero",
    "recursion.ethereum_leaf_link.projection.inactive_verifier_index_1_zero",
    "recursion.ethereum_leaf_link.projection.inactive_statement_scope_zero",
    "recursion.ethereum_leaf_link.projection.inactive_statement_index_zero",
    "recursion.ethereum_leaf_link.projection.inactive_expected_zero",
    "recursion.ethereum_leaf_link.projection.inactive_value_zero",
    "recursion.ethereum_leaf_link.projection.constant_source_zero",
    "recursion.ethereum_leaf_link.projection.expected_value",
};

pub const MainColumns = struct {
    value: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.value};
    }
};

pub const PreprocessedColumns = struct {
    active: types.ValueId,
    raw_mask: types.ValueId,
    verifier_mask: types.ValueId,
    constant_source_mask: types.ValueId,
    global_statement_mask: types.ValueId,
    local_statement_mask: types.ValueId,
    expected_mask: types.ValueId,
    raw_scope: types.ValueId,
    raw_index: types.ValueId,
    raw_join_mask: types.ValueId,
    raw_join_scope: types.ValueId,
    raw_join_index: types.ValueId,
    verifier_kind: types.ValueId,
    verifier_index_0: types.ValueId,
    verifier_index_1: types.ValueId,
    statement_scope: types.ValueId,
    statement_index: types.ValueId,
    expected: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.active,
            self.raw_mask,
            self.verifier_mask,
            self.constant_source_mask,
            self.global_statement_mask,
            self.local_statement_mask,
            self.expected_mask,
            self.raw_scope,
            self.raw_index,
            self.raw_join_mask,
            self.raw_join_scope,
            self.raw_join_index,
            self.verifier_kind,
            self.verifier_index_0,
            self.verifier_index_1,
            self.statement_scope,
            self.statement_index,
            self.expected,
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
            return error.InvalidEthereumLeafLinkProjectionDefinition;
        }
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidEthereumLeafLinkProjectionDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidEthereumLeafLinkProjectionDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidEthereumLeafLinkProjectionDefinition;
            }
        }
        try validateEvent(self, 0, .recursion_vm_public_claim_word, .consume);
        try validateEvent(self, 1, .recursion_vm_public_claim_word, .consume);
        try validateEvent(self, 2, .recursion_verifier_input_word, .consume);
        try validateEvent(self, 3, .recursion_statement_word, .emit);
        try validateEvent(self, 4, .recursion_statement_word, .consume);
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
            if (index <= 6 or index == 9) .selector else .felt,
            span,
        );
    }
    const preprocessed = PreprocessedColumns{
        .active = pp[0],
        .raw_mask = pp[1],
        .verifier_mask = pp[2],
        .constant_source_mask = pp[3],
        .global_statement_mask = pp[4],
        .local_statement_mask = pp[5],
        .expected_mask = pp[6],
        .raw_scope = pp[7],
        .raw_index = pp[8],
        .raw_join_mask = pp[9],
        .raw_join_scope = pp[10],
        .raw_join_index = pp[11],
        .verifier_kind = pp[12],
        .verifier_index_0 = pp[13],
        .verifier_index_1 = pp[14],
        .statement_scope = pp[15],
        .statement_index = pp[16],
        .expected = pp[17],
    };
    const one = try arena.constantField(1, span);
    const zero = try arena.constantField(0, span);
    const inactive = try arena.sub(one, preprocessed.active, span);
    const source_partition = try arena.sub(
        try arena.add(
            try arena.add(preprocessed.raw_mask, preprocessed.verifier_mask, span),
            preprocessed.constant_source_mask,
            span,
        ),
        try arena.mul(preprocessed.raw_mask, preprocessed.verifier_mask, span),
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try booleanRoot(&arena, preprocessed.active, one, span),
        try booleanRoot(&arena, preprocessed.raw_mask, one, span),
        try booleanRoot(&arena, preprocessed.verifier_mask, one, span),
        try booleanRoot(&arena, preprocessed.constant_source_mask, one, span),
        try booleanRoot(&arena, preprocessed.global_statement_mask, one, span),
        try booleanRoot(&arena, preprocessed.local_statement_mask, one, span),
        try booleanRoot(&arena, preprocessed.expected_mask, one, span),
        try booleanRoot(&arena, preprocessed.raw_join_mask, one, span),
        try arena.sub(preprocessed.active, source_partition, span),
        try arena.mul(preprocessed.raw_join_mask, inactive, span),
        try arena.mul(preprocessed.global_statement_mask, inactive, span),
        try arena.mul(preprocessed.local_statement_mask, inactive, span),
        try arena.mul(preprocessed.expected_mask, inactive, span),
        try arena.mul(inactive, preprocessed.raw_scope, span),
        try arena.mul(inactive, preprocessed.raw_index, span),
        try arena.mul(inactive, preprocessed.raw_join_scope, span),
        try arena.mul(inactive, preprocessed.raw_join_index, span),
        try arena.mul(inactive, preprocessed.verifier_kind, span),
        try arena.mul(inactive, preprocessed.verifier_index_0, span),
        try arena.mul(inactive, preprocessed.verifier_index_1, span),
        try arena.mul(inactive, preprocessed.statement_scope, span),
        try arena.mul(inactive, preprocessed.statement_index, span),
        try arena.mul(inactive, preprocessed.expected, span),
        try arena.mul(inactive, main.value, span),
        try arena.mul(preprocessed.constant_source_mask, main.value, span),
        try arena.mul(
            preprocessed.expected_mask,
            try arena.sub(main.value, preprocessed.expected, span),
            span,
        ),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }
    const raw_tuple = [_]types.ValueId{
        preprocessed.raw_scope,
        preprocessed.raw_index,
        main.value,
    };
    const verifier_tuple = [_]types.ValueId{
        zero,
        preprocessed.verifier_kind,
        preprocessed.verifier_index_0,
        preprocessed.verifier_index_1,
        main.value,
    };
    const raw_join_tuple = [_]types.ValueId{
        preprocessed.raw_join_scope,
        preprocessed.raw_join_index,
        main.value,
    };
    const statement_tuple = [_]types.ValueId{
        preprocessed.statement_scope,
        preprocessed.statement_index,
        main.value,
    };
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        .{
            .{
                .domain = .recursion_vm_public_claim_word,
                .role = .consume,
                .values = &raw_tuple,
                .weight = preprocessed.raw_mask,
            },
            .{
                .domain = .recursion_vm_public_claim_word,
                .role = .consume,
                .values = &raw_join_tuple,
                .weight = preprocessed.raw_join_mask,
            },
            .{
                .domain = .recursion_verifier_input_word,
                .role = .consume,
                .values = &verifier_tuple,
                .weight = preprocessed.verifier_mask,
            },
            .{
                .domain = .recursion_statement_word,
                .role = .emit,
                .values = &statement_tuple,
                .weight = preprocessed.global_statement_mask,
            },
            .{
                .domain = .recursion_statement_word,
                .role = .consume,
                .values = &statement_tuple,
                .weight = preprocessed.local_statement_mask,
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
        return error.InvalidEthereumLeafLinkProjectionDefinition;
    const binding = event.binding orelse
        return error.InvalidEthereumLeafLinkProjectionDefinition;
    const schema = relation.get(domain);
    if (types.idIndex(definition.events[index]) != index or
        event.kind != .component_call or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        event.access_ordinal != null)
    {
        return error.InvalidEthereumLeafLinkProjectionDefinition;
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    if (value.len != 2 * @sizeOf(digest.Digest)) @compileError(message);
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

pub fn logicalRow(
    value: M31,
    active: u32,
    raw_mask: u32,
    verifier_mask: u32,
    constant_source_mask: u32,
    global_statement_mask: u32,
    local_statement_mask: u32,
    expected_mask: u32,
    raw_scope: u32,
    raw_index: u32,
    raw_join_mask: u32,
    raw_join_scope: u32,
    raw_join_index: u32,
    verifier_kind: u32,
    verifier_index_0: u32,
    verifier_index_1: u32,
    statement_scope: u32,
    statement_index: u32,
    expected: u32,
) Row {
    return .{
        value,
        M31.fromCanonical(active),
        M31.fromCanonical(raw_mask),
        M31.fromCanonical(verifier_mask),
        M31.fromCanonical(constant_source_mask),
        M31.fromCanonical(global_statement_mask),
        M31.fromCanonical(local_statement_mask),
        M31.fromCanonical(expected_mask),
        M31.fromCanonical(raw_scope),
        M31.fromCanonical(raw_index),
        M31.fromCanonical(raw_join_mask),
        M31.fromCanonical(raw_join_scope),
        M31.fromCanonical(raw_join_index),
        M31.fromCanonical(verifier_kind),
        M31.fromCanonical(verifier_index_0),
        M31.fromCanonical(verifier_index_1),
        M31.fromCanonical(statement_scope),
        M31.fromCanonical(statement_index),
        M31.fromCanonical(expected),
    };
}

comptime {
    if (leaf_source.VERIFIER_ID != 0 or
        relation.universalDescriptor(.recursion_vm_public_claim_word).arity != 3 or
        relation.universalDescriptor(.recursion_verifier_input_word).arity != 5 or
        relation.universalDescriptor(.recursion_statement_word).arity != 3)
    {
        @compileError("Ethereum leaf-link projection relation ABI drifted");
    }
}
