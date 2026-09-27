//! Field-native source component for the recursive Ethereum leaf wrapper.
//!
//! Metadata and link words are private wrapper witnesses whose public
//! identities are established by the two Poseidon callers. Transcript claims
//! are the exact 42 QM31 values consumed by the dynamic Ethereum row-18
//! verifier program. Digest rows publish only M31 words; SHA-256 custody never
//! enters this AIR.

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
const composition_witness = @import("vm_air_composition_input_witness.zig");

const M31 = core.fields.m31.M31;

pub const STABLE_NAME = "recursion.ethereum_leaf_link.source.v1";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;

pub const METADATA_SCOPE: u32 = 0x4d33_5731; // "M3W1"
pub const LINK_SCOPE: u32 = 0x4c33_5731; // "L3W1"
pub const GLOBAL_STATEMENT_SCOPE: u32 = 0x4733_5331; // "G3S1"
pub const LEAF_AUTHORITY_SCOPE: u32 = 0x4c41_5331; // "LAS1"
pub const METADATA_DIGEST_KIND: u32 = 0x4d33_4431; // "M3D1"
pub const LINK_DIGEST_KIND: u32 = 0x4c33_4431; // "L3D1"
pub const LOCAL_AUTHORITY_DIGEST_KIND: u32 = 0x4c41_4931; // "LAI1"
pub const LOCAL_WIRE_DIGEST_KIND: u32 = 0x4c57_4931; // "LWI1"
pub const LOCAL_RECEIPT_DIGEST_KIND: u32 = 0x4c52_4931; // "LRI1"
pub const PROGRAM_AUTHORITY_KIND: u32 = 0x5052_4731; // "PRG1"
pub const PREPROCESSED_ROOT_KIND: u32 = 0x5050_5231; // "PPR1"
pub const PROVIDER_RELATION_CONTEXT_KIND: u32 = 0x5052_4331; // "PRC1"
pub const PROVIDER_CORE_CLAIM_KIND: u32 = 0x5043_4331; // "PCC1"
pub const PROVIDER_MANIFEST_KIND: u32 = 0x5053_4d31; // "PSM1"
pub const PROVIDER_CANCELLATION_KIND: u32 = 0x5053_4131; // "PSA1"
pub const VERIFIER_ID: u32 = composition_witness.SEGMENT_VERIFIER_ID;
pub const TRANSCRIPT_CLAIM_KIND: u32 =
    composition_witness.TRANSCRIPT_CLAIMED_SUM_KIND;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 10;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 13;
pub const RELATION_EVENT_COUNT: usize = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = RELATION_EVENT_COUNT;
pub const INTERACTION_COLUMN_COUNT: usize = 4 * INTERACTION_BATCH_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX =
    "3b0a062152bc68526b3615286272a57c5a4358b9a327115931ddebb5380dc815";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid Ethereum leaf-link source semantic digest",
);

comptime {
    for (.{
        METADATA_SCOPE,
        LINK_SCOPE,
        GLOBAL_STATEMENT_SCOPE,
        LEAF_AUTHORITY_SCOPE,
        METADATA_DIGEST_KIND,
        LINK_DIGEST_KIND,
        LOCAL_AUTHORITY_DIGEST_KIND,
        LOCAL_WIRE_DIGEST_KIND,
        LOCAL_RECEIPT_DIGEST_KIND,
        PROGRAM_AUTHORITY_KIND,
        PREPROCESSED_ROOT_KIND,
        PROVIDER_RELATION_CONTEXT_KIND,
        PROVIDER_CORE_CLAIM_KIND,
        PROVIDER_MANIFEST_KIND,
        PROVIDER_CANCELLATION_KIND,
    }) |value| if (value >= core.fields.m31.Modulus)
        @compileError("Ethereum leaf-link relation tag is not canonical M31");
    if (VERIFIER_ID != 0 or TRANSCRIPT_CLAIM_KIND != 5)
        @compileError("Ethereum transcript-claim ABI drifted");
}

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.ethereum_leaf_link.source.value",
};

pub const PREPROCESSED_COLUMN_NAMES =
    [PREPROCESSED_COLUMN_COUNT][]const u8{
        "recursion_ethereum_leaf_link_source_active",
        "recursion_ethereum_leaf_link_source_raw_mask",
        "recursion_ethereum_leaf_link_source_verifier_mask",
        "recursion_ethereum_leaf_link_source_transcript_mask",
        "recursion_ethereum_leaf_link_source_statement_mask",
        "recursion_ethereum_leaf_link_source_scope",
        "recursion_ethereum_leaf_link_source_kind",
        "recursion_ethereum_leaf_link_source_index_0",
        "recursion_ethereum_leaf_link_source_index_1",
        "recursion_ethereum_leaf_link_source_use_count",
    };

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.ethereum_leaf_link.source.active_boolean",
    "recursion.ethereum_leaf_link.source.raw_boolean",
    "recursion.ethereum_leaf_link.source.verifier_boolean",
    "recursion.ethereum_leaf_link.source.transcript_boolean",
    "recursion.ethereum_leaf_link.source.statement_boolean",
    "recursion.ethereum_leaf_link.source.partition",
    "recursion.ethereum_leaf_link.source.statement_implies_active",
    "recursion.ethereum_leaf_link.source.inactive_scope_zero",
    "recursion.ethereum_leaf_link.source.inactive_kind_zero",
    "recursion.ethereum_leaf_link.source.inactive_index_0_zero",
    "recursion.ethereum_leaf_link.source.inactive_index_1_zero",
    "recursion.ethereum_leaf_link.source.inactive_use_count_zero",
    "recursion.ethereum_leaf_link.source.inactive_value_zero",
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
    transcript_mask: types.ValueId,
    statement_mask: types.ValueId,
    scope: types.ValueId,
    kind: types.ValueId,
    index_0: types.ValueId,
    index_1: types.ValueId,
    use_count: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.active,
            self.raw_mask,
            self.verifier_mask,
            self.transcript_mask,
            self.statement_mask,
            self.scope,
            self.kind,
            self.index_0,
            self.index_1,
            self.use_count,
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
            return error.InvalidEthereumLeafLinkSourceDefinition;
        }
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidEthereumLeafLinkSourceDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidEthereumLeafLinkSourceDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidEthereumLeafLinkSourceDefinition;
            }
        }
        try validateEvent(
            self,
            0,
            .recursion_vm_public_claim_word,
            .emit,
            &.{
                self.preprocessed.scope,
                self.preprocessed.index_0,
                self.main.value,
            },
        );
        try validateEvent(
            self,
            1,
            .recursion_verifier_input_word,
            .emit,
            &.{
                constantValue(&self.arena, VERIFIER_ID) orelse
                    return error.InvalidEthereumLeafLinkSourceDefinition,
                self.preprocessed.kind,
                self.preprocessed.index_0,
                self.preprocessed.index_1,
                self.main.value,
            },
        );
        try validateEvent(
            self,
            2,
            .recursion_statement_word,
            .emit,
            &.{
                self.preprocessed.scope,
                self.preprocessed.index_0,
                self.main.value,
            },
        );
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
            if (index <= 4) .selector else .felt,
            span,
        );
    }
    const preprocessed = PreprocessedColumns{
        .active = pp[0],
        .raw_mask = pp[1],
        .verifier_mask = pp[2],
        .transcript_mask = pp[3],
        .statement_mask = pp[4],
        .scope = pp[5],
        .kind = pp[6],
        .index_0 = pp[7],
        .index_1 = pp[8],
        .use_count = pp[9],
    };
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const inactive = try arena.sub(one, preprocessed.active, span);
    const partition = try arena.add(
        try arena.add(preprocessed.raw_mask, preprocessed.verifier_mask, span),
        preprocessed.transcript_mask,
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try booleanRoot(&arena, preprocessed.active, one, span),
        try booleanRoot(&arena, preprocessed.raw_mask, one, span),
        try booleanRoot(&arena, preprocessed.verifier_mask, one, span),
        try booleanRoot(&arena, preprocessed.transcript_mask, one, span),
        try booleanRoot(&arena, preprocessed.statement_mask, one, span),
        try arena.sub(preprocessed.active, partition, span),
        try arena.mul(preprocessed.statement_mask, inactive, span),
        try arena.mul(inactive, preprocessed.scope, span),
        try arena.mul(inactive, preprocessed.kind, span),
        try arena.mul(inactive, preprocessed.index_0, span),
        try arena.mul(inactive, preprocessed.index_1, span),
        try arena.mul(inactive, preprocessed.use_count, span),
        try arena.mul(inactive, main.value, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }
    const raw_weight = try arena.mul(
        preprocessed.raw_mask,
        preprocessed.use_count,
        span,
    );
    const verifier_weight = try arena.mul(
        try arena.add(
            preprocessed.verifier_mask,
            preprocessed.transcript_mask,
            span,
        ),
        preprocessed.use_count,
        span,
    );
    const raw_tuple = [_]types.ValueId{
        preprocessed.scope,
        preprocessed.index_0,
        main.value,
    };
    const verifier_tuple = [_]types.ValueId{
        zero,
        preprocessed.kind,
        preprocessed.index_0,
        preprocessed.index_1,
        main.value,
    };
    const statement_tuple = [_]types.ValueId{
        preprocessed.scope,
        preprocessed.index_0,
        main.value,
    };
    const events = [RELATION_EVENT_COUNT]types.EffectId{
        try relation_effect.append(&arena, .{
            .domain = .recursion_vm_public_claim_word,
            .role = .emit,
            .values = &raw_tuple,
            .weight = raw_weight,
        }, span),
        try relation_effect.append(&arena, .{
            .domain = .recursion_verifier_input_word,
            .role = .emit,
            .values = &verifier_tuple,
            .weight = verifier_weight,
        }, span),
        try relation_effect.append(&arena, .{
            .domain = .recursion_statement_word,
            .role = .emit,
            .values = &statement_tuple,
            .weight = preprocessed.statement_mask,
        }, span),
    };
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
    values: []const types.ValueId,
) !void {
    const event = definition.arena.effect(definition.events[index]) orelse
        return error.InvalidEthereumLeafLinkSourceDefinition;
    const binding = event.binding orelse
        return error.InvalidEthereumLeafLinkSourceDefinition;
    const actual = definition.arena.effectValues(definition.events[index]) orelse
        return error.InvalidEthereumLeafLinkSourceDefinition;
    const schema = relation.get(domain);
    if (types.idIndex(definition.events[index]) != index or
        event.kind != .component_call or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        event.access_ordinal != null or !std.mem.eql(types.ValueId, actual, values))
    {
        return error.InvalidEthereumLeafLinkSourceDefinition;
    }
}

fn constantValue(arena: *const ir.Arena, expected: u32) ?types.ValueId {
    for (arena.nodesView(), 0..) |node, index| switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| if (value == expected) return @enumFromInt(index),
            .unsigned => {},
        },
        else => {},
    };
    return null;
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
    transcript_mask: u32,
    statement_mask: u32,
    scope: u32,
    kind: u32,
    index_0: u32,
    index_1: u32,
    use_count: u32,
) Row {
    return .{
        value,
        M31.fromCanonical(active),
        M31.fromCanonical(raw_mask),
        M31.fromCanonical(verifier_mask),
        M31.fromCanonical(transcript_mask),
        M31.fromCanonical(statement_mask),
        M31.fromCanonical(scope),
        M31.fromCanonical(kind),
        M31.fromCanonical(index_0),
        M31.fromCanonical(index_1),
        M31.fromCanonical(use_count),
    };
}
