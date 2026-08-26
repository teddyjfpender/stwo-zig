//! Typed publisher for the capture-backed SegmentV2 publication input.
//!
//! One deliberately separate component emits two disjoint authenticated
//! classes from its own committed trace:
//!
//! - 55 `recursion_verifier_input_word(2, LUP2, index, 0, value)` tuples for
//!   the row-37 publication bridge; and
//! - 84 `recursion_verifier_input_word(0, 12, item, limb, value)` tuples for
//!   row 18's 21 detailed VM composition claims.
//!
//! It has no relation to `recursion_wire`, so it cannot self-cancel either
//! consumer or hide a cross-domain residual.

const std = @import("std");

const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const direct_program = @import("direct_constraint_program.zig");
const relation_effect = @import("relation_effect.zig");
const leaf_source = @import("../segment_leaf_authority_v2.zig");
const composition_witness = @import("vm_air_composition_input_witness.zig");

pub const STABLE_NAME =
    "recursion.segment_v2.publication_input_provider.v1";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;

pub const LUP2_VERIFIER_ID: u32 = leaf_source.SEGMENT_V2_VERIFIER_ID;
pub const LUP2_SOURCE_KIND: u32 = leaf_source.PUBLIC_LOGUP_V2_KIND;
pub const DETAILED_VERIFIER_ID: u32 =
    composition_witness.SEGMENT_VERIFIER_ID;
pub const DETAILED_SOURCE_KIND: u32 =
    composition_witness.VM_CLAIMED_SUM_KIND;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
pub const PREPROCESSED_COLUMN_COUNT: usize = 4;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 7;
pub const RELATION_EVENT_COUNT: usize = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

// Regenerated from this file's typed IR. The focused authority test pins both
// this semantic identity and the compiler profile before integration.
pub const SEMANTIC_DIGEST_HEX =
    "5b62519820b6cf232304c74537a8612f3956a0f90fa898bc560668cd54e1d32c";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid SegmentV2 publication-input provider semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.segment_v2.publication_input_provider.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_segment_v2_publication_input_provider_active",
    "recursion_segment_v2_publication_input_provider_lup2_class",
    "recursion_segment_v2_publication_input_provider_index_0",
    "recursion_segment_v2_publication_input_provider_index_1",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.segment_v2.publication_input_provider.active_boolean",
    "recursion.segment_v2.publication_input_provider.lup2_class_boolean",
    "recursion.segment_v2.publication_input_provider.lup2_implies_active",
    "recursion.segment_v2.publication_input_provider.lup2_limb_zero",
    "recursion.segment_v2.publication_input_provider.inactive_index_0_zero",
    "recursion.segment_v2.publication_input_provider.inactive_index_1_zero",
    "recursion.segment_v2.publication_input_provider.inactive_value_zero",
};

pub const MainColumns = struct {
    value: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.value};
    }
};

pub const PreprocessedColumns = struct {
    active: types.ValueId,
    lup2_class: types.ValueId,
    index_0: types.ValueId,
    index_1: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{ self.active, self.lup2_class, self.index_0, self.index_1 };
    }
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    verifier: types.ValueId,
    source_kind: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    event: types.EffectId,

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
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or
            self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidPublicationInputProviderDefinition;
        }

        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            0,
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            2,
        );
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidPublicationInputProviderDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidPublicationInputProviderDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidPublicationInputProviderDefinition;
            }
        }

        const tuple = [_]types.ValueId{
            self.verifier,
            self.source_kind,
            self.preprocessed.index_0,
            self.preprocessed.index_1,
            self.main.value,
        };
        try validateEffect(
            &self.arena,
            self.event,
            .recursion_verifier_input_word,
            .emit,
            self.preprocessed.active,
            &tuple,
        );
    }
};

pub const StaticProfile = struct {
    arena_nodes: u16,
    compiled_nodes: u16,
    direct_constraints: u16,
    relation_events: u16,
    interaction_batches: u16,
    interaction_columns: u16,
    maximum_constraint_degree: u32,
};

pub const EXPECTED_STATIC_PROFILE = StaticProfile{
    .arena_nodes = 25,
    .compiled_nodes = 20,
    .direct_constraints = DIRECT_CONSTRAINT_COUNT,
    .relation_events = RELATION_EVENT_COUNT,
    .interaction_batches = INTERACTION_BATCH_COUNT,
    .interaction_columns = INTERACTION_COLUMN_COUNT,
    .maximum_constraint_degree = MAXIMUM_CONSTRAINT_DEGREE,
};

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

pub fn staticProfile(definition: *const Definition) !StaticProfile {
    try definition.validate();
    const program = try direct_program.authenticate(
        &definition.arena,
        SEMANTIC_DIGEST,
        LOGICAL_INPUT_COUNT,
    );
    return .{
        .arena_nodes = program.node_count,
        .compiled_nodes = program.compiled_node_count,
        .direct_constraints = program.constraint_count,
        .relation_events = RELATION_EVENT_COUNT,
        .interaction_batches = INTERACTION_BATCH_COUNT,
        .interaction_columns = INTERACTION_COLUMN_COUNT,
        .maximum_constraint_degree = MAXIMUM_CONSTRAINT_DEGREE,
    };
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const main = MainColumns{
        .value = try arena.input(MAIN_COLUMN_NAMES[0], .felt, span),
    };
    const preprocessed = PreprocessedColumns{
        .active = try arena.input(
            PREPROCESSED_COLUMN_NAMES[0],
            .selector,
            span,
        ),
        .lup2_class = try arena.input(
            PREPROCESSED_COLUMN_NAMES[1],
            .selector,
            span,
        ),
        .index_0 = try arena.input(
            PREPROCESSED_COLUMN_NAMES[2],
            .felt,
            span,
        ),
        .index_1 = try arena.input(
            PREPROCESSED_COLUMN_NAMES[3],
            .felt,
            span,
        ),
    };
    const one = try arena.constantField(1, span);
    const inactive = try arena.sub(one, preprocessed.active, span);
    const lup2_inactive = try arena.sub(one, preprocessed.lup2_class, span);
    const lup2_verifier = try arena.constantField(LUP2_VERIFIER_ID, span);
    const lup2_kind = try arena.constantField(LUP2_SOURCE_KIND, span);
    const detailed_kind = try arena.constantField(DETAILED_SOURCE_KIND, span);
    const verifier = try arena.mul(
        preprocessed.lup2_class,
        lup2_verifier,
        span,
    );
    const source_kind = try arena.add(
        try arena.mul(preprocessed.lup2_class, lup2_kind, span),
        try arena.mul(
            try arena.mul(preprocessed.active, lup2_inactive, span),
            detailed_kind,
            span,
        ),
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.mul(
            preprocessed.active,
            try arena.sub(preprocessed.active, one, span),
            span,
        ),
        try arena.mul(
            preprocessed.lup2_class,
            try arena.sub(preprocessed.lup2_class, one, span),
            span,
        ),
        try arena.mul(preprocessed.lup2_class, inactive, span),
        try arena.mul(preprocessed.lup2_class, preprocessed.index_1, span),
        try arena.mul(inactive, preprocessed.index_0, span),
        try arena.mul(inactive, preprocessed.index_1, span),
        try arena.mul(inactive, main.value, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);

    const tuple = [_]types.ValueId{
        verifier,
        source_kind,
        preprocessed.index_0,
        preprocessed.index_1,
        main.value,
    };
    const event = try relation_effect.append(&arena, .{
        .domain = .recursion_verifier_input_word,
        .role = .emit,
        .values = &tuple,
        .weight = preprocessed.active,
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .verifier = verifier,
        .source_kind = source_kind,
        .roots = roots,
        .constraints = constraints,
        .event = event,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_count: usize,
) !void {
    if (values.len != names.len)
        return error.InvalidPublicationInputProviderDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidPublicationInputProviderDefinition;
        const node = arena.node(value) orelse
            return error.InvalidPublicationInputProviderDefinition;
        const selector = local_index < selector_count;
        if (!std.meta.eql(
            node.key.ty,
            if (selector) types.Type.selector else .felt,
        )) return error.InvalidPublicationInputProviderDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidPublicationInputProviderDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidPublicationInputProviderDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidPublicationInputProviderDefinition;
    }
}

fn validateEffect(
    arena: *const ir.Arena,
    effect_id: types.EffectId,
    domain: relation.Domain,
    role: relation.Role,
    weight: types.ValueId,
    values: []const types.ValueId,
) !void {
    if (types.idIndex(effect_id) != 0)
        return error.InvalidPublicationInputProviderDefinition;
    const item = arena.effect(effect_id) orelse
        return error.InvalidPublicationInputProviderDefinition;
    const binding = item.binding orelse
        return error.InvalidPublicationInputProviderDefinition;
    const schema = relation.get(domain);
    const actual_values = arena.effectValues(effect_id) orelse
        return error.InvalidPublicationInputProviderDefinition;
    if (item.kind != .component_call or item.liveness != weight or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, actual_values, values))
    {
        return error.InvalidPublicationInputProviderDefinition;
    }
}

fn hexDigest(comptime text: []const u8, comptime message: []const u8) digest.Digest {
    if (text.len != 2 * @sizeOf(digest.Digest)) @compileError(message);
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, text) catch @compileError(message);
    return result;
}

comptime {
    if (LUP2_VERIFIER_ID != 2 or LUP2_SOURCE_KIND != 0x4c55_5032 or
        DETAILED_VERIFIER_ID != 0 or DETAILED_SOURCE_KIND != 12 or
        LOGICAL_INPUT_COUNT != 5 or DIRECT_CONSTRAINT_COUNT != 7 or
        RELATION_EVENT_COUNT != 1 or INTERACTION_BATCH_COUNT != 1 or
        INTERACTION_COLUMN_COUNT != 4 or MAXIMUM_CONSTRAINT_DEGREE != 2 or
        relation.universalDescriptor(.recursion_verifier_input_word).arity != 5)
    {
        @compileError("SegmentV2 publication-input provider AIR drifted");
    }
}
