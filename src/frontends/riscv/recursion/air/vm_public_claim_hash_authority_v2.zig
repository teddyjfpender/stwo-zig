//! SegmentV2 row-13 AIR: native-sum relay plus authority-hash custody.
//!
//! The V2 statement authority is verifier-owned preprocessing.  Each canonical
//! Poseidon call is fixed as a 32-word `(input, output)` tuple and requested
//! from the one shared row-34 provider.  The first active row also consumes
//! the verifier schedule's `bind_protocol` step.  Keeping those tuples out of
//! committed main columns prevents an outer prover from substituting a
//! different, internally valid hash program.
//!
//! The same rows retain the sixteen native-public-sum relay values used by the
//! V2 arithmetic graph.  Relay and authority masks may overlap; the physical
//! trace contains exactly their union and pads with the all-zero row.

const std = @import("std");

const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const direct_program = @import("direct_constraint_program.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME =
    "recursion.segment_public_claim_hash_authority.v2";
pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;

pub const POSEIDON_WIDTH: usize = 16;
pub const POSEIDON_TUPLE_WIDTH: usize = 2 * POSEIDON_WIDTH;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 15 + POSEIDON_TUPLE_WIDTH;
pub const PARAMETER_COUNT: usize = 1;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 7;
pub const RELATION_EVENT_COUNT: usize = 5;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 3;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const NATIVE_SUM_CIRCUIT_ID: u32 = 42;
pub const CONTROL_RELAY_CIRCUIT_ID: u32 = 43;
pub const BIND_PROTOCOL_VERIFIER_ID: u32 = 0;
pub const BIND_PROTOCOL_SEQUENCE: u32 = 0;
pub const BIND_PROTOCOL_TAG: u32 = 1;

// Regenerated through `computeSemanticDigest` and pinned before integration.
pub const SEMANTIC_DIGEST_HEX =
    "5ac9b884c34209fe024dfc65d50594276276ef0a8d18629dc87378f60b26f347";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid SegmentV2 claim-hash authority semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.segment_public_claim_hash_authority.v2.enabler",
    "recursion.segment_public_claim_hash_authority.v2.relay_value",
};

pub const PREPROCESSED_COLUMN_NAMES = blk: {
    var names: [PREPROCESSED_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion_segment_public_claim_hash_authority_v2_row_mask";
    names[1] = "recursion_segment_public_claim_hash_authority_v2_relay_mask";
    names[2] = "recursion_segment_public_claim_hash_authority_v2_authority_mask";
    names[3] = "recursion_segment_public_claim_hash_authority_v2_bind_mask";
    for (0..5) |index| names[4 + index] = std.fmt.comptimePrint(
        "recursion_segment_public_claim_hash_authority_v2_source_{d}",
        .{index},
    );
    names[9] = "recursion_segment_public_claim_hash_authority_v2_arithmetic_circuit";
    names[10] = "recursion_segment_public_claim_hash_authority_v2_arithmetic_node";
    names[11] = "recursion_segment_public_claim_hash_authority_v2_arithmetic_uses";
    names[12] = "recursion_segment_public_claim_hash_authority_v2_control_circuit";
    names[13] = "recursion_segment_public_claim_hash_authority_v2_control_node";
    names[14] = "recursion_segment_public_claim_hash_authority_v2_control_uses";
    for (0..POSEIDON_TUPLE_WIDTH) |index| names[15 + index] =
        std.fmt.comptimePrint(
            "recursion_segment_public_claim_hash_authority_v2_poseidon_{d}",
            .{index},
        );
    break :blk names;
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.segment_public_claim_hash_authority.v2.param.zero",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.segment_public_claim_hash_authority.v2.enabler_matches_row",
    "recursion.segment_public_claim_hash_authority.v2.padding_value_zero",
    "recursion.segment_public_claim_hash_authority.v2.nonrelay_value_zero",
    "recursion.segment_public_claim_hash_authority.v2.relay_within_row",
    "recursion.segment_public_claim_hash_authority.v2.authority_within_row",
    "recursion.segment_public_claim_hash_authority.v2.bind_requires_authority",
    "recursion.segment_public_claim_hash_authority.v2.row_is_union",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    relay_value: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.relay_value };
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    relay_mask: types.ValueId,
    authority_mask: types.ValueId,
    bind_mask: types.ValueId,
    source_fields: [5]types.ValueId,
    arithmetic_circuit_id: types.ValueId,
    arithmetic_node_id: types.ValueId,
    arithmetic_use_count: types.ValueId,
    control_circuit_id: types.ValueId,
    control_node_id: types.ValueId,
    control_use_count: types.ValueId,
    poseidon_tuple: [POSEIDON_TUPLE_WIDTH]types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.relay_mask,
            self.authority_mask,
            self.bind_mask,
        } ++ self.source_fields ++ .{
            self.arithmetic_circuit_id,
            self.arithmetic_node_id,
            self.arithmetic_use_count,
            self.control_circuit_id,
            self.control_node_id,
            self.control_use_count,
        } ++ self.poseidon_tuple;
    }
};

pub const Parameters = struct {
    zero: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{self.zero};
    }
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    arithmetic_weight: types.ValueId,
    control_weight: types.ValueId,
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
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or
            self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidClaimHashAuthorityV2Definition;
        }
        try validateInputGroup(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            &.{0},
        );
        try validateInputGroup(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1, 2, 3 },
        );
        try validateInputGroup(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{},
        );
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidClaimHashAuthorityV2Definition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidClaimHashAuthorityV2Definition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidClaimHashAuthorityV2Definition;
            }
        }
        try validateEvents(self);
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
    .arena_nodes = 66,
    .compiled_nodes = 16,
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
        .direct_constraints = DIRECT_CONSTRAINT_COUNT,
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
        .enabler = try arena.input(MAIN_COLUMN_NAMES[0], .selector, span),
        .relay_value = try arena.input(MAIN_COLUMN_NAMES[1], .felt, span),
    };
    var inputs: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&inputs, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(
            name,
            if (index < 4) .selector else .felt,
            span,
        );
    const preprocessed = PreprocessedColumns{
        .row_mask = inputs[0],
        .relay_mask = inputs[1],
        .authority_mask = inputs[2],
        .bind_mask = inputs[3],
        .source_fields = inputs[4..9].*,
        .arithmetic_circuit_id = inputs[9],
        .arithmetic_node_id = inputs[10],
        .arithmetic_use_count = inputs[11],
        .control_circuit_id = inputs[12],
        .control_node_id = inputs[13],
        .control_use_count = inputs[14],
        .poseidon_tuple = inputs[15..][0..POSEIDON_TUPLE_WIDTH].*,
    };
    const parameters = Parameters{
        .zero = try arena.input(PARAMETER_NAMES[0], .felt, span),
    };
    const one = try arena.constantField(1, span);
    const inactive = try arena.sub(one, preprocessed.row_mask, span);
    const nonrelay = try arena.sub(
        preprocessed.row_mask,
        preprocessed.relay_mask,
        span,
    );
    const overlap_mask = try arena.mul(
        preprocessed.relay_mask,
        preprocessed.authority_mask,
        span,
    );
    const union_mask = try arena.sub(
        try arena.add(
            preprocessed.relay_mask,
            preprocessed.authority_mask,
            span,
        ),
        overlap_mask,
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(inactive, main.relay_value, span),
        try arena.mul(nonrelay, main.relay_value, span),
        try arena.mul(preprocessed.relay_mask, inactive, span),
        try arena.mul(preprocessed.authority_mask, inactive, span),
        try arena.mul(
            preprocessed.bind_mask,
            try arena.sub(one, preprocessed.authority_mask, span),
            span,
        ),
        try arena.sub(preprocessed.row_mask, union_mask, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
        constraint.* = try arena.assertZero(
            name,
            root,
            null,
            .semantic,
            span,
        );

    const arithmetic_weight = try arena.mul(
        preprocessed.relay_mask,
        preprocessed.arithmetic_use_count,
        span,
    );
    const control_weight = try arena.mul(
        preprocessed.relay_mask,
        preprocessed.control_use_count,
        span,
    );
    const tuples = relationTuples(preprocessed, main, parameters);
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        .{
            .{
                .domain = .recursion_wire,
                .role = .consume,
                .values = &tuples.source,
                .weight = preprocessed.relay_mask,
            },
            .{
                .domain = .recursion_wire,
                .role = .emit,
                .values = &tuples.arithmetic,
                .weight = arithmetic_weight,
            },
            .{
                .domain = .recursion_wire,
                .role = .emit,
                .values = &tuples.control,
                .weight = control_weight,
            },
            .{
                .domain = .poseidon2_io,
                .role = .request,
                .values = &tuples.poseidon,
                .weight = preprocessed.authority_mask,
            },
            .{
                .domain = .recursion_step,
                .role = .consume,
                .values = &tuples.bind_protocol,
                .weight = preprocessed.bind_mask,
            },
        },
        span,
    );
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .arithmetic_weight = arithmetic_weight,
        .control_weight = control_weight,
        .roots = roots,
        .constraints = constraints,
        .events = events,
    };
}

const RelationTuples = struct {
    source: [6]types.ValueId,
    arithmetic: [6]types.ValueId,
    control: [6]types.ValueId,
    poseidon: [POSEIDON_TUPLE_WIDTH]types.ValueId,
    bind_protocol: [7]types.ValueId,
};

fn relationTuples(
    preprocessed: PreprocessedColumns,
    main: MainColumns,
    parameters: Parameters,
) RelationTuples {
    return .{
        .source = .{
            preprocessed.source_fields[0],
            preprocessed.source_fields[1],
            main.relay_value,
            preprocessed.source_fields[2],
            preprocessed.source_fields[3],
            preprocessed.source_fields[4],
        },
        .arithmetic = .{
            preprocessed.arithmetic_circuit_id,
            preprocessed.arithmetic_node_id,
            main.relay_value,
            parameters.zero,
            parameters.zero,
            parameters.zero,
        },
        .control = .{
            preprocessed.control_circuit_id,
            preprocessed.control_node_id,
            main.relay_value,
            parameters.zero,
            parameters.zero,
            parameters.zero,
        },
        .poseidon = preprocessed.poseidon_tuple,
        .bind_protocol = .{
            parameters.zero,
            parameters.zero,
            // `bind_protocol` is verifier step tag one.
            preprocessed.bind_mask,
            parameters.zero,
            parameters.zero,
            parameters.zero,
            parameters.zero,
        },
    };
}

fn validateEvents(self: *const Definition) !void {
    const expected = [_]struct { domain: relation.Domain, role: relation.Role }{
        .{ .domain = .recursion_wire, .role = .consume },
        .{ .domain = .recursion_wire, .role = .emit },
        .{ .domain = .recursion_wire, .role = .emit },
        .{ .domain = .poseidon2_io, .role = .request },
        .{ .domain = .recursion_step, .role = .consume },
    };
    for (self.events, expected, 0..) |effect_id, want, index| {
        if (types.idIndex(effect_id) != index)
            return error.InvalidClaimHashAuthorityV2Definition;
        const item = self.arena.effect(effect_id) orelse
            return error.InvalidClaimHashAuthorityV2Definition;
        const binding = item.binding orelse
            return error.InvalidClaimHashAuthorityV2Definition;
        const schema = relation.get(want.domain);
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidClaimHashAuthorityV2Definition;
        if (item.kind != .component_call or item.access_ordinal != null or
            binding.schema != schema.id or
            binding.schema_version != schema.version or
            binding.role != want.role or values.len != schema.fields.len)
        {
            return error.InvalidClaimHashAuthorityV2Definition;
        }
    }
}

fn validateInputGroup(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) !void {
    if (values.len != names.len)
        return error.InvalidClaimHashAuthorityV2Definition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidClaimHashAuthorityV2Definition;
        const node = arena.node(value) orelse
            return error.InvalidClaimHashAuthorityV2Definition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        if (!std.meta.eql(node.key.ty, if (selector) types.Type.selector else .felt))
            return error.InvalidClaimHashAuthorityV2Definition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidClaimHashAuthorityV2Definition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidClaimHashAuthorityV2Definition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidClaimHashAuthorityV2Definition;
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    if (value.len != 2 * @sizeOf(digest.Digest)) @compileError(message);
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (POSEIDON_TUPLE_WIDTH !=
        relation.universalDescriptor(.poseidon2_io).arity or
        INTERACTION_BATCH_COUNT != 3 or INTERACTION_COLUMN_COUNT != 12 or
        RELATION_EVENT_COUNT != 5 or LOOKUP_BATCH_SIZE != 2)
    {
        @compileError("SegmentV2 claim-hash authority relation geometry drifted");
    }
}
