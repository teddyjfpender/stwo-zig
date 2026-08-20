//! Versioned typed AIR contracts for resumed-segment public rows 12--17.
//!
//! V2 does not replay native RISC-V lookup events in the outer 47-domain
//! registry.  Each row is instead a verifier-owned relay: it consumes one
//! authenticated recursion-local source word and may publish that value into
//! the single native-public-sum arithmetic circuit or the one-word control
//! relay.  Rows 30--32 remain the sole owners of arithmetic graph equations.
//!
//! All six contracts use the same deliberately small polynomial kernel.  The
//! source domain, tuple arity, and value coordinate are compile-time protocol
//! data, so there is no row-time domain dispatch.  Distinct stable names keep
//! the versioned ownership surface explicit; contracts with identical source
//! ABIs intentionally share a semantic digest.

const std = @import("std");

const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;

const RELAY_MAIN_COLUMN_COUNT: usize = 2;
const RELAY_PREPROCESSED_COLUMN_COUNT: usize = 14;
const RELAY_PARAMETER_COUNT: usize = 1;
const RELAY_LOGICAL_INPUT_COUNT: usize =
    RELAY_MAIN_COLUMN_COUNT + RELAY_PREPROCESSED_COLUMN_COUNT +
    RELAY_PARAMETER_COUNT;
const RELAY_DIRECT_CONSTRAINT_COUNT: usize = 5;
const RELAY_RELATION_EVENT_COUNT: usize = 3;
const RELAY_LOOKUP_BATCH_SIZE: u8 = 2;
const RELAY_INTERACTION_BATCH_COUNT: usize = 2;
const RELAY_INTERACTION_COLUMN_COUNT: usize = 8;
const RELAY_REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
const RELAY_MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;

pub const MAIN_COLUMN_NAMES = [RELAY_MAIN_COLUMN_COUNT][]const u8{
    "recursion.segment_public_v2.enabler",
    "recursion.segment_public_v2.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [RELAY_PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_segment_public_v2_row_mask",
    "recursion_segment_public_v2_arithmetic_mask",
    "recursion_segment_public_v2_control_mask",
    "recursion_segment_public_v2_source_0",
    "recursion_segment_public_v2_source_1",
    "recursion_segment_public_v2_source_2",
    "recursion_segment_public_v2_source_3",
    "recursion_segment_public_v2_source_4",
    "recursion_segment_public_v2_arithmetic_circuit_id",
    "recursion_segment_public_v2_arithmetic_node_id",
    "recursion_segment_public_v2_arithmetic_use_count",
    "recursion_segment_public_v2_control_circuit_id",
    "recursion_segment_public_v2_control_node_id",
    "recursion_segment_public_v2_control_use_count",
};

pub const PARAMETER_NAMES = [RELAY_PARAMETER_COUNT][]const u8{
    "recursion.segment_public_v2.param.zero",
};

pub const CONSTRAINT_NAMES = [RELAY_DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.segment_public_v2.enabler_matches_row_mask",
    "recursion.segment_public_v2.padding_value_zero",
    "recursion.segment_public_v2.arithmetic_mask_within_row",
    "recursion.segment_public_v2.control_mask_within_row",
    "recursion.segment_public_v2.relay_masks_disjoint",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    value: types.ValueId,

    pub fn physical(self: MainColumns) [RELAY_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.value };
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    arithmetic_mask: types.ValueId,
    control_mask: types.ValueId,
    source_fields: [5]types.ValueId,
    arithmetic_circuit_id: types.ValueId,
    arithmetic_node_id: types.ValueId,
    arithmetic_use_count: types.ValueId,
    control_circuit_id: types.ValueId,
    control_node_id: types.ValueId,
    control_use_count: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [RELAY_PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.arithmetic_mask,
            self.control_mask,
        } ++ self.source_fields ++ .{
            self.arithmetic_circuit_id,
            self.arithmetic_node_id,
            self.arithmetic_use_count,
            self.control_circuit_id,
            self.control_node_id,
            self.control_use_count,
        };
    }
};

pub const Parameters = struct {
    zero: types.ValueId,

    pub fn physical(self: Parameters) [RELAY_PARAMETER_COUNT]types.ValueId {
        return .{self.zero};
    }
};

pub const Config = struct {
    stable_name: []const u8,
    source_domain: relation.Domain,
    source_arity: u8,
    value_position: u8,
    semantic_digest: digest.Digest,
};

const wire_relay_digest = hexDigest(
    "b7eed8855dae04c9094b14eae6bc5cabe49cc006ca2882de6737f0e4ecfb6251",
    "invalid V2 public wire-relay semantic digest",
);
const challenge_relay_digest = hexDigest(
    "798777f69f69a38ebb35aedb1b91fc40846fe72a5edae2e013f518f7daad6d41",
    "invalid V2 public challenge-relay semantic digest",
);

pub const PublicationHeader = Relay(.{
    .stable_name = "recursion.segment_public_publication_header.v2",
    .source_domain = .recursion_wire,
    .source_arity = 6,
    .value_position = 2,
    .semantic_digest = wire_relay_digest,
});

pub const NativePublicSums =
    @import("vm_public_claim_hash_authority_v2.zig");

pub const PublicationSeal = Relay(.{
    .stable_name = "recursion.segment_public_publication_seal.v2",
    .source_domain = .recursion_wire,
    .source_arity = 6,
    .value_position = 2,
    .semantic_digest = wire_relay_digest,
});

pub const StatementBoundary = Relay(.{
    .stable_name = "recursion.segment_public_statement_boundary.v2",
    .source_domain = .recursion_wire,
    .source_arity = 6,
    .value_position = 2,
    .semantic_digest = wire_relay_digest,
});

pub const NativeChallenges = Relay(.{
    .stable_name = "recursion.segment_public_native_challenges.v2",
    .source_domain = .recursion_relation_challenge_word,
    .source_arity = 5,
    .value_position = 4,
    .semantic_digest = challenge_relay_digest,
});

pub const ControlRelay = @import("vm_public_logup_control_v2.zig");

pub const OverrideActivationV2 = enum(u8) {
    active_v2_override = 1,
};

/// Cycle-free handoff to the central V2 catalog. Every geometry field is
/// projected from its authoritative AIR type rather than copied by callers.
pub const ComponentOverrideV2 = struct {
    component_index: u8,
    activation: OverrideActivationV2,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    relation_events: u16,
    protocol_constraint_degree: u8,
    profiled_constraint_degree: u8,
    semantic_digest: digest.Digest,
};

pub const COMPONENT_OVERRIDE_TABLE_V2 = [_]ComponentOverrideV2{
    overrideFor(PublicationHeader, 12),
    overrideFor(NativePublicSums, 13),
    overrideFor(PublicationSeal, 14),
    overrideFor(StatementBoundary, 15),
    overrideFor(NativeChallenges, 16),
    overrideFor(ControlRelay, 17),
};

pub fn Relay(comptime config: Config) type {
    comptime {
        if (config.source_arity == 0 or config.source_arity > 6 or
            config.value_position >= config.source_arity)
        {
            @compileError("invalid V2 public relay source geometry");
        }
        if (relation.universalDescriptor(config.source_domain).arity !=
            config.source_arity)
        {
            @compileError("V2 public relay source ABI drifted");
        }
    }

    return struct {
        const Self = @This();

        pub const STABLE_NAME = config.stable_name;
        pub const PHYSICAL_MAIN_COLUMN_COUNT = RELAY_MAIN_COLUMN_COUNT;
        pub const PREPROCESSED_COLUMN_COUNT = RELAY_PREPROCESSED_COLUMN_COUNT;
        pub const LOGICAL_INPUT_COUNT = RELAY_LOGICAL_INPUT_COUNT;
        pub const DIRECT_CONSTRAINT_COUNT = RELAY_DIRECT_CONSTRAINT_COUNT;
        pub const RELATION_EVENT_COUNT = RELAY_RELATION_EVENT_COUNT;
        pub const LOOKUP_BATCH_SIZE = RELAY_LOOKUP_BATCH_SIZE;
        pub const INTERACTION_BATCH_COUNT = RELAY_INTERACTION_BATCH_COUNT;
        pub const INTERACTION_COLUMN_COUNT = RELAY_INTERACTION_COLUMN_COUNT;
        pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE =
            RELAY_REFERENCE_MAXIMUM_CONSTRAINT_DEGREE;
        pub const MAXIMUM_CONSTRAINT_DEGREE =
            RELAY_MAXIMUM_CONSTRAINT_DEGREE;
        pub const SEMANTIC_DIGEST = config.semantic_digest;

        pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
            InvalidSegmentPublicRelayDefinition,
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

            pub fn validate(self: *const Definition) ValidationError!void {
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
                    return error.InvalidSegmentPublicRelayDefinition;
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
                    &.{ 0, 1, 2 },
                );
                try validateInputs(
                    &self.arena,
                    &self.parameters.physical(),
                    &PARAMETER_NAMES,
                    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
                    &.{},
                );
                for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
                    constraint_id,
                    root,
                    name,
                    index,
                | {
                    const constraint = self.arena.constraint(constraint_id) orelse
                        return error.InvalidSegmentPublicRelayDefinition;
                    const actual_name = self.arena.name(constraint.name) orelse
                        return error.InvalidSegmentPublicRelayDefinition;
                    if (types.idIndex(constraint_id) != index or
                        constraint.root != root or constraint.gate != null or
                        constraint.category != .semantic or
                        !std.mem.eql(u8, actual_name, name))
                    {
                        return error.InvalidSegmentPublicRelayDefinition;
                    }
                }
                const tuples = sourceAndWireTuples(
                    self.preprocessed,
                    self.main,
                    self.parameters,
                );
                try validateEvent(
                    self,
                    0,
                    config.source_domain,
                    .consume,
                    self.preprocessed.row_mask,
                    tuples.source[0..config.source_arity],
                );
                try validateEvent(
                    self,
                    1,
                    .recursion_wire,
                    .emit,
                    self.arithmetic_weight,
                    &tuples.arithmetic,
                );
                try validateEvent(
                    self,
                    2,
                    .recursion_wire,
                    .emit,
                    self.control_weight,
                    &tuples.control,
                );
            }
        };

        pub fn build(allocator: std.mem.Allocator) !Definition {
            var result = try buildDefinition(allocator);
            errdefer result.deinit();
            try result.validate();
            return result;
        }

        pub fn semanticIdentity(
            allocator: std.mem.Allocator,
        ) !digest.Identity {
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
            };
            var preprocessing: [Self.PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
            for (&preprocessing, PREPROCESSED_COLUMN_NAMES, 0..) |
                *value,
                name,
                index,
            | value.* = try arena.input(
                name,
                if (index <= 2) .selector else .felt,
                span,
            );
            const preprocessed = PreprocessedColumns{
                .row_mask = preprocessing[0],
                .arithmetic_mask = preprocessing[1],
                .control_mask = preprocessing[2],
                .source_fields = preprocessing[3..8].*,
                .arithmetic_circuit_id = preprocessing[8],
                .arithmetic_node_id = preprocessing[9],
                .arithmetic_use_count = preprocessing[10],
                .control_circuit_id = preprocessing[11],
                .control_node_id = preprocessing[12],
                .control_use_count = preprocessing[13],
            };
            const parameters = Parameters{
                .zero = try arena.input(PARAMETER_NAMES[0], .felt, span),
            };
            const one = try arena.constantField(1, span);
            const inactive = try arena.sub(one, preprocessed.row_mask, span);
            const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
                try arena.sub(main.enabler, preprocessed.row_mask, span),
                try arena.mul(inactive, main.value, span),
                try arena.mul(preprocessed.arithmetic_mask, inactive, span),
                try arena.mul(preprocessed.control_mask, inactive, span),
                try arena.mul(
                    preprocessed.arithmetic_mask,
                    preprocessed.control_mask,
                    span,
                ),
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
                preprocessed.arithmetic_mask,
                preprocessed.arithmetic_use_count,
                span,
            );
            const control_weight = try arena.mul(
                preprocessed.control_mask,
                preprocessed.control_use_count,
                span,
            );
            const tuples = sourceAndWireTuples(preprocessed, main, parameters);
            const events = try relation_effect.appendGroup(
                RELATION_EVENT_COUNT,
                &arena,
                .{
                    .{
                        .domain = config.source_domain,
                        .role = .consume,
                        .values = tuples.source[0..config.source_arity],
                        .weight = preprocessed.row_mask,
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

        const Tuples = struct {
            source: [6]types.ValueId,
            arithmetic: [6]types.ValueId,
            control: [6]types.ValueId,
        };

        fn sourceAndWireTuples(
            preprocessed: PreprocessedColumns,
            main: MainColumns,
            parameters: Parameters,
        ) Tuples {
            var source_tuple = [_]types.ValueId{parameters.zero} ** 6;
            var field: usize = 0;
            inline for (0..config.source_arity) |index| {
                if (index == config.value_position) {
                    source_tuple[index] = main.value;
                } else {
                    source_tuple[index] = preprocessed.source_fields[field];
                    field += 1;
                }
            }
            return .{
                .source = source_tuple,
                .arithmetic = .{
                    preprocessed.arithmetic_circuit_id,
                    preprocessed.arithmetic_node_id,
                    main.value,
                    parameters.zero,
                    parameters.zero,
                    parameters.zero,
                },
                .control = .{
                    preprocessed.control_circuit_id,
                    preprocessed.control_node_id,
                    main.value,
                    parameters.zero,
                    parameters.zero,
                    parameters.zero,
                },
            };
        }
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidSegmentPublicRelayDefinition}!void {
    if (values.len != names.len)
        return error.InvalidSegmentPublicRelayDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidSegmentPublicRelayDefinition;
        const node = arena.node(value) orelse
            return error.InvalidSegmentPublicRelayDefinition;
        var expected: types.Type = .felt;
        for (selector_indices) |index| if (index == local_index) {
            expected = .selector;
            break;
        };
        if (!std.meta.eql(node.key.ty, expected))
            return error.InvalidSegmentPublicRelayDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidSegmentPublicRelayDefinition,
        };
        const actual = arena.name(name_id) orelse
            return error.InvalidSegmentPublicRelayDefinition;
        if (!std.mem.eql(u8, actual, name))
            return error.InvalidSegmentPublicRelayDefinition;
    }
}

fn validateEvent(
    definition: anytype,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    weight: types.ValueId,
    tuple: []const types.ValueId,
) error{InvalidSegmentPublicRelayDefinition}!void {
    const effect_id = definition.events[index];
    const effect = definition.arena.effect(effect_id) orelse
        return error.InvalidSegmentPublicRelayDefinition;
    const binding = effect.binding orelse
        return error.InvalidSegmentPublicRelayDefinition;
    const schema = relation.get(domain);
    const values = definition.arena.effectValues(effect_id) orelse
        return error.InvalidSegmentPublicRelayDefinition;
    if (types.idIndex(effect_id) != index or
        effect.kind != .component_call or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        effect.liveness != weight or effect.access_ordinal != null or
        !std.mem.eql(types.ValueId, values, tuple))
    {
        return error.InvalidSegmentPublicRelayDefinition;
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

fn overrideFor(
    comptime ComponentAir: type,
    comptime component_index: u8,
) ComponentOverrideV2 {
    return .{
        .component_index = component_index,
        .activation = .active_v2_override,
        .preprocessed_columns = ComponentAir.PREPROCESSED_COLUMN_COUNT,
        .main_columns = ComponentAir.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = ComponentAir.INTERACTION_COLUMN_COUNT,
        .direct_constraints = ComponentAir.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = ComponentAir.INTERACTION_BATCH_COUNT,
        .relation_events = ComponentAir.RELATION_EVENT_COUNT,
        .protocol_constraint_degree = ComponentAir.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = ComponentAir.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = ComponentAir.SEMANTIC_DIGEST,
    };
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 2 or
        RELAY_INTERACTION_COLUMN_COUNT != 4 * RELAY_INTERACTION_BATCH_COUNT or
        COMPONENT_OVERRIDE_TABLE_V2.len != 6 or
        COMPONENT_OVERRIDE_TABLE_V2[0].component_index != 12 or
        COMPONENT_OVERRIDE_TABLE_V2[5].component_index != 17)
    {
        @compileError("V2 public relay AIR geometry drifted");
    }
}
