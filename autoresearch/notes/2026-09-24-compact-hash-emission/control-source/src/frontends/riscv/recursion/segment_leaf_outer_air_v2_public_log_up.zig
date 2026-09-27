//! Internal segment leaf outer air v2 authority shard; use segment_leaf_outer_air_v2.zig publicly.

const dependency_0 = @import("segment_leaf_outer_air_v2_contract.zig");

const constantValue = dependency_0.constantValue;
const digest = dependency_0.digest;
const hexDigest = dependency_0.hexDigest;
const ir = dependency_0.ir;
const relation_effect = dependency_0.relation_effect;
const relation_interaction = dependency_0.relation_interaction;
const source = dependency_0.source;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const types = dependency_0.types;
const validateEffect = dependency_0.validateEffect;
const validateInputs = dependency_0.validateInputs;
const validate_mod = dependency_0.validate_mod;

pub const PublicLogUp = struct {
    pub const STABLE_NAME = "recursion.segment_leaf_v2.public_logup_source.v2";
    pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
    pub const PREPROCESSED_COLUMN_COUNT: usize = 2;
    pub const PARAMETER_COUNT: usize = 0;
    pub const LOGICAL_INPUT_COUNT: usize =
        PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
    pub const DIRECT_CONSTRAINT_COUNT: usize = 3;
    pub const RELATION_EVENT_COUNT: usize = 2;
    pub const LOOKUP_BATCH_SIZE: u8 = 2;
    pub const INTERACTION_BATCH_COUNT: usize = 1;
    pub const INTERACTION_COLUMN_COUNT: usize = 4;
    pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
    pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

    pub const SEMANTIC_DIGEST_HEX =
        "9ae005cf8fbb6e7f28deb8582556dd7835a031c541971a7264d439a37f6a4613";
    pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
        SEMANTIC_DIGEST_HEX,
        "invalid segment-leaf V2 public-LogUp semantic digest",
    );

    pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
        "recursion.segment_leaf_v2.public_logup_source.value",
    };
    pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
        "recursion_segment_leaf_v2_public_logup_source_active",
        "recursion_segment_leaf_v2_public_logup_source_index",
    };
    pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
        "recursion.segment_leaf_v2.public_logup_source.active_boolean",
        "recursion.segment_leaf_v2.public_logup_source.inactive_index_zero",
        "recursion.segment_leaf_v2.public_logup_source.inactive_value_zero",
    };

    pub const MainColumns = struct {
        value: types.ValueId,

        pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
            return .{self.value};
        }
    };

    pub const PreprocessedColumns = struct {
        active: types.ValueId,
        index: types.ValueId,

        pub fn physical(
            self: PreprocessedColumns,
        ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
            return .{ self.active, self.index };
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
            const verifier = constantValue(
                &self.arena,
                source_v2.SEGMENT_V2_VERIFIER_ID,
            ) orelse return error.InvalidDefinition;
            const kind = constantValue(
                &self.arena,
                source_v2.PUBLIC_LOGUP_V2_KIND,
            ) orelse return error.InvalidDefinition;
            const zero = constantValue(&self.arena, 0) orelse
                return error.InvalidDefinition;
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
                return error.InvalidDefinition;
            }
            try validateInputs(
                &self.arena,
                &self.main.physical(),
                &MAIN_COLUMN_NAMES,
                0,
                null,
            );
            try validateInputs(
                &self.arena,
                &self.preprocessed.physical(),
                &PREPROCESSED_COLUMN_NAMES,
                PHYSICAL_MAIN_COLUMN_COUNT,
                0,
            );
            for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
                constraint_id,
                root,
                expected_name,
                index,
            | {
                const item = self.arena.constraint(constraint_id) orelse
                    return error.InvalidDefinition;
                const actual_name = self.arena.name(item.name) orelse
                    return error.InvalidDefinition;
                if (types.idIndex(constraint_id) != index or item.root != root or
                    item.gate != null or item.category != .semantic or
                    !std.mem.eql(u8, actual_name, expected_name))
                {
                    return error.InvalidDefinition;
                }
            }
            const input_tuple = [_]types.ValueId{
                verifier,
                kind,
                self.preprocessed.index,
                zero,
                self.main.value,
            };
            try validateEffect(
                &self.arena,
                self.events[0],
                0,
                .recursion_verifier_input_word,
                .consume,
                self.preprocessed.active,
                &input_tuple,
            );
            const bridge_circuit = constantValue(
                &self.arena,
                source_v2.PUBLICATION_BRIDGE_CIRCUIT_ID,
            ) orelse return error.InvalidDefinition;
            const bridge_tuple = [_]types.ValueId{
                bridge_circuit,
                self.preprocessed.index,
                self.main.value,
                zero,
                zero,
                zero,
            };
            try validateEffect(
                &self.arena,
                self.events[1],
                1,
                .recursion_wire,
                .emit,
                self.preprocessed.active,
                &bridge_tuple,
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

    pub fn logicalRow(
        value: @import("stwo_core").fields.m31.M31,
        active: @import("stwo_core").fields.m31.M31,
        index: @import("stwo_core").fields.m31.M31,
    ) Row {
        return .{ value, active, index };
    }

    fn buildRaw(allocator: std.mem.Allocator) !Definition {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const span = source.SourceSpan.generated();
        const main = MainColumns{
            .value = try arena.input(MAIN_COLUMN_NAMES[0], .felt, span),
        };
        const preprocessed = PreprocessedColumns{
            .active = try arena.input(PREPROCESSED_COLUMN_NAMES[0], .selector, span),
            .index = try arena.input(PREPROCESSED_COLUMN_NAMES[1], .felt, span),
        };
        const one = try arena.constantField(1, span);
        const inactive = try arena.sub(one, preprocessed.active, span);
        const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
            try arena.mul(
                preprocessed.active,
                try arena.sub(preprocessed.active, one, span),
                span,
            ),
            try arena.mul(inactive, preprocessed.index, span),
            try arena.mul(inactive, main.value, span),
        };
        var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
        for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
            constraint.* = try arena.assertZero(name, root, null, .semantic, span);
        const verifier = try arena.constantField(source_v2.SEGMENT_V2_VERIFIER_ID, span);
        const kind = try arena.constantField(source_v2.PUBLIC_LOGUP_V2_KIND, span);
        const bridge_circuit = try arena.constantField(
            source_v2.PUBLICATION_BRIDGE_CIRCUIT_ID,
            span,
        );
        const zero = try arena.constantField(0, span);
        const input_tuple = [_]types.ValueId{
            verifier,
            kind,
            preprocessed.index,
            zero,
            main.value,
        };
        const bridge_tuple = [_]types.ValueId{
            bridge_circuit,
            preprocessed.index,
            main.value,
            zero,
            zero,
            zero,
        };
        const events = try relation_effect.appendGroup(
            RELATION_EVENT_COUNT,
            &arena,
            .{
                .{
                    .domain = .recursion_verifier_input_word,
                    .role = .consume,
                    .values = &input_tuple,
                    .weight = preprocessed.active,
                },
                .{
                    .domain = .recursion_wire,
                    .role = .emit,
                    .values = &bridge_tuple,
                    .weight = preprocessed.active,
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
};

pub fn validateNamedInput(
    arena: *const ir.Arena,
    value: types.ValueId,
    expected_name: []const u8,
    expected_index: usize,
    expected_type: types.Type,
) !void {
    if (types.idIndex(value) != expected_index)
        return error.InvalidDefinition;
    const node = arena.node(value) orelse return error.InvalidDefinition;
    if (!std.meta.eql(node.key.ty, expected_type))
        return error.InvalidDefinition;
    const name_id = switch (node.key.op) {
        .input => |input_name| input_name,
        else => return error.InvalidDefinition,
    };
    const actual_name = arena.name(name_id) orelse
        return error.InvalidDefinition;
    if (!std.mem.eql(u8, actual_name, expected_name))
        return error.InvalidDefinition;
}
