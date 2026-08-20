//! Internal segment leaf outer air v2 authority shard; use segment_leaf_outer_air_v2.zig publicly.

const dependency_0 = @import("segment_leaf_outer_air_v2_contract.zig");
const dependency_1 = @import("segment_leaf_outer_air_v2_public_log_up.zig");

const Statement = dependency_0.Statement;
const constantValue = dependency_0.constantValue;
const digest = dependency_0.digest;
const hexDigest = dependency_0.hexDigest;
const ir = dependency_0.ir;
const relation_effect = dependency_0.relation_effect;
const relation_interaction = dependency_0.relation_interaction;
const source = dependency_0.source;
const std = dependency_0.std;
const transcript_payload = dependency_0.transcript_payload;
const types = dependency_0.types;
const validateEffect = dependency_0.validateEffect;
const validateNamedInput = dependency_1.validateNamedInput;
const validate_mod = dependency_0.validate_mod;

/// Versioned row-11 consumer for a resumed-segment statement.
///
/// The appended V2 boundary `Statement` source owns the statement-word
/// emission that frozen row 10 used to perform, so this component consumes it
/// directly and never re-emits the same tuple. In the same row it consumes
/// every ProgramV2 statement payload:
///
/// * item 0: the eight verifier-owned statement-header limbs;
/// * item 1: the sixteen limbs of the eight-word wire identity;
/// * item 2: every canonical wire word.
///
/// The wire-identity limbs are range checked and recombined against the exact
/// `CONTEXT_SCOPE` digest words. Structurally encoded u16 wire words are also
/// range checked. Full wire-hash and statement-authority sponge closure are a
/// separate, explicitly fail-closed capability of the outer driver.
pub const StatementSemanticsV2 = struct {
    pub const STABLE_NAME = "recursion.segment_leaf_v2.statement_semantics.v2";
    pub const TRANSCRIPT_VERIFIER_ID: u32 = 0;
    pub const TRANSCRIPT_STATEMENT_KIND: u32 =
        @intFromEnum(transcript_payload.VerifierInputKind.statement);
    pub const HEADER_ITEM: u32 = 0;
    pub const WIRE_ID_ITEM: u32 = 1;
    pub const WIRE_WORD_ITEM: u32 = 2;
    /// Disjoint recursion-wire namespace consumed by V2 public-spine row 15.
    /// Circuit 44 remains owned by the source-37 publication lane.
    pub const BOUNDARY_BRIDGE_CIRCUIT_ID: u32 = 45;

    pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 10;
    pub const PREPROCESSED_COLUMN_COUNT: usize = 16;
    pub const PARAMETER_COUNT: usize = 0;
    pub const LOGICAL_INPUT_COUNT: usize =
        PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
    pub const DIRECT_CONSTRAINT_COUNT: usize = 15;
    pub const RELATION_EVENT_COUNT: usize = 7;
    pub const LOOKUP_BATCH_SIZE: u8 = 2;
    pub const INTERACTION_BATCH_COUNT: usize = 4;
    pub const INTERACTION_COLUMN_COUNT: usize = 16;
    pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
    pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

    // Regenerated from the typed IR by the focused source test. This value is
    // deliberately pinned before the component can be authenticated.
    pub const SEMANTIC_DIGEST_HEX =
        "4af9b4d32b2f77041729ab8fc458bf845d39a1246984b54878a7cc9ce33f6915";
    pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
        SEMANTIC_DIGEST_HEX,
        "invalid V2 statement-semantics digest",
    );

    pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
        "recursion.segment_leaf_v2.statement_semantics.enabler",
        "recursion.segment_leaf_v2.statement_semantics.source_value",
        "recursion.segment_leaf_v2.statement_semantics.verifier_a",
        "recursion.segment_leaf_v2.statement_semantics.verifier_b",
        "recursion.segment_leaf_v2.statement_semantics.source_low_byte",
        "recursion.segment_leaf_v2.statement_semantics.source_high_byte",
        "recursion.segment_leaf_v2.statement_semantics.verifier_a_low_byte",
        "recursion.segment_leaf_v2.statement_semantics.verifier_a_high_byte",
        "recursion.segment_leaf_v2.statement_semantics.verifier_b_low_byte",
        "recursion.segment_leaf_v2.statement_semantics.verifier_b_high_byte",
    };
    pub const PREPROCESSED_COLUMN_NAMES =
        [PREPROCESSED_COLUMN_COUNT][]const u8{
            "recursion_segment_leaf_v2_statement_semantics_row_mask",
            "recursion_segment_leaf_v2_statement_semantics_source_mask",
            "recursion_segment_leaf_v2_statement_semantics_verifier_a_mask",
            "recursion_segment_leaf_v2_statement_semantics_verifier_b_mask",
            "recursion_segment_leaf_v2_statement_semantics_header_mask",
            "recursion_segment_leaf_v2_statement_semantics_recombine_mask",
            "recursion_segment_leaf_v2_statement_semantics_source_u16_mask",
            "recursion_segment_leaf_v2_statement_semantics_verifier_a_u16_mask",
            "recursion_segment_leaf_v2_statement_semantics_verifier_b_u16_mask",
            "recursion_segment_leaf_v2_statement_semantics_source_scope",
            "recursion_segment_leaf_v2_statement_semantics_source_index",
            "recursion_segment_leaf_v2_statement_semantics_verifier_item",
            "recursion_segment_leaf_v2_statement_semantics_verifier_a_index",
            "recursion_segment_leaf_v2_statement_semantics_verifier_b_index",
            "recursion_segment_leaf_v2_statement_semantics_expected_header",
            "recursion_segment_leaf_v2_statement_semantics_boundary_bridge_mask",
        };
    pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
        "recursion.segment_leaf_v2.statement_semantics.enabler_matches_row_mask",
        "recursion.segment_leaf_v2.statement_semantics.inactive_source_zero",
        "recursion.segment_leaf_v2.statement_semantics.inactive_verifier_a_zero",
        "recursion.segment_leaf_v2.statement_semantics.inactive_verifier_b_zero",
        "recursion.segment_leaf_v2.statement_semantics.header_value",
        "recursion.segment_leaf_v2.statement_semantics.wire_id_recombination",
        "recursion.segment_leaf_v2.statement_semantics.source_u16_decomposition",
        "recursion.segment_leaf_v2.statement_semantics.verifier_a_u16_decomposition",
        "recursion.segment_leaf_v2.statement_semantics.verifier_b_u16_decomposition",
        "recursion.segment_leaf_v2.statement_semantics.inactive_source_low_byte_zero",
        "recursion.segment_leaf_v2.statement_semantics.inactive_source_high_byte_zero",
        "recursion.segment_leaf_v2.statement_semantics.inactive_verifier_a_low_byte_zero",
        "recursion.segment_leaf_v2.statement_semantics.inactive_verifier_a_high_byte_zero",
        "recursion.segment_leaf_v2.statement_semantics.inactive_verifier_b_low_byte_zero",
        "recursion.segment_leaf_v2.statement_semantics.inactive_verifier_b_high_byte_zero",
    };

    pub const MainColumns = struct {
        enabler: types.ValueId,
        source_value: types.ValueId,
        verifier_a: types.ValueId,
        verifier_b: types.ValueId,
        source_low_byte: types.ValueId,
        source_high_byte: types.ValueId,
        verifier_a_low_byte: types.ValueId,
        verifier_a_high_byte: types.ValueId,
        verifier_b_low_byte: types.ValueId,
        verifier_b_high_byte: types.ValueId,

        pub fn physical(
            self: MainColumns,
        ) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
            return .{
                self.enabler,
                self.source_value,
                self.verifier_a,
                self.verifier_b,
                self.source_low_byte,
                self.source_high_byte,
                self.verifier_a_low_byte,
                self.verifier_a_high_byte,
                self.verifier_b_low_byte,
                self.verifier_b_high_byte,
            };
        }
    };

    pub const PreprocessedColumns = struct {
        row_mask: types.ValueId,
        source_mask: types.ValueId,
        verifier_a_mask: types.ValueId,
        verifier_b_mask: types.ValueId,
        header_mask: types.ValueId,
        recombine_mask: types.ValueId,
        source_u16_mask: types.ValueId,
        verifier_a_u16_mask: types.ValueId,
        verifier_b_u16_mask: types.ValueId,
        source_scope: types.ValueId,
        source_index: types.ValueId,
        verifier_item: types.ValueId,
        verifier_a_index: types.ValueId,
        verifier_b_index: types.ValueId,
        expected_header: types.ValueId,
        boundary_bridge_mask: types.ValueId,

        pub fn physical(
            self: PreprocessedColumns,
        ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
            return .{
                self.row_mask,
                self.source_mask,
                self.verifier_a_mask,
                self.verifier_b_mask,
                self.header_mask,
                self.recombine_mask,
                self.source_u16_mask,
                self.verifier_a_u16_mask,
                self.verifier_b_u16_mask,
                self.source_scope,
                self.source_index,
                self.verifier_item,
                self.verifier_a_index,
                self.verifier_b_index,
                self.expected_header,
                self.boundary_bridge_mask,
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
                self.arena.effectsView().len != RELATION_EVENT_COUNT or
                self.arena.hints.items.len != 0 or
                self.arena.functions.items.len != 0 or
                self.arena.calls.items.len != 0 or
                self.arena.range_refinements.items.len != 0 or
                self.arena.fixed_table_requests.items.len != 0)
            {
                return error.InvalidDefinition;
            }
            try validateRoutingInputs(self);
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
            const verifier = constantValue(
                &self.arena,
                TRANSCRIPT_VERIFIER_ID,
            ) orelse return error.InvalidDefinition;
            const kind = constantValue(
                &self.arena,
                TRANSCRIPT_STATEMENT_KIND,
            ) orelse return error.InvalidDefinition;
            const source_tuple = [_]types.ValueId{
                self.preprocessed.source_scope,
                self.preprocessed.source_index,
                self.main.source_value,
            };
            const verifier_a_tuple = [_]types.ValueId{
                verifier,
                kind,
                self.preprocessed.verifier_item,
                self.preprocessed.verifier_a_index,
                self.main.verifier_a,
            };
            const verifier_b_tuple = [_]types.ValueId{
                verifier,
                kind,
                self.preprocessed.verifier_item,
                self.preprocessed.verifier_b_index,
                self.main.verifier_b,
            };
            const source_range = [_]types.ValueId{
                self.main.source_low_byte,
                self.main.source_high_byte,
            };
            const verifier_a_range = [_]types.ValueId{
                self.main.verifier_a_low_byte,
                self.main.verifier_a_high_byte,
            };
            const verifier_b_range = [_]types.ValueId{
                self.main.verifier_b_low_byte,
                self.main.verifier_b_high_byte,
            };
            const zero = constantValue(&self.arena, 0) orelse
                return error.InvalidDefinition;
            const bridge_circuit = constantValue(
                &self.arena,
                BOUNDARY_BRIDGE_CIRCUIT_ID,
            ) orelse return error.InvalidDefinition;
            const boundary_bridge_tuple = [_]types.ValueId{
                bridge_circuit,
                self.preprocessed.source_index,
                self.main.source_value,
                zero,
                zero,
                zero,
            };
            try validateEffect(
                &self.arena,
                self.events[0],
                0,
                .recursion_statement_word,
                .consume,
                self.preprocessed.source_mask,
                &source_tuple,
            );
            try validateEffect(
                &self.arena,
                self.events[1],
                1,
                .recursion_verifier_input_word,
                .consume,
                self.preprocessed.verifier_a_mask,
                &verifier_a_tuple,
            );
            try validateEffect(
                &self.arena,
                self.events[2],
                2,
                .recursion_verifier_input_word,
                .consume,
                self.preprocessed.verifier_b_mask,
                &verifier_b_tuple,
            );
            try validateEffect(
                &self.arena,
                self.events[3],
                3,
                .range_check_8_8,
                .request,
                self.preprocessed.source_u16_mask,
                &source_range,
            );
            try validateEffect(
                &self.arena,
                self.events[4],
                4,
                .range_check_8_8,
                .request,
                self.preprocessed.verifier_a_u16_mask,
                &verifier_a_range,
            );
            try validateEffect(
                &self.arena,
                self.events[5],
                5,
                .range_check_8_8,
                .request,
                self.preprocessed.verifier_b_u16_mask,
                &verifier_b_range,
            );
            try validateEffect(
                &self.arena,
                self.events[6],
                6,
                .recursion_wire,
                .emit,
                self.preprocessed.boundary_bridge_mask,
                &boundary_bridge_tuple,
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
        var main_values: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
        for (&main_values, MAIN_COLUMN_NAMES, 0..) |*value, name, index|
            value.* = try arena.input(
                name,
                if (index == 0) .selector else if (index >= 4) .byte else .felt,
                span,
            );
        const main = MainColumns{
            .enabler = main_values[0],
            .source_value = main_values[1],
            .verifier_a = main_values[2],
            .verifier_b = main_values[3],
            .source_low_byte = main_values[4],
            .source_high_byte = main_values[5],
            .verifier_a_low_byte = main_values[6],
            .verifier_a_high_byte = main_values[7],
            .verifier_b_low_byte = main_values[8],
            .verifier_b_high_byte = main_values[9],
        };
        var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
        for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |
            *value,
            name,
            index,
        | value.* = try arena.input(
            name,
            if (index < 9 or index == 15) .selector else .felt,
            span,
        );
        const preprocessed = PreprocessedColumns{
            .row_mask = preprocessed_values[0],
            .source_mask = preprocessed_values[1],
            .verifier_a_mask = preprocessed_values[2],
            .verifier_b_mask = preprocessed_values[3],
            .header_mask = preprocessed_values[4],
            .recombine_mask = preprocessed_values[5],
            .source_u16_mask = preprocessed_values[6],
            .verifier_a_u16_mask = preprocessed_values[7],
            .verifier_b_u16_mask = preprocessed_values[8],
            .source_scope = preprocessed_values[9],
            .source_index = preprocessed_values[10],
            .verifier_item = preprocessed_values[11],
            .verifier_a_index = preprocessed_values[12],
            .verifier_b_index = preprocessed_values[13],
            .expected_header = preprocessed_values[14],
            .boundary_bridge_mask = preprocessed_values[15],
        };
        const one = try arena.constantField(1, span);
        const byte_radix = try arena.constantField(256, span);
        const limb_radix = try arena.constantField(1 << 16, span);
        const inactive_source = try arena.sub(one, preprocessed.source_mask, span);
        const inactive_a = try arena.sub(one, preprocessed.verifier_a_mask, span);
        const inactive_b = try arena.sub(one, preprocessed.verifier_b_mask, span);
        const inactive_source_u16 = try arena.sub(one, preprocessed.source_u16_mask, span);
        const inactive_a_u16 = try arena.sub(one, preprocessed.verifier_a_u16_mask, span);
        const inactive_b_u16 = try arena.sub(one, preprocessed.verifier_b_u16_mask, span);
        const source_decomposition = try arena.add(
            main.source_low_byte,
            try arena.mul(byte_radix, main.source_high_byte, span),
            span,
        );
        const a_decomposition = try arena.add(
            main.verifier_a_low_byte,
            try arena.mul(byte_radix, main.verifier_a_high_byte, span),
            span,
        );
        const b_decomposition = try arena.add(
            main.verifier_b_low_byte,
            try arena.mul(byte_radix, main.verifier_b_high_byte, span),
            span,
        );
        const recombined = try arena.add(
            main.verifier_a,
            try arena.mul(limb_radix, main.verifier_b, span),
            span,
        );
        const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
            try arena.sub(main.enabler, preprocessed.row_mask, span),
            try arena.mul(inactive_source, main.source_value, span),
            try arena.mul(inactive_a, main.verifier_a, span),
            try arena.mul(inactive_b, main.verifier_b, span),
            try arena.mul(
                preprocessed.header_mask,
                try arena.sub(main.verifier_a, preprocessed.expected_header, span),
                span,
            ),
            try arena.mul(
                preprocessed.recombine_mask,
                try arena.sub(main.source_value, recombined, span),
                span,
            ),
            try arena.mul(
                preprocessed.source_u16_mask,
                try arena.sub(main.source_value, source_decomposition, span),
                span,
            ),
            try arena.mul(
                preprocessed.verifier_a_u16_mask,
                try arena.sub(main.verifier_a, a_decomposition, span),
                span,
            ),
            try arena.mul(
                preprocessed.verifier_b_u16_mask,
                try arena.sub(main.verifier_b, b_decomposition, span),
                span,
            ),
            try arena.mul(inactive_source_u16, main.source_low_byte, span),
            try arena.mul(inactive_source_u16, main.source_high_byte, span),
            try arena.mul(inactive_a_u16, main.verifier_a_low_byte, span),
            try arena.mul(inactive_a_u16, main.verifier_a_high_byte, span),
            try arena.mul(inactive_b_u16, main.verifier_b_low_byte, span),
            try arena.mul(inactive_b_u16, main.verifier_b_high_byte, span),
        };
        var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
        for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
            constraint.* = try arena.assertZero(name, root, null, .semantic, span);

        const verifier = try arena.constantField(TRANSCRIPT_VERIFIER_ID, span);
        const kind = try arena.constantField(TRANSCRIPT_STATEMENT_KIND, span);
        const source_tuple = [_]types.ValueId{
            preprocessed.source_scope,
            preprocessed.source_index,
            main.source_value,
        };
        const verifier_a_tuple = [_]types.ValueId{
            verifier,
            kind,
            preprocessed.verifier_item,
            preprocessed.verifier_a_index,
            main.verifier_a,
        };
        const verifier_b_tuple = [_]types.ValueId{
            verifier,
            kind,
            preprocessed.verifier_item,
            preprocessed.verifier_b_index,
            main.verifier_b,
        };
        const source_range = [_]types.ValueId{
            main.source_low_byte,
            main.source_high_byte,
        };
        const verifier_a_range = [_]types.ValueId{
            main.verifier_a_low_byte,
            main.verifier_a_high_byte,
        };
        const verifier_b_range = [_]types.ValueId{
            main.verifier_b_low_byte,
            main.verifier_b_high_byte,
        };
        const bridge_circuit = try arena.constantField(
            BOUNDARY_BRIDGE_CIRCUIT_ID,
            span,
        );
        const zero = try arena.constantField(0, span);
        const boundary_bridge_tuple = [_]types.ValueId{
            bridge_circuit,
            preprocessed.source_index,
            main.source_value,
            zero,
            zero,
            zero,
        };
        const events = [RELATION_EVENT_COUNT]types.EffectId{
            try relation_effect.append(&arena, .{
                .domain = .recursion_statement_word,
                .role = .consume,
                .values = &source_tuple,
                .weight = preprocessed.source_mask,
            }, span),
            try relation_effect.append(&arena, .{
                .domain = .recursion_verifier_input_word,
                .role = .consume,
                .values = &verifier_a_tuple,
                .weight = preprocessed.verifier_a_mask,
            }, span),
            try relation_effect.append(&arena, .{
                .domain = .recursion_verifier_input_word,
                .role = .consume,
                .values = &verifier_b_tuple,
                .weight = preprocessed.verifier_b_mask,
            }, span),
            try relation_effect.append(&arena, .{
                .domain = .range_check_8_8,
                .role = .request,
                .values = &source_range,
                .weight = preprocessed.source_u16_mask,
            }, span),
            try relation_effect.append(&arena, .{
                .domain = .range_check_8_8,
                .role = .request,
                .values = &verifier_a_range,
                .weight = preprocessed.verifier_a_u16_mask,
            }, span),
            try relation_effect.append(&arena, .{
                .domain = .range_check_8_8,
                .role = .request,
                .values = &verifier_b_range,
                .weight = preprocessed.verifier_b_u16_mask,
            }, span),
            try relation_effect.append(&arena, .{
                .domain = .recursion_wire,
                .role = .emit,
                .values = &boundary_bridge_tuple,
                .weight = preprocessed.boundary_bridge_mask,
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

    fn validateRoutingInputs(definition: *const Definition) !void {
        for (definition.main.physical(), MAIN_COLUMN_NAMES, 0..) |
            value,
            expected_name,
            index,
        | try validateNamedInput(
            &definition.arena,
            value,
            expected_name,
            index,
            if (index == 0) .selector else if (index >= 4) .byte else .felt,
        );
        for (
            definition.preprocessed.physical(),
            PREPROCESSED_COLUMN_NAMES,
            0..,
        ) |value, expected_name, local_index| try validateNamedInput(
            &definition.arena,
            value,
            expected_name,
            PHYSICAL_MAIN_COLUMN_COUNT + local_index,
            if (local_index < 9 or local_index == 15) .selector else .felt,
        );
    }
};
