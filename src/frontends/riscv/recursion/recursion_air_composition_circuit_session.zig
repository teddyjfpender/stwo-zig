//! Internal recursion air composition circuit authority shard; use recursion_air_composition_circuit.zig publicly.

const dependency_0 = @import("recursion_air_composition_circuit_contract.zig");

const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const COMPOSITION_TREE_INDEX = dependency_0.COMPOSITION_TREE_INDEX;
const CaptureLayout = dependency_0.CaptureLayout;
const Circuit = dependency_0.Circuit;
const Error = dependency_0.Error;
const KindState = dependency_0.KindState;
const M31 = dependency_0.M31;
const POSEIDON_AUX_START = dependency_0.POSEIDON_AUX_START;
const ProgramStatistics = dependency_0.ProgramStatistics;
const RELATION_CHALLENGE_COUNT = dependency_0.RELATION_CHALLENGE_COUNT;
const ROSTER_CLAIM_COUNT = dependency_0.ROSTER_CLAIM_COUNT;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const advanceProviderState = dependency_0.advanceProviderState;
const circle = dependency_0.circle;
const circuitDigest = dependency_0.circuitDigest;
const graph_mod = dependency_0.graph_mod;
const m31 = dependency_0.m31;
const manifest_mod = dependency_0.manifest_mod;
const poseidon_air = dependency_0.poseidon_air;
const qm31 = dependency_0.qm31;
const recorder = dependency_0.recorder;
const relation = dependency_0.relation;
const roster = dependency_0.roster;
const shared_provider = dependency_0.shared_provider;
const shared_provider_composition = dependency_0.shared_provider_composition;
const span_statement = dependency_0.span_statement;
const statement_input = dependency_0.statement_input;
const std = dependency_0.std;
const takeSecure = dependency_0.takeSecure;
const universal = dependency_0.universal;
const verifier_types = dependency_0.verifier_types;

/// Cold graph-construction transaction.  It must stay at a stable address
/// while active because the generic recorder installs its builder thread-locally.
pub const Session = struct {
    allocator: std.mem.Allocator,
    builder: recorder.Builder,
    bindings: []graph_mod.RecursionInputBinding,
    profile: graph_mod.InputProfile,
    manifest: *const manifest_mod.Manifest,
    layout: CaptureLayout,
    sampled_values: []recorder.Scalar,
    parent_binary_selector: recorder.Scalar,
    child_kind_selectors: [3]recorder.Scalar,
    statement_words: [STATEMENT_WORD_COUNT]recorder.Scalar,
    claim_inputs: [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
    challenges: recorder.ChallengeSet,
    composition_randomness: recorder.Scalar,
    oods_point: circle.CirclePoint(recorder.Scalar),
    split_composition: recorder.Scalar,
    denominator_cache: recorder.DenominatorCache,
    programs: [3]KindState,
    poseidon_claim_closure_recorded: bool = false,
    finished: bool = false,

    /// `capture` is the successful native verifier capture.  Geometry is
    /// derived from its sampled-point layout and column logs plus the sealed
    /// universal manifest; no caller-supplied composition profile is accepted.
    pub fn create(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        capture: anytype,
    ) Error!*Session {
        try manifest.validate();
        if (manifest.roster_count != ROSTER_CLAIM_COUNT)
            return error.InvalidManifest;

        var layout = try CaptureLayout.init(allocator, manifest, capture);
        errdefer layout.deinit();
        const sample_count = std.math.cast(u32, capture.sampled_values.len) orelse
            return error.CircuitTooLarge;
        const profile = graph_mod.InputProfile{
            .sampled_value_count = sample_count,
            .claimed_sum_count = COMPOSITION_CLAIM_INPUT_COUNT,
            .relation_challenge_count = RELATION_CHALLENGE_COUNT,
        };
        const input_count = try graph_mod.recursionInputCount(profile);
        if (input_count >= m31.Modulus) return error.CircuitTooLarge;

        const bindings = try allocator.alloc(
            graph_mod.RecursionInputBinding,
            input_count,
        );
        errdefer allocator.free(bindings);
        const sampled = try allocator.alloc(recorder.Scalar, sample_count);
        errdefer allocator.free(sampled);
        const base_inputs = try allocator.alloc(recorder.Scalar, input_count);
        defer allocator.free(base_inputs);

        const self = try allocator.create(Session);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .builder = recorder.Builder.init(allocator),
            .bindings = bindings,
            .profile = profile,
            .manifest = manifest,
            .layout = layout,
            .sampled_values = sampled,
            .parent_binary_selector = undefined,
            .child_kind_selectors = undefined,
            .statement_words = undefined,
            .claim_inputs = undefined,
            .challenges = undefined,
            .composition_randomness = undefined,
            .oods_point = undefined,
            .split_composition = undefined,
            .denominator_cache = .{null} ** circle.M31_CIRCLE_LOG_ORDER,
            .programs = .{ KindState{}, KindState{}, KindState{} },
            .poseidon_claim_closure_recorded = false,
        };
        errdefer self.builder.deinit();

        const operation_hint = std.math.mul(
            usize,
            manifest.total_constraints,
            3,
        ) catch return error.CircuitTooLarge;
        try self.builder.reserve(input_count, operation_hint);
        for (base_inputs, bindings, 0..) |*value, *binding, index| {
            const input = try self.builder.input();
            const source = graph_mod.expectedRecursionSource(profile, index) orelse
                return error.BindingCountMismatch;
            value.* = input.value;
            binding.* = .{ .node_id = input.node_id, .source = source };
        }

        try self.builder.activate();
        errdefer if (self.builder.active) self.builder.deactivate();

        var cursor: usize = 0;
        self.parent_binary_selector = base_inputs[cursor];
        cursor += 1;
        @memcpy(&self.child_kind_selectors, base_inputs[cursor..][0..3]);
        cursor += 3;
        @memcpy(&self.statement_words, base_inputs[cursor..][0..STATEMENT_WORD_COUNT]);
        cursor += STATEMENT_WORD_COUNT;
        for (self.sampled_values) |*value| value.* = takeSecure(base_inputs, &cursor);
        for (&self.claim_inputs) |*value| value.* = takeSecure(base_inputs, &cursor);
        var challenge_draws: [RELATION_CHALLENGE_COUNT][2]recorder.Scalar = undefined;
        for (&challenge_draws) |*pair| {
            pair[0] = takeSecure(base_inputs, &cursor);
            pair[1] = takeSecure(base_inputs, &cursor);
        }
        self.composition_randomness = takeSecure(base_inputs, &cursor);
        const oods_seed = takeSecure(base_inputs, &cursor);
        if (cursor != input_count) return error.BindingCountMismatch;

        self.challenges = try recorder.ChallengeSet.init(challenge_draws);
        self.oods_point = recorder.pointFromSeed(oods_seed);
        self.split_composition = try self.reconstructComposition();
        try self.bindChildKind();
        try self.constrainGlobalLogup();
        try self.builder.check();

        // Ownership moved into the stable session object.
        layout = undefined;
        return self;
    }

    pub fn deinit(self: *Session) void {
        if (self.builder.active) self.builder.deactivate();
        self.builder.deinit();
        self.layout.deinit();
        self.allocator.free(self.sampled_values);
        self.allocator.free(self.bindings);
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    /// Records one initialized heterogeneous adapter.  The manifest placement
    /// and both compiler seals are rechecked before graph replay.  Crucially,
    /// the LogUp shift is reconstructed from the row's symbolic claimed-sum
    /// input; `component.claimed_sum` and `component.claimed_sum_shift` are
    /// never read and can never become graph constants.
    pub fn recordComponent(
        self: *Session,
        comptime Runtime: type,
        kind: graph_mod.ProofKind,
        row: roster.Component,
        component: anytype,
    ) Error!usize {
        if (self.finished or !self.builder.active)
            return error.CircuitAlreadyFinished;
        const kind_index = @intFromEnum(kind);
        const state = &self.programs[kind_index];
        const row_index: u8 = @intFromEnum(row);
        if (state.next_row != row_index) return error.ComponentOrderMismatch;
        if (row_index >= @intFromEnum(roster.Component.poseidon2))
            return error.ProviderRequiresExactRecorder;

        const expected = self.manifest.placements[row_index] orelse
            return error.InvalidManifest;
        if (!component.placement.eql(expected) or
            component.log_size != expected.geometry.log_size or
            component.direct.input_count != Runtime.LOGICAL_INPUT_COUNT or
            component.direct.constraint_count != expected.geometry.direct_constraints or
            Runtime.BATCH_COUNT != expected.geometry.interaction_batches or
            Runtime.INTERACTION_COLUMN_COUNT != expected.geometry.interaction_columns)
        {
            return error.ComponentGeometryMismatch;
        }
        if (!std.mem.eql(
            u8,
            &component.direct.semantic_digest,
            &expected.geometry.semantic_digest,
        ) or !std.mem.eql(
            u8,
            &component.relation_plan.semantic_digest,
            &expected.geometry.semantic_digest,
        ) or !std.mem.eql(
            u8,
            &component.relation_plan.registry_order_digest,
            &relation.registryOrderDigest(),
        )) {
            return error.ComponentProgramSealMismatch;
        }

        const parameter_count = component.parameters.len;
        if (Runtime.LOGICAL_INPUT_COUNT !=
            @as(usize, expected.geometry.main_columns) +
                expected.geometry.preprocessed_columns + parameter_count)
        {
            return error.ComponentGeometryMismatch;
        }
        var logical_row: [Runtime.LOGICAL_INPUT_COUNT]recorder.Scalar = undefined;
        var cursor: usize = 0;
        for (0..expected.geometry.main_columns) |column| {
            logical_row[cursor] = try self.layout.at(
                self.sampled_values,
                manifest_mod.MAIN_TREE_INDEX,
                @as(usize, expected.main_offset) + column,
                0,
            );
            cursor += 1;
        }
        for (0..expected.geometry.preprocessed_columns) |column| {
            logical_row[cursor] = try self.layout.at(
                self.sampled_values,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                @as(usize, expected.preprocessed_offset) + column,
                0,
            );
            cursor += 1;
        }
        for (component.parameters) |parameter| {
            logical_row[cursor] = recorder.Scalar.fromBase(parameter);
            cursor += 1;
        }
        std.debug.assert(cursor == logical_row.len);

        var interaction_current: [Runtime.BATCH_COUNT]recorder.Scalar = undefined;
        for (&interaction_current, 0..) |*value, batch| {
            const final = batch + 1 == Runtime.BATCH_COUNT;
            value.* = try self.sampledInteraction(
                @as(usize, expected.interaction_offset) + 4 * batch,
                if (final) 1 else 0,
            );
        }
        const final_previous_row = try self.sampledInteraction(
            @as(usize, expected.interaction_offset) +
                4 * (Runtime.BATCH_COUNT - 1),
            0,
        );
        const denominator = try recorder.quotientDenominator(
            expected.geometry.log_size,
            self.layout.quotient_max_log_degree_bound,
            self.oods_point,
            &self.denominator_cache,
        );
        const n = M31.fromU64(@as(u64, 1) << @intCast(expected.geometry.log_size));
        const claimed_sum_shift = self.claim_inputs[row_index].mul(
            recorder.Scalar.fromBase(try n.inv()),
        );
        const recorded_count = try recorder.recordComponent(
            Runtime,
            component,
            logical_row,
            interaction_current,
            final_previous_row,
            claimed_sum_shift,
            &self.challenges,
            self.composition_randomness,
            denominator,
            &state.accumulation,
        );
        const expected_count: usize = @as(usize, expected.geometry.direct_constraints) +
            expected.geometry.interaction_batches;
        if (recorded_count != expected_count)
            return error.ComponentGeometryMismatch;
        state.constraint_count = std.math.add(
            usize,
            state.constraint_count,
            recorded_count,
        ) catch return error.CircuitTooLarge;
        state.next_row += 1;
        return recorded_count;
    }

    /// Replays authenticated shared-provider row 34 in native verifier order.
    /// The adapter is used only to revalidate equation/placement authority;
    /// its concrete claims are deliberately ignored.  Both partial claims are
    /// symbolic verifier inputs in the V1.1 tail ABI and are closed to roster
    /// claim 34 by a separately active-gated graph output.
    pub fn recordPoseidonProvider(
        self: *Session,
        kind: graph_mod.ProofKind,
        adapter: *const shared_provider.Poseidon2Adapter,
    ) Error!usize {
        if (self.finished or !self.builder.active)
            return error.CircuitAlreadyFinished;
        const row_index: u8 = @intFromEnum(roster.Component.poseidon2);
        const state = &self.programs[@intFromEnum(kind)];
        if (state.next_row != row_index) return error.ComponentOrderMismatch;
        _ = try adapter.binding(self.manifest);

        const placement = self.manifest.placements[row_index] orelse
            return error.InvalidManifest;
        if (!adapter.placement.eql(placement) or
            !std.meta.eql(
                placement.geometry,
                shared_provider.Poseidon2Adapter.manifestGeometry(
                    placement.geometry.log_size,
                ),
            ))
        {
            return error.ComponentGeometryMismatch;
        }

        var main: [poseidon_air.N_MAIN_COLUMNS]recorder.Scalar = undefined;
        for (&main, 0..) |*value, column| value.* = try self.layout.at(
            self.sampled_values,
            manifest_mod.MAIN_TREE_INDEX,
            @as(usize, placement.main_offset) + column,
            0,
        );
        const is_first = try self.layout.at(
            self.sampled_values,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            placement.preprocessed_offset,
            0,
        );
        var current: [poseidon_air.N_SUMS]recorder.Scalar = undefined;
        var previous: [poseidon_air.N_SUMS]recorder.Scalar = undefined;
        for (&current, &previous, 0..) |*current_value, *previous_value, batch| {
            const offset = @as(usize, placement.interaction_offset) +
                qm31.SECURE_EXTENSION_DEGREE * batch;
            current_value.* = try self.sampledInteraction(offset, 0);
            previous_value.* = try self.sampledInteraction(offset, 1);
        }
        const partial_claims = self.claim_inputs[POSEIDON_AUX_START..COMPOSITION_CLAIM_INPUT_COUNT][0..poseidon_air.N_SUMS].*;
        const denominator = try recorder.quotientDenominator(
            placement.geometry.log_size,
            self.layout.quotient_max_log_degree_bound,
            self.oods_point,
            &self.denominator_cache,
        );
        const recorded_count = try shared_provider_composition.recordPoseidon2(
            main,
            is_first,
            current,
            previous,
            partial_claims,
            &self.challenges,
            self.composition_randomness,
            denominator,
            &state.accumulation,
        );
        if (recorded_count != placement.geometry.direct_constraints +
            placement.geometry.interaction_batches)
        {
            return error.ComponentGeometryMismatch;
        }
        if (!self.poseidon_claim_closure_recorded) {
            try self.constrainActive(
                shared_provider_composition.poseidonClaimClosure(
                    partial_claims,
                    self.claim_inputs[row_index],
                ),
            );
            self.poseidon_claim_closure_recorded = true;
        }
        try advanceProviderState(state, recorded_count);
        return recorded_count;
    }

    /// Replays authenticated shared-provider row 35 through its shipped table
    /// interaction evaluator.  As with row 34, the adapter's concrete claim is
    /// admission evidence only; the root consumes symbolic roster claim 35.
    pub fn recordRangeCheck8x8Provider(
        self: *Session,
        kind: graph_mod.ProofKind,
        adapter: *const shared_provider.RangeCheck8x8Adapter,
    ) Error!usize {
        if (self.finished or !self.builder.active)
            return error.CircuitAlreadyFinished;
        const row_index: u8 = @intFromEnum(roster.Component.range_check_8_8);
        const state = &self.programs[@intFromEnum(kind)];
        if (state.next_row != row_index) return error.ComponentOrderMismatch;
        _ = try adapter.binding(self.manifest);

        const placement = self.manifest.placements[row_index] orelse
            return error.InvalidManifest;
        if (!adapter.placement.eql(placement) or
            !std.meta.eql(
                placement.geometry,
                shared_provider.RangeCheck8x8Adapter.manifestGeometry(),
            ))
        {
            return error.ComponentGeometryMismatch;
        }

        const tuple = [2]recorder.Scalar{
            try self.layout.at(
                self.sampled_values,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                @as(usize, placement.preprocessed_offset) + 1,
                0,
            ),
            try self.layout.at(
                self.sampled_values,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                @as(usize, placement.preprocessed_offset) + 2,
                0,
            ),
        };
        const is_first = try self.layout.at(
            self.sampled_values,
            manifest_mod.PREPROCESSED_TREE_INDEX,
            placement.preprocessed_offset,
            0,
        );
        const signed_multiplicity = try self.layout.at(
            self.sampled_values,
            manifest_mod.MAIN_TREE_INDEX,
            placement.main_offset,
            0,
        );
        const current = try self.sampledInteraction(
            placement.interaction_offset,
            0,
        );
        const previous = try self.sampledInteraction(
            placement.interaction_offset,
            1,
        );
        const denominator = try recorder.quotientDenominator(
            placement.geometry.log_size,
            self.layout.quotient_max_log_degree_bound,
            self.oods_point,
            &self.denominator_cache,
        );
        const recorded_count = try shared_provider_composition.recordRangeCheck8x8(
            tuple,
            signed_multiplicity,
            current,
            previous,
            is_first,
            self.claim_inputs[row_index],
            &self.challenges,
            self.composition_randomness,
            denominator,
            &state.accumulation,
        );
        if (recorded_count != placement.geometry.direct_constraints +
            placement.geometry.interaction_batches)
        {
            return error.ComponentGeometryMismatch;
        }
        try advanceProviderState(state, recorded_count);
        return recorded_count;
    }

    pub fn sampledValue(
        self: *const Session,
        tree: usize,
        column: usize,
        sample: usize,
    ) Error!recorder.Scalar {
        return self.layout.at(self.sampled_values, tree, column, sample);
    }

    pub fn claimedSum(
        self: *const Session,
        row: roster.Component,
    ) recorder.Scalar {
        return self.claim_inputs[@intFromEnum(row)];
    }

    pub fn poseidonPartialClaim(
        self: *const Session,
        index: u1,
    ) recorder.Scalar {
        return self.claim_inputs[POSEIDON_AUX_START + index];
    }

    pub fn relationChallenges(self: *const Session) *const recorder.ChallengeSet {
        return &self.challenges;
    }

    pub fn point(self: *const Session) circle.CirclePoint(recorder.Scalar) {
        return self.oods_point;
    }

    pub fn finish(self: *Session) Error!Circuit {
        if (self.finished or !self.builder.active)
            return error.CircuitAlreadyFinished;
        if (!self.poseidon_claim_closure_recorded)
            return error.IncompleteProofKindProgram;
        for (self.programs) |program| {
            if (program.next_row != ROSTER_CLAIM_COUNT or
                program.constraint_count != self.manifest.total_constraints)
            {
                return error.IncompleteProofKindProgram;
            }
        }

        for (self.programs, &self.child_kind_selectors) |program, selector| {
            try self.builder.constrainZero(
                self.parent_binary_selector.mul(selector).mul(
                    self.split_composition.sub(program.accumulation),
                ),
            );
        }
        try self.builder.check();
        self.builder.deactivate();
        self.finished = true;

        var recorded = try self.builder.finish();
        errdefer recorded.deinit();
        const statistics = ProgramStatistics{
            .constraints_per_kind = .{
                self.programs[0].constraint_count,
                self.programs[1].constraint_count,
                self.programs[2].constraint_count,
            },
            .roster_rows_per_kind = .{
                self.programs[0].next_row,
                self.programs[1].next_row,
                self.programs[2].next_row,
            },
            .sampled_values = self.sampled_values.len,
            .graph_inputs = recorded.input_count,
            .graph_nodes = recorded.nodes.len,
            .composition_log_size = self.layout.composition_log_size,
            .composition_log_split = self.layout.composition_log_split,
            .quotient_max_log_degree_bound = self.layout.quotient_max_log_degree_bound,
            .fri_log_blowup = self.layout.fri_log_blowup,
        };
        var result = Circuit{
            .allocator = self.allocator,
            .recorded = recorded,
            .bindings = self.bindings,
            .input_profile = self.profile,
            .manifest_seal = self.manifest.seal,
            .statistics = statistics,
            .identity_digest = undefined,
        };
        result.identity_digest = circuitDigest(&result);
        try result.validate();

        const allocator = self.allocator;
        self.layout.deinit();
        allocator.free(self.sampled_values);
        self.builder.deinit();
        self.* = undefined;
        allocator.destroy(self);
        return result;
    }

    fn sampledInteraction(
        self: *const Session,
        column: usize,
        sample: usize,
    ) Error!recorder.Scalar {
        var partials: [qm31.SECURE_EXTENSION_DEGREE]recorder.Scalar = undefined;
        for (&partials, 0..) |*partial, coordinate| {
            partial.* = try self.layout.at(
                self.sampled_values,
                manifest_mod.INTERACTION_TREE_INDEX,
                column + coordinate,
                sample,
            );
        }
        return recorder.fromPartialEvals(partials);
    }

    fn reconstructComposition(self: *const Session) Error!recorder.Scalar {
        const chunk_count = verifier_types.compositionChunkCount(
            self.layout.composition_log_split,
        ) orelse return error.InvalidCompositionGeometry;
        var chunks: [
            @as(usize, 1) <<
                verifier_types.MAX_COMPOSITION_LOG_SPLIT
        ]recorder.Scalar = undefined;
        for (chunks[0..chunk_count], 0..) |*chunk, chunk_index| {
            var partials: [qm31.SECURE_EXTENSION_DEGREE]recorder.Scalar = undefined;
            for (&partials, 0..) |*partial, coordinate| {
                partial.* = try self.layout.at(
                    self.sampled_values,
                    COMPOSITION_TREE_INDEX,
                    chunk_index * qm31.SECURE_EXTENSION_DEGREE + coordinate,
                    0,
                );
            }
            chunk.* = recorder.fromPartialEvals(partials);
        }
        return recorder.reconstructSplitComposition(
            chunks[0..chunk_count],
            self.oods_point,
            self.layout.composition_log_size,
            self.layout.composition_log_split,
        );
    }

    fn bindChildKind(self: *Session) Error!void {
        const one = recorder.Scalar.one();
        const segment = self.child_kind_selectors[
            @intFromEnum(
                graph_mod.ProofKind.segment_leaf,
            )
        ];
        const binary = self.child_kind_selectors[
            @intFromEnum(
                graph_mod.ProofKind.binary_node,
            )
        ];
        const empty = self.child_kind_selectors[
            @intFromEnum(
                graph_mod.ProofKind.empty_leaf,
            )
        ];
        try self.constrainActive(
            segment.add(binary).add(empty).sub(one),
        );
        for (self.child_kind_selectors) |selector|
            try self.constrainActive(selector.mul(one.sub(selector)));

        const height = self.statement_words[span_statement.canonical_layout.slot_height];
        try self.constrainActive(segment.add(empty).mul(height));
        const safe_height = height.add(one).sub(binary);
        const height_inverse = safe_height.inverse();
        try self.constrainActive(safe_height.mul(height_inverse).sub(one));
        try self.constrainActive(height.mul(height_inverse).sub(binary));

        const body_tag = self.statement_words[span_statement.canonical_layout.body_tag];
        try self.constrainActive(segment.mul(body_tag.sub(
            recorder.Scalar.fromBase(M31.fromU64(@intFromEnum(
                span_statement.Tag.executed_body,
            ))),
        )));
        try self.constrainActive(empty.mul(body_tag.sub(
            recorder.Scalar.fromBase(M31.fromU64(@intFromEnum(
                span_statement.Tag.empty_body,
            ))),
        )));
    }

    fn constrainGlobalLogup(self: *Session) Error!void {
        const challenge = self.challenges.get(.recursion_statement_word);
        var public_sum = recorder.Scalar.zero();
        const scope = recorder.Scalar.fromBase(M31.fromU64(
            statement_input.PARENT_STATEMENT_SCOPE,
        ));
        for (self.statement_words, 0..) |word, word_index| {
            const tuple = [_]recorder.Scalar{
                scope,
                recorder.Scalar.fromBase(M31.fromU64(word_index)),
                word,
            };
            public_sum = public_sum.add((try challenge.combine(&tuple)).inverse());
        }
        var claimed_total = recorder.Scalar.zero();
        for (self.claim_inputs[0..ROSTER_CLAIM_COUNT]) |claim|
            claimed_total = claimed_total.add(claim);
        try self.constrainActive(claimed_total.add(public_sum));
    }

    fn constrainActive(self: *Session, value: recorder.Scalar) Error!void {
        try self.builder.constrainZero(self.parent_binary_selector.mul(value));
    }
};
