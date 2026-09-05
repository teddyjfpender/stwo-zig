//! Internal shard of recursion_air_composition_segment_recorder_v3.zig; use the public facade.

const dependency_0 = @import("recursion_air_composition_segment_recorder_v3_error.zig");

const std = dependency_0.std;
const circle = dependency_0.circle;
const M31 = dependency_0.M31;
const qm31 = dependency_0.qm31;
const relation = dependency_0.relation;
const poseidon_air = dependency_0.poseidon_air;
const capture_layout = dependency_0.capture_layout;
const recorder = dependency_0.recorder;
const universal_catalog = dependency_0.universal_catalog;
const universal_roster = dependency_0.universal_roster;
const shared_provider = dependency_0.shared_provider;
const shared_provider_composition = dependency_0.shared_provider_composition;
const complete_segment_cohort = dependency_0.complete_segment_cohort;
const SEGMENT_ROW_COUNT = dependency_0.SEGMENT_ROW_COUNT;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const POSEIDON_ROW = dependency_0.POSEIDON_ROW;
const RANGE_ROW = dependency_0.RANGE_ROW;
const POSEIDON_AUX_START = dependency_0.POSEIDON_AUX_START;
const Error = dependency_0.Error;
const ProgramResultV3 = dependency_0.ProgramResultV3;

/// Manifest-parametric borrowed view over one active graph-construction
/// transaction. Every slice and authority object must remain at a stable
/// address through `finishProgram`; the returned result itself owns no borrow.
pub fn ProgramRecorderForManifest(
    comptime manifest_contract: type,
    comptime proof_kind: capture_layout.ProofKind,
    comptime program_row_count: usize,
) type {
    return struct {
        const Self = @This();
        pub const PoseidonAdapter =
            shared_provider.Poseidon2AdapterForManifest(manifest_contract);
        pub const RangeCheck8x8Adapter =
            shared_provider.RangeCheck8x8AdapterForManifest(manifest_contract);

        builder: *recorder.Builder,
        manifest: *const manifest_contract.Manifest,
        layout: *const capture_layout.CaptureLayoutV3,
        sampled_values: []const recorder.Scalar,
        claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
        challenges: *const recorder.ChallengeSet,
        composition_randomness: recorder.Scalar,
        oods_point: circle.CirclePoint(recorder.Scalar),
        denominator_cache: *recorder.DenominatorCache,
        canonical_empty_layout_identity: ?[32]u8 = null,
        next_row: u8 = 0,
        constraint_count: usize = 0,
        accumulation: recorder.Scalar = recorder.Scalar.zero(),
        finished: bool = false,

        pub fn init(
            builder: *recorder.Builder,
            manifest: *const manifest_contract.Manifest,
            layout: *const capture_layout.CaptureLayoutV3,
            sampled_values: []const recorder.Scalar,
            claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
            challenges: *const recorder.ChallengeSet,
            composition_randomness: recorder.Scalar,
            oods_point: circle.CirclePoint(recorder.Scalar),
            denominator_cache: *recorder.DenominatorCache,
        ) Error!Self {
            if (!builder.active) return error.CircuitAlreadyFinished;
            try manifest.validate();
            switch (proof_kind) {
                .segment_leaf => try layout.validateAgainstSegment(manifest),
                .binary_node => try layout.validateAgainstBinary(manifest),
                // Empty and binary programs intentionally share the universal
                // column geometry.  They remain distinct programs because the
                // initialized adapters retain different proof-kind parameters;
                // the empty witness supplies a canonical zero sample vector.
                .empty_leaf => try layout.validateAgainstBinary(manifest),
            }
            if (manifest.roster_count != program_row_count)
                return error.InvalidManifest;
            if (sampled_values.len != layout.sampled_value_count)
                return error.InvalidSampleInputCount;
            return .{
                .builder = builder,
                .manifest = manifest,
                .layout = layout,
                .sampled_values = sampled_values,
                .claim_inputs = claim_inputs,
                .challenges = challenges,
                .composition_randomness = composition_randomness,
                .oods_point = oods_point,
                .denominator_cache = denominator_cache,
            };
        }

        /// Binary recorder for a non-V1 authenticated 36-row manifest. The
        /// concrete manifest type remains a comptime authority and the family
        /// discriminator is sealed by the capture layout itself.
        pub fn initAuthenticatedBinary(
            builder: *recorder.Builder,
            manifest: *const manifest_contract.Manifest,
            comptime family: capture_layout.ManifestFamily,
            layout: *const capture_layout.CaptureLayoutV3,
            sampled_values: []const recorder.Scalar,
            claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
            challenges: *const recorder.ChallengeSet,
            composition_randomness: recorder.Scalar,
            oods_point: circle.CirclePoint(recorder.Scalar),
            denominator_cache: *recorder.DenominatorCache,
        ) !Self {
            if (proof_kind != .binary_node or family == .universal_v1 or
                family == .segment_v2)
            {
                return error.InvalidManifest;
            }
            if (!builder.active) return error.CircuitAlreadyFinished;
            try manifest.validate();
            try layout.validateAgainstAuthenticatedBinary(family, manifest);
            if (manifest.roster_count != program_row_count)
                return error.InvalidManifest;
            if (sampled_values.len != layout.sampled_value_count)
                return error.InvalidSampleInputCount;
            return .{
                .builder = builder,
                .manifest = manifest,
                .layout = layout,
                .sampled_values = sampled_values,
                .claim_inputs = claim_inputs,
                .challenges = challenges,
                .composition_randomness = composition_randomness,
                .oods_point = oods_point,
                .denominator_cache = denominator_cache,
            };
        }

        /// Dedicated proofless-empty admission.  The layout owns a deep copy
        /// of universal capture geometry under an empty-specific identity;
        /// callers therefore cannot route a binary capture layout directly
        /// into this lane.  Samples are still supplied through the shared
        /// fixed graph ABI, where the canonical-empty provider constrains the
        /// complete slice to zero before this inactive shell is selected.
        pub fn initCanonicalEmpty(
            builder: *recorder.Builder,
            manifest: *const manifest_contract.Manifest,
            layout: *const capture_layout.CanonicalEmptyCaptureLayoutV3,
            sampled_values: []const recorder.Scalar,
            claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
            challenges: *const recorder.ChallengeSet,
            composition_randomness: recorder.Scalar,
            oods_point: circle.CirclePoint(recorder.Scalar),
            denominator_cache: *recorder.DenominatorCache,
        ) Error!Self {
            if (comptime (proof_kind != .empty_leaf or
                program_row_count != universal_roster.COMPONENT_COUNT))
                return error.InvalidManifest;
            try layout.validateAgainst(manifest, &layout.geometry);
            var result = try Self.init(
                builder,
                manifest,
                &layout.geometry,
                sampled_values,
                claim_inputs,
                challenges,
                composition_randomness,
                oods_point,
                denominator_cache,
            );
            result.canonical_empty_layout_identity = layout.identity;
            return result;
        }

        /// Replays one manifest-admitted typed component.  Rows 34/35 have
        /// dedicated methods because their native components predate the generic
        /// direct-program shell; every other SegmentV2 row uses this path.
        pub fn recordComponent(
            self: *Self,
            comptime Runtime: type,
            row: manifest_contract.ComponentKey,
            component: anytype,
        ) Error!usize {
            try self.requireActive();
            const row_index: u8 = @intFromEnum(row);
            if (self.next_row != row_index) return error.ComponentOrderMismatch;
            if (row_index == POSEIDON_ROW or row_index == RANGE_ROW)
                return error.ProviderRequiresExactRecorder;

            const expected = self.manifest.placements[row_index] orelse
                return error.InvalidManifest;
            if (!component.placement.eql(expected) or
                component.log_size != expected.geometry.log_size or
                component.direct.input_count != Runtime.LOGICAL_INPUT_COUNT or
                component.direct.constraint_count !=
                    expected.geometry.direct_constraints or
                Runtime.BATCH_COUNT != expected.geometry.interaction_batches or
                Runtime.INTERACTION_COLUMN_COUNT !=
                    expected.geometry.interaction_columns)
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

            var logical_row: [Runtime.LOGICAL_INPUT_COUNT]recorder.Scalar =
                undefined;
            var cursor: usize = 0;
            for (0..expected.geometry.main_columns) |column| {
                logical_row[cursor] = try self.layout.at(
                    self.sampled_values,
                    capture_layout.MAIN_TREE_INDEX,
                    @as(usize, expected.main_offset) + column,
                    0,
                );
                cursor += 1;
            }
            for (0..expected.geometry.preprocessed_columns) |column| {
                logical_row[cursor] = try self.layout.at(
                    self.sampled_values,
                    capture_layout.PREPROCESSED_TREE_INDEX,
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

            var interaction_current: [Runtime.BATCH_COUNT]recorder.Scalar =
                undefined;
            for (&interaction_current, 0..) |*value, batch| {
                const final = batch + 1 == Runtime.BATCH_COUNT;
                value.* = try self.sampledInteraction(
                    @as(usize, expected.interaction_offset) +
                        qm31.SECURE_EXTENSION_DEGREE * batch,
                    if (final) 1 else 0,
                );
            }
            const final_previous_row = if (Runtime.BATCH_COUNT == 0)
                recorder.Scalar.zero()
            else
                try self.sampledInteraction(
                    @as(usize, expected.interaction_offset) +
                        qm31.SECURE_EXTENSION_DEGREE *
                            (Runtime.BATCH_COUNT - 1),
                    0,
                );
            const denominator = try recorder.quotientDenominator(
                expected.geometry.log_size,
                self.layout.quotient_max_log_degree_bound,
                self.oods_point,
                self.denominator_cache,
            );
            const trace_size = @as(u64, 1) <<
                @intCast(expected.geometry.log_size);
            const inverse_trace_size = try M31.fromU64(trace_size).inv();
            const claimed_sum_shift = self.claim_inputs[row_index].mul(
                recorder.Scalar.fromBase(inverse_trace_size),
            );
            const recorded_count = try recorder.recordComponent(
                Runtime,
                component,
                logical_row,
                interaction_current,
                final_previous_row,
                claimed_sum_shift,
                self.challenges,
                self.composition_randomness,
                denominator,
                &self.accumulation,
            );
            try self.advance(expected, recorded_count);
            return recorded_count;
        }

        /// Inferred-runtime entry point for initialized generic adapters.  Every
        /// adapter produced by `universal_typed_component` publishes the exact
        /// runtime type that authenticated its retained relation plan, eliminating
        /// a 37-entry hand-maintained runtime dispatch table here.
        pub fn recordTypedComponent(
            self: *Self,
            row: manifest_contract.ComponentKey,
            component: anytype,
        ) Error!usize {
            const Adapter = @TypeOf(component.*);
            return self.recordComponent(
                Adapter.RelationRuntime,
                row,
                component,
            );
        }

        /// Replays the exact aggregate already admitted by the concrete SegmentV2
        /// proof engine.  The structural argument is deliberately generic so this
        /// frontend module does not depend back on a CPU integration package.  Its
        /// required fields match that package's `Components { noncore, core }`
        /// custody object and nothing else enters the graph.
        pub fn recordCompleteCohort(
            self: *Self,
            components: anytype,
        ) Error!ProgramResultV3 {
            if (proof_kind != .segment_leaf or program_row_count != SEGMENT_ROW_COUNT)
                return error.InvalidManifest;
            return complete_segment_cohort.record(self, components);
        }

        /// Replays one exact 36-row universal cohort.  Binary and empty lanes
        /// have identical physical placement but must be supplied as separately
        /// initialized component aggregates: proof-kind parameters are part of
        /// each adapter and are never rewritten by this recorder.
        pub fn recordCompleteUniversalCohort(
            self: *Self,
            components: anytype,
        ) Error!ProgramResultV3 {
            if (proof_kind == .segment_leaf or
                program_row_count != universal_roster.COMPONENT_COUNT)
            {
                return error.InvalidManifest;
            }

            _ = try self.recordTypedComponent(
                .control,
                &components.non_fri.transcript.control,
            );
            _ = try self.recordTypedComponent(
                .transcript_air,
                &components.non_fri.transcript.transcript_air,
            );
            _ = try self.recordTypedComponent(
                .transcript_binding,
                &components.non_fri.transcript.transcript_binding,
            );
            _ = try self.recordTypedComponent(
                .transcript_state,
                &components.non_fri.transcript.transcript_state,
            );
            _ = try self.recordTypedComponent(
                .transcript_word,
                &components.non_fri.transcript.transcript_word,
            );
            _ = try self.recordTypedComponent(
                .transcript_payload,
                &components.non_fri.transcript.transcript_payload,
            );
            _ = try self.recordTypedComponent(
                .pow_check,
                &components.non_fri.transcript.pow_check,
            );
            _ = try self.recordTypedComponent(
                .pow_frame,
                &components.non_fri.transcript.pow_frame,
            );
            _ = try self.recordTypedComponent(
                .relation_challenge,
                &components.non_fri.transcript.relation_challenge,
            );
            _ = try self.recordTypedComponent(
                .verifier_randomness,
                &components.non_fri.transcript.verifier_randomness,
            );
            _ = try self.recordTypedComponent(
                .statement_input,
                &components.non_fri.statement.statement_input,
            );
            _ = try self.recordTypedComponent(
                .statement_semantics_input,
                &components.non_fri.statement.statement_semantics,
            );
            _ = try self.recordTypedComponent(
                .vm_public_claim_input,
                &components.non_fri.inactive.claim_input,
            );
            _ = try self.recordTypedComponent(
                .vm_public_claim_hash,
                &components.non_fri.inactive.claim_hash,
            );
            _ = try self.recordTypedComponent(
                .vm_public_io_hash,
                &components.non_fri.inactive.io_hash,
            );
            _ = try self.recordTypedComponent(
                .vm_public_claim_semantics_input,
                &components.non_fri.inactive.claim_semantics,
            );
            _ = try self.recordTypedComponent(
                .vm_public_logup_input,
                &components.non_fri.inactive.public_logup,
            );
            _ = try self.recordTypedComponent(
                .vm_public_logup_control,
                &components.non_fri.inactive.public_logup_control,
            );
            _ = try self.recordTypedComponent(
                .vm_air_composition_input,
                &components.fri.composition_input,
            );
            _ = try self.recordTypedComponent(
                .vm_air_composition_control,
                &components.fri.composition_control,
            );
            _ = try self.recordTypedComponent(.query_bits, &components.fri.query_bits);
            _ = try self.recordTypedComponent(
                .query_mapping,
                &components.fri.query_mapping,
            );
            _ = try self.recordTypedComponent(.merkle_root, &components.fri.merkle_root);
            _ = try self.recordTypedComponent(
                .trace_merkle,
                &components.fri.trace_merkle,
            );
            _ = try self.recordTypedComponent(
                .pcs_deep_input,
                &components.fri.pcs_deep,
            );
            _ = try self.recordTypedComponent(
                .fri_merkle_leaf,
                &components.fri.fri_leaf,
            );
            _ = try self.recordTypedComponent(
                .fri_merkle_node,
                &components.fri.fri_node,
            );
            _ = try self.recordTypedComponent(
                .fri_merkle_anchor,
                &components.fri.fri_anchor,
            );
            _ = try self.recordTypedComponent(
                .fri_verifier_control,
                &components.fri.fri_control,
            );
            _ = try self.recordTypedComponent(
                .fri_verifier_input,
                &components.fri.fri_input,
            );
            _ = try self.recordTypedComponent(.qm31_mul, &components.fri.multiply);
            _ = try self.recordTypedComponent(.qm31_inv, &components.fri.inverse);
            _ = try self.recordTypedComponent(.linear_ops, &components.fri.linear);
            _ = try self.recordTypedComponent(.merkle_path, &components.fri.merkle_path);
            _ = try self.recordPoseidonProvider(&components.fri.poseidon2);
            _ = try self.recordRangeCheck8x8Provider(
                &components.non_fri.statement.range_check,
            );
            return self.finishProgram();
        }

        /// Catalog-driven universal replay for canonical inactive/empty graph
        /// construction. `owners` is the declaration-ordered 34-element tuple
        /// built from `universal_catalog.LOGICAL_ROWS`; each entry owns a real
        /// initialized `.component`.  This is the SSOT alternative to inventing
        /// an empty-only 34-field aggregate or another row dispatch table.
        pub fn recordCompleteUniversalCatalog(
            self: *Self,
            owners: anytype,
            poseidon: *const PoseidonAdapter,
            range: *const RangeCheck8x8Adapter,
        ) Error!ProgramResultV3 {
            if (proof_kind == .segment_leaf or
                program_row_count != universal_roster.COMPONENT_COUNT)
            {
                return error.InvalidManifest;
            }
            inline for (universal_catalog.LOGICAL_ROWS, 0..) |entry, index| {
                _ = try self.recordTypedComponent(
                    entry.row,
                    &owners[index].component,
                );
            }
            _ = try self.recordPoseidonProvider(poseidon);
            _ = try self.recordRangeCheck8x8Provider(range);
            return self.finishProgram();
        }

        /// Canonical proofless-empty replay.  The 34 typed rows evaluate their
        /// selector-zero programs normally. Rows 34/35 have no proof trace to
        /// replay, so their separately authenticated adapters advance explicit
        /// zero-polynomial shells. The graph-level empty provider has already
        /// constrained every shared sample and provider claim to zero.
        pub fn recordCompleteCanonicalEmptyCatalog(
            self: *Self,
            owners: anytype,
            poseidon: *const PoseidonAdapter,
            range: *const RangeCheck8x8Adapter,
        ) Error!ProgramResultV3 {
            if (proof_kind != .empty_leaf or
                program_row_count != universal_roster.COMPONENT_COUNT or
                self.canonical_empty_layout_identity == null)
            {
                return error.InvalidManifest;
            }
            inline for (universal_catalog.LOGICAL_ROWS, 0..) |entry, index| {
                _ = try self.recordTypedComponent(
                    entry.row,
                    &owners[index].component,
                );
            }
            _ = try self.recordCanonicalEmptyPoseidonShell(poseidon);
            _ = try self.recordCanonicalEmptyRangeShell(range);
            return self.finishProgram();
        }

        fn recordCanonicalEmptyPoseidonShell(
            self: *Self,
            adapter: *const PoseidonAdapter,
        ) Error!usize {
            try self.requireActive();
            if (self.next_row != POSEIDON_ROW or
                self.canonical_empty_layout_identity == null)
            {
                return error.ComponentOrderMismatch;
            }
            _ = adapter.binding(self.manifest) catch
                return error.ManifestAuthorityMismatch;
            const placement = self.manifest.placements[POSEIDON_ROW] orelse
                return error.InvalidManifest;
            if (!adapter.placement.eql(placement) or
                !std.meta.eql(
                    placement.geometry,
                    PoseidonAdapter.manifestGeometry(
                        placement.geometry.log_size,
                    ),
                ))
            {
                return error.ComponentGeometryMismatch;
            }
            const shell_constraint_count =
                @as(usize, placement.geometry.direct_constraints) +
                placement.geometry.interaction_batches;
            try self.advance(placement, shell_constraint_count);
            return shell_constraint_count;
        }

        fn recordCanonicalEmptyRangeShell(
            self: *Self,
            adapter: *const RangeCheck8x8Adapter,
        ) Error!usize {
            try self.requireActive();
            if (self.next_row != RANGE_ROW or
                self.canonical_empty_layout_identity == null)
            {
                return error.ComponentOrderMismatch;
            }
            _ = adapter.binding(self.manifest) catch
                return error.ManifestAuthorityMismatch;
            const placement = self.manifest.placements[RANGE_ROW] orelse
                return error.InvalidManifest;
            if (!adapter.placement.eql(placement) or
                !std.meta.eql(
                    placement.geometry,
                    RangeCheck8x8Adapter.manifestGeometry(),
                ))
            {
                return error.ComponentGeometryMismatch;
            }
            const shell_constraint_count =
                @as(usize, placement.geometry.direct_constraints) +
                placement.geometry.interaction_batches;
            try self.advance(placement, shell_constraint_count);
            return shell_constraint_count;
        }

        /// Exact native row-34 replay.  The adapter's concrete claims are
        /// admission evidence only; the graph consumes V3 claim inputs 39/40.
        /// Their closure to roster claim 34 is owned once by the V3 global claim
        /// policy and is intentionally not duplicated here.
        pub fn recordPoseidonProvider(
            self: *Self,
            adapter: *const PoseidonAdapter,
        ) Error!usize {
            return self.recordPoseidonProviderAt(
                @enumFromInt(POSEIDON_ROW),
                POSEIDON_AUX_START,
                adapter,
            );
        }

        /// Manifest-parametric native Poseidon replay for an authenticated
        /// binary family whose provider row and auxiliary-claim slots differ
        /// from the frozen SegmentV2/universal roster. The concrete manifest
        /// key and slot are comptime authority; existing callers retain the
        /// exact row-34/slots-39-40 route above.
        pub fn recordPoseidonProviderAt(
            self: *Self,
            comptime row: manifest_contract.ComponentKey,
            comptime partial_start: usize,
            adapter: *const PoseidonAdapter,
        ) Error!usize {
            try self.requireActive();
            const row_index: u8 = @intFromEnum(row);
            if (self.next_row != row_index or
                partial_start + poseidon_air.N_SUMS >
                    COMPOSITION_CLAIM_INPUT_COUNT)
            {
                return error.ComponentOrderMismatch;
            }
            _ = adapter.binding(self.manifest) catch
                return error.ManifestAuthorityMismatch;

            const placement = self.manifest.placements[row_index] orelse
                return error.InvalidManifest;
            if (!adapter.placement.eql(placement) or
                !std.meta.eql(
                    placement.geometry,
                    PoseidonAdapter.manifestGeometry(
                        placement.geometry.log_size,
                    ),
                ))
            {
                return error.ComponentGeometryMismatch;
            }

            var main: [poseidon_air.N_MAIN_COLUMNS]recorder.Scalar = undefined;
            for (&main, 0..) |*value, column| value.* = try self.layout.at(
                self.sampled_values,
                capture_layout.MAIN_TREE_INDEX,
                @as(usize, placement.main_offset) + column,
                0,
            );
            const is_first = try self.layout.at(
                self.sampled_values,
                capture_layout.PREPROCESSED_TREE_INDEX,
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
            const partial_claims = self.claim_inputs[partial_start .. partial_start + poseidon_air.N_SUMS].*;
            const denominator = try recorder.quotientDenominator(
                placement.geometry.log_size,
                self.layout.quotient_max_log_degree_bound,
                self.oods_point,
                self.denominator_cache,
            );
            const recorded_count = try shared_provider_composition.recordPoseidon2(
                main,
                is_first,
                current,
                previous,
                partial_claims,
                self.challenges,
                self.composition_randomness,
                denominator,
                &self.accumulation,
            );
            try self.advance(placement, recorded_count);
            return recorded_count;
        }

        /// Exact native row-35 replay.  No caller-provided tuple or multiplicity
        /// enters this boundary: all values come from the authenticated capture.
        pub fn recordRangeCheck8x8Provider(
            self: *Self,
            adapter: *const RangeCheck8x8Adapter,
        ) Error!usize {
            try self.requireActive();
            if (self.next_row != RANGE_ROW) return error.ComponentOrderMismatch;
            _ = adapter.binding(self.manifest) catch
                return error.ManifestAuthorityMismatch;

            const placement = self.manifest.placements[RANGE_ROW] orelse
                return error.InvalidManifest;
            if (!adapter.placement.eql(placement) or
                !std.meta.eql(
                    placement.geometry,
                    RangeCheck8x8Adapter.manifestGeometry(),
                ))
            {
                return error.ComponentGeometryMismatch;
            }

            const tuple = [2]recorder.Scalar{
                try self.layout.at(
                    self.sampled_values,
                    capture_layout.PREPROCESSED_TREE_INDEX,
                    @as(usize, placement.preprocessed_offset) + 1,
                    0,
                ),
                try self.layout.at(
                    self.sampled_values,
                    capture_layout.PREPROCESSED_TREE_INDEX,
                    @as(usize, placement.preprocessed_offset) + 2,
                    0,
                ),
            };
            const is_first = try self.layout.at(
                self.sampled_values,
                capture_layout.PREPROCESSED_TREE_INDEX,
                placement.preprocessed_offset,
                0,
            );
            const signed_multiplicity = try self.layout.at(
                self.sampled_values,
                capture_layout.MAIN_TREE_INDEX,
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
                self.denominator_cache,
            );
            const recorded_count =
                try shared_provider_composition.recordRangeCheck8x8(
                    tuple,
                    signed_multiplicity,
                    current,
                    previous,
                    is_first,
                    self.claim_inputs[RANGE_ROW],
                    self.challenges,
                    self.composition_randomness,
                    denominator,
                    &self.accumulation,
                );
            try self.advance(placement, recorded_count);
            return recorded_count;
        }

        pub fn finishProgram(
            self: *Self,
        ) Error!ProgramResultV3 {
            try self.requireActive();
            if (self.next_row != program_row_count or
                self.constraint_count != self.manifest.total_constraints)
            {
                return if (proof_kind == .segment_leaf)
                    error.IncompleteSegmentProgram
                else
                    error.IncompleteProgram;
            }
            try self.builder.check();
            self.finished = true;
            return .{
                .accumulation = self.accumulation,
                .constraint_count = self.constraint_count,
                .row_count = self.next_row,
            };
        }

        pub fn sampledValue(
            self: *const Self,
            tree: usize,
            column: usize,
            sample: usize,
        ) Error!recorder.Scalar {
            return self.layout.at(self.sampled_values, tree, column, sample);
        }

        pub fn claimedSum(
            self: *const Self,
            row: manifest_contract.ComponentKey,
        ) recorder.Scalar {
            return self.claim_inputs[@intFromEnum(row)];
        }

        pub fn poseidonPartialClaim(
            self: *const Self,
            index: u1,
        ) recorder.Scalar {
            return self.claim_inputs[POSEIDON_AUX_START + index];
        }

        fn sampledInteraction(
            self: *const Self,
            column: usize,
            sample: usize,
        ) Error!recorder.Scalar {
            var partials: [qm31.SECURE_EXTENSION_DEGREE]recorder.Scalar =
                undefined;
            for (&partials, 0..) |*partial, coordinate| {
                partial.* = try self.layout.at(
                    self.sampled_values,
                    capture_layout.INTERACTION_TREE_INDEX,
                    column + coordinate,
                    sample,
                );
            }
            return recorder.fromPartialEvals(partials);
        }

        fn advance(
            self: *Self,
            placement: manifest_contract.Placement,
            recorded_count: usize,
        ) Error!void {
            const expected_count: usize =
                @as(usize, placement.geometry.direct_constraints) +
                placement.geometry.interaction_batches;
            if (recorded_count != expected_count)
                return error.ComponentGeometryMismatch;
            self.constraint_count = std.math.add(
                usize,
                self.constraint_count,
                recorded_count,
            ) catch return error.CircuitTooLarge;
            self.next_row += 1;
        }

        fn requireActive(self: *const Self) Error!void {
            if (self.finished or !self.builder.active)
                return error.CircuitAlreadyFinished;
            try self.builder.check();
        }
    };
}
