//! Internal shard of segment_transcript_outer_source.zig; use the public facade.

const dependency_0 = @import("segment_transcript_outer_source_executors.zig");
const dependency_2 = @import("segment_transcript_outer_source_stage.zig");

const std = dependency_0.std;
const domain_audit = dependency_0.domain_audit;
const component_init = dependency_0.component_init;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const fixed_wire = dependency_0.fixed_wire;
const segment_witness = dependency_0.segment_witness;
const framework = dependency_0.framework;
const relation_interaction = dependency_0.relation_interaction;
const manifest_mod = dependency_0.manifest_mod;
const roster = dependency_0.roster;
const schedule = dependency_0.schedule;
const universal = dependency_0.universal;
const universal_manifest = dependency_0.universal_manifest;
const control_air = dependency_0.control_air;
const control_witness = dependency_0.control_witness;
const transcript_air = dependency_0.transcript_air;
const transcript_air_witness = dependency_0.transcript_air_witness;
const transcript_binding_air = dependency_0.transcript_binding_air;
const transcript_binding_witness = dependency_0.transcript_binding_witness;
const transcript_state_air = dependency_0.transcript_state_air;
const transcript_state_witness = dependency_0.transcript_state_witness;
const transcript_word_air = dependency_0.transcript_word_air;
const transcript_word_witness = dependency_0.transcript_word_witness;
const transcript_payload_air = dependency_0.transcript_payload_air;
const transcript_payload_witness = dependency_0.transcript_payload_witness;
const pow_check_air = dependency_0.pow_check_air;
const pow_frame_air = dependency_0.pow_frame_air;
const relation_challenge_air = dependency_0.relation_challenge_air;
const relation_challenge_witness = dependency_0.relation_challenge_witness;
const verifier_randomness_air = dependency_0.verifier_randomness_air;
const verifier_randomness_witness = dependency_0.verifier_randomness_witness;
const FIRST_ROW = dependency_0.FIRST_ROW;
const ROW_COUNT = dependency_0.ROW_COUNT;
const ControlRelation = dependency_0.ControlRelation;
const TranscriptAirRelation = dependency_0.TranscriptAirRelation;
const TranscriptBindingRelation = dependency_0.TranscriptBindingRelation;
const TranscriptStateRelation = dependency_0.TranscriptStateRelation;
const TranscriptWordRelation = dependency_0.TranscriptWordRelation;
const TranscriptPayloadRelation = dependency_0.TranscriptPayloadRelation;
const PowCheckRelation = dependency_0.PowCheckRelation;
const PowFrameRelation = dependency_0.PowFrameRelation;
const RelationChallengeRelation = dependency_0.RelationChallengeRelation;
const VerifierRandomnessRelation = dependency_0.VerifierRandomnessRelation;
const ControlFramework = dependency_0.ControlFramework;
const TranscriptAirFramework = dependency_0.TranscriptAirFramework;
const TranscriptBindingFramework = dependency_0.TranscriptBindingFramework;
const TranscriptStateFramework = dependency_0.TranscriptStateFramework;
const TranscriptWordFramework = dependency_0.TranscriptWordFramework;
const TranscriptPayloadFramework = dependency_0.TranscriptPayloadFramework;
const PowCheckFramework = dependency_0.PowCheckFramework;
const PowFrameFramework = dependency_0.PowFrameFramework;
const RelationChallengeFramework = dependency_0.RelationChallengeFramework;
const VerifierRandomnessFramework = dependency_0.VerifierRandomnessFramework;
const LogSizes = dependency_0.LogSizes;
const DomainAudits = dependency_0.DomainAudits;
const PowLogSizes = dependency_0.PowLogSizes;
const Parameters = dependency_0.Parameters;
const Claims = dependency_0.Claims;
const Owners = dependency_0.Owners;
const Executors = dependency_0.Executors;
const Components = dependency_0.Components;
const deriveLogSizes = dependency_2.deriveLogSizes;
const rowIndex = dependency_2.rowIndex;
const appendTupleContributions = dependency_2.appendTupleContributions;
const generateIntoStage = dependency_2.generateIntoStage;
const Stage = dependency_2.Stage;
const preflightDestination = dependency_2.preflightDestination;
const traceSize = dependency_2.traceSize;
const sourceColumnCount = dependency_2.sourceColumnCount;

/// Authority and transactional tree writer for one fixed-wire profile.
///
/// Integration order is fixed: construct after native verification, install
/// these ten log sizes before manifest sealing, fill/commit preprocessed and
/// main trees, draw universal relations, fill/commit interactions, then call
/// `initComponents` and keep the returned value stable through prove/verify.
pub fn Source(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    return struct {
        allocator: std.mem.Allocator,
        vm_schedule_digest: [8]u32,
        recursion_schedule_digest: [8]u32,
        log_sizes: LogSizes,
        parameters: Parameters,
        control_preprocessing: control_witness.Preprocessed,
        owners: Owners,
        executors: Executors,

        const Self = @This();
        pub const Prepared = segment_witness.Prepared(dimensions);

        pub fn init(
            allocator: std.mem.Allocator,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            pow_log_sizes: PowLogSizes,
        ) !Self {
            try prepared.validateAgainst(preprocessing, vm_plan, recursion_plan);
            try pow_log_sizes.validateFor(prepared);
            var control_preprocessing = try control_witness.Preprocessed.init(
                allocator,
                vm_plan,
                recursion_plan,
            );
            errdefer control_preprocessing.deinit();
            var owners = try Owners.init(allocator);
            errdefer owners.deinit();
            const executors = try Executors.init(&owners);
            const result = Self{
                .allocator = allocator,
                .vm_schedule_digest = vm_plan.authority_digest,
                .recursion_schedule_digest = recursion_plan.authority_digest,
                .log_sizes = try deriveLogSizes(
                    &control_preprocessing,
                    preprocessing,
                    prepared,
                    pow_log_sizes,
                ),
                .parameters = Parameters.segmentLeaf(),
                .control_preprocessing = control_preprocessing,
                .owners = owners,
                .executors = executors,
            };
            try result.validateAgainst(
                vm_plan,
                recursion_plan,
                preprocessing,
                prepared,
            );
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.owners.deinit();
            self.control_preprocessing.deinit();
            self.* = undefined;
        }

        /// Writes only rows 0--9 into an existing full-roster log vector.
        pub fn installLogSizes(self: *const Self, destination: *universal_manifest.LogSizes) void {
            inline for (0..ROW_COUNT) |index| destination[FIRST_ROW + index] = self.log_sizes[index];
        }

        /// Exact rows 0--9 cell count retained by the transactional fallback
        /// for `tree`. Fresh zero-owned sinks use the direct rollback path and
        /// therefore retain zero additional staging cells.
        pub fn stagingCellCount(self: *const Self, tree: usize) !usize {
            var total: usize = 0;
            inline for (0..ROW_COUNT) |index| {
                const column_count = sourceColumnCount(index, tree) orelse
                    return error.InvalidTreeIndex;
                const row_size = try traceSize(self.log_sizes[index]);
                total = std.math.add(
                    usize,
                    total,
                    std.math.mul(usize, column_count, row_size) catch
                        return error.ArithmeticOverflow,
                ) catch return error.ArithmeticOverflow;
            }
            return total;
        }

        /// Exact byte counterpart of `stagingCellCount` for capacity reports.
        pub fn stagingByteCount(self: *const Self, tree: usize) !usize {
            return std.math.mul(
                usize,
                try self.stagingCellCount(tree),
                @sizeOf(M31),
            ) catch return error.ArithmeticOverflow;
        }

        pub fn validateAgainst(
            self: *const Self,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
        ) !void {
            if (!std.meta.eql(self.vm_schedule_digest, vm_plan.authority_digest) or
                !std.meta.eql(
                    self.recursion_schedule_digest,
                    recursion_plan.authority_digest,
                ))
            {
                return error.ScheduleAuthorityMismatch;
            }
            try self.control_preprocessing.validateAgainst(vm_plan, recursion_plan);
            try prepared.validateAgainst(preprocessing, vm_plan, recursion_plan);
            const expected_logs = try deriveLogSizes(
                &self.control_preprocessing,
                preprocessing,
                prepared,
                .{
                    .check = self.log_sizes[rowIndex(.pow_check)],
                    .frame = self.log_sizes[rowIndex(.pow_frame)],
                },
            );
            if (!std.meta.eql(self.log_sizes, expected_logs))
                return error.SourceLogSizeMismatch;
            if (!std.meta.eql(self.parameters, Parameters.segmentLeaf()))
                return error.PreparedAuthorityMismatch;
            try self.owners.validate();
            try self.executors.validate(&self.owners);
        }

        pub fn validateManifest(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
        ) !void {
            try manifest.validate();
            inline for (0..ROW_COUNT) |index| {
                const row: roster.Component = @enumFromInt(FIRST_ROW + index);
                const placement = try manifest.placement(row);
                if (placement.geometry.roster_row != FIRST_ROW + index or
                    placement.geometry.log_size != self.log_sizes[index])
                {
                    return error.ManifestGeometryMismatch;
                }
            }
        }

        /// Transactional preprocessed fill. Fresh zero sinks are written
        /// directly with allocation-free rollback; arbitrary sinks retain a
        /// copy-on-success staging allocation.
        pub fn fillPreprocessedInto(
            self: *const Self,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            manifest: *const manifest_mod.Manifest,
            destination: []const []M31,
        ) !void {
            try self.validateAgainst(vm_plan, recursion_plan, preprocessing, prepared);
            try self.validateManifest(manifest);
            try preflightDestination(manifest, manifest_mod.PREPROCESSED_TREE_INDEX, destination);
            var stage = try Stage.init(
                self.allocator,
                manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );
            defer stage.deinit();

            var control_columns = try stage.columns(
                control_air.PREPROCESSED_COLUMN_COUNT,
                .control,
            );
            try self.control_preprocessing.generateInto(
                &control_columns,
                vm_plan,
                recursion_plan,
            );
            var binding_columns = try stage.columns(
                transcript_binding_air.PREPROCESSED_COLUMN_COUNT,
                .transcript_binding,
            );
            try self.executors.transcript_binding.generatePreprocessedInto(
                &preprocessing.transcript_binding,
                &binding_columns,
            );
            var state_columns = try stage.columns(
                transcript_state_air.PREPROCESSED_COLUMN_COUNT,
                .transcript_state,
            );
            try self.executors.transcript_state.generatePreprocessedInto(
                &preprocessing.transcript_state,
                &state_columns,
            );
            var word_columns = try stage.columns(
                transcript_word_air.PREPROCESSED_COLUMN_COUNT,
                .transcript_word,
            );
            try self.executors.transcript_word.generatePreprocessedInto(
                &preprocessing.transcript_word,
                &word_columns,
            );
            var payload_columns = try stage.columns(
                transcript_payload_air.PREPROCESSED_COLUMN_COUNT,
                .transcript_payload,
            );
            try self.executors.transcript_payload.generatePreprocessedInto(
                &preprocessing.transcript_payload,
                &payload_columns,
            );
            var relation_columns = try stage.columns(
                relation_challenge_air.PREPROCESSED_COLUMN_COUNT,
                .relation_challenge,
            );
            try self.executors.relation_challenge.generatePreprocessedInto(
                &preprocessing.relation_challenge,
                &relation_columns,
                vm_plan,
                recursion_plan,
            );
            var randomness_columns = try stage.columns(
                verifier_randomness_air.PREPROCESSED_COLUMN_COUNT,
                .verifier_randomness,
            );
            try self.executors.verifier_randomness.generatePreprocessedInto(
                &preprocessing.verifier_randomness,
                &randomness_columns,
                vm_plan,
                recursion_plan,
            );
            stage.commit(manifest);
        }

        /// Transactional proof-derived main fill. All nine active main families
        /// consume snapshots from the same checked `Prepared` aggregate.
        pub fn fillMainInto(
            self: *const Self,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            manifest: *const manifest_mod.Manifest,
            destination: []const []M31,
        ) !void {
            try self.validateAgainst(vm_plan, recursion_plan, preprocessing, prepared);
            try self.validateManifest(manifest);
            try preflightDestination(manifest, manifest_mod.MAIN_TREE_INDEX, destination);
            var stage = try Stage.init(
                self.allocator,
                manifest,
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );
            defer stage.deinit();

            var transcript_columns = try stage.columns(
                transcript_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .transcript_air,
            );
            try self.executors.transcript_air.generateMainInto(
                &prepared.transcript_air,
                &transcript_columns,
            );
            var binding_columns = try stage.columns(
                transcript_binding_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .transcript_binding,
            );
            try self.executors.transcript_binding.generateMainInto(
                &prepared.transcript_binding,
                &preprocessing.transcript_binding,
                &binding_columns,
            );
            var state_columns = try stage.columns(
                transcript_state_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .transcript_state,
            );
            try self.executors.transcript_state.generateMainInto(
                &prepared.transcript_state,
                &preprocessing.transcript_state,
                &state_columns,
            );
            var word_columns = try stage.columns(
                transcript_word_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .transcript_word,
            );
            try self.executors.transcript_word.generateMainInto(
                &preprocessing.transcript_word,
                &prepared.transcript_word,
                &word_columns,
            );
            var payload_columns = try stage.columns(
                transcript_payload_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .transcript_payload,
            );
            try self.executors.transcript_payload.generateMainInto(
                &preprocessing.transcript_payload,
                &prepared.transcript_payload,
                &payload_columns,
            );
            var pow_check_columns = try stage.columns(
                pow_check_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .pow_check,
            );
            try self.executors.pow_check.generateMainInto(
                &prepared.pow_check,
                &pow_check_columns,
                self.log_sizes[rowIndex(.pow_check)],
            );
            var pow_frame_columns = try stage.columns(
                pow_frame_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .pow_frame,
            );
            try self.executors.pow_frame.generateMainInto(
                &prepared.pow_frame,
                &pow_frame_columns,
                self.log_sizes[rowIndex(.pow_frame)],
            );
            var relation_columns = try stage.columns(
                relation_challenge_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .relation_challenge,
            );
            try self.executors.relation_challenge.generateMainInto(
                &prepared.relation_challenge,
                &preprocessing.relation_challenge,
                &relation_columns,
            );
            var randomness_columns = try stage.columns(
                verifier_randomness_air.PHYSICAL_MAIN_COLUMN_COUNT,
                .verifier_randomness,
            );
            try self.executors.verifier_randomness.generateMainInto(
                &prepared.verifier_randomness,
                &preprocessing.verifier_randomness,
                &randomness_columns,
            );
            stage.commit(manifest);
        }

        /// Generates all ten framework LogUp traces transactionally and
        /// returns their exact claimed sums. Fresh zero sinks avoid retaining
        /// a second complete rows 0--9 interaction tree.
        pub fn fillInteractionInto(
            self: *const Self,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            destination: []const []M31,
        ) !Claims {
            try self.validateAgainst(vm_plan, recursion_plan, preprocessing, prepared);
            try self.validateManifest(manifest);
            try relations.validate();
            try preflightDestination(manifest, manifest_mod.INTERACTION_TREE_INDEX, destination);
            var stage = try Stage.init(
                self.allocator,
                manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
            );
            defer stage.deinit();

            const claims = Claims{
                .control = try self.generateControlInteraction(relations, &stage),
                .transcript_air = try self.generateTranscriptAirInteraction(
                    prepared,
                    relations,
                    &stage,
                ),
                .transcript_binding = try self.generateTranscriptBindingInteraction(
                    preprocessing,
                    prepared,
                    relations,
                    &stage,
                ),
                .transcript_state = try self.generateTranscriptStateInteraction(
                    preprocessing,
                    prepared,
                    relations,
                    &stage,
                ),
                .transcript_word = try self.generateTranscriptWordInteraction(
                    preprocessing,
                    prepared,
                    relations,
                    &stage,
                ),
                .transcript_payload = try self.generateTranscriptPayloadInteraction(
                    preprocessing,
                    prepared,
                    relations,
                    &stage,
                ),
                .pow_check = try self.generatePowCheckInteraction(prepared, relations, &stage),
                .pow_frame = try self.generatePowFrameInteraction(prepared, relations, &stage),
                .relation_challenge = try self.generateRelationChallengeInteraction(
                    preprocessing,
                    prepared,
                    relations,
                    &stage,
                ),
                .verifier_randomness = try self.generateVerifierRandomnessInteraction(
                    preprocessing,
                    prepared,
                    relations,
                    &stage,
                ),
            };
            stage.commit(manifest);
            return claims;
        }

        /// Cold provenance pass for the exact rows used by
        /// `fillInteractionInto`. It is intentionally separate from trace
        /// generation so production proving pays no extra evaluation or
        /// allocation cost. Every returned domain decomposition is checked
        /// against the already-produced component claim.
        pub fn auditInteractionDomains(
            self: *const Self,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            claims: Claims,
            tuple_ledger: ?*relation_interaction.TupleLedger,
        ) !DomainAudits {
            return domain_audit.audit(
                self,
                vm_plan,
                recursion_plan,
                preprocessing,
                prepared,
                relations,
                claims,
                tuple_ledger,
                DomainAudits,
                rowIndex,
                appendTupleContributions,
            );
        }

        pub fn initComponents(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            claims: Claims,
        ) !Components {
            return component_init.init(
                self,
                manifest,
                relations,
                claims,
                Components,
                rowIndex,
            );
        }

        fn generateControlInteraction(
            self: *const Self,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                ControlRelation.Row,
                self.control_preprocessing.rows.len,
            );
            defer self.allocator.free(rows);
            for (rows, self.control_preprocessing.rows) |*target, source|
                target.* = control_witness.logicalRow(source, .segment_leaf);
            return generateIntoStage(
                ControlFramework,
                self.allocator,
                &self.owners.control.relation,
                rows,
                self.log_sizes[rowIndex(.control)],
                relations,
                stage,
                .control,
            );
        }

        fn generateTranscriptAirInteraction(
            self: *const Self,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                TranscriptAirRelation.Row,
                prepared.transcript_air.rows.len,
            );
            defer self.allocator.free(rows);
            for (rows, prepared.transcript_air.rows) |*target, source|
                target.* = try transcript_air_witness.logicalRow(source);
            return generateIntoStage(
                TranscriptAirFramework,
                self.allocator,
                &self.owners.transcript_air.relation,
                rows,
                self.log_sizes[rowIndex(.transcript_air)],
                relations,
                stage,
                .transcript_air,
            );
        }

        fn generateTranscriptBindingInteraction(
            self: *const Self,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                TranscriptBindingRelation.Row,
                preprocessing.transcript_binding.rows.len,
            );
            defer self.allocator.free(rows);
            for (
                rows,
                prepared.transcript_binding.rows,
                preprocessing.transcript_binding.rows,
            ) |*target, main, pp| target.* = transcript_binding_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
            );
            return generateIntoStage(
                TranscriptBindingFramework,
                self.allocator,
                &self.owners.transcript_binding.relation,
                rows,
                self.log_sizes[rowIndex(.transcript_binding)],
                relations,
                stage,
                .transcript_binding,
            );
        }

        fn generateTranscriptStateInteraction(
            self: *const Self,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                TranscriptStateRelation.Row,
                preprocessing.transcript_state.rows.len,
            );
            defer self.allocator.free(rows);
            for (
                rows,
                prepared.transcript_state.rows,
                preprocessing.transcript_state.rows,
            ) |*target, main, pp| target.* = transcript_state_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
            );
            return generateIntoStage(
                TranscriptStateFramework,
                self.allocator,
                &self.owners.transcript_state.relation,
                rows,
                self.log_sizes[rowIndex(.transcript_state)],
                relations,
                stage,
                .transcript_state,
            );
        }

        fn generateTranscriptWordInteraction(
            self: *const Self,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                TranscriptWordRelation.Row,
                preprocessing.transcript_word.rows.len,
            );
            defer self.allocator.free(rows);
            for (
                rows,
                preprocessing.transcript_word.rows,
                prepared.transcript_word.values,
            ) |*target, pp, value| target.* = try transcript_word_witness.logicalRow(
                pp,
                value,
                .segment_leaf,
            );
            return generateIntoStage(
                TranscriptWordFramework,
                self.allocator,
                &self.owners.transcript_word.relation,
                rows,
                self.log_sizes[rowIndex(.transcript_word)],
                relations,
                stage,
                .transcript_word,
            );
        }

        fn generateTranscriptPayloadInteraction(
            self: *const Self,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                TranscriptPayloadRelation.Row,
                preprocessing.transcript_payload.rows.len,
            );
            defer self.allocator.free(rows);
            for (
                rows,
                preprocessing.transcript_payload.rows,
                prepared.transcript_payload.values,
            ) |*target, pp, value| target.* = try transcript_payload_witness.logicalRow(
                pp,
                value,
                .segment_leaf,
            );
            return generateIntoStage(
                TranscriptPayloadFramework,
                self.allocator,
                &self.owners.transcript_payload.relation,
                rows,
                self.log_sizes[rowIndex(.transcript_payload)],
                relations,
                stage,
                .transcript_payload,
            );
        }

        fn generatePowCheckInteraction(
            self: *const Self,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                PowCheckRelation.Row,
                prepared.pow_check.invocations.len,
            );
            defer self.allocator.free(rows);
            for (rows, 0..) |*target, index|
                target.* = prepared.pow_check.preparedRow(index);
            return generateIntoStage(
                PowCheckFramework,
                self.allocator,
                &self.owners.pow_check.relation,
                rows,
                self.log_sizes[rowIndex(.pow_check)],
                relations,
                stage,
                .pow_check,
            );
        }

        fn generatePowFrameInteraction(
            self: *const Self,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                PowFrameRelation.Row,
                prepared.pow_frame.invocations.len,
            );
            defer self.allocator.free(rows);
            for (rows, 0..) |*target, index|
                target.* = prepared.pow_frame.preparedRow(index);
            return generateIntoStage(
                PowFrameFramework,
                self.allocator,
                &self.owners.pow_frame.relation,
                rows,
                self.log_sizes[rowIndex(.pow_frame)],
                relations,
                stage,
                .pow_frame,
            );
        }

        fn generateRelationChallengeInteraction(
            self: *const Self,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                RelationChallengeRelation.Row,
                preprocessing.relation_challenge.rows.len,
            );
            defer self.allocator.free(rows);
            for (
                rows,
                prepared.relation_challenge.rows,
                preprocessing.relation_challenge.rows,
            ) |*target, main, pp| target.* = relation_challenge_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
            );
            return generateIntoStage(
                RelationChallengeFramework,
                self.allocator,
                &self.owners.relation_challenge.relation,
                rows,
                self.log_sizes[rowIndex(.relation_challenge)],
                relations,
                stage,
                .relation_challenge,
            );
        }

        fn generateVerifierRandomnessInteraction(
            self: *const Self,
            preprocessing: *const segment_witness.Preprocessing,
            prepared: *const Prepared,
            relations: *const universal.UniversalRelations,
            stage: *Stage,
        ) !QM31 {
            const rows = try self.allocator.alloc(
                VerifierRandomnessRelation.Row,
                preprocessing.verifier_randomness.rows.len,
            );
            defer self.allocator.free(rows);
            for (
                rows,
                prepared.verifier_randomness.rows,
                preprocessing.verifier_randomness.rows,
            ) |*target, main, pp| target.* = verifier_randomness_witness.logicalInputs(
                main,
                pp,
                .segment_leaf,
            );
            return generateIntoStage(
                VerifierRandomnessFramework,
                self.allocator,
                &self.owners.verifier_randomness.relation,
                rows,
                self.log_sizes[rowIndex(.verifier_randomness)],
                relations,
                stage,
                .verifier_randomness,
            );
        }
    };
}
