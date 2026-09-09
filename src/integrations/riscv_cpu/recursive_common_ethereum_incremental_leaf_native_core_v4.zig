//! Genuine rows-18--34 owner for the schema-3 Ethereum incremental wrapper.
//!
//! This owner reuses the authenticated native verifier core.  Its shared
//! Poseidon prefix is ordered exactly as the wrapper transcript requires:
//! first every call recorded while cold-verifying the stage-101 proof, then
//! every call which commits NodePublic and the padded role-aware IO stream.
//! The verifier core appends its own calls and is the sole row-34 provider.
//!
//! The runtime campaign authority is borrowed and never flattened into a
//! compile-time leaf count.  This module owns no rows 0--17 and cannot mint a
//! wrapper proof or a fold-child capability by itself.

const std = @import("std");
const native_identity_hash = @import("recursive_common_ethereum_incremental_leaf_native_identity_hash_v4.zig");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const child_public =
    @import("recursive_common_ethereum_incremental_leaf_child_public_v4.zig");
const complete_provider =
    @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const public_sums =
    @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig");
const recursive_core = @import("recursive_fri_outer.zig");

const child_statement_mod = @import("recursive_common_ethereum_incremental_leaf_child_statement_v4.zig");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const recorder = recursion.air.composition_graph_recorder;
const lowering = recursion.air.verifier_arithmetic_lowering;
const schedule = recursion.air.verifier_schedule;
const transcript_shape = recursion.transcript_shape;
const shared_schedule = recursion.segment_shared_poseidon_schedule_v2;
const PoseidonCall = shared_schedule.Call;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 18;
pub const LAST_ROW: usize = 34;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const NATIVE_RELATION_COUNT: u32 = 25;
pub const FIXED_PUBLIC_LOGUP_TERM_COUNT: u32 = 69;
pub const VM_AIR_INSTRUCTION_COUNT: u32 =
    schedule.VM_PROGRAM_SPEC_V1.air_instruction_count;
pub const ROWS_18_THROUGH_34_AVAILABLE = true;
pub const RUNTIME_CAMPAIGN_GEOMETRY_REQUIRED = true;
pub const SHARED_PROVIDER_FINALIZED_BY_COMPLETE_COHORT = true;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-native-core/v4-schema3\x00";

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalNativeCoreMismatchV4,
};
pub const CompleteProviderGeometryV4 =
    complete_provider.CompleteProviderGeometryV4;
pub const NativeCoreComponentsV4 =
    recursive_core.NativeSegmentCoreComponentsForManifest(manifest_mod);

/// Borrowed, verifier-owned input boundary for universal row 16.  The fixed
/// public-sum circuit is built with one base-field value per input; exposing
/// the complete QM31 cells here lets the row owner recheck that invariant
/// before narrowing.  Bindings and use counts come from the same authenticated
/// circuit and are never reconstructed from a producer-supplied index list.
pub const PublicInputViewV4 = struct {
    circuit_id: u32,
    bindings: []const public_sums.InputSourceV4,
    values: []const QM31,
    use_counts: []const u32,
    program_identity_sha256: [32]u8,
    evaluation_identity_sha256: [32]u8,

    pub fn validate(self: PublicInputViewV4) Error!void {
        if (self.circuit_id != public_sums.CIRCUIT_ID or
            self.bindings.len == 0 or
            self.values.len != self.bindings.len or
            self.use_counts.len != self.bindings.len or
            std.mem.allEqual(u8, &self.program_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.evaluation_identity_sha256, 0))
        {
            return error.EthereumIncrementalNativeCoreMismatchV4;
        }
        for (self.values) |value| {
            const words = value.toM31Array();
            if (!words[1].isZero() or !words[2].isZero() or
                !words[3].isZero())
            {
                return error.EthereumIncrementalNativeCoreMismatchV4;
            }
        }
    }
};

/// Borrowed plan pair used by universal row 17. The plans are the exact pair
/// already authenticated by `NativeSegmentCoreV2`; row 17 must not derive a
/// second schedule from caller-provided proof dimensions.
pub const ScheduleViewV4 = struct {
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
    vm_public_term_count: u32,
    recursion_public_term_count: u32,

    pub fn validate(self: ScheduleViewV4) !void {
        try self.vm.validate();
        try self.recursion.validate();
        if (self.vm.schema != .vm or self.recursion.schema != .recursion or
            self.vm.spec.public_logup_term_count !=
                self.vm_public_term_count or
            self.recursion.spec.public_logup_term_count !=
                self.recursion_public_term_count)
        {
            return error.EthereumIncrementalNativeCoreMismatchV4;
        }
    }
};

/// Stable heap owner. `NativeSegmentCoreV2` retains pointers into the program,
/// evaluation, plans, boundary layout, and campaign materializer, so this
/// boundary deliberately returns an opaque pointer rather than a movable
/// aggregate.
pub fn OwnerV4(comptime Engine: type) type {
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const ChildPublic = child_public.OwnerV4(Engine);
    const Evaluation = public_sums.OwnedRuntimeEvaluationV4(Engine);
    const Core = recursive_core.NativeSegmentCoreV2;

    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
            statement: *const child_statement_mod.OwnerV4(Engine),
        ) !*Self {
            return initWithLogSizes(
                allocator,
                materialized,
                child,
                statement,
                null,
                null,
            );
        }

        /// Rebuilds rows 18--34 at the authenticated padding target. This is
        /// a genuine trace-generation path: the requested vector is passed
        /// into the native core before Tree0/1/2 allocation.
        pub fn initForLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
            statement: *const child_statement_mod.OwnerV4(Engine),
            requested_log_sizes: recursive_core.NativeSegmentCoreLogSizesV2,
        ) !*Self {
            return initWithLogSizes(
                allocator,
                materialized,
                child,
                statement,
                requested_log_sizes,
                null,
            );
        }

        pub fn initWithIdentityHashes(allocator: std.mem.Allocator, materialized: *const Materialized, child: *const ChildPublic, statement: *const child_statement_mod.OwnerV4(Engine), requested_log_sizes: ?recursive_core.NativeSegmentCoreLogSizesV2, hashes: ?*const native_identity_hash.OwnedPlan) !*Self {
            return initWithLogSizes(allocator, materialized, child, statement, requested_log_sizes, hashes);
        }

        fn initWithLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *const ChildPublic,
            statement: *const child_statement_mod.OwnerV4(Engine),
            requested_log_sizes: ?recursive_core.NativeSegmentCoreLogSizesV2,
            identity_hashes: ?*const native_identity_hash.OwnedPlan,
        ) !*Self {
            try materialized.validate();
            // Child metadata reads project its owned preparation. Admit the
            // caller's child and its live source explicitly at this boundary.
            try child.validate();
            try statement.validate();
            const child_binding = try child.binding();
            if (!std.mem.eql(
                u8,
                &child_binding.stage101_capability_identity_sha256,
                &materialized.base.input.capability_identity_sha256,
            ) or !std.mem.eql(
                u8,
                &child_binding.role_io_identity_sha256,
                &materialized.role_aware_io.identity_sha256,
            )) return error.EthereumIncrementalNativeCoreMismatchV4;
            const statement_arithmetic = if (materialized.initial_input_admission != null) try recursion.ethereum_statement_arithmetic_v4.Prepared.initForEthereumInitialInputs(
                allocator,
                try statement.loweringCircuit(),
                try statement.loweringEvaluation(),
                try child.claimReference(),
                try child.semanticsPrepared(),
            ) else if (materialized.base.input.stage101.profile.usesFieldTranscript()) try recursion.ethereum_statement_arithmetic_v4.Prepared.initForEthereumNativeRoots(
                allocator,
                try statement.loweringCircuit(),
                try statement.loweringEvaluation(),
                try child.claimReference(),
                try child.semanticsPrepared(),
            ) else try recursion.ethereum_statement_arithmetic_v4.Prepared.init(
                allocator,
                try statement.loweringCircuit(),
                try statement.loweringEvaluation(),
                try child.claimReference(),
                try child.semanticsPrepared(),
            );
            var statement_arithmetic_owned = true;
            errdefer if (statement_arithmetic_owned) statement_arithmetic.deinit();
            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);

            const selected_profile = materialized.base.input.stage101.profile.circuitProfile();
            const completion = materialized.base.input.stage101.role_aware_public.value.completion;
            const completion_policy: @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig").CompletionPolicyV1 = if (selected_profile == .fixed_program_narrow_v1 and completion != null and completion.?.kind == .halt_flag) .terminal_halt_v1 else .nonfinal_program_v1;
            var program = if (materialized.initial_input_admission) |initial| try public_sums.OwnedFixedProgramV4.initForInitialInputs(allocator, materialized.campaign_authority, materialized.program_admission orelse return error.EthereumInitialProgramOpeningRequired, initial) else if (materialized.base.composition.program().input_profile.vm_native_continuation_roots) try public_sums.OwnedFixedProgramV4.initWithNativeRoots(allocator, materialized.campaign_authority, materialized.program_admission, materialized.base.input.global_admission != null, selected_profile, completion_policy) else try public_sums.OwnedFixedProgramV4.initWithCompletionPolicy(allocator, materialized.campaign_authority, materialized.program_admission, materialized.base.input.global_admission != null, selected_profile, completion_policy);
            var program_owned = true;
            errdefer if (program_owned) program.deinit();
            var evaluation = try Evaluation.init(
                allocator,
                &program,
                materialized,
            );
            var evaluation_owned = true;
            errdefer if (evaluation_owned) evaluation.deinit();

            var plans = try buildPlans(
                allocator,
                &materialized.base.captured_fri,
                materialized.campaign_authority.view().provider_geometry.role_io_tuple_capacity,
            );
            var plans_owned = true;
            errdefer if (plans_owned) for (&plans) |*plan| plan.deinit();

            const transcript_calls =
                materialized.base.transcript.execution.poseidon_calls;
            const child_io_hash_calls = try child.ioHashCalls();
            const publication_calls = materialized.schedule.callsSlice();
            const identity_calls: []const PoseidonCall = if (identity_hashes) |hashes| hashes.calls() else &.{};
            const authority_count = std.math.add(
                usize,
                child_io_hash_calls.len,
                try std.math.add(usize, publication_calls.len, identity_calls.len),
            ) catch return error.ArithmeticOverflow;
            const boundary_count = std.math.add(
                usize,
                transcript_calls.len,
                authority_count,
            ) catch return error.ArithmeticOverflow;
            const boundary_calls = try allocator.alloc(
                PoseidonCall,
                boundary_count,
            );
            errdefer allocator.free(boundary_calls);
            writeTranscriptCalls(
                boundary_calls[0..transcript_calls.len],
                transcript_calls,
            );
            var boundary_cursor = transcript_calls.len;
            @memcpy(
                boundary_calls[boundary_cursor..][0..child_io_hash_calls.len],
                child_io_hash_calls,
            );
            boundary_cursor += child_io_hash_calls.len;
            @memcpy(
                boundary_calls[boundary_cursor..][0..publication_calls.len],
                publication_calls,
            );
            boundary_cursor += publication_calls.len;
            @memcpy(boundary_calls[boundary_cursor..][0..identity_calls.len], identity_calls);
            boundary_cursor += identity_calls.len;
            if (boundary_cursor != boundary_calls.len)
                return error.EthereumIncrementalNativeCoreMismatchV4;
            const boundary_layout =
                try shared_schedule.SharedPoseidonCallLayoutV2
                    .initBoundaryPrefix(
                    transcript_calls.len,
                    authority_count,
                    boundary_calls,
                );

            backing.* = .{
                .allocator = allocator,
                .materialized = materialized,
                .materialized_identity_sha256 = materialized.identity_sha256,
                .campaign_identity_sha256 = materialized.campaign_authority.view().authority_identity_sha256,
                .transcript_call_count = transcript_calls.len,
                .publication_call_count = publication_calls.len,
                .identity_call_count = identity_calls.len,
                .identity_hashes = identity_hashes,
                .child = child,
                .statement_arithmetic = statement_arithmetic,
                .child_binding = child_binding,
                .program = program,
                .evaluation = evaluation,
                .vm_plan = plans[0],
                .recursion_plan = plans[1],
                .boundary_calls = boundary_calls,
                .boundary_layout = boundary_layout,
                .core = undefined,
                .core_initialized = false,
                .prepared_provider = undefined,
                .identity_sha256 = undefined,
            };
            statement_arithmetic_owned = false;
            program_owned = false;
            evaluation_owned = false;
            plans_owned = false;
            errdefer backing.destroyInitialized();

            const core_inputs = recursive_core.NativeSegmentCoreAuthorityInputsV4{
                .statement_arithmetic = backing.statement_arithmetic,
                .captured = &materialized.base.captured_fri,
                .vm_air = materialized.base.composition.source(),
                .verifier_plans = .{
                    .vm = &backing.vm_plan,
                    .recursion = &backing.recursion_plan,
                },
                .public_native_sum_lane = backing.program.loweringLane(),
                .public_native_sum_evaluation = try backing.evaluation.loweringEvaluation(
                    &backing.program,
                ),
                .public_native_sum_evaluation_id = backing.evaluation.evaluation_identity_sha256,
                .full_query_words = &materialized.base.transcript.query_words,
                .boundary_layout = &backing.boundary_layout,
                .boundary_calls = backing.boundary_calls,
            };
            backing.core = if (requested_log_sizes) |logs|
                try Core.initVersionedV4ForLogSizes(
                    allocator,
                    core_inputs,
                    logs,
                )
            else
                try Core.initVersionedV4(allocator, core_inputs);
            backing.core_initialized = true;
            backing.prepared_provider = try completeProviderGeometryFromStorage(backing);
            backing.identity_sha256 = ownerIdentity(backing, backing.prepared_provider);
            _ = try backing.validatePrepared();
            try (try handle(backing).publicInputView()).validate();
            try (try handle(backing).scheduleView()).validate();
            return handle(backing);
        }

        pub const testing = if (@import("builtin").is_test) struct {
            pub fn exercisePreparedRegression(self: *Self, allocator: std.mem.Allocator, relations: *const recursion.air.universal_challenges.UniversalRelations, providers: *const recursion.air.universal_shared_provider.SharedProviderRelations) !Core.testing.Receipt {
                try self.validateComplete();
                return Core.testing.exercisePreparedRegression(&storage(self).core, allocator, relations, providers);
            }
        } else struct {};

        pub fn deinit(self: *Self) void {
            storage(self).destroyInitialized();
        }

        pub fn validate(self: *const Self) !void {
            _ = try storageConst(self).validate();
        }

        pub fn componentLogSizes(self: *const Self) ![ROW_COUNT]u32 {
            return storageConst(self).core.authority.log_sizes;
        }

        pub fn validateAgainstManifest(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
        ) !void {
            try self.validate();
            try self.validatePreparedAgainstManifest(manifest);
        }

        /// Check the manifest projection of the privately owned core. The
        /// enclosing geometry validates the native source in the same operation;
        /// standalone input admission must use validateAgainstManifest instead.
        pub fn validatePreparedAgainstManifest(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
        ) !void {
            _ = try storageConst(self).validatePrepared();
            try validateCoreManifest(&storageConst(self).core, manifest);
        }

        /// Must be called exactly once after the complete 36-row manifest has
        /// validated this owner. No partial owner may finalize row 34.
        pub fn finalizeSharedProviderMain(
            self: *Self,
            manifest: *const manifest_mod.Manifest,
        ) !void {
            try self.validateAgainstManifest(manifest);
            try storage(self).core.finalizeSharedProviderMain();
            try storage(self).core.validateComplete();
        }

        /// Keep the native core private: a const pointer to Core would still
        /// expose mutable graph, trace and provider slices to its consumers.
        pub fn validateComplete(self: *const Self) !void {
            try self.validate();
            try self.validatePreparedComplete();
        }

        /// Check the mutable native core and provider readiness after the
        /// enclosing Geometry boundary has admitted the shared source. This
        /// retains the full core check and does not cache source validation.
        pub fn validatePreparedComplete(self: *const Self) !void {
            try storageConst(self).core.validatePreparedComplete();
        }

        pub fn validateGenerated(
            self: *const Self,
            generated: *const Core.GeneratedInteractionsV2,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
        ) !void {
            try generated.validateAgainst(
                &storageConst(self).core,
                relations,
                provider_relations,
            );
        }

        /// Rebinds the exact authenticated rows 18--34 AIR definitions to the
        /// role-0 universal manifest. The legacy SegmentV2 component family is
        /// left nominally unchanged; equality of every projected placement is
        /// checked before any adapter is constructed.
        pub fn initComponents(
            self: *Self,
            manifest: *const manifest_mod.Manifest,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
            generated: *const Core.GeneratedInteractionsV2,
        ) !NativeCoreComponentsV4 {
            try self.validatePreparedAgainstManifest(manifest);
            return recursive_core.initNativeSegmentCoreComponentsForManifest(
                manifest_mod,
                &storage(self).core,
                manifest,
                relations,
                provider_relations,
                generated,
            );
        }

        /// Read-only diagnostic traversal; no detached core or proof authority.
        pub fn auditTypedAirRows(self: *const Self, observer: anytype) !void {
            return recursive_core.auditNativeSegmentCoreTypedAirRows(&storageConst(self).core, observer);
        }

        pub fn fillPreprocessedInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            destination: []const []M31,
        ) !void {
            try self.validatePreparedAgainstManifest(manifest);
            const core = &storageConst(self).core;
            try publishCoreTree(
                core,
                &core.preprocessed_tree,
                manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );
        }

        pub fn fillMainInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            destination: []const []M31,
        ) !void {
            try self.validatePreparedAgainstManifest(manifest);
            const core = &storageConst(self).core;
            try core.validatePreparedComplete();
            try publishCoreTree(
                core,
                &core.main_tree,
                manifest,
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );
        }

        pub fn prepareInteractions(
            self: *Self,
            allocator: std.mem.Allocator,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
        ) !Core.GeneratedInteractionsV2 {
            _ = try storageConst(self).validatePrepared();
            return storage(self).core.prepareInteractions(
                allocator,
                relations,
                provider_relations,
            );
        }

        pub fn fillInteractionInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            generated: *const Core.GeneratedInteractionsV2,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
            destination: []const []M31,
        ) !void {
            try self.validatePreparedAgainstManifest(manifest);
            const core = &storageConst(self).core;
            try generated.validateAgainst(core, relations, provider_relations);
            try publishCoreTree(
                core,
                &core.interaction_tree,
                manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
            );
        }

        /// Resource-only bound from retained, authenticated schedules. It does
        /// not re-evaluate rows or mint proof authority. Zero-weight events may
        /// leave slack; padding domains do not inflate the logical row counts.
        pub fn tupleContributionUpperBound(self: *const Self) !usize {
            const core = &storageConst(self).core;
            const authority = &core.authority;
            const vm_air = if (authority.vm_air) |*value| value else return error.EthereumIncrementalNativeCoreMismatchV4;
            const row_events = [_][2]usize{
                .{ core.prepared_relation_rows.vm_input.len, vm_air.relation.events.len },
                .{ authority.composition_control_preprocessing.rows.len, authority.composition_control_relation.events.len },
                .{ authority.query_bits_preprocessing.rows.len, authority.query_bits_relation.events.len },
                .{ authority.query_mapping_preprocessing.rows.len, authority.query_mapping_relation.events.len },
                .{ authority.merkle_root_preprocessing.rows.len, authority.merkle_root_relation.events.len },
                .{ core.prepared_relation_rows.trace_merkle.len, authority.trace_merkle_relation.events.len },
                .{ authority.pcs_preprocessing.rows.len, authority.pcs_relation.events.len },
                .{ core.prepared_relation_rows.fri_leaf.len, authority.fri_leaf_relation.events.len },
                .{ core.prepared_relation_rows.fri_node.len, authority.fri_node_relation.events.len },
                .{ core.prepared_relation_rows.fri_anchor.len, authority.fri_anchor_relation.events.len },
                .{ core.prepared_relation_rows.control.len, authority.control_relation.events.len },
                .{ authority.input_preprocessing.rows.len, authority.input_relation.events.len },
                .{ core.invocations.multiply.len, authority.multiply_relation.events.len },
                .{ core.invocations.inverse.len, authority.inverse_relation.events.len },
                .{ core.invocations.linear.len, authority.linear_relation.events.len },
                .{ core.merkle_paths.invocations.len, authority.merkle_path_relation.events.len },
            };
            var count: usize = 0;
            for (row_events) |item| count = try std.math.add(
                usize,
                count,
                try std.math.mul(usize, item[0], item[1]),
            );
            count = try std.math.add(usize, count, core.poseidonCallCount());
            for (authority.lowering_plan.public_terms) |term| {
                if (term.active_in == .segment and term.multiplicity != 0)
                    count = try std.math.add(usize, count, 1);
            }
            return count;
        }

        pub fn appendTupleContributions(
            self: *const Self,
            allocator: std.mem.Allocator,
            ledger: *recursion.air.relation_interaction.TupleLedger,
        ) !void {
            _ = try storageConst(self).validatePrepared();
            return storageConst(self).core.appendTupleContributions(
                allocator,
                ledger,
                recursion.air.relation_interaction.allDomainMask(),
            );
        }

        pub fn publicWireBoundaryClaim(
            self: *const Self,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
        ) !QM31 {
            // The lowering plan owns its fixed terms, admitted at construction.
            // Finalizing provider columns/generating Tree2 never changes them.
            // Reuse the shared reduction; validate only the new challenge input.
            try relations.validate();
            return storageConst(self).core.authority.lowering_plan.publicBoundaryClaim(.segment_leaf, relations);
        }

        /// Symbolic projection of the same admitted constant/output anchors as
        /// publicWireBoundaryClaim. Challenges remain graph inputs; no observed
        /// boundary scalar or graph evaluation becomes a circuit constant.
        pub fn recordPublicWireBoundary(
            self: *const Self,
            challenges: *const recorder.ChallengeSet,
        ) !recorder.Scalar {
            const authority = &storageConst(self).core.authority;
            return recordPublicWireTerms(authority.lowering_plan.public_terms, challenges);
        }

        pub fn publicWireBoundaryTermCount(self: *const Self) !u32 {
            const count = std.math.cast(u32, storageConst(self).core.authority.lowering_plan.counts(.segment_leaf).public) orelse return error.ArithmeticOverflow;
            if (count == 0) return error.V2CoreCohortMismatch;
            return count;
        }

        /// Value-only projection of immutable construction-admitted geometry.
        /// No caller can mutate the private core through this returned value.
        pub fn verifierParameters(self: *const Self) !@import("ethereum_wrapper_verifier_components_v1.zig").AdmissionParametersV1 {
            const core = &storageConst(self).core;
            return .{
                .query_reference = core.authority.query_bits_reference,
                .poseidon_active_rows = std.math.cast(u32, core.poseidonCallCount()) orelse return error.ArithmeticOverflow,
            };
        }

        /// Copy circuit constants and designated output anchors, never their
        /// evaluated boundary claim. The detached key binds this exact list.
        pub fn copyPublicWireTerms(self: *const Self, allocator: std.mem.Allocator) ![]lowering.PublicWireTerm {
            const authority = &storageConst(self).core.authority;
            const count = try self.publicWireBoundaryTermCount();
            const terms = try allocator.alloc(lowering.PublicWireTerm, count);
            var at: usize = 0;
            for (authority.lowering_plan.public_terms) |term| if (term.active_in == .segment) {
                terms[at] = term;
                at += 1;
            };
            std.debug.assert(at == terms.len);
            return terms;
        }

        /// Copy from the privately owned immutable program admitted at native
        /// core construction. No caller-authored graph or digest is accepted.
        pub fn completionPolicy(self: *const Self) @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig").CompletionPolicyV1 {
            return storageConst(self).program.completionPolicy();
        }

        pub fn initialPacketPreprocessing(self: *const Self) ![recursion.air.ethereum_initial_input_packet_v1.ROW_COUNT]recursion.air.ethereum_initial_input_packet_v1.Preprocessing {
            const program = &storageConst(self).program;
            const shape = program.initial_claim_shape orelse return error.InvalidEthereumInitialInputAdmission;
            const packet = recursion.air.ethereum_initial_input_packet_v1;
            return packet.preprocessing(try packet.lane.Shape.init(shape.max_input_words), &program.circuit, public_sums.CIRCUIT_ID, try program.initialPacketFirstInput());
        }

        pub fn initialPacketWords(self: *const Self) ![recursion.air.ethereum_initial_input_packet_v1.INPUT_COUNT]M31 {
            const backing = storageConst(self);
            const first = try backing.program.initialPacketFirstInput();
            var result: [recursion.air.ethereum_initial_input_packet_v1.INPUT_COUNT]M31 = undefined;
            for (&result, 0..) |*word, index| {
                const input = first + index;
                if (input >= backing.program.bindings.len or !std.meta.eql(backing.program.bindings[input], public_sums.InputSourceV4{ .initial_packet_limb = @intCast(index) })) return error.InvalidEthereumInitialInputAdmission;
                word.* = try backing.evaluation.evaluation.values[input].tryIntoM31();
            }
            return result;
        }

        pub fn publicSumsProgramIdentity(self: *const Self) [32]u8 {
            return storageConst(self).program.program_identity_sha256;
        }

        pub fn authorityIdentity(self: *const Self) ![32]u8 {
            return storageConst(self).identity_sha256;
        }

        /// Stable borrowed view consumed by the role-0 public-spine owner.
        /// `Self` is an opaque heap handle, so all three slices remain at fixed
        /// addresses until `deinit` and cannot be invalidated by a move.
        /// Construction admits these privately owned, immutable allocations.
        /// Provider finalization and interaction generation never mutate them.
        /// Input/proof boundaries call `validate` explicitly; reads do not
        /// revalidate the borrowed materializer through every child owner.
        pub fn publicInputView(self: *const Self) !PublicInputViewV4 {
            const backing = storageConst(self);
            const count = backing.program.bindings.len;
            if (backing.evaluation.evaluation.values.len < count or
                backing.program.circuit.useCounts().len < count)
            {
                return error.EthereumIncrementalNativeCoreMismatchV4;
            }
            const result = PublicInputViewV4{
                .circuit_id = public_sums.CIRCUIT_ID,
                .bindings = backing.program.bindings,
                .values = backing.evaluation.evaluation.values[0..count],
                .use_counts = backing.program.circuit.useCounts()[0..count],
                .program_identity_sha256 = backing.program.program_identity_sha256,
                .evaluation_identity_sha256 = backing.evaluation.evaluation_identity_sha256,
            };
            return result;
        }

        /// Stable borrowed view consumed by the role-0 control-slice owner.
        pub fn scheduleView(self: *const Self) !ScheduleViewV4 {
            const backing = storageConst(self);
            const result = ScheduleViewV4{
                .vm = &backing.vm_plan,
                .recursion = &backing.recursion_plan,
                .vm_public_term_count = backing.vm_plan.spec.public_logup_term_count,
                .recursion_public_term_count = backing.recursion_plan.spec.public_logup_term_count,
            };
            return result;
        }

        /// Exact live geometry for the shared row-34 provider.  Campaign
        /// publication geometry alone is intentionally insufficient here.
        pub fn completeProviderGeometry(
            self: *const Self,
        ) !CompleteProviderGeometryV4 {
            return storageConst(self).prepared_provider;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            materialized_identity_sha256: [32]u8,
            campaign_identity_sha256: [32]u8,
            transcript_call_count: usize,
            publication_call_count: usize,
            identity_call_count: usize,
            identity_hashes: ?*const native_identity_hash.OwnedPlan,
            child: *const ChildPublic,
            statement_arithmetic: *recursion.ethereum_statement_arithmetic_v4.Prepared,
            child_binding: child_public.ChildPublicBindingV4,
            program: public_sums.OwnedFixedProgramV4,
            evaluation: Evaluation,
            vm_plan: schedule.Plan,
            recursion_plan: schedule.Plan,
            boundary_calls: []PoseidonCall,
            boundary_layout: shared_schedule.SharedPoseidonCallLayoutV2,
            core: Core,
            core_initialized: bool,
            /// Independently derived fixed call inventory, immutable after
            /// construction. Explicit validation re-derives it from the core.
            prepared_provider: CompleteProviderGeometryV4,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !CompleteProviderGeometryV4 {
                try self.child.validate();
                const expected_child_binding = try self.child.binding();
                try self.evaluation.validateAgainst(&self.program, self.materialized);
                try self.core.validateCoreReady();
                try self.boundary_layout.validate(self.boundary_calls);
                if (!std.meta.eql(try completeProviderGeometryFromStorage(self), self.prepared_provider)) return error.EthereumIncrementalNativeCoreMismatchV4;
                if (!std.meta.eql(self.child_binding, expected_child_binding) or
                    !std.meta.eql(self.materialized_identity_sha256, self.materialized.identity_sha256) or
                    !std.meta.eql(self.campaign_identity_sha256, self.materialized.campaign_authority.view().authority_identity_sha256) or
                    self.transcript_call_count != self.materialized.base.transcript.execution.poseidon_calls.len or
                    self.publication_call_count != self.materialized.schedule.calls.len or
                    self.identity_call_count != identityHashCallCount(self)) return error.EthereumIncrementalNativeCoreMismatchV4;
                return self.validatePrepared();
            }

            fn validatePrepared(self: *const Storage) !CompleteProviderGeometryV4 {
                try self.vm_plan.validate();
                try self.recursion_plan.validate();
                try self.boundary_layout.validateReceipt();
                if (!self.core_initialized) return error.EthereumIncrementalNativeCoreMismatchV4;
                try self.core.validatePreparedCoreReady();
                const complete = self.prepared_provider;
                try complete.validate();
                if (self.core.authority.statement_arithmetic != self.statement_arithmetic or
                    self.vm_plan.schema != .vm or self.recursion_plan.schema != .recursion or
                    self.boundary_layout.transcript.count() catch 0 != self.transcript_call_count or
                    self.boundary_layout.statement_authority.count() catch 0 !=
                        @as(usize, self.child_binding.child_io_hash_call_count) + self.publication_call_count + self.identity_call_count or
                    !std.mem.eql(u8, &self.identity_sha256, &ownerIdentity(self, complete))) return error.EthereumIncrementalNativeCoreMismatchV4;
                return complete;
            }

            fn destroyInitialized(self: *Storage) void {
                const allocator = self.allocator;
                if (self.core_initialized) self.core.deinit();
                self.statement_arithmetic.deinit();
                allocator.free(self.boundary_calls);
                self.recursion_plan.deinit();
                self.vm_plan.deinit();
                self.evaluation.deinit();
                self.program.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        fn handle(value: *Storage) *Self {
            return @ptrCast(value);
        }

        fn storage(value: *Self) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn storageConst(value: *const Self) *const Storage {
            return @ptrCast(@alignCast(value));
        }

        fn ownerIdentity(value: *const Storage, complete: CompleteProviderGeometryV4) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(IDENTITY_DOMAIN);
            hashInt(&hash, u16, FORMAT_VERSION);
            hashInt(&hash, u16, SCHEMA_VERSION);
            hash.update(&value.materialized_identity_sha256);
            hash.update(&value.campaign_identity_sha256);
            hash.update(&value.child_binding.identity_sha256);
            hash.update(&value.program.program_identity_sha256);
            hash.update(&value.evaluation.evaluation_identity_sha256);
            for (value.vm_plan.authority_digest) |word|
                hashInt(&hash, u32, word);
            for (value.recursion_plan.authority_digest) |word|
                hashInt(&hash, u32, word);
            hash.update(&value.boundary_layout.identity);
            hash.update(&value.core.authority_id);
            hash.update(&complete.identity_sha256);
            return hash.finalResult();
        }
    };
}

fn writeTranscriptCalls(
    destination: []PoseidonCall,
    source: []const recursion.recording_poseidon_channel_v4.PoseidonCall,
) void {
    std.debug.assert(destination.len == source.len);
    for (destination, source) |*output, input| {
        var words: [frontend.air.memory_commitment.poseidon2_air.WIDTH]u32 =
            undefined;
        for (&words, input.input) |*word, value| word.* = value.toU32();
        output.* = .{
            .input = words,
            .wide = false,
            .io = true,
            .narrow_output = null,
        };
    }
}

fn completeProviderGeometryFromStorage(value: anytype) !CompleteProviderGeometryV4 {
    // The core is private to this owner. Validate once before projecting its
    // complete provider inputs; no mutation or retained validation flag intervenes.
    try value.core.validatePreparedCoreReady();
    const calls = try value.core.completePoseidonCalls();
    const layout = value.core.complete_layout;
    const logs = value.core.authority.log_sizes;
    const sealed = try CompleteProviderGeometryV4.mint(
        &layout,
        calls,
        .{
            .child_io_hash = value.child_binding.child_io_hash_call_count,
            .field_publication = @intCast(value.publication_call_count),
            .native_identity_hash = @intCast(value.identity_call_count),
        },
        logs[ROW_COUNT - 1],
    );
    if (@as(usize, sealed.stage101_transcript_call_count) !=
        value.transcript_call_count or
        @as(usize, sealed.child_io_hash_call_count) !=
            value.child_binding.child_io_hash_call_count or
        @as(usize, sealed.field_publication_call_count) !=
            value.publication_call_count or
        @as(usize, sealed.native_identity_hash_call_count) != value.identity_call_count or
        @as(usize, sealed.total_call_count) != calls.len)
    {
        return error.EthereumIncrementalNativeCoreMismatchV4;
    }
    return sealed;
}

fn identityHashCallCount(value: anytype) usize {
    return if (value.identity_hashes) |hashes| hashes.calls().len else 0;
}

/// The native core and focused transcript replay share these exact VM/recursion
/// plans. Callers own both elements and must deinit them after use.
pub const PlanPairV4 = [2]schedule.Plan;

pub fn buildPlans(
    allocator: std.mem.Allocator,
    captured: *const recursion.captured_fri.Owned,
    role_io_tuple_capacity: u32,
) !PlanPairV4 {
    const shape = try scheduleShape(captured);
    const public_term_count = std.math.add(u32, FIXED_PUBLIC_LOGUP_TERM_COUNT, role_io_tuple_capacity) catch
        return error.ArithmeticOverflow;
    const vm_spec = try schedule.ProgramSpec.init(.vm, NATIVE_RELATION_COUNT, public_term_count, VM_AIR_INSTRUCTION_COUNT, NATIVE_RELATION_COUNT);
    var vm = try schedule.Plan.initShape(allocator, vm_spec, shape);
    errdefer vm.deinit();
    const recursion_plan = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, shape);
    return .{ vm, recursion_plan };
}

fn scheduleShape(value: *const recursion.captured_fri.Owned) !schedule.ScheduleShape {
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    if (value.trace_tree_heights.len != tree_heights.len)
        return error.EthereumIncrementalNativeCoreMismatchV4;
    @memcpy(&tree_heights, value.trace_tree_heights);
    return transcript_shape.derive(
        value.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = value.sampled_value_count,
            .queried_values_per_query = value.queried_values_per_query,
            .claimed_sum_count = value.claimed_sum_count,
            .interaction_pow_bits = value.interaction_pow_bits,
            .pcs_pow_bits = value.pcs_pow_bits,
        },
    );
}

/// The retained verifier core was originally parameterized by the appended
/// SegmentV2 manifest.  Role-0 uses the same canonical rows 18--34 through the
/// 36-row universal manifest, so admission compares every owned placement
/// field and copies by the two explicit offsets instead of casting nominal
/// manifest types.
fn validateCoreManifest(core: anytype, manifest: *const manifest_mod.Manifest) !void {
    try core.validatePreparedCoreReady();
    try core.authority.manifest.validate();
    try manifest.validate();
    inline for (FIRST_ROW..LAST_ROW + 1) |row| {
        const source = core.authority.manifest.placements[row] orelse
            return error.EthereumIncrementalNativeCoreMismatchV4;
        const target = manifest.placements[row] orelse
            return error.EthereumIncrementalNativeCoreMismatchV4;
        if (!std.meta.eql(source.geometry, target.geometry))
            return error.EthereumIncrementalNativeCoreMismatchV4;
    }
}

fn publishCoreTree(
    core: anytype,
    source_tree: anytype,
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    try validateCoreManifest(core, manifest);
    const expected_columns: usize = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(manifest.total_preprocessed_columns),
        manifest_mod.MAIN_TREE_INDEX => @intCast(manifest.total_main_columns),
        manifest_mod.INTERACTION_TREE_INDEX => @intCast(manifest.total_interaction_columns),
        else => return error.EthereumIncrementalNativeCoreMismatchV4,
    };
    if (destination.len != expected_columns)
        return error.EthereumIncrementalNativeCoreMismatchV4;

    inline for (FIRST_ROW..LAST_ROW + 1) |row| {
        const source = core.authority.manifest.placements[row].?;
        const target = manifest.placements[row].?;
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(target.geometry.preprocessed_columns),
            manifest_mod.MAIN_TREE_INDEX => @intCast(target.geometry.main_columns),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(target.geometry.interaction_columns),
            else => unreachable,
        };
        const source_offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(source.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(source.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(source.interaction_offset),
            else => unreachable,
        };
        const target_offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(target.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(target.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(target.interaction_offset),
            else => unreachable,
        };
        if (source_offset + count > source_tree.columns.len or
            target_offset + count > destination.len)
        {
            return error.EthereumIncrementalNativeCoreMismatchV4;
        }
        for (0..count) |local| {
            const source_column = source_tree.columns[source_offset + local];
            const target_column = destination[target_offset + local];
            if (target_column.len != source_column.len)
                return error.EthereumIncrementalNativeCoreMismatchV4;
            for (target_column) |value| if (!value.isZero())
                return error.EthereumIncrementalNativeCoreMismatchV4;
            const source_start = @intFromPtr(source_column.ptr);
            const source_end = std.math.add(
                usize,
                source_start,
                std.math.mul(usize, source_column.len, @sizeOf(M31)) catch
                    return error.ArithmeticOverflow,
            ) catch return error.ArithmeticOverflow;
            const target_start = @intFromPtr(target_column.ptr);
            const target_end = std.math.add(
                usize,
                target_start,
                std.math.mul(usize, target_column.len, @sizeOf(M31)) catch
                    return error.ArithmeticOverflow,
            ) catch return error.ArithmeticOverflow;
            if (source_start < target_end and target_start < source_end)
                return error.EthereumIncrementalNativeCoreMismatchV4;
        }
    }

    inline for (FIRST_ROW..LAST_ROW + 1) |row| {
        const source = core.authority.manifest.placements[row].?;
        const target = manifest.placements[row].?;
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(target.geometry.preprocessed_columns),
            manifest_mod.MAIN_TREE_INDEX => @intCast(target.geometry.main_columns),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(target.geometry.interaction_columns),
            else => unreachable,
        };
        const source_offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(source.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(source.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(source.interaction_offset),
            else => unreachable,
        };
        const target_offset: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(target.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(target.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(target.interaction_offset),
            else => unreachable,
        };
        for (0..count) |local| @memcpy(
            destination[target_offset + local],
            source_tree.columns[source_offset + local],
        );
    }
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

/// Arithmetic projection of an already admitted lowering authority. This does
/// not admit a new graph or establish semantics for its constants. The native
/// owner supplies the same immutable plan/reference used by its AIR rows.
/// Keep tuple ordering and signs identical to lowering.Plan.publicBoundaryClaim.
pub fn recordAdmittedPublicWireBoundary(
    plan: *const lowering.Plan,
    reference: lowering.Reference,
    challenges: *const recorder.ChallengeSet,
) !recorder.Scalar {
    try plan.validateAgainst(reference);
    return recordPublicWireTerms(plan.public_terms, challenges);
}

/// Same symbolic tuple equation for a detached key's independently admitted
/// fixed anchors. This does not authenticate a caller-supplied anchor list.
pub fn recordPublicWireTerms(
    terms: []const lowering.PublicWireTerm,
    challenges: *const recorder.ChallengeSet,
) !recorder.Scalar {
    const challenge = challenges.get(.recursion_wire);
    var sum = recorder.Scalar.zero();
    for (terms) |term| {
        if (term.active_in != .segment) continue;
        if (term.circuit_id >= stwo_core.fields.m31.Modulus or
            term.node_id >= stwo_core.fields.m31.Modulus or
            term.multiplicity == 0 or
            term.multiplicity >= stwo_core.fields.m31.Modulus or
            term.role == .request) return error.InvalidPublicAnchor;
        const words = term.value.toM31Array();
        const denominator = try challenge.combine(&.{
            recorder.Scalar.fromBase(M31.fromCanonical(term.circuit_id)),
            recorder.Scalar.fromBase(M31.fromCanonical(term.node_id)),
            recorder.Scalar.fromBase(words[0]),
            recorder.Scalar.fromBase(words[1]),
            recorder.Scalar.fromBase(words[2]),
            recorder.Scalar.fromBase(words[3]),
        });
        const contribution = recorder.Scalar.fromBase(
            M31.fromCanonical(term.multiplicity),
        ).mul(denominator.inverse());
        sum = if (term.role == .consume)
            sum.sub(contribution)
        else
            sum.add(contribution);
    }
    return sum;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 18 or
        LAST_ROW != 34 or ROW_COUNT != 17 or NATIVE_RELATION_COUNT != 25 or
        FIXED_PUBLIC_LOGUP_TERM_COUNT != 69 or
        VM_AIR_INSTRUCTION_COUNT != 101 or
        !ROWS_18_THROUGH_34_AVAILABLE or
        !RUNTIME_CAMPAIGN_GEOMETRY_REQUIRED or
        !SHARED_PROVIDER_FINALIZED_BY_COMPLETE_COHORT or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental native core V4 drifted");
    }
    _ = M31;
}
