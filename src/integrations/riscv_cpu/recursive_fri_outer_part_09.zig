//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const global_closure = context.d_global_closure;
        const air = context.d_air;
        const circuit_mod = context.d_circuit_mod;
        const pcs_circuit_mod = context.d_pcs_circuit_mod;
        const universal = context.d_universal;
        const poseidon2_air = context.d_poseidon2_air;
        const LogIndex = context.d_LogIndex;
        const Engine = context.d_Engine;
        const VerifiedOuterProofV1 = context.d_VerifiedOuterProofV1;
        const SegmentProviderClaimV2 = context.d_SegmentProviderClaimV2;
        const SegmentGlobalClosureReceiptV2 = context.d_SegmentGlobalClosureReceiptV2;
        const CapturePublication = context.d_CapturePublication;
        const STAGE_TELEMETRY_ENV = context.d_STAGE_TELEMETRY_ENV;
        const CLOSURE_DIAGNOSTIC_ENV = context.d_CLOSURE_DIAGNOSTIC_ENV;
        const Error = context.d_Error;
        const ExecutionOptions = context.d_ExecutionOptions;
        const VerifierPlans = context.d_VerifierPlans;
        const SegmentTranscriptInputs = context.d_SegmentTranscriptInputs;
        const Receipt = context.d_Receipt;
        const ProofExecutionPool = context.d_ProofExecutionPool;
        const ScheduleFacts = context.d_ScheduleFacts;
        const proveCaptured = context.d_proveCaptured;
        const verifyCaptured = context.d_verifyCaptured;
        const segmentClosureReceiptIdentity = context.d_segmentClosureReceiptIdentity;
        const allRelationDomainMask = context.d_allRelationDomainMask;
        const stageTelemetryPoolBinding = context.d_stageTelemetryPoolBinding;
        const stageTelemetryPublicationIdentity = context.d_stageTelemetryPublicationIdentity;

        pub fn proveAndVerifyCapturedImpl(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: ?*const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: ?VerifierPlans,
            segment_transcript: ?SegmentTranscriptInputs,
            execution: ExecutionOptions,
            publication: ?CapturePublication,
        ) !Receipt {
            comptime @import("stwo_prover_api").assertProverEngine(Engine);
            try captured.evaluation.validateAgainst(&captured.circuit);
            try captured.pcs_evaluation.validateAgainst(&captured.pcs_circuit);
            const schedule_facts = ScheduleFacts.fromCaptured(captured);

            var execution_pool: ProofExecutionPool = .{};
            try execution_pool.initInPlace(allocator, execution.worker_count);
            defer execution_pool.deinit();
            const effective_worker_count = try execution_pool.visibleWorkerCount();
            stageTelemetryPoolBinding(
                execution.worker_count,
                effective_worker_count,
            );

            var prove_timer = try std.time.Timer.start();
            var bundle = try proveCaptured(
                allocator,
                captured,
                vm_air,
                verifier_plans,
                segment_transcript,
                &execution_pool,
            );
            var proof_owned = true;
            defer if (proof_owned) bundle.proof.deinit(allocator);
            const prove_ns = prove_timer.read();
            const proof_size = bundle.proof.sizeEstimate();

            if (execution.mutation_probes == .enabled) {
                var mutated_claims = bundle.claims;
                mutated_claims.public_boundaries.wire =
                    mutated_claims.public_boundaries.wire.add(QM31.one());
                try expectEarlyRejection(
                    error.AuthorityMismatch,
                    allocator,
                    captured,
                    captured.circuit.profile(),
                    captured.pcs_circuit.profile(),
                    captured.trace_tree_heights,
                    captured.column_log_sizes,
                    schedule_facts,
                    vm_air,
                    verifier_plans,
                    segment_transcript,
                    &bundle.proof,
                    &proof_owned,
                    mutated_claims,
                );
                mutated_claims = bundle.claims;
                mutated_claims.public_boundaries.verifier_input =
                    mutated_claims.public_boundaries.verifier_input.add(QM31.one());
                try expectEarlyRejection(
                    error.AuthorityMismatch,
                    allocator,
                    captured,
                    captured.circuit.profile(),
                    captured.pcs_circuit.profile(),
                    captured.trace_tree_heights,
                    captured.column_log_sizes,
                    schedule_facts,
                    vm_air,
                    verifier_plans,
                    segment_transcript,
                    &bundle.proof,
                    &proof_owned,
                    mutated_claims,
                );
                mutated_claims = bundle.claims;
                mutated_claims.input_wire = mutated_claims.input_wire.add(QM31.one());
                try expectEarlyRejection(
                    error.WireClosureMismatch,
                    allocator,
                    captured,
                    captured.circuit.profile(),
                    captured.pcs_circuit.profile(),
                    captured.trace_tree_heights,
                    captured.column_log_sizes,
                    schedule_facts,
                    vm_air,
                    verifier_plans,
                    segment_transcript,
                    &bundle.proof,
                    &proof_owned,
                    mutated_claims,
                );
                mutated_claims = bundle.claims;
                mutated_claims.composition_control =
                    mutated_claims.composition_control.add(QM31.one());
                try expectEarlyRejection(
                    error.AuthorityMismatch,
                    allocator,
                    captured,
                    captured.circuit.profile(),
                    captured.pcs_circuit.profile(),
                    captured.trace_tree_heights,
                    captured.column_log_sizes,
                    schedule_facts,
                    vm_air,
                    verifier_plans,
                    segment_transcript,
                    &bundle.proof,
                    &proof_owned,
                    mutated_claims,
                );
                if (vm_air != null) {
                    mutated_claims = bundle.claims;
                    mutated_claims.vm_input = mutated_claims.vm_input.add(QM31.one());
                    try expectEarlyRejection(
                        error.AuthorityMismatch,
                        allocator,
                        captured,
                        captured.circuit.profile(),
                        captured.pcs_circuit.profile(),
                        captured.trace_tree_heights,
                        captured.column_log_sizes,
                        schedule_facts,
                        vm_air,
                        verifier_plans,
                        segment_transcript,
                        &bundle.proof,
                        &proof_owned,
                        mutated_claims,
                    );
                }
                const root_word = bundle.proof.commitment_scheme_proof.commitments.items[0][0];
                bundle.proof.commitment_scheme_proof.commitments.items[0][0] =
                    root_word ^ 1;
                var failed_publication: VerifiedOuterProofV1 = undefined;
                @memset(std.mem.asBytes(&failed_publication), 0xa5);
                const publication_before = std.mem.asBytes(
                    &failed_publication,
                )[0..@sizeOf(VerifiedOuterProofV1)].*;
                const root_rejection = verifyCaptured(
                    allocator,
                    captured,
                    captured.circuit.profile(),
                    captured.pcs_circuit.profile(),
                    captured.trace_tree_heights,
                    captured.column_log_sizes,
                    schedule_facts,
                    vm_air,
                    verifier_plans,
                    segment_transcript,
                    &bundle.proof,
                    &proof_owned,
                    bundle.claims,
                    .{ .verified = &failed_publication },
                );
                if (!proof_owned) return error.MutationConsumedProof;
                bundle.proof.commitment_scheme_proof.commitments.items[0][0] = root_word;
                if (root_rejection) |_| return error.MutationAccepted else |err| {
                    if (err != error.PreprocessedRootMismatch)
                        return error.MutationWrongError;
                }
                if (!std.mem.eql(
                    u8,
                    &publication_before,
                    std.mem.asBytes(&failed_publication),
                )) return error.MutationPublishedOutput;
            }

            var verify_timer = try std.time.Timer.start();
            const verification_metrics = try verifyCaptured(
                allocator,
                captured,
                captured.circuit.profile(),
                captured.pcs_circuit.profile(),
                captured.trace_tree_heights,
                captured.column_log_sizes,
                schedule_facts,
                vm_air,
                verifier_plans,
                segment_transcript,
                &bundle.proof,
                &proof_owned,
                bundle.claims,
                publication,
            );
            std.debug.assert(!proof_owned);
            const verify_ns = verify_timer.read();
            stageTelemetryPublicationIdentity(publication);
            return .{
                .proof_size_estimate = proof_size,
                .prove_ns = prove_ns,
                .assembly_ns = bundle.assembly_ns,
                .assembly_profile = bundle.assembly_profile,
                .stark_prove_ns = bundle.stark_prove_ns,
                .verify_ns = verify_ns,
                .vm_input_log_size = bundle.log_sizes[LogIndex.vm_input],
                .composition_control_log_size = bundle.log_sizes[LogIndex.composition_control],
                .query_bits_log_size = bundle.log_sizes[LogIndex.query_bits],
                .query_mapping_log_size = bundle.log_sizes[LogIndex.query_mapping],
                .merkle_root_log_size = bundle.log_sizes[LogIndex.merkle_root],
                .trace_merkle_log_size = bundle.log_sizes[LogIndex.trace_merkle],
                .pcs_deep_log_size = bundle.log_sizes[LogIndex.pcs_deep],
                .fri_leaf_log_size = bundle.log_sizes[LogIndex.fri_leaf],
                .fri_node_log_size = bundle.log_sizes[LogIndex.fri_node],
                .fri_anchor_log_size = bundle.log_sizes[LogIndex.fri_anchor],
                .control_log_size = bundle.log_sizes[LogIndex.fri_control],
                .input_log_size = bundle.log_sizes[LogIndex.fri_input],
                .multiply_log_size = bundle.log_sizes[LogIndex.multiply],
                .inverse_log_size = bundle.log_sizes[LogIndex.inverse],
                .linear_log_size = bundle.log_sizes[LogIndex.linear],
                .merkle_path_log_size = bundle.log_sizes[LogIndex.merkle_path],
                .poseidon2_log_size = bundle.log_sizes[LogIndex.poseidon2],
                .poseidon2_call_count = bundle.poseidon2_call_count,
                .pcs_graph_nodes = bundle.pcs_graph_nodes,
                .pcs_graph_inputs = bundle.pcs_graph_inputs,
                .pcs_graph_outputs = bundle.pcs_graph_outputs,
                .vm_graph_nodes = if (vm_air) |prepared| prepared.circuit.nodes.len else 0,
                .vm_graph_inputs = if (vm_air) |prepared| prepared.circuit.bindings.len else 0,
                .vm_graph_outputs = if (vm_air) |prepared| prepared.circuit.outputs.len else 0,
                .vm_schedule_rows = if (vm_air) |prepared| prepared.preprocessing.rows.len else 0,
                .arithmetic_active_counts = bundle.arithmetic_active_counts,
                .arithmetic_capacity_rows = bundle.arithmetic_capacity_rows,
                .worker_count = execution.worker_count,
                .preprocessed_columns = bundle.geometry[0],
                .main_columns = bundle.geometry[1],
                .interaction_columns = bundle.geometry[2],
                .constraints = bundle.geometry[3],
                .roster_count = if (vm_air != null)
                    air.universal_roster.COMPONENT_COUNT
                else
                    16,
                .active_verifier_rows = if (vm_air != null) 34 else 15,
                .active_provider_rows = if (vm_air != null) 2 else 1,
                .transcript_draws = bundle.transcript_draws,
                .mutation_probe_mode = execution.mutation_probes,
                .mutation_rejections = if (execution.mutation_probes == .enabled)
                    4 + @as(u8, @intFromBool(vm_air != null))
                else
                    0,
                .exact_domain_closure_checked = verification_metrics.exact_domain_closure_checked,
                .exact_domain_closure_ns = verification_metrics.exact_domain_closure_ns,
            };
        }

        pub fn expectEarlyRejection(
            expected: anyerror,
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            profile: circuit_mod.Profile,
            pcs_profile: pcs_circuit_mod.Profile,
            trace_tree_heights: []const u32,
            column_log_sizes: []const []const u32,
            schedule_facts: ScheduleFacts,
            vm_air: ?*const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: ?VerifierPlans,
            segment_transcript: ?SegmentTranscriptInputs,
            proof: *recursion.engine.Proof,
            proof_owned: *bool,
            claims: Claims,
        ) !void {
            const owned_before = proof_owned.*;
            if (verifyCaptured(
                allocator,
                captured,
                profile,
                pcs_profile,
                trace_tree_heights,
                column_log_sizes,
                schedule_facts,
                vm_air,
                verifier_plans,
                segment_transcript,
                proof,
                proof_owned,
                claims,
                null,
            )) |_| {
                return error.MutationAccepted;
            } else |err| {
                if (proof_owned.* != owned_before or !proof_owned.*)
                    return error.MutationConsumedProof;
                if (err != expected) return error.MutationWrongError;
            }
        }

        pub const PublicBoundaryClaims = struct {
            wire: QM31,
            verifier_input: QM31,

            fn total(self: PublicBoundaryClaims) QM31 {
                return self.wire.add(self.verifier_input);
            }

            fn eql(self: PublicBoundaryClaims, other: PublicBoundaryClaims) bool {
                return self.wire.eql(other.wire) and
                    self.verifier_input.eql(other.verifier_input);
            }
        };

        pub const Claims = struct {
            segment_leaf: ?recursion.segment_leaf_outer_bundle.Claims,
            vm_input: QM31,
            composition_control: QM31,
            query_bits: QM31,
            query_mapping: QM31,
            merkle_root: QM31,
            trace_merkle: QM31,
            pcs_deep: QM31,
            fri_leaf: QM31,
            fri_node: QM31,
            fri_anchor: QM31,
            control: QM31,
            input: QM31,
            multiply: QM31,
            inverse: QM31,
            linear: QM31,
            merkle_path: QM31,
            poseidon2: [poseidon2_air.N_SUMS]QM31,
            public_boundaries: PublicBoundaryClaims,
            input_wire: QM31,

            fn verifyWireClosure(self: Claims) Error!void {
                if (!self.input_wire
                    .add(self.multiply)
                    .add(self.inverse)
                    .add(self.linear)
                    .add(self.public_boundaries.wire)
                    .isZero())
                {
                    return error.WireClosureMismatch;
                }
            }
        };

        pub const RelationDomain = @TypeOf(
            recursion.segment_statement_outer_source.GLOBAL_CLOSURE_EDGES[0].domain,
        );
        pub const DomainAudit = air.relation_interaction.DomainAudit;
        pub const TupleLedger = air.relation_interaction.TupleLedger;
        pub const TupleRole = @TypeOf(
            @as(air.relation_interaction.TupleContribution, undefined).role,
        );

        pub fn relationDomainBit(comptime domain: RelationDomain) u64 {
            return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(domain)));
        }

        /// Diagnostic-only, exact decomposition of every universal roster claim by
        /// relation domain. The production path does not construct this value unless
        /// explicitly requested through `CLOSURE_DIAGNOSTIC_ENV`.
        pub const ClosureAudit = struct {
            rows: [air.universal_roster.COMPONENT_COUNT]DomainAudit,
            public_boundaries: PublicBoundaryClaims,
            tuple_ledger: TupleLedger,
            collect_tuples: bool,

            pub fn init(
                allocator: std.mem.Allocator,
                collect_tuples: bool,
            ) ClosureAudit {
                return .{
                    .rows = [_]DomainAudit{emptyDomainAudit()} **
                        air.universal_roster.COMPONENT_COUNT,
                    .public_boundaries = .{
                        .wire = QM31.zero(),
                        .verifier_input = QM31.zero(),
                    },
                    .tuple_ledger = TupleLedger.init(allocator),
                    .collect_tuples = collect_tuples,
                };
            }

            pub fn tupleLedger(self: *ClosureAudit) ?*TupleLedger {
                return if (self.collect_tuples) &self.tuple_ledger else null;
            }

            pub fn deinit(self: *ClosureAudit) void {
                self.tuple_ledger.deinit();
                self.* = undefined;
            }
        };

        pub const ExactClosurePreflightV2 = struct {
            row_claims_id: [32]u8,
            active_domain_mask: u64,
            prefix_totals: [global_closure.DOMAIN_COUNT]QM31,
            provider_claim: SegmentProviderClaimV2,
            public_boundaries: global_closure.PublicBoundariesV2,
            closed_totals: [global_closure.DOMAIN_COUNT]QM31,
            framework_total: QM31,

            pub fn finalize(
                self: ExactClosurePreflightV2,
                manifest_id: recursion.poseidon2_channel.Digest,
                verifier_receipt_id: recursion.poseidon2_channel.Digest,
                relation_replay_id: recursion.poseidon2_channel.Digest,
            ) !SegmentGlobalClosureReceiptV2 {
                var result = SegmentGlobalClosureReceiptV2{
                    .checked_domain_mask = allRelationDomainMask(),
                    .active_domain_mask = self.active_domain_mask,
                    .native_manifest_id = manifest_id,
                    .native_verifier_receipt_id = verifier_receipt_id,
                    .native_relation_replay_id = relation_replay_id,
                    .row_claims_id = self.row_claims_id,
                    .prefix_totals = self.prefix_totals,
                    .provider_claim = self.provider_claim,
                    .public_boundaries = self.public_boundaries,
                    .closed_totals = self.closed_totals,
                    .framework_total = self.framework_total,
                    .closure_id = undefined,
                };
                result.closure_id = segmentClosureReceiptIdentity(&result);
                try result.validate();
                return result;
            }

            /// Fail-atomic materialization used by the post-STARK publication path.
            /// The caller's destination is untouched until the complete receipt and
            /// both identity families validate.
            pub fn finalizeInto(
                self: ExactClosurePreflightV2,
                manifest_id: recursion.poseidon2_channel.Digest,
                verifier_receipt_id: recursion.poseidon2_channel.Digest,
                relation_replay_id: recursion.poseidon2_channel.Digest,
                destination: *SegmentGlobalClosureReceiptV2,
            ) !void {
                const staged = try self.finalize(
                    manifest_id,
                    verifier_receipt_id,
                    relation_replay_id,
                );
                destination.* = staged;
            }
        };

        pub fn emptyDomainAudit() DomainAudit {
            return .{
                .values = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT,
                .total = QM31.zero(),
                .logical_rows = 0,
                .event_terms = 0,
            };
        }

        pub fn recordDomainAudit(
            allocator: std.mem.Allocator,
            plan: anytype,
            rows: anytype,
            relations: *const universal.UniversalRelations,
            claimed_sum: QM31,
            audit_out: ?*ClosureAudit,
            row: air.universal_roster.Component,
        ) !void {
            if (audit_out) |audit| {
                const domain_audit = plan.auditPreparedDomainSums(
                    allocator,
                    rows,
                    relations,
                    claimed_sum,
                ) catch |err| {
                    if (std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV)) {
                        std.debug.print(
                            "  recursive-outer exact-domain row={d} name={s} failed={s}\n",
                            .{
                                @intFromEnum(row),
                                air.universal_roster.DESCRIPTORS[@intFromEnum(row)].name,
                                @errorName(err),
                            },
                        );
                    }
                    return err;
                };
                audit.rows[@intFromEnum(row)] = domain_audit;
                if (audit.tupleLedger()) |ledger|
                    try plan.appendPreparedTupleContributions(
                        ledger,
                        @intCast(@intFromEnum(row)),
                        rows,
                        air.relation_interaction.allDomainMask(),
                    );
            }
        }

        pub fn recordSingleDomainAudit(
            audit_out: ?*ClosureAudit,
            row: air.universal_roster.Component,
            domain: RelationDomain,
            claimed_sum: QM31,
            logical_rows: usize,
            event_terms: usize,
        ) void {
            if (audit_out) |audit| {
                var result = emptyDomainAudit();
                result.values[@intFromEnum(domain)] = claimed_sum;
                result.total = claimed_sum;
                result.logical_rows = logical_rows;
                result.event_terms = event_terms;
                audit.rows[@intFromEnum(row)] = result;
            }
        }
    };
}
