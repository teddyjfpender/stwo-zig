//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const stwo_core = context.d_stwo_core;
        const frontend = context.d_frontend;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const global_closure = context.d_global_closure;
        const air = context.d_air;
        const query_bits_witness = context.d_query_bits_witness;
        const schedule = context.d_schedule;
        const composition_graph = context.d_composition_graph;
        const lowering = context.d_lowering;
        const universal = context.d_universal;
        const segment_transcript_source_v2 = context.d_segment_transcript_source_v2;
        const public_native_sum = context.d_public_native_sum;
        const SegmentTranscriptSource = context.d_SegmentTranscriptSource;
        const SegmentPublicSource = context.d_SegmentPublicSource;
        const V2_ROWS_18_35_PREFLIGHT_FORMAT_VERSION = context.d_V2_ROWS_18_35_PREFLIGHT_FORMAT_VERSION;
        const V2_UNIVERSAL_ROSTER_COMPONENT_COUNT = context.d_V2_UNIVERSAL_ROSTER_COMPONENT_COUNT;
        const V2_AUTHORITY_SOURCE_COMPONENT_COUNT = context.d_V2_AUTHORITY_SOURCE_COMPONENT_COUNT;
        const V2_TARGET_COMPONENT_COUNT = context.d_V2_TARGET_COMPONENT_COUNT;
        const validateMaterializedArithmeticLane = context.d_validateMaterializedArithmeticLane;
        const classifySingleArithmeticLaneTupleClosure = context.d_classifySingleArithmeticLaneTupleClosure;
        const RelationDomain = context.d_RelationDomain;
        const TupleLedger = context.d_TupleLedger;
        const relationDomainBit = context.d_relationDomainBit;
        const emptyDomainAudit = context.d_emptyDomainAudit;
        const Authority = context.d_Authority;
        const InvocationBuffers = context.d_InvocationBuffers;
        const validateAuxiliaryDigest = context.d_validateAuxiliaryDigest;
        const validateCoreDomainAudit = context.d_validateCoreDomainAudit;
        const v2Rows18Through35PreflightIdentity = context.d_v2Rows18Through35PreflightIdentity;
        const requireSha256Id = context.d_requireSha256Id;
        const allRelationDomainMask = context.d_allRelationDomainMask;

        pub fn testSingleArithmeticLaneTupleClosure() !void {
            const nodes = [_]composition_graph.Node{
                .{ .op = .input },
                .{ .op = .input },
                .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } },
                .{ .op = .{ .add = .{ .lhs = 2, .rhs = 0 } } },
            };
            const outputs = [_]u32{3};
            const graph_digest = composition_graph.computeGraphDigest(&nodes, &outputs);
            const graph = try composition_graph.CircuitGraph.authenticate(
                &nodes,
                &outputs,
                graph_digest,
            );
            const lanes = [_]lowering.Lane{
                .{
                    .circuit_id = public_native_sum.CIRCUIT_ID,
                    .active_in = .segment,
                    .circuit_identity = graph_digest,
                    .graph = graph,
                },
                .{
                    .circuit_id = public_native_sum.CIRCUIT_ID + 1,
                    .active_in = .binary,
                    .circuit_identity = graph_digest,
                    .graph = graph,
                },
            };
            const reference = try lowering.Reference.seal(&lanes);
            var plan = try lowering.Plan.init(std.testing.allocator, reference);
            defer plan.deinit();

            const two = QM31.fromBase(M31.fromCanonical(2));
            const minus_one = QM31.one().neg();
            const minus_two = two.neg();
            var values = [_]QM31{ two, minus_one, minus_two, QM31.zero() };
            const lane_evaluations = [_]lowering.Evaluation{
                .{
                    .circuit_identity = graph_digest,
                    .values = &values,
                },
                .{
                    .circuit_identity = graph_digest,
                    .values = &values,
                },
            };
            const evaluations = lowering.Evaluations{ .lanes = &lane_evaluations };
            var owned_invocations = try InvocationBuffers.init(
                std.testing.allocator,
                plan.counts(.segment_leaf),
            );
            defer owned_invocations.deinit();
            try plan.materializeInto(
                reference,
                evaluations,
                .segment_leaf,
                owned_invocations.view(),
            );
            try validateMaterializedArithmeticLane(
                reference,
                evaluations,
                .segment_leaf,
                owned_invocations.view(),
                public_native_sum.CIRCUIT_ID,
            );

            var use_count_scratch: [nodes.len]u32 = undefined;
            var ledger = TupleLedger.init(std.testing.allocator);
            defer ledger.deinit();
            const closed = try classifySingleArithmeticLaneTupleClosure(
                lanes[0],
                lane_evaluations[0],
                owned_invocations.view(),
                &use_count_scratch,
                &ledger,
                true,
            );
            try std.testing.expectEqual(@as(usize, 9), closed.contribution_count);
            try std.testing.expectEqual(@as(usize, 0), closed.unmatched_tuple_count);

            // Omitting only the authenticated graph boundary leaves operation rows
            // internally coherent, but exposes the exact missing-emitter/consumer
            // signature seen by the concrete 39-row classifier.
            ledger.contributions.clearRetainingCapacity();
            const omitted_boundary = try classifySingleArithmeticLaneTupleClosure(
                lanes[0],
                lane_evaluations[0],
                owned_invocations.view(),
                &use_count_scratch,
                &ledger,
                false,
            );
            try std.testing.expectEqual(
                @as(usize, 6),
                omitted_boundary.contribution_count,
            );
            try std.testing.expectEqual(
                @as(usize, 3),
                omitted_boundary.unmatched_tuple_count,
            );

            // The lowering API intentionally accepts shape-correct evaluations.  A
            // stale internal value must therefore fail this outer custody gate, and
            // the exact classifier should expose both broken producer/consumer seams.
            values[2] = minus_two.sub(QM31.one());
            try plan.materializeInto(
                reference,
                evaluations,
                .segment_leaf,
                owned_invocations.view(),
            );
            try std.testing.expectError(
                error.MaterializedArithmeticResultMismatch,
                validateMaterializedArithmeticLane(
                    reference,
                    evaluations,
                    .segment_leaf,
                    owned_invocations.view(),
                    public_native_sum.CIRCUIT_ID,
                ),
            );
            ledger.contributions.clearRetainingCapacity();
            const stale = try classifySingleArithmeticLaneTupleClosure(
                lanes[0],
                lane_evaluations[0],
                owned_invocations.view(),
                &use_count_scratch,
                &ledger,
                true,
            );
            try std.testing.expectEqual(@as(usize, 4), stale.unmatched_tuple_count);
        }

        test "native SegmentV2 core admits only the canonical empty domain audit" {
            const empty = emptyDomainAudit();
            try validateCoreDomainAudit(empty, QM31.zero());

            var mutated = empty;
            mutated.event_terms = 1;
            try std.testing.expectError(
                error.V2CoreCohortMismatch,
                validateCoreDomainAudit(mutated, QM31.zero()),
            );
            mutated = empty;
            mutated.logical_rows = 1;
            try std.testing.expectError(
                error.V2CoreCohortMismatch,
                validateCoreDomainAudit(mutated, QM31.zero()),
            );
            mutated = empty;
            mutated.values[
                @intFromEnum(RelationDomain.recursion_fri_merkle_route)
            ] = QM31.one();
            try std.testing.expectError(
                error.V2CoreCohortMismatch,
                validateCoreDomainAudit(mutated, QM31.zero()),
            );
            try std.testing.expectError(
                error.V2CoreCohortMismatch,
                validateCoreDomainAudit(empty, QM31.one()),
            );
        }

        /// Value-only CPU resource request for one recursive outer proof. The worker
        /// count changes execution only: commitments, transcripts, claims, and proof
        /// bytes remain canonical across worker counts.
        pub const MutationProbeMode = enum(u8) {
            enabled,
            disabled,
        };

        pub const ExecutionOptions = struct {
            worker_count: usize = 1,
            /// Adversarial re-verifications are a development soundness fleet, not
            /// part of one production proving transaction. Benchmarks disable only
            /// these probes; the independent honest verifier and custody publication
            /// remain mandatory.
            mutation_probes: MutationProbeMode = .enabled,
        };

        pub const TupleClosureReport = air.relation_interaction.TupleClosureReport;

        /// Challenge-independent fast gate over the five relation domains currently
        /// being closed by the universal segment-leaf assembly. A zero report proves
        /// exact tuple/multiplicity cancellation for this mask only; it deliberately
        /// does not relabel the verifier-subsystem receipt as a complete parent.
        pub const TupleClosureFrontierReceipt = struct {
            domain_mask: u64,
            report: TupleClosureReport,
            setup_ns: u64,
            row_prepare_ns: u64,
            classify_ns: u64,

            pub fn frontierClosed(self: TupleClosureFrontierReceipt) bool {
                return self.domain_mask == TUPLE_CLOSURE_FRONTIER_MASK and
                    self.report.isClosed();
            }

            pub fn wholeRosterClosed(_: TupleClosureFrontierReceipt) bool {
                return false;
            }
        };

        pub const TUPLE_CLOSURE_FRONTIER_MASK: u64 =
            relationDomainBit(.recursion_merkle_node) |
            relationDomainBit(.recursion_wire) |
            relationDomainBit(.recursion_verifier_input_word) |
            relationDomainBit(.recursion_verifier_randomness_word) |
            relationDomainBit(.recursion_statement_word);

        /// Exact verifier-owned plans already used by the native leaf transcript.
        /// The outer proof rebuilds them from their sealed specs and rejects any
        /// mismatch; it never substitutes a default public-I/O capacity.
        pub const VerifierPlans = struct {
            vm: *const schedule.Plan,
            recursion: *const schedule.Plan,
        };

        /// Allocation-free validation receipt for the already implemented universal
        /// verifier core (rows 18--35).  V2 has two additional boundary-source
        /// components, so the target is 38 committed components: two V2 sources plus
        /// the frozen 36-row universal roster.  The 47-domain target is explicit,
        /// while the closed mask remains zero until the missing routing/semantic rows
        /// join the same proof.  This prevents a partial subsystem from being
        /// mislabeled as recursion.
        pub const V2Rows18Through35PreflightReceipt = struct {
            format_version: u16 = V2_ROWS_18_35_PREFLIGHT_FORMAT_VERSION,
            universal_roster_count: u8 = V2_UNIVERSAL_ROSTER_COMPONENT_COUNT,
            authority_source_count: u8 = V2_AUTHORITY_SOURCE_COMPONENT_COUNT,
            target_component_count: u8 = V2_TARGET_COMPONENT_COUNT,
            domain_count: u8 = global_closure.DOMAIN_COUNT,
            target_domain_mask: u64,
            closed_domain_mask: u64 = 0,
            rows_18_35_inputs_validated: bool = true,
            rows_0_9_verified: bool = false,
            exact_47_domain_closure_verified: bool = false,
            outer_stark_verified: bool = false,
            wire_id: recursion.poseidon2_channel.Digest,
            statement_authority_id: recursion.poseidon2_channel.Digest,
            authority_manifest_id: recursion.poseidon2_channel.Digest,
            authority_prepared_id: recursion.poseidon2_channel.Digest,
            fri_circuit_id: [32]u8,
            pcs_circuit_id: [32]u8,
            vm_air_circuit_id: [32]u8,
            vm_plan_id: recursion.poseidon2_channel.Digest,
            recursion_plan_id: recursion.poseidon2_channel.Digest,
            transcript_program_id: recursion.poseidon2_channel.Digest,
            transcript_execution_id: recursion.poseidon2_channel.Digest,
            transcript_evidence_id: recursion.poseidon2_channel.Digest,
            transcript_final_digest: recursion.poseidon2_channel.Digest,
            transcript_trace_receipt: [32]u8,
            transcript_frame_count: u32,
            transcript_poseidon_call_count: u32,
            transcript_pow_check_count: u32,
            transcript_final_draw_count: u32,
            authority_poseidon_call_count: u32,
            identity: [32]u8,

            pub fn validate(self: *const V2Rows18Through35PreflightReceipt) !void {
                if (self.format_version != V2_ROWS_18_35_PREFLIGHT_FORMAT_VERSION or
                    self.universal_roster_count != V2_UNIVERSAL_ROSTER_COMPONENT_COUNT or
                    self.authority_source_count != V2_AUTHORITY_SOURCE_COMPONENT_COUNT or
                    self.target_component_count != V2_TARGET_COMPONENT_COUNT or
                    self.domain_count != global_closure.DOMAIN_COUNT or
                    self.target_domain_mask != allRelationDomainMask() or
                    self.closed_domain_mask != 0 or
                    !self.rows_18_35_inputs_validated or self.rows_0_9_verified or
                    self.exact_47_domain_closure_verified or self.outer_stark_verified or
                    self.transcript_frame_count == 0 or
                    self.transcript_poseidon_call_count == 0 or
                    self.transcript_pow_check_count != 2 or
                    self.transcript_final_draw_count == 0 or
                    self.authority_poseidon_call_count == 0)
                {
                    return error.V2Rows18Through35PreflightMismatch;
                }
                inline for (.{
                    self.wire_id,
                    self.statement_authority_id,
                    self.authority_manifest_id,
                    self.authority_prepared_id,
                    self.vm_plan_id,
                    self.recursion_plan_id,
                    self.transcript_program_id,
                    self.transcript_execution_id,
                    self.transcript_evidence_id,
                    self.transcript_final_digest,
                }) |digest| try validateAuxiliaryDigest(digest);
                inline for (.{
                    self.fri_circuit_id,
                    self.pcs_circuit_id,
                    self.vm_air_circuit_id,
                    self.transcript_trace_receipt,
                    self.identity,
                }) |digest| try requireSha256Id(digest);
                if (!std.mem.eql(
                    u8,
                    &self.identity,
                    &v2Rows18Through35PreflightIdentity(self),
                )) return error.V2Rows18Through35PreflightMismatch;
            }

            pub fn productionReady(_: *const V2Rows18Through35PreflightReceipt) bool {
                return false;
            }
        };

        pub fn preflightV2Rows18Through35(
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
            pcs_config: stwo_core.pcs.PcsConfig,
            data: *const frontend.air.public_data_v2.PublicDataV2,
            component_descs: []const frontend.air.statement.FamilyComponentDesc,
            infra_descs: []const frontend.air.statement.InfraComponentDesc,
            transcript_program: *const recursion.transcript_program_v2.Program,
            transcript_execution: *const recursion.transcript_program_v2.Execution,
            transcript_evidence: *const recursion.transcript_program_v2.Evidence,
            expected_wire_id: recursion.poseidon2_channel.Digest,
            expected_statement_authority_id: recursion.poseidon2_channel.Digest,
            authority_manifest_id: recursion.poseidon2_channel.Digest,
            authority_prepared_id: recursion.poseidon2_channel.Digest,
            authority_poseidon_call_count: usize,
        ) !V2Rows18Through35PreflightReceipt {
            try captured.evaluation.validateAgainst(&captured.circuit);
            try captured.pcs_evaluation.validateAgainst(&captured.pcs_circuit);
            try vm_air.validate();
            try verifier_plans.vm.validate();
            try verifier_plans.recursion.validate();
            if (verifier_plans.vm.schema != .vm or
                verifier_plans.recursion.schema != .recursion or
                authority_poseidon_call_count == 0)
            {
                return error.V2Rows18Through35PreflightMismatch;
            }
            try transcript_program.validateAgainst(
                verifier_plans.vm,
                pcs_config,
                data,
                component_descs,
                infra_descs,
            );
            try transcript_execution.validateAgainst(transcript_program);
            try transcript_evidence.validateAgainst(
                transcript_execution,
                transcript_program,
            );
            if (!std.meta.eql(transcript_evidence.wire_id, expected_wire_id) or
                !std.meta.eql(
                    transcript_evidence.statement_authority_id,
                    expected_statement_authority_id,
                )) return error.V2TranscriptEvidenceUnavailable;
            try validateAuxiliaryDigest(authority_manifest_id);
            try validateAuxiliaryDigest(authority_prepared_id);
            var result = V2Rows18Through35PreflightReceipt{
                .target_domain_mask = allRelationDomainMask(),
                .wire_id = expected_wire_id,
                .statement_authority_id = expected_statement_authority_id,
                .authority_manifest_id = authority_manifest_id,
                .authority_prepared_id = authority_prepared_id,
                .fri_circuit_id = captured.circuit.identity_digest,
                .pcs_circuit_id = captured.pcs_circuit.identity_digest,
                .vm_air_circuit_id = vm_air.circuit.identity_digest,
                .vm_plan_id = verifier_plans.vm.authority_digest,
                .recursion_plan_id = verifier_plans.recursion.authority_digest,
                .transcript_program_id = transcript_evidence.program_id,
                .transcript_execution_id = transcript_execution.identity,
                .transcript_evidence_id = transcript_evidence.identity,
                .transcript_final_digest = transcript_evidence.final_digest,
                .transcript_trace_receipt = transcript_evidence.trace_receipt,
                .transcript_frame_count = transcript_evidence.frame_count,
                .transcript_poseidon_call_count = transcript_evidence.poseidon_call_count,
                .transcript_pow_check_count = transcript_evidence.pow_check_count,
                .transcript_final_draw_count = transcript_evidence.final_draw_count,
                .authority_poseidon_call_count = std.math.cast(
                    u32,
                    authority_poseidon_call_count,
                ) orelse return error.ArithmeticOverflow,
                .identity = undefined,
            };
            result.identity = v2Rows18Through35PreflightIdentity(&result);
            try result.validate();
            return result;
        }

        /// Verifier-authenticated transcript material for universal rows 0--9. Both
        /// values are constructed from the successful native leaf verification and
        /// remain externally owned for the duration of prove/verify.
        pub const SegmentPublicInputs = struct {
            source: *const SegmentPublicSource,
            prepared: *const recursion.segment_public_outer_source.Prepared,
            leaf_preprocessing: *const recursion.segment_leaf_authority.Preprocessing,
            leaf: *const recursion.segment_leaf_authority.Prepared,
            data: *const frontend.air.public_data.PublicData,
        };

        pub const SegmentStatementInputs = struct {
            authority: *const recursion.segment_statement_outer_source.Authority,
            workspace: *recursion.segment_statement_outer_source.Workspace,
            prepared: *const recursion.segment_statement_outer_source.Prepared,
        };

        pub const SegmentTranscriptInputs = struct {
            preprocessing: *const recursion.segment_transcript_witness.Preprocessing,
            prepared: *const SegmentTranscriptSource.Prepared,
            statement: SegmentStatementInputs,
            public: SegmentPublicInputs,
        };

        pub const PreparedQueryWitness = struct {
            allocator: std.mem.Allocator,
            owned_words: ?[]M31,
            value: query_bits_witness.QueryWitness,

            pub fn init(
                allocator: std.mem.Allocator,
                captured: *const recursion.captured_fri.Owned,
                segment_transcript: ?SegmentTranscriptInputs,
            ) !PreparedQueryWitness {
                const inputs = segment_transcript orelse return .{
                    .allocator = allocator,
                    .owned_words = null,
                    .value = .{ .segment_leaf = captured.raw_queries },
                };
                if (captured.circuit.lifting_log_size >= 31)
                    return error.InvalidProofShape;
                const words = try allocator.alloc(M31, captured.raw_queries.len);
                errdefer allocator.free(words);
                try inputs.prepared.writeRawQueryWords(inputs.preprocessing, words);
                try validateQueryWordProjection(
                    captured.circuit.lifting_log_size,
                    words,
                    captured.raw_queries,
                );
                return .{
                    .allocator = allocator,
                    .owned_words = words,
                    .value = .{ .segment_leaf = words },
                };
            }

            /// SegmentV2 query positions intentionally retain only the Merkle-domain
            /// low bits. Row 20 must instead decompose the complete row-9 transcript
            /// word, then prove that its verifier-selected projection equals the
            /// captured position. The V2 source performs a dry validation pass before
            /// copying, and this owner publishes nothing until that projection check
            /// succeeds for every query.
            pub fn initV2(
                allocator: std.mem.Allocator,
                captured: *const recursion.captured_fri.Owned,
                prepared: *const segment_transcript_source_v2.PreparedV2,
                program: *const recursion.transcript_program_v2.Program,
                execution: *const recursion.transcript_program_v2.Execution,
                plan: *const schedule.Plan,
            ) !PreparedQueryWitness {
                const words = try allocator.alloc(M31, captured.raw_queries.len);
                errdefer allocator.free(words);
                try prepared.writeRawQueryWords(words, program, execution, plan);
                try validateQueryWordProjection(
                    captured.circuit.lifting_log_size,
                    words,
                    captured.raw_queries,
                );
                return .{
                    .allocator = allocator,
                    .owned_words = words,
                    .value = .{ .segment_leaf = words },
                };
            }

            pub fn deinit(self: *PreparedQueryWitness) void {
                if (self.owned_words) |words| self.allocator.free(words);
                self.* = undefined;
            }
        };

        pub fn validateQueryWordProjection(
            lifting_log_size: u32,
            full_words: []const M31,
            positions: []const M31,
        ) !void {
            if (lifting_log_size >= 31 or full_words.len != positions.len)
                return error.InvalidProofShape;
            const mask = (@as(u32, 1) << @intCast(lifting_log_size)) - 1;
            for (full_words, positions) |full, position| {
                if ((full.toU32() & mask) != position.toU32())
                    return error.AuthorityMismatch;
            }
        }

        pub const AssemblyProfile = struct {
            setup_ns: u64 = 0,
            preprocessed_fill_ns: u64 = 0,
            preprocessed_commit_ns: u64 = 0,
            main_fill_ns: u64 = 0,
            main_commit_ns: u64 = 0,
            interaction_fill_ns: u64 = 0,
            interaction_commit_ns: u64 = 0,
            component_seal_ns: u64 = 0,

            pub fn total(self: AssemblyProfile) u64 {
                return self.setup_ns +
                    self.preprocessed_fill_ns +
                    self.preprocessed_commit_ns +
                    self.main_fill_ns +
                    self.main_commit_ns +
                    self.interaction_fill_ns +
                    self.interaction_commit_ns +
                    self.component_seal_ns;
            }
        };
    };
}
