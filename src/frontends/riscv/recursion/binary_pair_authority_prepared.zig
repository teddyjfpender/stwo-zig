//! Internal binary pair authority authority shard; use binary_pair_authority.zig publicly.

const dependency_0 = @import("binary_pair_authority_contract.zig");

const Error = dependency_0.Error;
const PROOF_KIND = dependency_0.PROOF_KIND;
const PairInputs = dependency_0.PairInputs;
const PlanAdmission = dependency_0.PlanAdmission;
const QM31 = dependency_0.QM31;
const RowContract = dependency_0.RowContract;
const TranscriptPreprocessing = dependency_0.TranscriptPreprocessing;
const VALIDATION_SCRATCH_LEN = dependency_0.VALIDATION_SCRATCH_LEN;
const executionDigest = dependency_0.executionDigest;
const fixed_profile = dependency_0.fixed_profile;
const fixed_wire = dependency_0.fixed_wire;
const pair_node = dependency_0.pair_node;
const pow_check = dependency_0.pow_check;
const pow_frame = dependency_0.pow_frame;
const proof_kind = dependency_0.proof_kind;
const protocol = dependency_0.protocol;
const recordFromAuthority = dependency_0.recordFromAuthority;
const relation_challenge = dependency_0.relation_challenge;
const schedule = dependency_0.schedule;
const secureSlicesEql = dependency_0.secureSlicesEql;
const slicesOverlap = dependency_0.slicesOverlap;
const span_statement = dependency_0.span_statement;
const statementId = dependency_0.statementId;
const statement_circuit = dependency_0.statement_circuit;
const statement_input = dependency_0.statement_input;
const std = dependency_0.std;
const traceLogSize = dependency_0.traceLogSize;
const transcript_air = dependency_0.transcript_air;
const transcript_binding = dependency_0.transcript_binding;
const transcript_payload = dependency_0.transcript_payload;
const transcript_program = dependency_0.transcript_program;
const transcript_state = dependency_0.transcript_state;
const transcript_word = dependency_0.transcript_word;
const validatePlans = dependency_0.validatePlans;
const validateRandomnessSnapshot = dependency_0.validateRandomnessSnapshot;
const validateRelationSnapshot = dependency_0.validateRelationSnapshot;
const validateSealedPlanPair = dependency_0.validateSealedPlanPair;
const validateStatementPositions = dependency_0.validateStatementPositions;
const verifierRandomnessCount = dependency_0.verifierRandomnessCount;
const verifier_randomness = dependency_0.verifier_randomness;
const writeVerifierRandomness = dependency_0.writeVerifierRandomness;

/// One reusable allocation for mutation-resistant statement-circuit replay.
/// Keeping this outside `Prepared` avoids doubling every retained row-11
/// snapshot and makes repeated validation allocation-free.
pub const ValidationWorkspace = struct {
    allocator: std.mem.Allocator,
    secure_storage: []QM31,

    pub fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!ValidationWorkspace {
        return .{
            .allocator = allocator,
            .secure_storage = try allocator.alloc(QM31, VALIDATION_SCRATCH_LEN),
        };
    }

    pub fn deinit(self: *ValidationWorkspace) void {
        self.allocator.free(self.secure_storage);
        self.* = undefined;
    }

    pub fn validate(self: *const ValidationWorkspace) Error!void {
        if (self.secure_storage.len != VALIDATION_SCRATCH_LEN)
            return error.ValidationWorkspaceMismatch;
    }
};

/// Verifier-produced metadata retained beside one successful child capture.
/// No identity is trusted from this record: `Prepared.init` re-derives the
/// statement, fixed-proof, transcript, and summary identities and compares the
/// complete result to `verified` before pair authentication.
pub const VerifiedChildCapture = struct {
    present: bool = true,
    statement: span_statement.SpanStatement,
    canonical_summary_bytes: []const u8,
    verified: pair_node.VerifiedChildV1,
};

pub fn FixedChild(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    return struct {
        shape: fixed_profile.ProofShapeV1,
        proof: *const fixed_wire.FixedStarkProofWire(dimensions),
        capture: VerifiedChildCapture,
    };
}

pub fn Prepared(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    const Child = FixedChild(dimensions);

    return struct {
        executions: [2]transcript_program.Execution,
        transcript_air: transcript_air.PreparedBatch,
        transcript_binding: transcript_binding.MainWitness,
        transcript_state: transcript_state.MainWitness,
        transcript_word: transcript_word.PreparedBatch,
        transcript_payload: transcript_payload.PreparedBatch,
        pow_check: pow_check.PreparedBatch,
        pow_frame: pow_frame.PreparedBatch,
        relation_challenge: relation_challenge.MainWitness,
        verifier_randomness: verifier_randomness.MainWitness,
        statement_semantics: statement_circuit.Evaluation,

        left_statement: span_statement.SpanStatement,
        right_statement: span_statement.SpanStatement,
        parent_statement: span_statement.SpanStatement,
        left_words: span_statement.StatementWords,
        right_words: span_statement.StatementWords,
        parent_words: span_statement.StatementWords,

        authority: pair_node.VerifierAuthorityV1,
        record: pair_node.PairNodeRecordV1,
        authenticated_root: pair_node.RootAuthenticatedPairV1,
        plan_digest: protocol.Digest,
        contract: RowContract,

        const Self = @This();

        /// Failure-atomic construction from two independently verified fixed
        /// child materials. The fixed-wire encoding is the canonical proof-ID
        /// preimage, eliminating a second untrusted proof-byte representation.
        pub fn init(
            allocator: std.mem.Allocator,
            admission: PlanAdmission,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            transcript_preprocessing: *const TranscriptPreprocessing,
            statement_preprocessing: *const statement_input.Preprocessed,
            semantics_circuit: *const statement_circuit.Circuit,
            validation_workspace: *ValidationWorkspace,
            pair_inputs: PairInputs,
            children: [2]Child,
        ) !Self {
            try validatePlans(
                allocator,
                admission,
                vm_plan,
                recursion_plans,
                children[0].shape,
                children[1].shape,
            );
            try transcript_preprocessing.validateAgainst(vm_plan, recursion_plans[0]);
            try statement_preprocessing.validate();
            try semantics_circuit.validate();
            try pair_inputs.context.validate();
            try pair_inputs.root_pin.validate();
            if (!std.meta.eql(
                pair_inputs.context.aggregator_vk_id,
                pair_inputs.root_pin.expected_aggregator_vk_id,
            )) return error.ChildCaptureMismatch;

            for (children) |child| {
                if (!child.capture.present) return error.ChildOmitted;
                if (child.capture.canonical_summary_bytes.len == 0)
                    return error.EmptyProofSummary;
                try child.capture.statement.validate();
                try child.shape.validate();
                try child.proof.validateAgainstShape(child.shape);
            }
            try validateStatementPositions(pair_inputs.context.pair_index, children);

            const left_statement = children[0].capture.statement;
            const right_statement = children[1].capture.statement;
            const parent_statement = try span_statement.SpanStatement.fold(
                left_statement,
                right_statement,
            );
            const left_words = try left_statement.canonicalWords();
            const right_words = try right_statement.canonicalWords();
            const parent_words = try parent_statement.canonicalWords();
            const execution_statement_id = statementId(&parent_words);
            if (!std.meta.eql(
                execution_statement_id,
                pair_inputs.context.execution_statement_id,
            )) return error.ExecutionStatementMismatch;

            var executions: [2]transcript_program.Execution = undefined;
            var execution_count: usize = 0;
            errdefer for (executions[0..execution_count]) |*execution| execution.deinit();
            executions[0] = try transcript_program.executeFixedTranscript(
                dimensions,
                allocator,
                recursion_plans[0],
                &left_words,
                .recursion,
                children[0].proof,
            );
            execution_count = 1;
            executions[1] = try transcript_program.executeFixedTranscript(
                dimensions,
                allocator,
                recursion_plans[1],
                &right_words,
                .recursion,
                children[1].proof,
            );
            execution_count = 2;

            const proof_encoding = try allocator.alloc(
                u8,
                fixed_wire.serializedByteCount(dimensions),
            );
            defer allocator.free(proof_encoding);
            const verified_children = try deriveAndCheckChildren(
                dimensions,
                proof_encoding,
                pair_inputs.context,
                children,
                &executions,
                .{ left_words, right_words },
            );
            const authority = pair_node.VerifierAuthorityV1{
                .context = pair_inputs.context,
                .children = verified_children,
            };
            const record = try recordFromAuthority(&authority);
            const suite = try pair_node.prepareProtocolSuite();
            const authenticated_root = try pair_node.authenticateRootPrepared(
                &suite,
                &authority,
                &record,
                &pair_inputs.root_pin,
            );

            const left_trace = executions[0].trace();
            const right_trace = executions[1].trace();
            const transcript_source = transcript_air.Source{ .binary_node = .{
                .left = .{ .plan = recursion_plans[0], .trace = &left_trace },
                .right = .{ .plan = recursion_plans[1], .trace = &right_trace },
            } };
            var transcript_air_value = try transcript_air.PreparedBatch.init(
                allocator,
                transcript_source,
            );
            errdefer transcript_air_value.deinit();
            var transcript_binding_value = try transcript_binding.MainWitness.init(
                allocator,
                &transcript_preprocessing.transcript_binding,
                .{ .binary_node = .{
                    .left = .{ .plan = recursion_plans[0], .trace = &left_trace },
                    .right = .{ .plan = recursion_plans[1], .trace = &right_trace },
                } },
            );
            errdefer transcript_binding_value.deinit();
            var transcript_state_value = try transcript_state.MainWitness.init(
                allocator,
                &transcript_preprocessing.transcript_state,
                .{ .binary_node = .{
                    .left = .{ .plan = recursion_plans[0], .trace = &left_trace },
                    .right = .{ .plan = recursion_plans[1], .trace = &right_trace },
                } },
            );
            errdefer transcript_state_value.deinit();
            var transcript_word_value = try transcript_word.PreparedBatch.init(
                allocator,
                &transcript_preprocessing.transcript_word,
                vm_plan,
                recursion_plans[0],
                .{ .binary_node = .{ .left = &left_trace, .right = &right_trace } },
            );
            errdefer transcript_word_value.deinit();
            var transcript_payload_value = try transcript_payload.PreparedBatch.init(
                allocator,
                &transcript_preprocessing.transcript_payload,
                vm_plan,
                recursion_plans[0],
                .{ .binary_node = .{ .left = &left_trace, .right = &right_trace } },
            );
            errdefer transcript_payload_value.deinit();
            var pow_frame_value = try pow_frame.PreparedBatch.init(
                allocator,
                .{ .binary_node = .{
                    .left = .{ .plan = recursion_plans[0], .trace = &left_trace },
                    .right = .{ .plan = recursion_plans[1], .trace = &right_trace },
                } },
            );
            errdefer pow_frame_value.deinit();

            const pow_invocations = try allocator.alloc(
                pow_check.Invocation,
                pow_frame_value.invocations.len,
            );
            defer allocator.free(pow_invocations);
            for (pow_invocations, pow_frame_value.invocations) |*target, source| {
                target.* = .{
                    .verifier_id = source.verifier_id,
                    .kind = source.kind,
                    .check = source.check,
                };
            }
            var pow_check_value = try pow_check.PreparedBatch.init(
                allocator,
                pow_invocations,
            );
            errdefer pow_check_value.deinit();

            const left_relation_draws = try allocator.alloc(
                relation_challenge.Draw,
                executions[0].relationChallengeCount(),
            );
            defer allocator.free(left_relation_draws);
            const right_relation_draws = try allocator.alloc(
                relation_challenge.Draw,
                executions[1].relationChallengeCount(),
            );
            defer allocator.free(right_relation_draws);
            try executions[0].writeRelationChallenges(left_relation_draws);
            try executions[1].writeRelationChallenges(right_relation_draws);
            var relation_challenge_value = try relation_challenge.MainWitness.init(
                allocator,
                &transcript_preprocessing.relation_challenge,
                .{ .binary_node = .{
                    .left = left_relation_draws,
                    .right = right_relation_draws,
                } },
            );
            errdefer relation_challenge_value.deinit();

            const left_randomness = try allocator.alloc(
                verifier_randomness.Draw,
                verifierRandomnessCount(&executions[0]),
            );
            defer allocator.free(left_randomness);
            const right_randomness = try allocator.alloc(
                verifier_randomness.Draw,
                verifierRandomnessCount(&executions[1]),
            );
            defer allocator.free(right_randomness);
            try writeVerifierRandomness(&executions[0], left_randomness);
            try writeVerifierRandomness(&executions[1], right_randomness);
            var verifier_randomness_value = try verifier_randomness.MainWitness.init(
                allocator,
                &transcript_preprocessing.verifier_randomness,
                .{ .binary_node = .{
                    .left = left_randomness,
                    .right = right_randomness,
                } },
            );
            errdefer verifier_randomness_value.deinit();

            var statement_semantics_value = try semantics_circuit.evaluate(
                allocator,
                statement_circuit.Witness.forBinary(
                    &left_words,
                    &right_words,
                    &parent_words,
                ),
            );
            errdefer statement_semantics_value.deinit();

            const result = Self{
                .executions = executions,
                .transcript_air = transcript_air_value,
                .transcript_binding = transcript_binding_value,
                .transcript_state = transcript_state_value,
                .transcript_word = transcript_word_value,
                .transcript_payload = transcript_payload_value,
                .pow_check = pow_check_value,
                .pow_frame = pow_frame_value,
                .relation_challenge = relation_challenge_value,
                .verifier_randomness = verifier_randomness_value,
                .statement_semantics = statement_semantics_value,
                .left_statement = left_statement,
                .right_statement = right_statement,
                .parent_statement = parent_statement,
                .left_words = left_words,
                .right_words = right_words,
                .parent_words = parent_words,
                .authority = authority,
                .record = record,
                .authenticated_root = authenticated_root,
                .plan_digest = recursion_plans[0].authority_digest,
                .contract = .{},
            };
            try result.validateAgainst(
                vm_plan,
                recursion_plans,
                transcript_preprocessing,
                statement_preprocessing,
                semantics_circuit,
                validation_workspace,
                pair_inputs.root_pin,
            );
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.statement_semantics.deinit();
            self.verifier_randomness.deinit();
            self.relation_challenge.deinit();
            self.pow_frame.deinit();
            self.pow_check.deinit();
            self.transcript_payload.deinit();
            self.transcript_word.deinit();
            self.transcript_state.deinit();
            self.transcript_binding.deinit();
            self.transcript_air.deinit();
            self.executions[1].deinit();
            self.executions[0].deinit();
            self.* = undefined;
        }

        /// Allocation-free replay of the exact retained rows 1--9 authority.
        ///
        /// This is the hot-path seam for committed-tree writers. It checks
        /// both native transcript executions and every typed row snapshot,
        /// but deliberately does not repeat pair-root authentication or the
        /// independent statement-semantics circuit. `init` has already
        /// performed those cold custody checks before publishing `Prepared`.
        pub fn validateTranscriptSnapshots(
            self: *const Self,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            transcript_preprocessing: *const TranscriptPreprocessing,
        ) !void {
            try validateSealedPlanPair(recursion_plans);
            if (!std.meta.eql(self.plan_digest, recursion_plans[0].authority_digest))
                return error.PlanMismatch;
            try self.contract.validate();
            try transcript_preprocessing.validateAgainst(vm_plan, recursion_plans[0]);
            for (&self.executions, recursion_plans) |*execution, plan| {
                try execution.validateAgainst(plan);
                try execution.replayNative(plan);
            }
            const left_trace = self.executions[0].trace();
            const right_trace = self.executions[1].trace();
            const lane_source = transcript_air.Source{ .binary_node = .{
                .left = .{ .plan = recursion_plans[0], .trace = &left_trace },
                .right = .{ .plan = recursion_plans[1], .trace = &right_trace },
            } };
            try self.transcript_air.validateAgainstSource(lane_source);
            try self.transcript_binding.validateAgainstSource(
                &transcript_preprocessing.transcript_binding,
                .{ .binary_node = lane_source.binary_node },
            );
            try self.transcript_state.validateAgainstSource(
                &transcript_preprocessing.transcript_state,
                .{ .binary_node = .{
                    .left = .{ .plan = recursion_plans[0], .trace = &left_trace },
                    .right = .{ .plan = recursion_plans[1], .trace = &right_trace },
                } },
            );
            try self.transcript_word.validateAgainstSource(
                &transcript_preprocessing.transcript_word,
                vm_plan,
                recursion_plans[0],
                .{ .binary_node = .{ .left = &left_trace, .right = &right_trace } },
            );
            try self.transcript_payload.validateAgainstSource(
                &transcript_preprocessing.transcript_payload,
                vm_plan,
                recursion_plans[0],
                .{ .binary_node = .{ .left = &left_trace, .right = &right_trace } },
            );
            try self.pow_frame.validateAgainstSource(.{ .binary_node = .{
                .left = .{ .plan = recursion_plans[0], .trace = &left_trace },
                .right = .{ .plan = recursion_plans[1], .trace = &right_trace },
            } });
            if (self.pow_check.invocations.len != self.pow_frame.invocations.len)
                return error.TranscriptSnapshotMismatch;
            for (self.pow_check.invocations, self.pow_frame.invocations) |check, frame| {
                if (!std.meta.eql(check, pow_check.Invocation{
                    .verifier_id = frame.verifier_id,
                    .kind = frame.kind,
                    .check = frame.check,
                })) return error.TranscriptSnapshotMismatch;
            }
            try self.pow_check.validate();
            try validateRelationSnapshot(
                &self.executions,
                &transcript_preprocessing.relation_challenge,
                &self.relation_challenge,
            );
            try validateRandomnessSnapshot(
                &self.executions,
                &transcript_preprocessing.verifier_randomness,
                &self.verifier_randomness,
            );
        }

        /// Allocation-free cold replay of every retained authority snapshot,
        /// including statement semantics and pair-root authentication.
        pub fn validateAgainst(
            self: *const Self,
            vm_plan: *const schedule.Plan,
            recursion_plans: [2]*const schedule.Plan,
            transcript_preprocessing: *const TranscriptPreprocessing,
            statement_preprocessing: *const statement_input.Preprocessed,
            semantics_circuit: *const statement_circuit.Circuit,
            validation_workspace: *ValidationWorkspace,
            root_pin: pair_node.RootVkPinV1,
        ) !void {
            try self.validateTranscriptSnapshots(
                vm_plan,
                recursion_plans,
                transcript_preprocessing,
            );
            try statement_preprocessing.validate();
            try semantics_circuit.validate();
            try validation_workspace.validate();
            const folded = try span_statement.SpanStatement.fold(
                self.left_statement,
                self.right_statement,
            );
            if (!std.meta.eql(folded, self.parent_statement) or
                !std.meta.eql(try self.left_statement.canonicalWords(), self.left_words) or
                !std.meta.eql(try self.right_statement.canonicalWords(), self.right_words) or
                !std.meta.eql(try self.parent_statement.canonicalWords(), self.parent_words))
            {
                return error.TranscriptSnapshotMismatch;
            }
            const semantic_inputs = self.statement_semantics.inputs();
            const semantic_values = self.statement_semantics.values();
            if (self.statement_semantics.input_count != statement_circuit.INPUT_COUNT or
                !std.mem.eql(
                    u8,
                    &self.statement_semantics.circuit_identity,
                    &semantics_circuit.identity_digest,
                ) or
                self.statement_semantics.inputs().len != statement_circuit.INPUT_COUNT or
                self.statement_semantics.values().len != statement_circuit.NODE_COUNT or
                slicesOverlap(
                    validation_workspace.secure_storage,
                    self.statement_semantics.storage,
                ))
            {
                return error.TranscriptSnapshotMismatch;
            }
            const replay = validation_workspace.secure_storage;
            const replay_inputs = replay[0..statement_circuit.INPUT_COUNT];
            const replay_values = replay[statement_circuit.INPUT_COUNT..];
            try semantics_circuit.evaluateIntoAssumeValid(
                statement_circuit.Witness.forBinary(
                    &self.left_words,
                    &self.right_words,
                    &self.parent_words,
                ),
                replay_inputs,
                replay_values,
            );
            if (!secureSlicesEql(replay_inputs, semantic_inputs) or
                !secureSlicesEql(replay_values, semantic_values))
            {
                return error.TranscriptSnapshotMismatch;
            }
            const suite = try pair_node.prepareProtocolSuite();
            const expected = try pair_node.authenticateRootPrepared(
                &suite,
                &self.authority,
                &self.record,
                &root_pin,
            );
            if (!std.meta.eql(expected, self.authenticated_root))
                return error.ChildCaptureMismatch;
        }

        /// Universal rows 0--11 in roster order. Rows 6/7 are witness-sized;
        /// callers may raise those two logs, never lower them.
        pub fn minimumLogSizes(
            self: *const Self,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            transcript_preprocessing: *const TranscriptPreprocessing,
            statement_preprocessing: *const statement_input.Preprocessed,
        ) ![12]u32 {
            try self.contract.validate();
            var control_rows = try std.math.add(
                usize,
                vm_plan.steps.len,
                try std.math.mul(usize, recursion_plan.steps.len, 2),
            );
            control_rows = @max(control_rows, 1);
            return .{
                traceLogSize(control_rows),
                self.transcript_air.log_size,
                transcript_preprocessing.transcript_binding.log_size,
                transcript_preprocessing.transcript_state.log_size,
                transcript_preprocessing.transcript_word.log_size,
                transcript_preprocessing.transcript_payload.log_size,
                traceLogSize(@max(self.pow_check.invocations.len, 1)),
                traceLogSize(@max(self.pow_frame.invocations.len, 1)),
                transcript_preprocessing.relation_challenge.log_size,
                transcript_preprocessing.verifier_randomness.log_size,
                statement_preprocessing.log_size,
                traceLogSize(statement_circuit.INPUT_COUNT),
            };
        }

        /// Usage sketch for `recursive_pair_outer`:
        ///
        /// 1. construct this value immediately after both native verifiers
        ///    publish their fixed captures;
        /// 2. install `minimumLogSizes` at rows 0--11, binary-inactive VM
        ///    source logs at rows 12--16, the two-lane binary control source
        ///    at row 17, and log 16 at row 35;
        /// 3. feed these retained snapshots to the existing typed adapters;
        /// 4. append rows 18--34 twice using the two captured FRI owners; and
        /// 5. seal, prove, independently verify, then publish the parent.
        pub fn proofKind(_: *const Self) proof_kind.ProofKind {
            return PROOF_KIND;
        }

        /// Allocation-free row-10 source. The direct writer consumes this
        /// union together with its verifier-owned preprocessing.
        pub fn statementWitness(self: *const Self) statement_input.StatementWitness {
            return .{ .binary_node = .{
                .left = &self.left_words,
                .right = &self.right_words,
                .parent = &self.parent_words,
            } };
        }
    };
}

pub fn deriveAndCheckChildren(
    comptime dimensions: fixed_wire.Dimensions,
    proof_encoding: []u8,
    context: pair_node.VerifierContextV1,
    children: [2]FixedChild(dimensions),
    executions: *const [2]transcript_program.Execution,
    statement_words: [2]span_statement.StatementWords,
) ![2]pair_node.VerifiedChildV1 {
    var result: [2]pair_node.VerifiedChildV1 = undefined;
    const challenge = try context.challengeContextId();
    const authority_context = try context.contextId();
    for (&result, children, executions, statement_words, 0..) |
        *target,
        child,
        execution,
        words,
        index,
    | {
        try child.proof.encodeInto(proof_encoding, child.shape);
        const transcript_digest = try executionDigest(execution.final_digest);
        target.* = .{
            .position = if (index == 0) .left else .right,
            .role = if (index == 0) .core_request else .poseidon2_provider,
            .leaf_index = context.pair_index * 2 + @as(u32, @intCast(index)),
            .pair_index = context.pair_index,
            .leaf_count = 1,
            .protocol_id = protocol.PROTOCOL_ID_WORDS,
            .session_id = context.session_id,
            .challenge_context_id = challenge,
            .authority_context_id = authority_context,
            .parent_vk_id = context.aggregator_vk_id,
            .statement_id = statementId(&words),
            .proof_id = protocol.proofId(proof_encoding),
            .transcript_id = protocol.transcriptId(
                transcript_digest,
                execution.final_draw_count,
            ),
            .summary_id = protocol.summaryId(child.capture.canonical_summary_bytes),
            .event_count = context.event_count,
            .signed_relation_total = child.capture.verified.signed_relation_total,
        };
        if (!std.meta.eql(target.*, child.capture.verified))
            return error.ChildCaptureMismatch;
    }
    if (std.meta.eql(result[0].proof_id, result[1].proof_id))
        return error.ChildCaptureMismatch;
    return result;
}
