//! One real generic-Poseidon V2 native proof crossing the complete owned
//! capture-to-recursive-preparation boundary.  This is deliberately separate
//! from the millisecond mutation root so routine development stays cheap.
const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");
const postcard = @import("interop_postcard");
const core_outer = integration.recursive_fri_outer;
const subject = integration.recursive_segment_v2_leaf_outer;
const noncore_gate = @import("recursive_segment_v2_noncore_owner_real_gate.zig");
const M31 = stwo_core.fields.m31.M31;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const recursion = frontend.recursion;
const segment_v2 = recursion.segment_statement_v2;
const span = recursion.span_statement;
const protocol = recursion.protocol;
const channel = recursion.poseidon2_channel;
const schedule = recursion.air.verifier_schedule;
const Engine = subject.Engine;
/// Development-only escape hatch for the concrete outer-proof hook. The
/// ordinary gate never observes this flag: only a hook that explicitly
/// implements `runTupleClosureDiagnostic` may take the short path, and the
/// complete no-environment proof/verification path remains byte-for-byte
/// unchanged.
pub const TUPLE_CLOSURE_DIAGNOSTIC_ENV =
    "STWO_RECURSION_OUTER_CLOSURE_DIAGNOSTIC";

const test_config = stwo_core.pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 1,
        // A one-step fold needs more than the fixed verifier's 16-round
        // capacity for this real trace. Two-step folding is both admitted by
        // the native prover and representable by the recursive schedule.
        .fold_step = 2,
    },
};

test "generic Poseidon2 native V2 capture prepares the owned recursive leaf" {
    try runGate(std.testing.allocator);
}

/// Direct heavy-gate entrypoint. The lean executable imports this declaration
/// without asking Zig's test runner to discover and codegen every transitive
/// dependency test, which keeps optimized recursion iteration practical.
pub fn runGate(allocator: std.mem.Allocator) !void {
    return runGateWithHook(allocator, NoOpHook);
}

/// Executes the one authoritative native-ingress fixture and exposes the
/// authenticated prepared leaf only after every core schedule, provider, and
/// independent-regeneration check below has passed. Hooks cannot influence
/// native proving, verification, capture construction, or core admission.
pub fn runGateWithHook(
    allocator: std.mem.Allocator,
    comptime Hook: type,
) !void {
    comptime {
        if (!@hasDecl(Hook, "run"))
            @compileError("native V2 ingress hook must declare run");
    }
    comptime {
        @import("stwo_prover_api").assertProverEngine(Engine);
        if (Engine.Channel != recursion.poseidon2_channel.Channel or
            Engine.Hasher != recursion.poseidon2_channel.MerkleHasher or
            Engine.Channel == recursion.native_scheduled_channel.Channel)
        {
            @compileError("V2 proof gate must use generic Poseidon2, never Blake2s or V1 scheduling");
        }
    }
    const elf = frontend.testing.guest_precompile_test_elf.build(
        false,
        .self_loop,
    );
    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
    defer session.deinit();
    var left_profile = try session.startSegment(1);
    defer left_profile.deinit();
    const left_result = &left_profile.base;
    var right_profile = try session.resumeSegment(left_result.continuation.?, 16);
    defer right_profile.deinit();
    const right_result = &right_profile.base;

    var declared_program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        left_result.execution_trace.rows.items,
        left_result.rw_memory.program_words,
        null,
    );
    defer declared_program.deinit(allocator);
    const public_input = digest("recursive-v2-poseidon-input");
    const public_output = digest("recursive-v2-poseidon-output");
    const initial_state = try machineState(
        left_result.entry_cpu,
        digest("recursive-v2-rw-entry"),
        digest("recursive-v2-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        digest("recursive-v2-rw-shared"),
        digest("recursive-v2-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        digest("recursive-v2-rw-exit"),
        digest("recursive-v2-io-exit"),
    );
    const total_cycles = try std.math.add(
        u64,
        @intCast(left_result.cycle_count),
        @intCast(right_result.cycle_count),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(declared_program.tree.root),
            initial_state,
            final_state,
            public_input,
            public_output,
            total_cycles,
        ),
        2,
    );
    const left_span = try leafStatement(
        job,
        left_result,
        initial_state,
        shared_state,
        try span.EdgeClaim.present(public_input),
        span.EdgeClaim.absent(),
    );
    const left_source = try segment_v2.SourceV2.fromSegmentResult(
        digest("recursive-v2-session"),
        left_span,
        left_result,
    );
    const words = try encode(allocator, &left_source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );

    var prove_timer = try std.time.Timer.start();
    var output = try prover.proveRiscVSegmentV2WithEngine(
        Engine,
        allocator,
        test_config,
        left_result,
        null,
        public_data,
    );
    const prove_ns = prove_timer.read();
    defer output.deinit(allocator);

    // Exercise the exact external-ingress chain before any allocating decoder
    // sees the native proof: authenticated V2 statement -> allocation-free
    // shape walk -> fresh owned proof. The verifier consumes only that decoded
    // value, never the prover's in-memory proof object.
    var proof_bytes: std.ArrayList(u8) = .empty;
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        proof_bytes.writer(allocator),
        output.proof,
    );
    try recursion.proof_ingress.validateV2ForVerifierConfig(
        proof_bytes.items,
        &output.statement,
        test_config,
        proof_bytes.items.len,
    );
    try std.testing.expectError(
        error.ProofResourceLimitExceeded,
        recursion.proof_ingress.validateV2ForVerifierConfig(
            proof_bytes.items,
            &output.statement,
            test_config,
            proof_bytes.items.len - 1,
        ),
    );
    var bad_statement = output.statement;
    bad_statement.authority_id[0] +%= 1;
    try std.testing.expectError(
        error.InvalidStatement,
        recursion.proof_ingress.validateV2ForVerifierConfig(
            proof_bytes.items,
            &bad_statement,
            test_config,
            proof_bytes.items.len,
        ),
    );
    var proof_stream = std.io.fixedBufferStream(proof_bytes.items);
    var decoded_proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var decoded_proof_moved = false;
    defer if (!decoded_proof_moved) decoded_proof.deinit(allocator);
    try std.testing.expectEqual(proof_bytes.items.len, proof_stream.pos);

    var capture: subject.NativeCapture = undefined;
    var verifier_channel = Engine.Channel{};
    decoded_proof_moved = true;
    var verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        Engine,
        allocator,
        test_config,
        output.statement,
        decoded_proof,
        output.interaction_claim,
        &verifier_channel,
        &capture,
    );
    const verify_ns = verify_timer.read();
    var capture_moved = false;
    defer if (!capture_moved) capture.deinit(allocator);
    try capture.validate();

    var profile = try recursion.captured_fri.Owned.init(
        allocator,
        recursion.captured_fri.ProfileConfig.fromPcs(test_config),
        &capture.proof,
    );
    defer profile.deinit();
    if (profile.trace_tree_heights.len != recursion.fixed_profile.TREE_COUNT)
        return error.InvalidProofShape;
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    @memcpy(&tree_heights, profile.trace_tree_heights);
    const shape = try recursion.transcript_shape.derive(
        profile.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = profile.sampled_value_count,
            .queried_values_per_query = profile.queried_values_per_query,
            .claimed_sum_count = profile.claimed_sum_count,
            .interaction_pow_bits = profile.interaction_pow_bits,
            .pcs_pow_bits = profile.pcs_pow_bits,
        },
    );
    var vm_plan = try schedule.Plan.initShape(
        allocator,
        try schedule.vmProgramSpec(0, 0),
        shape,
    );
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        shape,
    );
    defer recursion_plan.deinit();
    const keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
        digest("recursive-v2-segment-vk"),
        digest("recursive-v2-parent-vk"),
    );
    capture_moved = true;
    var bundle = try subject.PreparedNativeV2LeafOuter.init(
        allocator,
        allocator,
        &capture,
        test_config,
        output.interaction_claim.interaction_pow,
        keys,
        recursion.air.universal_challenges.UniversalRelations.dummy(),
        .{ .vm = &vm_plan, .recursion = &recursion_plan },
    );
    defer bundle.deinit();
    try bundle.validate();
    try std.testing.expectEqual(@as(u8, 18), bundle.rows_18_34_core.first_row);
    try std.testing.expectEqual(@as(u8, 34), bundle.rows_18_34_core.last_row);
    try std.testing.expectEqual(@as(u8, 17), bundle.rows_18_34_core.row_count);
    try std.testing.expect(bundle.rows_18_34_core.core_poseidon_call_count > 0);
    try std.testing.expect(!bundle.rows_18_34_core.productionReady());
    try std.testing.expect(!bundle.rows0Through9Publishable());
    try std.testing.expect(!bundle.exact47DomainClosureVerified());
    try std.testing.expect(!bundle.productionReady());
    try std.testing.expectEqual(
        bundle.transcript_execution.poseidonCalls().len,
        try bundle.shared_poseidon_layout.transcript.count(),
    );
    try std.testing.expectEqual(
        try bundle.authority_prepared.authorityPoseidonCallCount(),
        try bundle.shared_poseidon_layout.statement_authority.count(),
    );

    try std.testing.expectEqual(
        @as(usize, 0),
        try bundle.shared_poseidon_layout.verifier_core.count(),
    );
    try std.testing.expectEqual(
        @as(usize, 885),
        try bundle.shared_poseidon_layout.transcript.count(),
    );
    try std.testing.expectEqual(
        @as(usize, 14),
        try bundle.shared_poseidon_layout.statement_authority.count(),
    );
    try std.testing.expect(!bundle.shared_poseidon_layout.call_set_complete);

    // Exact tuple closure does not need the leaf fixture's repeated core
    // reconstructions, mutation fleet, or non-core tree publication. Retain
    // the expensive real native proof and verified-capture custody above,
    // then let an explicitly capable hook classify the authenticated 38-row
    // cohort directly. This is opt-in development plumbing, never a release
    // proof shortcut.
    if (comptime @hasDecl(Hook, "runTupleClosureDiagnostic")) {
        if (std.process.hasEnvVarConstant(TUPLE_CLOSURE_DIAGNOSTIC_ENV)) {
            try Hook.runTupleClosureDiagnostic(allocator, &bundle);
            return;
        }
    }

    const saved_call = bundle.row34_boundary_prefix_calls[0].input[0];
    bundle.row34_boundary_prefix_calls[0].input[0] +%= 1;
    try std.testing.expectError(error.CallLayoutMismatch, bundle.validate());
    bundle.row34_boundary_prefix_calls[0].input[0] = saved_call;
    try bundle.validate();

    const saved_core_identity = bundle.rows_18_34_core.identity;
    bundle.rows_18_34_core.identity[0] ^= 1;
    try std.testing.expectError(
        error.V2CoreRows18Through34PreflightMismatch,
        bundle.validate(),
    );
    bundle.rows_18_34_core.identity = saved_core_identity;
    try bundle.validate();

    // Turn the authenticated boundary prefix into the concrete native-leaf
    // verifier cohort. The owner is heap-stable at the integration boundary;
    // its in-place initializer still exercises the audited move-safe return
    // path internally, which protects ReleaseFast from stale stack pointers.
    const source_preflight = try integration.recursive_segment_v2_noncore_owner
        .PreflightV2.init(&bundle);
    var public_native_relations = integration.recursive_segment_v2_noncore_owner
        .nativeRelations(&bundle);
    const public_native_inputs = integration.recursive_segment_v2_noncore_owner
        .publicInputs(&bundle, &public_native_relations);
    var public_native_sum_source = try recursion
        .segment_public_native_sum_authority_v2.SourceV2.init(
        allocator,
        &source_preflight.public_prepared,
        public_native_inputs,
    );
    defer public_native_sum_source.deinit();
    var public_native_sum_evaluation = try recursion
        .segment_public_native_sum_authority_v2.OwnedEvaluationV2.init(
        allocator,
        &public_native_sum_source,
        &source_preflight.public_prepared,
        public_native_inputs,
    );
    defer public_native_sum_evaluation.deinit();
    const core_inputs = core_outer.NativeSegmentCoreAuthorityInputsV2{
        .captured = &bundle.captured_fri,
        .vm_air = &bundle.vm_air,
        .transcript_prepared = &source_preflight.transcript_prepared,
        .transcript_program = &bundle.transcript_program,
        .transcript_execution = &bundle.transcript_execution,
        .transcript_plan = &bundle.vm_plan,
        .public_native_sum_source = &public_native_sum_source,
        .public_native_sum_evaluation = &public_native_sum_evaluation,
        .verifier_plans = .{
            .vm = &bundle.vm_plan,
            .recursion = &bundle.recursion_plan,
        },
        .boundary_layout = &bundle.shared_poseidon_layout,
        .boundary_calls = bundle.row34_boundary_prefix_calls,
    };
    var core_init_timer = try std.time.Timer.start();
    const native_core = try allocator.create(core_outer.NativeSegmentCoreV2);
    core_outer.NativeSegmentCoreV2.initInPlace(
        native_core,
        allocator,
        core_inputs,
    ) catch |err| {
        allocator.destroy(native_core);
        return err;
    };
    const core_init_ns = core_init_timer.read();
    std.debug.print(
        "\nV2_NATIVE_CORE_STAGE stage=core_init elapsed_ms={d:.3}\n",
        .{milliseconds(core_init_ns)},
    );
    defer {
        native_core.deinit();
        allocator.destroy(native_core);
    }

    try native_core.validateCoreReady();
    try std.testing.expectError(
        error.V2CoreCohortMismatch,
        native_core.validateComplete(),
    );
    const core_calls = try native_core.corePoseidonCalls();
    const complete_calls = try native_core.completePoseidonCalls();
    try std.testing.expectEqual(
        @as(usize, bundle.rows_18_34_core.core_poseidon_call_count),
        core_calls.len,
    );
    try std.testing.expectEqual(@as(usize, 294), core_calls.len);
    try std.testing.expectEqual(
        bundle.row34_boundary_prefix_calls.len + core_calls.len,
        complete_calls.len,
    );
    try std.testing.expectEqual(@as(usize, 1_193), complete_calls.len);
    const complete_layout = try native_core.completeScheduleReceipt();
    try std.testing.expect(complete_layout.call_set_complete);
    try std.testing.expect(complete_layout.verifier_core_range_populated);
    try std.testing.expect(std.meta.eql(
        bundle.shared_poseidon_layout.transcript,
        complete_layout.transcript,
    ));
    try std.testing.expect(std.meta.eql(
        bundle.shared_poseidon_layout.statement_authority,
        complete_layout.statement_authority,
    ));
    try std.testing.expectEqual(core_calls.len, try complete_layout.verifier_core.count());
    const logs = try native_core.componentLogSizes();
    const expected_provider_log: u32 = @intCast(@max(
        @as(usize, 1),
        std.math.log2_int_ceil(usize, complete_calls.len),
    ));
    try std.testing.expectEqual(
        expected_provider_log,
        logs[core_outer.NATIVE_V2_CORE_ROW_COUNT - 1],
    );
    try std.testing.expectEqual(@as(u32, 11), expected_provider_log);

    var provider_timer = try std.time.Timer.start();
    try native_core.finalizeSharedProviderMain();
    const provider_ns = provider_timer.read();
    std.debug.print(
        "V2_NATIVE_CORE_STAGE stage=provider elapsed_ms={d:.3}\n",
        .{milliseconds(provider_ns)},
    );
    try native_core.validateComplete();
    try std.testing.expectError(
        error.V2CoreCohortMismatch,
        native_core.finalizeSharedProviderMain(),
    );

    const provider_relations = try recursion.air.universal_shared_provider
        .SharedProviderRelations.init(&bundle.outer_relations);
    var interaction_timer = try std.time.Timer.start();
    const generated = try native_core.prepareInteractions(
        allocator,
        &bundle.outer_relations,
        &provider_relations,
    );
    const interaction_ns = interaction_timer.read();
    std.debug.print(
        "V2_NATIVE_CORE_STAGE stage=interaction elapsed_ms={d:.3}\n",
        .{milliseconds(interaction_ns)},
    );
    try generated.validateAgainst(
        native_core,
        &bundle.outer_relations,
        &provider_relations,
    );
    var independent_timer = try std.time.Timer.start();
    const independently_generated =
        try core_outer.independentlyRebuildNativeSegmentCoreV2(
            allocator,
            core_inputs,
            &bundle.outer_relations,
            &provider_relations,
        );
    const independent_ns = independent_timer.read();
    std.debug.print(
        "V2_NATIVE_CORE_STAGE stage=independent elapsed_ms={d:.3}\n",
        .{milliseconds(independent_ns)},
    );
    try std.testing.expectEqualSlices(
        u8,
        &generated.identity,
        &independently_generated.identity,
    );
    try std.testing.expect(std.meta.eql(
        generated.claims,
        independently_generated.claims,
    ));
    try std.testing.expect(std.meta.eql(
        generated.audits,
        independently_generated.audits,
    ));

    // Exercise the complementary 21-row owner against this same successful
    // capture. Its helper owns only functional non-core validation; the
    // external hook below is the sole continuation allowed to spend time on
    // the aggregate 38-row STARK.
    try noncore_gate.runPrepared(allocator, &bundle);

    // This is deliberately the final fallible authority boundary before the
    // optional complete-outer-proof continuation. The hook receives only the
    // same verified, owned prepared leaf used above; no detached claims,
    // schedules, rows, or prover-side receipts cross this seam.
    try Hook.run(allocator, &bundle);

    std.debug.print(
        "\nV2_POSEIDON_RECURSIVE_INGRESS cycles={d} prove_ms={d:.3} " ++
            "verify_ms={d:.3} transcript_calls={d} authority_calls={d} " ++
            "core_calls={d} proof_bytes={d} core_cols={d}/{d}/{d} " ++
            "core_constraints={d} complete_provider_calls={d} " ++
            "complete_provider_log={d} core_init_ms={d:.3} " ++
            "provider_ms={d:.3} interaction_ms={d:.3} " ++
            "independent_ms={d:.3}\n",
        .{
            left_result.cycle_count,
            milliseconds(prove_ns),
            milliseconds(verify_ns),
            bundle.transcript_execution.poseidonCalls().len,
            try bundle.authority_prepared.authorityPoseidonCallCount(),
            bundle.rows_18_34_core.core_poseidon_call_count,
            proof_bytes.items.len,
            bundle.rows_18_34_core.preprocessed_columns,
            bundle.rows_18_34_core.main_columns,
            bundle.rows_18_34_core.interaction_columns,
            bundle.rows_18_34_core.constraint_count,
            complete_calls.len,
            expected_provider_log,
            milliseconds(core_init_ns),
            milliseconds(provider_ns),
            milliseconds(interaction_ns),
            milliseconds(independent_ns),
        },
    );
}

/// Builds two genuinely adjacent SegmentV2 leaves from one execution session
/// and crosses each through the native prove -> serialize -> preflight ->
/// decode -> independent verify -> owned recursive-ingress transaction.  The
/// hook observes the prepared leaves only after both verifier captures are
/// complete.  No duplicated child, synthetic publication, or detached claim
/// can enter a temporal-parent proof through this harness.
pub fn runTemporalPairGateWithHook(
    allocator: std.mem.Allocator,
    comptime Hook: type,
) !void {
    comptime {
        if (!@hasDecl(Hook, "run"))
            @compileError("temporal V2 pair hook must declare run");
        @import("stwo_prover_api").assertProverEngine(Engine);
        if (Engine.Channel != recursion.poseidon2_channel.Channel or
            Engine.Hasher != recursion.poseidon2_channel.MerkleHasher or
            Engine.Channel == recursion.native_scheduled_channel.Channel)
        {
            @compileError("temporal V2 pair gate must use generic Poseidon2");
        }
    }

    // Two real adjacent LUI executions with the same verifier profile; the
    // second segment then reaches the terminal self-loop. Keeping the opcode
    // family fixed makes this gate exercise
    // temporal custody rather than the separately tracked variable-profile
    // SegmentV2 publication-input extension.
    const elf = frontend.testing.guest_precompile_test_elf.buildTemporalPair();
    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
    defer session.deinit();
    var left_profile = try session.startSegment(1);
    defer left_profile.deinit();
    const left_result = &left_profile.base;
    var right_profile = try session.resumeSegment(left_result.continuation.?, 16);
    defer right_profile.deinit();
    const right_result = &right_profile.base;

    var declared_program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        left_result.execution_trace.rows.items,
        left_result.rw_memory.program_words,
        null,
    );
    defer declared_program.deinit(allocator);
    const public_input = digest("recursive-v2-poseidon-input");
    const public_output = digest("recursive-v2-poseidon-output");
    const initial_state = try machineState(
        left_result.entry_cpu,
        digest("recursive-v2-rw-entry"),
        digest("recursive-v2-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        digest("recursive-v2-rw-shared"),
        digest("recursive-v2-io-shared"),
    );
    const right_entry_state = try machineState(
        right_result.entry_cpu,
        digest("recursive-v2-rw-shared"),
        digest("recursive-v2-io-shared"),
    );
    if (!std.meta.eql(shared_state, right_entry_state))
        return error.InvalidTemporalBoundary;
    const final_state = try machineState(
        right_result.exit_cpu,
        digest("recursive-v2-rw-exit"),
        digest("recursive-v2-io-exit"),
    );
    const total_cycles = try std.math.add(
        u64,
        @intCast(left_result.cycle_count),
        @intCast(right_result.cycle_count),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(declared_program.tree.root),
            initial_state,
            final_state,
            public_input,
            public_output,
            total_cycles,
        ),
        2,
    );
    const statements = [2]span.SpanStatement{
        try leafStatement(
            job,
            left_result,
            initial_state,
            shared_state,
            try span.EdgeClaim.present(public_input),
            span.EdgeClaim.absent(),
        ),
        try leafStatement(
            job,
            right_result,
            shared_state,
            final_state,
            span.EdgeClaim.absent(),
            try span.EdgeClaim.present(public_output),
        ),
    };
    const keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
        digest("recursive-v2-segment-vk"),
        digest("recursive-v2-parent-vk"),
    );

    var left = try prepareTemporalNativeLeaf(
        allocator,
        left_result,
        statements[0],
        keys,
    );
    defer left.deinit();
    var right = try prepareTemporalNativeLeaf(
        allocator,
        right_result,
        statements[1],
        keys,
    );
    defer right.deinit();
    if (std.mem.eql(u8, &left.identity, &right.identity))
        return error.DuplicateTemporalLeaf;

    try Hook.run(allocator, &left, &right);
}

/// The intentionally narrow real-leaf transaction used by the temporal-pair
/// gate above.  It omits broad mutation/performance diagnostics already owned
/// by `runGateWithHook`, but retains every trust-boundary operation needed to
/// mint a prepared leaf: external bytes are shape-preflighted before decode,
/// the decoded proof is independently verified with capture, and the capture
/// moves only after the recursive owner has validated all derived authority.
pub fn prepareTemporalNativeLeaf(
    allocator: std.mem.Allocator,
    result: *const runner.SegmentResult,
    statement: span.SpanStatement,
    keys: recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2,
) !subject.PreparedNativeV2LeafOuter {
    const source = try segment_v2.SourceV2.fromSegmentResult(
        digest("recursive-v2-session"),
        statement,
        result,
    );
    const words = try encode(allocator, &source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );

    var output = try prover.proveRiscVSegmentV2WithEngine(
        Engine,
        allocator,
        test_config,
        result,
        null,
        public_data,
    );
    defer output.deinit(allocator);

    var proof_bytes: std.ArrayList(u8) = .empty;
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        proof_bytes.writer(allocator),
        output.proof,
    );
    try recursion.proof_ingress.validateV2ForVerifierConfig(
        proof_bytes.items,
        &output.statement,
        test_config,
        proof_bytes.items.len,
    );
    var proof_stream = std.io.fixedBufferStream(proof_bytes.items);
    var decoded_proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var decoded_proof_moved = false;
    defer if (!decoded_proof_moved) decoded_proof.deinit(allocator);
    if (proof_stream.pos != proof_bytes.items.len)
        return error.InvalidProofShape;

    var capture: subject.NativeCapture = undefined;
    var verifier_channel = Engine.Channel{};
    decoded_proof_moved = true;
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        Engine,
        allocator,
        test_config,
        output.statement,
        decoded_proof,
        output.interaction_claim,
        &verifier_channel,
        &capture,
    );
    var capture_moved = false;
    defer if (!capture_moved) capture.deinit(allocator);
    try capture.validate();

    var profile = try recursion.captured_fri.Owned.init(
        allocator,
        recursion.captured_fri.ProfileConfig.fromPcs(test_config),
        &capture.proof,
    );
    defer profile.deinit();
    if (profile.trace_tree_heights.len != recursion.fixed_profile.TREE_COUNT)
        return error.InvalidProofShape;
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    @memcpy(&tree_heights, profile.trace_tree_heights);
    const shape = try recursion.transcript_shape.derive(
        profile.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = profile.sampled_value_count,
            .queried_values_per_query = profile.queried_values_per_query,
            .claimed_sum_count = profile.claimed_sum_count,
            .interaction_pow_bits = profile.interaction_pow_bits,
            .pcs_pow_bits = profile.pcs_pow_bits,
        },
    );
    var vm_plan = try schedule.Plan.initShape(
        allocator,
        try schedule.vmProgramSpec(0, 0),
        shape,
    );
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        shape,
    );
    defer recursion_plan.deinit();

    var prepared = try subject.PreparedNativeV2LeafOuter.init(
        allocator,
        allocator,
        &capture,
        test_config,
        output.interaction_claim.interaction_pow,
        keys,
        recursion.air.universal_challenges.UniversalRelations.dummy(),
        .{ .vm = &vm_plan, .recursion = &recursion_plan },
    );
    capture_moved = true;
    errdefer prepared.deinit();
    try prepared.validate();
    return prepared;
}

const NoOpHook = struct {
    pub fn run(
        _: std.mem.Allocator,
        _: *const subject.PreparedNativeV2LeafOuter,
    ) !void {}
};

pub fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit: span.MachineState,
    input: span.EdgeClaim,
    output: span.EdgeClaim,
) !span.SpanStatement {
    if (result.global_first_cycle == 0) return error.InvalidGlobalCycle;
    return span.SpanStatement.segmentLeaf(
        job,
        result.segment_index,
        try span.ExecutedSpan.init(
            result.segment_index,
            1,
            result.global_first_cycle - 1,
            @intCast(result.cycle_count),
            entry,
            exit,
            input,
            output,
        ),
    );
}

pub fn machineState(
    cpu: runner.Cpu,
    rw_memory: span.Digest,
    public_io_state: span.Digest,
) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw_memory, public_io_state);
}

fn encode(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

pub fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x5632_504f); // "V2PO"
}

pub fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}
