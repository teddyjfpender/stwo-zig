//! Native prove/verify acceptance for the recursion-targeted hash and PCS.

const std = @import("std");
const postcard = @import("interop_postcard");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const committed = @import("committed_forgery_harness.zig");

const recursion = frontend.recursion;
const prover = frontend.prover_mod;
const orchestration = frontend.testing.prover_orchestration;
const Engine = recursion.engine.ScheduledProverEngineForBackend(CpuBackend);
const PcsConfig = @TypeOf(recursion.protocol.PCS_CONFIG);
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const leaf_support = @import("recursion_poseidon_leaf_test_support.zig");
const FRONTIER_COLUMN_LOG_DEGREE = leaf_support.FRONTIER_COLUMN_LOG_DEGREE;
const ACTIVE_OUTER_ENV = leaf_support.ACTIVE_OUTER_ENV;
const TUPLE_FRONTIER_ENV = leaf_support.TUPLE_FRONTIER_ENV;
const DISABLE_OUTER_MUTATIONS_ENV = leaf_support.DISABLE_OUTER_MUTATIONS_ENV;
const LEAF_DIMENSIONS = leaf_support.LEAF_DIMENSIONS;
const LeafWire = leaf_support.LeafWire;
const recursionOuterWorkerCount = leaf_support.recursionOuterWorkerCount;
const environmentFlag = leaf_support.environmentFlag;
const selectProfile = leaf_support.selectProfile;
const runAdapterMutationFleet = leaf_support.runAdapterMutationFleet;
const evaluateCapturedFriCircuit = leaf_support.evaluateCapturedFriCircuit;

const BODY = [_]u32{
    0x0010_0313, // ADDI x6, x0, 1
    0x0023_0393, // ADDI x7, x6, 2
    0x0073_0433, // ADD  x8, x6, x7
};

test "recursion Poseidon2 native leaf proves and independently verifies" {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    // Fail in constant time if the opt-in composition differential cannot
    // name every supported legacy or universal gate width.
    try riscv_cpu.recursive_fri_outer.validateCompositionDiagnosticRoster();
    const allocator = std.testing.allocator;
    const selection = try selectProfile(allocator);
    if (!std.meta.eql(selection.config, recursion.protocol.PCS_CONFIG))
        return error.ScheduledTranscriptRequiresFrozenProfile;
    var guest = try committed.Guest.init(allocator, .{
        .body = &BODY,
        .publish = 8,
        .completion = .self_loop,
    });
    defer guest.deinit();

    const input_capacity = std.math.cast(
        u32,
        guest.public.data.io_entries.input_words.len,
    ) orelse return error.InvalidMeasuredProfile;
    const output_capacity = std.math.cast(
        u32,
        guest.public.data.io_entries.output_words.len,
    ) orelse return error.InvalidMeasuredProfile;
    const claim_shape = try recursion.vm_public_claim.Shape.init(
        input_capacity,
        output_capacity,
    );
    var leaf_preprocessing = try recursion.segment_leaf_authority.Preprocessing.init(
        allocator,
        claim_shape,
    );
    defer leaf_preprocessing.deinit();
    var leaf_authority = try recursion.segment_leaf_authority.Prepared.init(
        allocator,
        &leaf_preprocessing,
        &guest.public.data,
    );
    defer leaf_authority.deinit();

    var transcript_plans = try recursion.segment_profile.initPlans(
        allocator,
        claim_shape.max_input_words,
        claim_shape.max_output_words,
    );
    defer transcript_plans.recursion.deinit();
    defer transcript_plans.vm.deinit();
    const vm_transcript_plan = &transcript_plans.vm;
    const recursion_transcript_plan = &transcript_plans.recursion;

    const resources_before = try frontend.process_usage.sample();
    var total_timer = try std.time.Timer.start();
    var prove_timer = try std.time.Timer.start();
    var proving_channel = try Engine.Channel.init(
        vm_transcript_plan,
        &leaf_authority,
    );
    var output = try orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        .prove,
        allocator,
        selection.config,
        &guest.run.execution_trace,
        &guest.run.state_chain_tracker,
        &guest.run.rw_memory,
        null,
        guest.public.data,
        &proving_channel,
        null,
        null,
    );
    const prove_ns = prove_timer.read();
    if (selection.measurement_mode) std.debug.print(
        "\n  A1_STAGE blowup_log={d} prove=ok\n",
        .{selection.candidate.log_blowup_factor},
    );
    var proof_released = false;
    defer if (proof_released)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);

    const proof_size = output.proof.sizeEstimate();
    const terminal_digest = proving_channel.digestWords();
    const transcript_draws = proving_channel.n_draws;

    var serialize_timer = try std.time.Timer.start();
    var proof_bytes: std.ArrayList(u8) = .empty;
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(
        recursion.engine.Hasher,
        proof_bytes.writer(allocator),
        output.proof,
    );
    const serialize_ns = serialize_timer.read();
    if (selection.measurement_mode) std.debug.print(
        "  A1_STAGE blowup_log={d} serialize=ok bytes={d}\n",
        .{ selection.candidate.log_blowup_factor, proof_bytes.items.len },
    );
    output.proof.deinit(allocator);
    proof_released = true;

    // External recursive proofs cross the allocation-free, statement-owned
    // shape walk before postcard is permitted to allocate any decoded vectors.
    var ingress_timer = try std.time.Timer.start();
    try recursion.proof_ingress.validateForVerifierConfig(
        proof_bytes.items,
        output.statement,
        selection.config,
        recursion.proof_ingress.DEFAULT_MAX_PROOF_BYTES,
    );
    const ingress_ns = ingress_timer.read();
    if (selection.measurement_mode) std.debug.print(
        "  A1_STAGE blowup_log={d} ingress=ok\n",
        .{selection.candidate.log_blowup_factor},
    );

    var decode_timer = try std.time.Timer.start();
    var proof_stream = std.io.fixedBufferStream(proof_bytes.items);
    var decoded = try postcard.deserializeProof(
        recursion.engine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var decoded_owned = true;
    defer if (decoded_owned) decoded.deinit(allocator);
    if (proof_stream.pos != proof_bytes.items.len)
        return error.TrailingProofBytes;
    const decode_ns = decode_timer.read();
    if (selection.measurement_mode) std.debug.print(
        "  A1_STAGE blowup_log={d} decode=ok\n",
        .{selection.candidate.log_blowup_factor},
    );
    var verifier_channel = try Engine.Channel.init(
        vm_transcript_plan,
        &leaf_authority,
    );
    var recursive_capture: prover.RecursiveLeafCaptureForEngine(Engine) = undefined;
    var recursive_capture_owned = false;
    defer if (recursive_capture_owned) recursive_capture.deinit(allocator);
    decoded_owned = false;
    var verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVWithEngineUsingChannelAndRecursiveLeafCapture(
        Engine,
        allocator,
        selection.config,
        output.statement,
        decoded,
        output.interaction_claim,
        &verifier_channel,
        &recursive_capture,
    );
    const verify_ns = verify_timer.read();
    if (selection.measurement_mode) std.debug.print(
        "  A1_STAGE blowup_log={d} verify=ok\n",
        .{selection.candidate.log_blowup_factor},
    );
    recursive_capture_owned = true;
    try recursive_capture.vm_air.validate();
    const proof_capture = &recursive_capture.proof;

    // Replay the exact production VM AIR over the authenticated verifier
    // capture.  This is the row-18 single-source differential gate: the graph
    // is recorded from the same generic constraint functions used by native
    // verification, then evaluated against only verifier-owned values.
    var composition_graph_timer = try std.time.Timer.start();
    var prepared_vm_air = try recursion.vm_air_composition_circuit.Prepared.init(
        allocator,
        &recursive_capture.vm_air,
        proof_capture,
    );
    defer prepared_vm_air.deinit();
    const composition_graph_ns = composition_graph_timer.read();
    const composition_replay_ns: u64 = 0;
    try std.testing.expectEqualSlices(
        u8,
        &prepared_vm_air.circuit.identity_digest,
        &prepared_vm_air.evaluation.circuit_identity,
    );

    // Compile the authenticated graph into row 18 and the shared arithmetic
    // providers, then materialize both from the same concrete evaluation.
    // This closes the production bridge between graph correctness and the
    // universal recursion trace layout.
    const lowering = recursion.air.verifier_arithmetic_lowering;
    const lowering_lanes = [_]lowering.Lane{
        .{
            .circuit_id = recursion.vm_air_composition_circuit.CIRCUIT_ID,
            .active_in = .segment,
            .circuit_identity = prepared_vm_air.circuit.identity_digest,
            .graph = prepared_vm_air.circuit.graph(),
        },
        // The shared providers are overlaid across both proof modes. Until the
        // pair-node composition producer is installed, use the same sealed DAG
        // as a capacity-identical inactive binary lane; only the selected
        // segment lane is materialized below.
        .{
            .circuit_id = recursion.vm_air_composition_circuit.CIRCUIT_ID + 1,
            .active_in = .binary,
            .circuit_identity = prepared_vm_air.circuit.identity_digest,
            .graph = prepared_vm_air.circuit.graph(),
        },
    };
    const lowering_reference = try lowering.Reference.seal(&lowering_lanes);
    var lowering_plan = try lowering.Plan.init(allocator, lowering_reference);
    defer lowering_plan.deinit();
    const lowering_counts = lowering_plan.counts(.segment_leaf);
    const multiply_invocations = try allocator.alloc(
        recursion.air.qm31_mul_full_witness.Invocation,
        lowering_counts.multiply,
    );
    defer allocator.free(multiply_invocations);
    const inverse_invocations = try allocator.alloc(
        recursion.air.qm31_inv_witness.Invocation,
        lowering_counts.inverse,
    );
    defer allocator.free(inverse_invocations);
    const linear_invocations = try allocator.alloc(
        recursion.air.linear_ops_witness.Invocation,
        lowering_counts.linear,
    );
    defer allocator.free(linear_invocations);
    const lowering_evaluations = [_]lowering.Evaluation{
        .{
            .circuit_identity = prepared_vm_air.evaluation.circuit_identity,
            .values = prepared_vm_air.evaluation.values,
        },
        .{
            .circuit_identity = prepared_vm_air.evaluation.circuit_identity,
            .values = prepared_vm_air.evaluation.values,
        },
    };
    try lowering_plan.materializeInto(
        lowering_reference,
        .{ .lanes = &lowering_evaluations },
        .segment_leaf,
        .{
            .multiply = multiply_invocations,
            .inverse = inverse_invocations,
            .linear = linear_invocations,
        },
    );
    std.debug.print(
        "  row18 VM AIR graph: nodes={d} inputs={d} outputs={d} " ++
            "schedule={d} arithmetic(mul/inv/linear)={d}/{d}/{d} " ++
            "build_ns={d} replay_ns={d}\n",
        .{
            prepared_vm_air.circuit.nodes.len,
            prepared_vm_air.circuit.bindings.len,
            prepared_vm_air.circuit.outputs.len,
            prepared_vm_air.preprocessing.rows.len,
            lowering_counts.multiply,
            lowering_counts.inverse,
            lowering_counts.linear,
            composition_graph_ns,
            composition_replay_ns,
        },
    );
    const measured_wire_bytes = try leaf_support.validateAndReportMeasurement(
        selection,
        &output,
        proof_capture,
        resources_before,
        .{
            .proof_size = proof_size,
            .proof_bytes_len = proof_bytes.items.len,
            .transcript_draws = transcript_draws,
            .verifier_draws = verifier_channel.n_draws,
            .prove_ns = prove_ns,
            .serialize_ns = serialize_ns,
            .ingress_ns = ingress_ns,
            .decode_ns = decode_ns,
            .verify_ns = verify_ns,
            .total_ns = total_timer.read(),
        },
    );

    // Materialize the verifier-owned fixed wire and its transcript rows before
    // entering the optional outer proof. Rows 0--9 consume these exact values;
    // constructing them here keeps the active proof on the same authenticated
    // custody path as the frozen adapter and parity checks below.
    const leaf_shape = try recursion.leaf_profile.deriveShape(
        LEAF_DIMENSIONS,
        &output.statement,
        proof_capture,
    );
    const leaf_wire = try allocator.create(LeafWire);
    defer allocator.destroy(leaf_wire);
    recursion.fixed_wire_adapter.populate(
        LEAF_DIMENSIONS,
        leaf_wire,
        leaf_shape,
        &output.statement,
        output.interaction_claim,
        proof_capture,
    ) catch |err| {
        std.debug.print("  fixed-wire adapter failed: {s}\n", .{@errorName(err)});
        return err;
    };
    try leaf_wire.validateAgainstShape(leaf_shape);

    var transcript_preprocessing =
        try recursion.segment_transcript_witness.Preprocessing.init(
            allocator,
            vm_transcript_plan,
            recursion_transcript_plan,
        );
    defer transcript_preprocessing.deinit();
    var public_claim_words: [recursion.poseidon2_channel.RATE]M31 = undefined;
    for (&public_claim_words, leaf_authority.claim.digest) |*destination, raw|
        destination.* = M31.fromCanonical(raw);
    var transcript_rows = try recursion.segment_transcript_witness.Prepared(
        LEAF_DIMENSIONS,
    ).init(
        allocator,
        &transcript_preprocessing,
        vm_transcript_plan,
        recursion_transcript_plan,
        &leaf_authority.statement.words,
        .{ .vm = public_claim_words },
        leaf_wire,
    );
    defer transcript_rows.deinit();
    try transcript_rows.execution.replayNative(vm_transcript_plan);
    for (
        terminal_digest,
        transcript_rows.execution.final_digest,
    ) |native_word, recursive_word| {
        try std.testing.expectEqual(native_word, recursive_word.toU32());
    }
    try std.testing.expectEqual(
        transcript_draws,
        transcript_rows.execution.final_draw_count,
    );

    const native_relations = frontend.air.relation_challenges.Relations.fromDrawSequence(
        &recursive_capture.vm_air.relation_draws,
    );
    const canonical_claim = try output.interaction_claim.canonical(&output.statement);
    var statement_authority = try recursion.segment_statement_outer_source.Authority.init(
        allocator,
        &leaf_preprocessing,
    );
    defer statement_authority.deinit();
    var statement_workspace = try recursion.segment_statement_outer_source.Workspace.init(
        allocator,
    );
    defer statement_workspace.deinit();
    var statement_rows = try recursion.segment_statement_outer_source.Prepared.init(
        allocator,
        &statement_authority,
        &statement_workspace,
        &leaf_preprocessing,
        &guest.public.data,
        &leaf_authority,
    );
    defer statement_rows.deinit();
    var public_source = recursion.segment_public_outer_source.Source.init(
        allocator,
        vm_transcript_plan,
        recursion_transcript_plan,
        &leaf_preprocessing,
        @intCast(canonical_claim.claimed_sums.len),
    ) catch |err| {
        std.debug.print("  rows12-17 source failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer public_source.deinit();
    var public_rows = recursion.segment_public_outer_source.Prepared.init(
        allocator,
        &public_source,
        &leaf_preprocessing,
        &leaf_authority,
        &guest.public.data,
        &native_relations,
        &canonical_claim.claimed_sums,
    ) catch |err| {
        std.debug.print("  rows12-17 prepared failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer public_rows.deinit();

    if (try environmentFlag(allocator, TUPLE_FRONTIER_ENV)) {
        var captured_fri = try recursion.captured_fri.Owned.init(
            allocator,
            recursion.captured_fri.ProfileConfig.fromPcs(selection.config),
            proof_capture,
        );
        defer captured_fri.deinit();
        const tuple_frontier = riscv_cpu.recursive_fri_outer
            .classifyCapturedTupleClosureWithVmAir(
            allocator,
            &captured_fri,
            &prepared_vm_air,
            .{
                .vm = vm_transcript_plan,
                .recursion = recursion_transcript_plan,
            },
            .{
                .preprocessing = &transcript_preprocessing,
                .prepared = &transcript_rows,
                .statement = .{
                    .authority = &statement_authority,
                    .workspace = &statement_workspace,
                    .prepared = &statement_rows,
                },
                .public = .{
                    .source = &public_source,
                    .prepared = &public_rows,
                    .leaf_preprocessing = &leaf_preprocessing,
                    .leaf = &leaf_authority,
                    .data = &guest.public.data,
                },
            },
        ) catch |err| {
            std.debug.print(
                "  OUTER_TUPLE_FRONTIER failed={s}\n",
                .{@errorName(err)},
            );
            return err;
        };
        std.debug.print(
            "  OUTER_TUPLE_FRONTIER contributions={d} unmatched={d} " ++
                "red_domains={d} setup_ns={d} row_prepare_ns={d} " ++
                "classify_ns={d}\n",
            .{
                tuple_frontier.report.contribution_count,
                tuple_frontier.report.unmatched_tuple_count,
                tuple_frontier.report.redDomainCount(),
                tuple_frontier.setup_ns,
                tuple_frontier.row_prepare_ns,
                tuple_frontier.classify_ns,
            },
        );
        for (tuple_frontier.report.unmatched_by_domain, 0..) |
            unmatched,
            domain_index,
        | {
            if (unmatched == 0) continue;
            std.debug.print(
                "  OUTER_TUPLE_FRONTIER domain[{d}] unmatched={d}\n",
                .{ domain_index, unmatched },
            );
        }
        if (!tuple_frontier.frontierClosed())
            return error.TupleClosureMismatch;
    }

    if (try environmentFlag(allocator, ACTIVE_OUTER_ENV)) {
        var captured_fri = try recursion.captured_fri.Owned.init(
            allocator,
            recursion.captured_fri.ProfileConfig.fromPcs(selection.config),
            proof_capture,
        );
        defer captured_fri.deinit();
        std.debug.print("  active FRI outer stage: capture=ok\n", .{});
        const outer_workers = try recursionOuterWorkerCount(allocator);
        const mutation_probe_mode: riscv_cpu.recursive_fri_outer.MutationProbeMode =
            if (try environmentFlag(allocator, DISABLE_OUTER_MUTATIONS_ENV))
                .disabled
            else
                .enabled;
        var verified_outer: riscv_cpu.recursive_fri_outer.VerifiedOuterProofV1 =
            undefined;
        var verified_outer_owned = false;
        defer if (verified_outer_owned) verified_outer.deinit(allocator);
        const outer = riscv_cpu.recursive_fri_outer.proveAndVerifyCapturedWithVmAirExecutionAndAdmission(
            allocator,
            &captured_fri,
            &prepared_vm_air,
            .{
                .vm = vm_transcript_plan,
                .recursion = recursion_transcript_plan,
            },
            .{
                .preprocessing = &transcript_preprocessing,
                .prepared = &transcript_rows,
                .statement = .{
                    .authority = &statement_authority,
                    .workspace = &statement_workspace,
                    .prepared = &statement_rows,
                },
                .public = .{
                    .source = &public_source,
                    .prepared = &public_rows,
                    .leaf_preprocessing = &leaf_preprocessing,
                    .leaf = &leaf_authority,
                    .data = &guest.public.data,
                },
            },
            .{
                .worker_count = outer_workers,
                .mutation_probes = mutation_probe_mode,
            },
            &verified_outer,
        ) catch |err| {
            std.debug.print("  active FRI outer stage: failed={s}\n", .{@errorName(err)});
            return err;
        };
        verified_outer_owned = true;
        verified_outer.validate() catch |err| {
            std.debug.print(
                "  active FRI outer publication: verified-bundle failed={s}\n",
                .{@errorName(err)},
            );
            return err;
        };
        std.debug.print(
            "  active FRI outer publication: verified-bundle=ok\n",
            .{},
        );
        try std.testing.expect(!verified_outer.productionReady());
        try std.testing.expectEqual(
            recursion.outer_parent_child_admission.ProofScope.verifier_subsystem,
            verified_outer.receipt.scope,
        );
        try std.testing.expectEqual(
            statement_rows.statement_words,
            verified_outer.statement_words,
        );
        const statement_tag = verified_outer.statement_words[
            recursion.span_statement.canonical_layout.body_tag
        ];
        verified_outer.statement_words[
            recursion.span_statement.canonical_layout.body_tag
        ] = M31.zero();
        try std.testing.expectError(
            error.CanonicalTagMismatch,
            verified_outer.validate(),
        );
        verified_outer.statement_words[
            recursion.span_statement.canonical_layout.body_tag
        ] = statement_tag;
        try verified_outer.validate();
        var recursion_child = recursion.captured_fri.Owned.init(
            allocator,
            riscv_cpu.recursive_fri_outer.captureProfileConfig(),
            &verified_outer.capture,
        ) catch |err| {
            std.debug.print(
                "  active FRI outer publication: captured-fri-bridge failed={s}\n",
                .{@errorName(err)},
            );
            return err;
        };
        defer recursion_child.deinit();
        std.debug.print(
            "  active FRI outer publication: captured-fri-bridge=ok\n",
            .{},
        );
        try recursion_child.evaluation.validateAgainst(&recursion_child.circuit);
        try recursion_child.pcs_evaluation.validateAgainst(&recursion_child.pcs_circuit);
        try std.testing.expectEqual(@as(u8, 36), outer.roster_count);
        try std.testing.expectEqual(@as(u8, 34), outer.active_verifier_rows);
        try std.testing.expectEqual(@as(u8, 2), outer.active_provider_rows);
        try std.testing.expectEqual(
            mutation_probe_mode,
            outer.mutation_probe_mode,
        );
        const expected_mutation_rejections: u8 =
            if (mutation_probe_mode == .enabled) 5 else 0;
        try std.testing.expectEqual(
            expected_mutation_rejections,
            outer.mutation_rejections,
        );
        std.debug.print(
            "  active FRI outer proof: " ++
                "logs(vm-input/composition-control/bits/map/root/trace/pcs/leaf/node/anchor/control/input/mul/inv/linear/path/poseidon)=" ++
                "{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d} " ++
                "columns={d}+{d}+{d} constraints={d} proof_estimate={d} " ++
                "prove_ns={d} assembly_ns={d} stark_prove_ns={d} verify_ns={d} " ++
                "poseidon_calls={d} workers={d} draws={d} " ++
                "mutation_mode={s} mutations={d}/5\n",
            .{
                outer.vm_input_log_size,
                outer.composition_control_log_size,
                outer.query_bits_log_size,
                outer.query_mapping_log_size,
                outer.merkle_root_log_size,
                outer.trace_merkle_log_size,
                outer.pcs_deep_log_size,
                outer.fri_leaf_log_size,
                outer.fri_node_log_size,
                outer.fri_anchor_log_size,
                outer.control_log_size,
                outer.input_log_size,
                outer.multiply_log_size,
                outer.inverse_log_size,
                outer.linear_log_size,
                outer.merkle_path_log_size,
                outer.poseidon2_log_size,
                outer.preprocessed_columns,
                outer.main_columns,
                outer.interaction_columns,
                outer.constraints,
                outer.proof_size_estimate,
                outer.prove_ns,
                outer.assembly_ns,
                outer.stark_prove_ns,
                outer.verify_ns,
                outer.poseidon2_call_count,
                outer.worker_count,
                outer.transcript_draws,
                @tagName(outer.mutation_probe_mode),
                outer.mutation_rejections,
            },
        );
        std.debug.print(
            "    universal roster={d}/36 active_verifier={d} active_provider={d}\n",
            .{
                outer.roster_count,
                outer.active_verifier_rows,
                outer.active_provider_rows,
            },
        );
        std.debug.print(
            "    VM graph: nodes={d} inputs={d} outputs={d} schedule={d}; " ++
                "PCS graph: nodes={d} inputs={d} outputs={d} " ++
                "arithmetic_active(mul/inv/linear)={d}/{d}/{d} " ++
                "capacity_rows={d}/{d}/{d}\n",
            .{
                outer.vm_graph_nodes,
                outer.vm_graph_inputs,
                outer.vm_graph_outputs,
                outer.vm_schedule_rows,
                outer.pcs_graph_nodes,
                outer.pcs_graph_inputs,
                outer.pcs_graph_outputs,
                outer.arithmetic_active_counts[0],
                outer.arithmetic_active_counts[1],
                outer.arithmetic_active_counts[2],
                outer.arithmetic_capacity_rows[0],
                outer.arithmetic_capacity_rows[1],
                outer.arithmetic_capacity_rows[2],
            },
        );
        std.debug.print(
            "    assembly(setup/pre-fill/pre-commit/main-fill/main-commit/" ++
                "interaction-fill/interaction-commit/seal)=" ++
                "{d}/{d}/{d}/{d}/{d}/{d}/{d}/{d}\n",
            .{
                outer.assembly_profile.setup_ns,
                outer.assembly_profile.preprocessed_fill_ns,
                outer.assembly_profile.preprocessed_commit_ns,
                outer.assembly_profile.main_fill_ns,
                outer.assembly_profile.main_commit_ns,
                outer.assembly_profile.interaction_fill_ns,
                outer.assembly_profile.interaction_commit_ns,
                outer.assembly_profile.component_seal_ns,
            },
        );
    }

    // Only frozen V1 may cross the production profile/adapter boundary.  The
    // other candidates are real prove/ingress/verify measurements, not a
    // back-door protocol negotiation mechanism.
    if (std.meta.eql(selection.config, recursion.protocol.PCS_CONFIG)) {
        const fri_evidence = try evaluateCapturedFriCircuit(
            allocator,
            selection.config,
            proof_capture,
        );
        std.debug.print(
            "  active FRI circuit: nodes={d} inputs={d} outputs={d} " ++
                "build_ns={d} evaluate_ns={d} mutation_rejected=true\n",
            .{
                fri_evidence.node_count,
                fri_evidence.input_count,
                fri_evidence.output_count,
                fri_evidence.build_ns,
                fri_evidence.evaluate_ns,
            },
        );
        try runAdapterMutationFleet(
            leaf_wire,
            leaf_shape,
            &output.statement,
            output.interaction_claim,
            proof_capture,
        );
        try recursion.fixed_wire_adapter.populate(
            LEAF_DIMENSIONS,
            leaf_wire,
            leaf_shape,
            &output.statement,
            output.interaction_claim,
            proof_capture,
        );
        try leaf_wire.validateAgainstShape(leaf_shape);

        const fixed_bytes = try allocator.alloc(
            u8,
            LeafWire.serialized_byte_count,
        );
        defer allocator.free(fixed_bytes);
        try leaf_wire.encodeInto(fixed_bytes, leaf_shape);
        try std.testing.expectEqual(
            @as(usize, @intCast(leaf_shape.proof_wire_bytes)),
            fixed_bytes.len,
        );
        try std.testing.expectEqual(measured_wire_bytes, fixed_bytes.len);
        std.debug.print(
            "  fixed capture: trees={d}/{d}/{d}/8 sampled={d} queried={d} " ++
                "depths={d}/{d}/{d}/{d} fri_layers={d} terminal={d} wire={d}\n",
            .{
                output.statement.nPreprocessedColumns(),
                output.statement.nMainColumns(),
                output.statement.nInteractionColumns(),
                proof_capture.sampled_values.len,
                proof_capture.queried_values.len,
                proof_capture.trace_paths[0].path_depth,
                proof_capture.trace_paths[1].path_depth,
                proof_capture.trace_paths[2].path_depth,
                proof_capture.trace_paths[3].path_depth,
                proof_capture.fri.layers.len,
                proof_capture.last_layer_coefficients.len,
                fixed_bytes.len,
            },
        );
    }
    for (proof_capture.fri.layers, 0..) |layer, index| {
        std.debug.print(
            "    fri[{d}]: step={d} width={d} path={d}\n",
            .{ index, layer.fold_step, layer.fold_width, layer.path_depth },
        );
    }
    try std.testing.expectEqual(
        terminal_digest,
        verifier_channel.digestWords(),
    );
    const zero_digest = [_]u32{0} ** recursion.poseidon2_channel.RATE;
    try std.testing.expect(!std.meta.eql(
        terminal_digest,
        zero_digest,
    ));
    std.debug.print(
        "\n  R-011 native leaf: proof_estimate={d} postcard_bytes={d} " ++
            "queries={d}/{d} transcript={any} draws={d}\n",
        .{
            proof_size,
            proof_bytes.items.len,
            proof_capture.queries.unique.len,
            proof_capture.queries.raw.len,
            terminal_digest,
            transcript_draws,
        },
    );
}
