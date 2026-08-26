//! Actual CPU PCS receipts for the R-008 split commitment boundary.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const pcs_core = @import("stwo_core").pcs;
const prover_api = @import("stwo_prover_api");
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const work_pool = @import("stwo_prover_engine").work_pool;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);
const support = frontend.testing.guest_precompile_main_trace_support;
const guest_statement = frontend.air.guest_precompile.statement;
const component_registry = frontend.air.guest_precompile.component_registry;
const aggregation_fixture = frontend.testing.aggregation_test_fixture;
const aggregation_types = frontend.testing.aggregation_types;
const production = frontend.prover_mod.main_trace_plan_execution_production;
const split_leaf_prepare = frontend.testing.split_leaf_prepare;
const split_leaf_statement = frontend.testing.split_leaf_statement;
const subject = frontend.prover_mod.guest_precompile.split_pcs_prepare;
const caller_finish = frontend.prover_mod.guest_precompile.split_caller_finish;
const provider_finish = frontend.prover_mod.guest_precompile.split_provider_finish;
const commitment_witness = frontend.testing.commitment_witness;
const statement_geometry = frontend.testing.statement_geometry;
const proof_workspace = frontend.testing.proof_workspace;
const main_trace_plan = frontend.testing.main_trace_plan;
const runner = frontend.runner;
const public_data_mod = frontend.air.public_data;
const test_support = @import("split_pcs_prepare_test_support.zig");

const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};
const Authorities = test_support.Authorities;
const OwnedPublicData = test_support.OwnedPublicData;
const authorities = test_support.authorities;
const BaseOwner = test_support.BaseOwner;
const appendColumns = test_support.appendColumns;
const Pair = test_support.Pair;
const preparePair = test_support.preparePair;
const identities = test_support.identities;
const ParallelReceipt = test_support.ParallelReceipt;

test "R-008 actual CPU PCS roots are deterministic across role completion order" {
    var forward = try preparePair(std.testing.allocator, 1, false);
    defer forward.deinit();
    var reverse = try preparePair(std.testing.allocator, 1, true);
    defer reverse.deinit();

    try std.testing.expectEqual(forward.caller.roots, reverse.caller.roots);
    try std.testing.expectEqual(forward.provider.roots, reverse.provider.roots);
    try std.testing.expectEqual(
        forward.caller.channel.digestBytes(),
        reverse.caller.channel.digestBytes(),
    );
    try std.testing.expectEqual(
        forward.provider.channel.digestBytes(),
        reverse.provider.channel.digestBytes(),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &forward.caller.roots[subject.tree1_index],
        &forward.provider.roots[subject.tree1_index],
    ));

    const caller_base_columns = forward.caller.ownership.tree1_columns -
        component_registry.caller_layout.main_columns;
    try std.testing.expectEqual(@as(usize, 34), caller_base_columns);
    try std.testing.expectEqual(
        @as(usize, component_registry.provider_main_columns),
        forward.provider.ownership.tree1_columns,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        forward.caller.ownership.commitment_source_plan_cell_copies,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        forward.provider.ownership.commitment_source_plan_cell_copies,
    );
    try std.testing.expectEqual(
        subject.caller_relation_source_columns * forward.caller.relation_source.domain_size,
        forward.caller.ownership.relation_source_capture_cell_copies,
    );
    try std.testing.expectEqual(
        subject.provider_relation_source_columns * forward.provider.relation_source.domain_size,
        forward.provider.ownership.relation_source_capture_cell_copies,
    );
    try std.testing.expectEqual(
        forward.caller.ownership.tree0_cells + forward.caller.ownership.tree1_cells,
        forward.caller.ownership.backend_source_detach_copy_upper_bound_cells,
    );
    try std.testing.expectEqual(
        forward.provider.ownership.tree0_cells + forward.provider.ownership.tree1_cells,
        forward.provider.ownership.backend_source_detach_copy_upper_bound_cells,
    );
    try std.testing.expectEqual(@as(usize, 0), forward.caller.ownership.nested_work_pools);
    try std.testing.expectEqual(@as(usize, 0), forward.provider.ownership.nested_work_pools);
    const caller_tree0 = std.fmt.bytesToHex(forward.caller.roots[0], .lower);
    const caller_tree1 = std.fmt.bytesToHex(forward.caller.roots[1], .lower);
    const provider_tree0 = std.fmt.bytesToHex(forward.provider.roots[0], .lower);
    const provider_tree1 = std.fmt.bytesToHex(forward.provider.roots[1], .lower);
    try std.testing.expectEqualStrings(
        "0603151d4eae9956bde55420e55111025c8e153d0de26547d828d9df69b35ff3",
        &caller_tree0,
    );
    try std.testing.expectEqualStrings(
        "e86307a7ff9f2f7e0470222189f58098e6e10c998989377dd5d3981787da71ce",
        &caller_tree1,
    );
    try std.testing.expectEqualStrings(
        "c590890b9d851f9e5a11d0e0ab5c9be3c3d9e9c4775ad12eb6ac3afe899d592e",
        &provider_tree0,
    );
    try std.testing.expectEqualStrings(
        "960e0c362cad3b30c7fadfca5fedc19e46295ed7fb9a425548ff7375608bc246",
        &provider_tree1,
    );
}

test "R-008 actual CPU PCS role preparation is serial-parallel identical" {
    var serial = try preparePair(std.testing.allocator, 1, false);
    defer serial.deinit();

    var caller = ParallelReceipt{ .role = .core_request };
    var provider = ParallelReceipt{ .role = .poseidon2_provider };
    const caller_thread = try std.Thread.spawn(.{}, ParallelReceipt.run, .{&caller});
    errdefer caller_thread.join();
    const provider_thread = try std.Thread.spawn(.{}, ParallelReceipt.run, .{&provider});
    caller_thread.join();
    provider_thread.join();

    if (caller.failure) |err| return err;
    if (provider.failure) |err| return err;
    try std.testing.expect(!caller.allocator_leaked);
    try std.testing.expect(!provider.allocator_leaked);
    try std.testing.expectEqual(serial.caller.roots, caller.roots);
    try std.testing.expectEqual(serial.provider.roots, provider.roots);
    try std.testing.expectEqual(
        serial.caller.channel.digestBytes(),
        caller.channel_digest,
    );
    try std.testing.expectEqual(
        serial.provider.channel.digestBytes(),
        provider.channel_digest,
    );
}

test "R-008 actual CPU roots cross one barrier before shared transcript binding" {
    var pair = try preparePair(std.testing.allocator, 1, false);
    defer pair.deinit();
    const authority = try authorities(1);
    const Barrier = subject.ManifestBarrierV1(Engine);
    const barrier = try Barrier.create(
        std.testing.allocator,
        authority.accepted,
        &pair.caller,
        &pair.provider,
    );
    defer barrier.deinit();
    const caller_identity = try identities(.core_request, &pair.caller);
    const provider_identity = try identities(.poseidon2_provider, &pair.provider);
    const caller_draws = pair.caller.channel.n_draws;
    const provider_draws = pair.provider.channel.n_draws;
    const caller_binding = try pair.caller.bindSession(
        &barrier.session,
        &caller_identity,
    );
    const provider_binding = try pair.provider.bindSession(
        &barrier.session,
        &provider_identity,
    );

    try std.testing.expectEqual(caller_binding, provider_binding);
    try std.testing.expectEqual(caller_draws, pair.caller.channel.n_draws);
    try std.testing.expectEqual(provider_draws, pair.provider.channel.n_draws);
    try std.testing.expectEqual(subject.CommitmentPhaseV1.session_bound, pair.caller.phase);
    try std.testing.expectEqual(subject.CommitmentPhaseV1.session_bound, pair.provider.phase);
}

test "R-008 actual CPU PCS zero-call roots retain canonical empty-call geometry" {
    var first = try preparePair(std.testing.allocator, 0, false);
    defer first.deinit();
    var second = try preparePair(std.testing.allocator, 0, true);
    defer second.deinit();

    try std.testing.expectEqual(first.caller.roots, second.caller.roots);
    try std.testing.expectEqual(first.provider.roots, second.provider.roots);
    try std.testing.expectEqual(@as(u64, 0), first.caller.guest_call_count);
    try std.testing.expectEqual(@as(u64, 0), first.provider.guest_call_count);
    const caller_tree0 = std.fmt.bytesToHex(first.caller.roots[0], .lower);
    const caller_tree1 = std.fmt.bytesToHex(first.caller.roots[1], .lower);
    const provider_tree0 = std.fmt.bytesToHex(first.provider.roots[0], .lower);
    const provider_tree1 = std.fmt.bytesToHex(first.provider.roots[1], .lower);
    try std.testing.expectEqualStrings(
        "fa174c2b405ddff7d094abaca3d4c3e7e4634bd6c6ed69c0d7bfc9cad36e28b1",
        &caller_tree0,
    );
    try std.testing.expectEqualStrings(
        "2e43015a8075ed33708fc4f39bd5aa955016bc7f534a5b5231f090513a6f2727",
        &caller_tree1,
    );
    try std.testing.expectEqualStrings(
        "614b6556ffbc8ec25a1b7d2bba4e3c2a23c413ef55e70d7ba20fdc9db1ebf9b3",
        &provider_tree0,
    );
    try std.testing.expectEqualStrings(
        "8f05939f5d46938c38674bf6eb7ab5705df3ed04ebb9c838db767cabc5e374ae",
        &provider_tree1,
    );
}

test "R-008 zero-call extension planning is byte-identical to the base plan" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(false, .self_loop);
    var run = try runner.runPoseidon2Extension(allocator, &elf, 16);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 0), run.calls.len());

    var public_data = try OwnedPublicData.init(allocator, &run);
    defer public_data.deinit();
    try commitment_witness.bindCompletion(
        &public_data.value,
        run.base.execution_trace.final_pc,
        &run.base.rw_memory,
    );
    var witness = try commitment_witness.CommitmentWitness.buildPoseidon2(
        allocator,
        &run.base.execution_trace,
        &run.execution_rows,
        &run.base.rw_memory,
        public_data.value.completion.?,
    );
    defer witness.deinit(allocator);
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const geometry = try statement_geometry.buildPoseidon2(
        allocator,
        workspace,
        &run.base.execution_trace,
        &witness,
        &run.base.state_chain_tracker,
        public_data.value,
        0,
        .proof,
    );
    const options = main_trace_plan.BuildOptions{
        .execution = .{
            .worker_count = 1,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        },
        .pool_capacity = 1,
        .worker_stack_bytes = work_pool.WORKER_STACK_SIZE,
        .enable_opcode_audit = false,
    };
    const base_plan = try main_trace_plan.build(&workspace.statement, options);
    const extension_plan = try main_trace_plan.buildPoseidon2(
        &workspace.statement,
        &geometry.extension,
        .{
            .ordinary_rows = run.base.execution_trace.rows.items.len,
            .call_records = run.calls.len(),
            .guest_execution_rows = run.execution_rows.rows().len,
        },
        options,
    );
    try std.testing.expect(std.meta.eql(base_plan, extension_plan));
}

test "P-003 Poseidon2 extension base producer publishes exact main-witness receipt" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(true, .self_loop);
    var run = try runner.runPoseidon2Extension(allocator, &elf, 16);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 1), run.calls.len());

    var public_data = try OwnedPublicData.init(allocator, &run);
    defer public_data.deinit();
    try commitment_witness.bindCompletion(
        &public_data.value,
        run.base.execution_trace.final_pc,
        &run.base.rw_memory,
    );
    var witness = try commitment_witness.CommitmentWitness.buildPoseidon2(
        allocator,
        &run.base.execution_trace,
        &run.execution_rows,
        &run.base.rw_memory,
        public_data.value.completion.?,
    );
    defer witness.deinit(allocator);
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const geometry = try statement_geometry.buildPoseidon2(
        allocator,
        workspace,
        &run.base.execution_trace,
        &witness,
        &run.base.state_chain_tracker,
        public_data.value,
        1,
        .proof,
    );

    const authority = try authorities(1);
    var caller_shadow = try split_leaf_prepare.prepareCaller(
        allocator,
        authority.caller,
        &workspace.statement,
        &geometry.extension,
        &run.calls,
        &run.execution_rows,
    );
    defer caller_shadow.deinit();

    const execution_request = prover_api.CpuCompositionExecutionRequest{
        .worker_count = 1,
        .host_byte_budget = std.math.maxInt(usize),
        .contention_policy = .strict,
    };
    const execution_counts = main_trace_plan.Poseidon2ExecutionCounts{
        .ordinary_rows = run.base.execution_trace.rows.items.len,
        .call_records = run.calls.len(),
        .guest_execution_rows = run.execution_rows.rows().len,
    };
    const plan = try main_trace_plan.buildPoseidon2(
        &workspace.statement,
        &geometry.extension,
        execution_counts,
        .{
            .execution = execution_request,
            .pool_capacity = 1,
            .worker_stack_bytes = work_pool.WORKER_STACK_SIZE,
            .enable_opcode_audit = false,
        },
    );
    const caller_columns = caller_shadow.main.committedColumns();
    var prepared = try production.Prepared.preparePoseidon2ForEngine(
        Engine,
        allocator,
        &plan,
        &workspace.statement,
        &geometry.extension,
        execution_counts,
        .{
            .execution_trace = &run.base.execution_trace,
            .witness = &witness,
            .geometry = geometry.base,
            .state_chain = &run.base.state_chain_tracker,
            .capture_main_witness_work = true,
            .poseidon2_caller_lookup = .{
                .extension = &geometry.extension,
                .columns = caller_columns,
                .log_size = caller_shadow.main.log_size,
                .n_rows = caller_shadow.main.n_rows,
            },
        },
    );
    defer prepared.deinit();
    _ = try prepared.execute(null);

    const receipt = try prepared.mainWitnessWorkReceipt();
    try std.testing.expectEqual(@as(u16, 2), receipt.schema_version);
    try std.testing.expect(!std.mem.allEqual(u8, &receipt.source_digest, 0));
    try std.testing.expectEqual(
        @as(u64, geometry.extension.counts.n_guest),
        receipt.completed.guest_lookup_rows,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        receipt.completed.guest_caller_trace_rows,
    );
    var ordinary_rows: u64 = 0;
    for (receipt.completed.opcode_rows) |count| ordinary_rows += count;
    try std.testing.expectEqual(
        @as(u64, @intCast(run.base.execution_trace.rows.items.len)),
        ordinary_rows,
    );
    try std.testing.expectEqual(@as(u64, 0), receipt.completed.counter_set_merges);
    try std.testing.expectEqual(
        prover_api.work_profile.Site.main_witness_field,
        receipt.delta().site,
    );
}

test "R-008 actual CPU caller preserves production base authority and verifies a STARK" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(true, .self_loop);
    var run = try runner.runPoseidon2Extension(allocator, &elf, 16);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 1), run.calls.len());
    try std.testing.expectEqual(
        run.calls.len(),
        run.execution_rows.rows().len,
    );

    var public_data = try OwnedPublicData.init(allocator, &run);
    defer public_data.deinit();
    try commitment_witness.bindCompletion(
        &public_data.value,
        run.base.execution_trace.final_pc,
        &run.base.rw_memory,
    );
    var witness = try commitment_witness.CommitmentWitness.buildPoseidon2(
        allocator,
        &run.base.execution_trace,
        &run.execution_rows,
        &run.base.rw_memory,
        public_data.value.completion.?,
    );
    defer witness.deinit(allocator);
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const geometry = try statement_geometry.buildPoseidon2(
        allocator,
        workspace,
        &run.base.execution_trace,
        &witness,
        &run.base.state_chain_tracker,
        public_data.value,
        1,
        .proof,
    );

    const authority = try authorities(1);
    var caller_shadow = try split_leaf_prepare.prepareCaller(
        allocator,
        authority.caller,
        &workspace.statement,
        &geometry.extension,
        &run.calls,
        &run.execution_rows,
    );
    var caller_shadow_owned = true;
    defer if (caller_shadow_owned) caller_shadow.deinit();
    var provider_shadow = try split_leaf_prepare.prepareProvider(
        allocator,
        authority.provider,
        &workspace.statement,
        &geometry.extension,
        &run.calls,
        &run.execution_rows,
    );
    var provider_shadow_owned = true;
    defer if (provider_shadow_owned) provider_shadow.deinit();

    const execution_request = prover_api.CpuCompositionExecutionRequest{
        .worker_count = 1,
        .host_byte_budget = std.math.maxInt(usize),
        .contention_policy = .strict,
    };
    const execution_counts = main_trace_plan.Poseidon2ExecutionCounts{
        .ordinary_rows = run.base.execution_trace.rows.items.len,
        .call_records = run.calls.len(),
        .guest_execution_rows = run.execution_rows.rows().len,
    };
    var wrong_counts = execution_counts;
    wrong_counts.guest_execution_rows = 0;
    try std.testing.expectError(
        error.InvalidPoseidon2ExecutionBinding,
        main_trace_plan.buildPoseidon2(
            &workspace.statement,
            &geometry.extension,
            wrong_counts,
            .{
                .execution = execution_request,
                .pool_capacity = 1,
                .worker_stack_bytes = work_pool.WORKER_STACK_SIZE,
                .enable_opcode_audit = false,
            },
        ),
    );
    const plan = try main_trace_plan.buildPoseidon2(
        &workspace.statement,
        &geometry.extension,
        execution_counts,
        .{
            .execution = execution_request,
            .pool_capacity = 1,
            .worker_stack_bytes = work_pool.WORKER_STACK_SIZE,
            .enable_opcode_audit = false,
        },
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(run.base.execution_trace.rows.items.len)),
        plan.ordinary_steps,
    );
    try std.testing.expectEqual(
        plan.ordinary_steps + geometry.extension.counts.n_guest,
        plan.total_steps,
    );

    const caller_columns = caller_shadow.main.committedColumns();
    var base_prepared = try production.Prepared.preparePoseidon2ForEngine(
        Engine,
        allocator,
        &plan,
        &workspace.statement,
        &geometry.extension,
        execution_counts,
        .{
            .execution_trace = &run.base.execution_trace,
            .witness = &witness,
            .geometry = geometry.base,
            .state_chain = &run.base.state_chain_tracker,
            .poseidon2_caller_lookup = .{
                .extension = &geometry.extension,
                .columns = caller_columns,
                .log_size = caller_shadow.main.log_size,
                .n_rows = caller_shadow.main.n_rows,
            },
        },
    );
    var base_prepared_owned = true;
    defer if (base_prepared_owned) base_prepared.deinit();
    _ = try base_prepared.execute(null);

    caller_shadow_owned = false;
    var caller = try subject.prepareCallerFromPublishedBase(
        Engine,
        allocator,
        test_config,
        &workspace.statement,
        &geometry.extension,
        &base_prepared,
        &caller_shadow,
        null,
    );
    var caller_owned = true;
    defer if (caller_owned) caller.deinit();
    provider_shadow_owned = false;
    var provider = try subject.prepareProvider(
        Engine,
        allocator,
        test_config,
        &workspace.statement,
        &geometry.extension,
        &provider_shadow,
        null,
    );
    defer provider.deinit();

    const Barrier = subject.ManifestBarrierV1(Engine);
    const barrier = try Barrier.create(
        allocator,
        authority.accepted,
        &caller,
        &provider,
    );
    defer barrier.deinit();
    const caller_identity = try identities(.core_request, &caller);
    const provider_identity = try identities(.poseidon2_provider, &provider);
    _ = try caller.bindSession(&barrier.session, &caller_identity);
    _ = try provider.bindSession(&barrier.session, &provider_identity);
    const caller_draws_before_tree2 = caller.channel.n_draws;
    try std.testing.expectEqual(@as(u32, 0), caller_draws_before_tree2);

    // The finish boundary consumes both caller PCS and retained base owners on
    // success or failure; the provider remains an independent live owner.
    caller_owned = false;
    base_prepared_owned = false;
    var completed = try caller_finish.finishCallerTree2(
        Engine,
        allocator,
        workspace,
        &geometry.extension,
        &witness,
        geometry.base,
        &barrier.session,
        &caller,
        &base_prepared,
        execution_request,
        null,
        null,
        null,
    );
    var completed_owned = true;
    defer if (completed_owned) completed.deinit();
    try completed.validate();
    try std.testing.expectEqual(
        // The following claim-frame mix resets the Blake2s draw counter. The
        // proof/verifier parity below authenticates all twelve base draws;
        // this terminal value ensures no unframed draw escaped afterwards.
        @as(u32, 0),
        completed.channel.n_draws,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        caller_finish.LOCAL_GUEST_RELATION_DRAWS,
    );
    try std.testing.expectEqual(
        @as(usize, workspace.statement.nInteractionColumns()),
        completed.ownership.base_columns,
    );
    try std.testing.expectEqual(
        @as(usize, caller_finish.caller_interaction_columns),
        completed.ownership.caller_columns,
    );
    try std.testing.expectEqual(@as(usize, 0), completed.ownership.nested_work_pools);
    try std.testing.expectEqual(@as(usize, 3), completed.roots.len);
    const caller_tree2_root = std.fmt.bytesToHex(completed.roots[2], .lower);
    try std.testing.expectEqualStrings(
        "517aae071b13ade54b1cc648eefbc6997ff56e5c6ef416791dd1fc9f890e4b3b",
        &caller_tree2_root,
    );
    completed.ownership.caller_cells += 1;
    try std.testing.expectError(
        error.InvalidPreparedCallerTree2,
        completed.validate(),
    );
    completed.ownership.caller_cells -= 1;

    completed_owned = false;
    var output = try completed.prove(workspace, null);
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved()
    else
        output.deinit();
    try std.testing.expectEqual(
        @as(usize, 4),
        output.proof.commitment_scheme_proof.commitments.items.len,
    );
    proof_moved = true;
    try caller_finish.verifyCallerStarkV1(
        Engine,
        allocator,
        test_config,
        &workspace.statement,
        &geometry.extension,
        &barrier.session,
        &caller_identity,
        output.proof,
        output.base_claim,
        output.caller_claim,
    );
}

test "R-008 actual CPU provider completes and independently verifies a three-tree STARK" {
    const allocator = std.testing.allocator;
    var core = support.coreFixture(1);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 1);
    var pair = try preparePair(allocator, 1, false);
    var pair_intact = true;
    defer if (pair_intact) pair.deinit() else pair.caller.deinit();
    const authority = try authorities(1);
    const Barrier = subject.ManifestBarrierV1(Engine);
    const barrier = try Barrier.create(
        allocator,
        authority.accepted,
        &pair.caller,
        &pair.provider,
    );
    defer barrier.deinit();
    const caller_identity = try identities(.core_request, &pair.caller);
    const provider_identity = try identities(.poseidon2_provider, &pair.provider);
    _ = try pair.caller.bindSession(&barrier.session, &caller_identity);
    _ = try pair.provider.bindSession(&barrier.session, &provider_identity);
    const provider_draws_before_tree2 = pair.provider.channel.n_draws;

    // `finishProviderTree2` consumes the provider owner on both success and
    // failure, while the caller remains a separate live scheme.
    pair_intact = false;
    var completed = try provider_finish.finishProviderTree2(
        Engine,
        allocator,
        &core,
        &extension,
        &barrier.session,
        &pair.provider,
        null,
        null,
    );
    var completed_owned = true;
    defer if (completed_owned) completed.deinit();
    try completed.validate();
    try std.testing.expectEqual(
        provider_draws_before_tree2,
        completed.channel.n_draws,
    );
    try std.testing.expectEqual(@as(usize, 3), completed.roots.len);
    try std.testing.expectEqual(
        @as(usize, provider_finish.provider_interaction_columns * 16),
        completed.tree2_cells,
    );
    const tree2_root = std.fmt.bytesToHex(completed.roots[2], .lower);
    try std.testing.expectEqualStrings(
        "2be5b355a95e51e51323eaec2fb7c59d670022b24981d032d1b540d0e5b34aff",
        &tree2_root,
    );
    var wrong_preprocessed_root = completed.roots[0];
    wrong_preprocessed_root[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProviderPreprocessedRoot,
        provider_finish.verifyProviderPreprocessedRootV1(
            Engine,
            allocator,
            test_config,
            completed.construction.descriptor,
            wrong_preprocessed_root,
        ),
    );

    const provider_claim = completed.claim;
    completed_owned = false;
    const proof = try completed.prove(null);
    try provider_finish.verifyProviderStarkV1(
        Engine,
        allocator,
        test_config,
        &core,
        &extension,
        &barrier.session,
        &provider_identity,
        proof,
        provider_claim,
    );
}

test "R-008 provider post-barrier cancellation consumes its private PCS owner" {
    const allocator = std.testing.allocator;
    var core = support.coreFixture(1);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 1);
    var pair = try preparePair(allocator, 1, false);
    var pair_intact = true;
    defer if (pair_intact) pair.deinit() else pair.caller.deinit();
    const authority = try authorities(1);
    const Barrier = subject.ManifestBarrierV1(Engine);
    const barrier = try Barrier.create(
        allocator,
        authority.accepted,
        &pair.caller,
        &pair.provider,
    );
    defer barrier.deinit();
    const provider_identity = try identities(.poseidon2_provider, &pair.provider);
    _ = try pair.provider.bindSession(&barrier.session, &provider_identity);
    var cancellation = subject.CancellationTokenV1{};
    cancellation.request();

    pair_intact = false;
    try std.testing.expectError(
        error.SplitProviderFinishCancelled,
        provider_finish.finishProviderTree2(
            Engine,
            allocator,
            &core,
            &extension,
            &barrier.session,
            &pair.provider,
            &cancellation,
            null,
        ),
    );
}

test "R-008 actual CPU PCS preparation cancellation consumes inputs and publishes nothing" {
    const allocator = std.testing.allocator;
    var core = support.coreFixture(1);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(allocator, 1);
    defer logs.deinit();
    const authority = try authorities(1);
    var caller_shadow = try split_leaf_prepare.prepareCaller(
        allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    var base = try BaseOwner.init(allocator, &core, 0x1020_3040);
    var cancellation = subject.CancellationTokenV1{};
    cancellation.request();
    try std.testing.expectError(
        error.SplitPcsPreparationCancelled,
        subject.prepareCaller(
            Engine,
            allocator,
            test_config,
            &core,
            &extension,
            &base.value,
            &caller_shadow,
            &cancellation,
        ),
    );
}

test "R-008 actual CPU PCS rejects incomplete caller base ownership transactionally" {
    const allocator = std.testing.allocator;
    var core = support.coreFixture(1);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(allocator, 1);
    defer logs.deinit();
    const authority = try authorities(1);
    var caller_shadow = try split_leaf_prepare.prepareCaller(
        allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    var base = try BaseOwner.initIncomplete(allocator, &core, 0x1020_3040);
    try std.testing.expectError(
        error.IncompleteCallerBaseMainCommitment,
        subject.prepareCaller(
            Engine,
            allocator,
            test_config,
            &core,
            &extension,
            &base.value,
            &caller_shadow,
            null,
        ),
    );
}
