//! Focused admission and real-device tests for the guest Metal profile.

const std = @import("std");
const core = @import("stwo_core");
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine");
const metal = @import("stwo_metal_backend");
const riscv = @import("stwo_riscv_frontend");
const subject = @import("guest_precompile.zig");

const Component = subject.AuthenticatedProfileEngine.Component;
const component_mod = prover_engine.air.component_prover;
const accumulation = prover_engine.air.accumulation;
const prepared_domain = prover_engine.air.prepared_domain;
const CirclePointQM31 = core.circle.CirclePointQM31;

const MockComponent = struct {
    constraint_count: usize,
    max_log_degree: u32 = 5,
    split: u32 = 1,
    prepared: bool = true,
    parallel: bool = false,
    identity: ?component_mod.ComponentProfileIdentity = null,
    capability: ?component_mod.BackendCompositionCapability = null,

    fn asComponent(self: *const MockComponent) Component {
        return .{
            .ctx = self,
            .vtable = &mock_vtable,
            .profile_identity = self.identity,
            .backend_composition_capability = self.capability,
            .prepare_domain_evaluator = if (self.prepared) prepare else null,
            .domain_parallel_evaluator = if (self.parallel) evaluateParallel else null,
        };
    }

    fn cast(context: *const anyopaque) *const MockComponent {
        return @ptrCast(@alignCast(context));
    }

    fn nConstraints(context: *const anyopaque) usize {
        return cast(context).constraint_count;
    }

    fn maxConstraintLogDegreeBound(context: *const anyopaque) u32 {
        return cast(context).max_log_degree;
    }

    fn compositionLogSplit(context: *const anyopaque) u32 {
        return cast(context).split;
    }

    fn traceLogDegreeBounds(
        _: *const anyopaque,
        _: std.mem.Allocator,
    ) anyerror!core.air.components.TraceLogDegreeBounds {
        return error.UnexpectedMockEvaluation;
    }

    fn maskPoints(
        _: *const anyopaque,
        _: std.mem.Allocator,
        _: CirclePointQM31,
        _: u32,
    ) anyerror!core.air.components.MaskPoints {
        return error.UnexpectedMockEvaluation;
    }

    fn preprocessedColumnIndices(
        _: *const anyopaque,
        _: std.mem.Allocator,
    ) anyerror![]usize {
        return error.UnexpectedMockEvaluation;
    }

    fn evaluatePoint(
        _: *const anyopaque,
        _: CirclePointQM31,
        _: *const core.air.components.MaskValues,
        _: *core.air.accumulation.PointEvaluationAccumulator,
        _: u32,
    ) anyerror!void {
        return error.UnexpectedMockEvaluation;
    }

    fn evaluateDomain(
        _: *const anyopaque,
        _: *const component_mod.Trace,
        _: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!void {
        return error.UnexpectedMockEvaluation;
    }

    fn prepare(
        _: *const anyopaque,
        _: std.mem.Allocator,
        _: *const component_mod.Trace,
        _: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation {
        return error.UnexpectedMockEvaluation;
    }

    fn evaluateParallel(
        _: *const anyopaque,
        _: *const component_mod.Trace,
        _: *accumulation.DomainEvaluationAccumulator,
        _: *prover_engine.work_pool.WorkPool,
    ) anyerror!void {
        return error.UnexpectedMockEvaluation;
    }
};

const mock_vtable = component_mod.ComponentProverVTable{
    .nConstraints = MockComponent.nConstraints,
    .maxConstraintLogDegreeBound = MockComponent.maxConstraintLogDegreeBound,
    .compositionLogSplit = MockComponent.compositionLogSplit,
    .traceLogDegreeBounds = MockComponent.traceLogDegreeBounds,
    .maskPoints = MockComponent.maskPoints,
    .preprocessedColumnIndices = MockComponent.preprocessedColumnIndices,
    .evaluateConstraintQuotientsAtPoint = MockComponent.evaluatePoint,
    .evaluateConstraintQuotientsOnDomain = MockComponent.evaluateDomain,
};

test "guest Metal profile admits only the reviewed canonical component tail" {
    const caller = MockComponent{
        .constraint_count = riscv.air.guest_precompile.caller_component.constraint_count,
        .identity = .riscv_guest_poseidon2_caller_v1,
    };
    const provider = MockComponent{
        .constraint_count = riscv.air.guest_precompile.provider_component.constraint_count,
        .identity = .riscv_guest_poseidon2_provider_v1,
    };
    const valid = [_]Component{ caller.asComponent(), provider.asComponent() };
    try subject.validateProfileComponents(&valid);

    try std.testing.expectError(
        error.ProfileComponentSetTooSmall,
        subject.validateProfileComponents(valid[0..1]),
    );

    var forged_same_geometry = caller;
    forged_same_geometry.identity = null;
    const forged = [_]Component{
        forged_same_geometry.asComponent(),
        provider.asComponent(),
    };
    try std.testing.expectError(
        error.CallerSemanticIdentityMismatch,
        subject.validateProfileComponents(&forged),
    );

    var swapped_caller = caller;
    swapped_caller.identity = .riscv_guest_poseidon2_provider_v1;
    var swapped_provider = provider;
    swapped_provider.identity = .riscv_guest_poseidon2_caller_v1;
    const swapped = [_]Component{
        swapped_caller.asComponent(),
        swapped_provider.asComponent(),
    };
    try std.testing.expectError(
        error.CallerSemanticIdentityMismatch,
        subject.validateProfileComponents(&swapped),
    );

    var malformed_caller = caller;
    malformed_caller.constraint_count -= 1;
    const malformed = [_]Component{
        malformed_caller.asComponent(),
        provider.asComponent(),
    };
    try std.testing.expectError(
        error.CallerConstraintGeometryMismatch,
        subject.validateProfileComponents(&malformed),
    );

    var partially_capable = caller;
    partially_capable.capability = .{
        .quadratic_sum_squares_v1 = .{
            .trace_tree_index = 1,
            .first_column = 0,
        },
    };
    const unreviewed = [_]Component{
        partially_capable.asComponent(),
        provider.asComponent(),
    };
    try std.testing.expectError(
        error.UnreviewedProfileBackendCapability,
        subject.validateProfileComponents(&unreviewed),
    );

    var unprepared = provider;
    unprepared.prepared = false;
    const missing_preparation = [_]Component{
        caller.asComponent(),
        unprepared.asComponent(),
    };
    try std.testing.expectError(
        error.ProfilePreparedEvaluatorMissing,
        subject.validateProfileComponents(&missing_preparation),
    );
}

test "guest Metal profile runtime admission requires a complete AOT identity" {
    const Snapshot = subject.AuthenticatedProfileEngine.RuntimeLifecycleSnapshot;
    const empty = Snapshot{
        .initialized = false,
        .identity = null,
        .active_call_leases = 0,
        .live_resident_resources = 0,
        .initialization_count = 0,
        .shutdown_count = 0,
    };
    try std.testing.expectError(
        error.AuthenticatedRuntimeRequired,
        subject.validateRuntimeLifecycle(empty),
    );

    var source = empty;
    source.initialized = true;
    source.identity = .{
        .origin = .diagnostic_source_jit,
        .source_sha256 = [_]u8{1} ** 32,
    };
    try std.testing.expectError(
        error.AuthenticatedRuntimeRequired,
        subject.validateRuntimeLifecycle(source),
    );

    var incomplete = source;
    incomplete.identity = .{
        .origin = .authenticated_core_aot,
        .source_sha256 = [_]u8{1} ** 32,
        .manifest_sha256 = [_]u8{2} ** 32,
    };
    try std.testing.expectError(
        error.IncompleteAuthenticatedRuntimeIdentity,
        subject.validateRuntimeLifecycle(incomplete),
    );

    var admitted = incomplete;
    admitted.identity.?.metallib_sha256 = [_]u8{3} ** 32;
    admitted.identity.?.metallib_bytes = 4096;
    try subject.validateRuntimeLifecycle(admitted);
}

test "guest Metal profile telemetry rejects every fallback and missing dispatch" {
    const Delta = subject.AuthenticatedProfileEngine.Backend.TelemetryDelta;
    const valid = Delta{
        .counters = .{ .resident_merkle_commits = 1 },
        .pipeline_cache = .{},
    };
    try subject.validateProofDelta(valid);
    try std.testing.expectError(
        error.ResidentBasePolynomialDispatchMissing,
        subject.validateTransactionDelta(valid),
    );

    var fallback = valid;
    fallback.counters.cpu_sampled_value_evaluations = 1;
    try std.testing.expectError(
        error.CpuFallbackObserved,
        subject.validateProofDelta(fallback),
    );

    var missing_base = valid;
    missing_base.counters.riscv_base_polynomial_eligible_components = 1;
    try std.testing.expectError(
        error.ResidentBasePolynomialDispatchMissing,
        subject.validateProofDelta(missing_base),
    );

    var resident_classes = valid;
    resident_classes.counters.riscv_base_polynomial_eligible_components = 2;
    resident_classes.counters.riscv_lookup_polynomial_eligible_components = 2;
    resident_classes.counters.metal_riscv_base_polynomial_batch_dispatches = 1;
    resident_classes.counters.metal_riscv_lookup_polynomial_batch_dispatches = 1;
    try subject.validateProofDelta(resident_classes);
    try subject.validateTransactionDelta(resident_classes);

    resident_classes.counters.resident_merkle_commits = 0;
    try std.testing.expectError(
        error.NoResidentCommitmentEvidence,
        subject.validateTransactionDelta(resident_classes),
    );
}

test "guest Metal profile preserves the ordinary Metal proof protocol types" {
    const Profile = subject.AuthenticatedProfileEngine;
    const Ordinary = metal.MetalProverEngine;
    try std.testing.expect(Profile.Backend == metal.MetalCommitBackend);
    try std.testing.expect(Profile.Hasher == Ordinary.Hasher);
    try std.testing.expect(Profile.MerkleChannel == Ordinary.MerkleChannel);
    try std.testing.expect(Profile.Channel == Ordinary.Channel);
    try std.testing.expect(Profile.Scheme == Ordinary.Scheme);
    try std.testing.expect(Profile.ExtendedProof == Ordinary.ExtendedProof);
}

test "guest Metal profile publishes exact versioned product identity" {
    try std.testing.expectEqualStrings(
        riscv.isa.execution_profile.poseidon2_name,
        subject.profile_identity,
    );
    try std.testing.expectEqualStrings(
        riscv.isa.execution_profile.poseidon2_capability,
        subject.capability_identity,
    );
    try std.testing.expectEqual(@as(u16, 1), subject.profile_version);
    try std.testing.expectEqualStrings(
        @tagName(component_mod.ComponentProfileIdentity.riscv_guest_poseidon2_caller_v1),
        subject.caller_component_identity,
    );
    try std.testing.expectEqualStrings(
        @tagName(component_mod.ComponentProfileIdentity.riscv_guest_poseidon2_provider_v1),
        subject.provider_component_identity,
    );
    try std.testing.expectEqualStrings(
        "reviewed_generic_direct_plus_logup_v1",
        subject.execution_placement,
    );
    try std.testing.expect(!subject.backend_fallback_allowed);
}

test "guest Metal profile proves and independently verifies when an AOT bundle is supplied" {
    const allocator = std.testing.allocator;
    const bundle_path = std.process.getEnvVarOwned(
        allocator,
        "STWO_RISCV_METAL_AOT_BUNDLE",
    ) catch return error.SkipZigTest;
    defer allocator.free(bundle_path);

    const lifecycle = metal.MetalProverEngine.runtimeLifecycleSnapshot();
    var owns_runtime = false;
    if (!lifecycle.initialized) {
        const manifest_digest = try readManifestTrustAnchor(allocator, bundle_path);
        try metal.MetalProverEngine.initializeRuntime(allocator, .{
            .authenticated_aot = .{
                .bundle_path = bundle_path,
                .manifest_sha256 = manifest_digest,
            },
        });
        owns_runtime = true;
    } else {
        try subject.validateRuntimeLifecycle(lifecycle);
    }
    defer if (owns_runtime) metal.MetalCommitBackend.shutdown() catch unreachable;

    var states: [8][16]u32 = undefined;
    for (&states, 0..) |*state, call_index| {
        for (state, 0..) |*word, lane| {
            word.* = @intCast(call_index * state.len + lane);
        }
    }
    var elf = try riscv.testing.guest_precompile_corpus_elf.buildWithCompletion(
        allocator,
        &states,
        .self_loop,
    );
    defer elf.deinit();
    var run = try riscv.runner.runPoseidon2Extension(allocator, elf.bytes, 32);
    defer run.deinit();
    try std.testing.expectEqual(states.len, run.calls.len());

    const input_words = try riscv.air.public_data.packInputWords(allocator, run.base.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(
        riscv.air.public_data.OutputWord,
        run.base.output_words.len,
    );
    defer allocator.free(output_words);
    for (output_words, run.base.output_words) |*destination, source_word| {
        destination.* = .{
            .addr = source_word.addr,
            .value = source_word.value,
            .clock = source_word.clock,
        };
    }
    const public_data = riscv.air.public_data.PublicData{
        .initial_pc = run.base.initial_pc,
        .final_pc = run.base.final_pc,
        .clock = std.math.cast(u32, run.base.step_count) orelse
            return error.ExecutionClockOutOfRange,
        .initial_regs = run.base.initial_regs,
        .final_regs = run.base.final_regs,
        .reg_last_clock = run.base.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try riscv.air.public_data.completionFromRun(run.base),
        .io_entries = .{
            .input_start = run.base.input_start,
            .input_len = std.math.cast(u32, run.base.input.len) orelse
                return error.InputLengthOutOfRange,
            .input_words = input_words,
            .output_len = run.base.output_len,
            .output_len_addr = run.base.output_len_addr,
            .output_data_addr = run.base.output_data_addr,
            .output_words = output_words,
        },
    };
    const pcs_config = core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
        },
    };
    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        @tagName(@import("builtin").mode),
        "riscv-metal-guest-poseidon2-exact-work",
        .{ .capture_tasks = true, .capture_work = true },
    );
    defer recorder.deinit();

    var output = try subject.provePoseidon2WithPublicData(
        allocator,
        pcs_config,
        &run.base.execution_trace,
        &run.calls,
        &run.execution_rows,
        &run.base.state_chain_tracker,
        &run.base.rw_memory,
        &recorder,
        public_data,
    );
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);

    proof_moved = true;
    try subject.verifyPoseidon2(
        allocator,
        pcs_config,
        output.statement,
        output.extension,
        output.artifact,
        output.proof,
        output.interaction_claim,
    );

    const work = recorder.workCaptureRecorder() orelse unreachable;
    try std.testing.expect(try work.finalizePlannedProducerCoverage());
    const snapshot = try recorder.workSnapshot();
    try snapshot.validate();
    try std.testing.expect(snapshot.completeExact());

    var tasks = try recorder.taskSnapshot(allocator);
    defer tasks.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), tasks.graphs.len);
    const graph = tasks.graphs[0];
    try std.testing.expectEqualStrings("metal_composition_riscv", graph.graph_id);
    try std.testing.expect(graph.events.len != 0);
    try std.testing.expectEqual(graph.events.len, graph.contributions.len);
    try std.testing.expectEqual(graph.events.len, graph.component_work.len);
    for (graph.events, graph.contributions, 0..) |event, contribution, index| {
        try std.testing.expect(event.task_class != .coordinator);
        try std.testing.expect(event.parallel_eligible);
        try std.testing.expect(event.terminal_status == .completed);
        try std.testing.expectEqualStrings(
            "riscv_fallback_component",
            event.component_kind,
        );
        try std.testing.expectEqual(@as(u32, 1), event.contribution_range.len);
        try std.testing.expectEqual(@as(u32, @intCast(index)), event.contribution_range.start);
        try std.testing.expect(contribution.role == .exclusive);
        try std.testing.expectEqual(event.key.component_registry_index, contribution.component_registry_index);
        try std.testing.expectEqual(@as(?u64, contribution.planned_rows), contribution.completed_rows);
    }
    try std.testing.expectEqual(@as(u32, 1), graph.summary.requested_workers);
    try std.testing.expectEqual(@as(u32, 1), graph.summary.admitted_workers);
    try std.testing.expectEqual(@as(u32, 1), graph.summary.pool_capacity);
}

fn readManifestTrustAnchor(
    allocator: std.mem.Allocator,
    bundle_path: []const u8,
) ![32]u8 {
    var directory = try std.fs.cwd().openDir(bundle_path, .{});
    defer directory.close();
    const encoded = try directory.readFileAlloc(
        allocator,
        "stwo_zig_core.manifest.sha256",
        256,
    );
    defer allocator.free(encoded);
    if (encoded.len < 64) return error.InvalidManifestTrustAnchor;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded[0..64]) catch
        return error.InvalidManifestTrustAnchor;
    return digest;
}
