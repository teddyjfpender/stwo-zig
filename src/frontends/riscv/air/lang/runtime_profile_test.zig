const std = @import("std");
const prover_api = @import("stwo_prover_api");
const runtime_profile = @import("runtime_profile.zig");
const static_registry = @import("static_profile_registry.zig");

const StageNode = prover_api.stage_profile.StageNode;
const StageProfile = prover_api.stage_profile.StageProfile;
const task = prover_api.task_profile;
const Sha256 = std.crypto.hash.sha2.Sha256;

const Fixture = struct {
    child: [1]StageNode = undefined,
    roots: [1]StageNode = undefined,
    events: [1]task.TaskEvent = undefined,
    contributions: [1]task.Contribution = undefined,
    component_work: [1]task.ComponentWork = undefined,
    graphs: [1]task.GraphRecord = undefined,

    fn init(self: *Fixture) void {
        self.child[0] = .{
            .id = "composition",
            .label = "Composition",
            .seconds = 20.0 / @as(f64, @floatFromInt(std.time.ns_per_s)),
        };
        self.roots[0] = .{
            .id = "prove",
            .label = "Prove",
            .seconds = 100.0 / @as(f64, @floatFromInt(std.time.ns_per_s)),
            .children = self.child[0..],
        };
        self.events[0] = .{
            .key = .{ .stage_rank = 1, .component_registry_index = 7 },
            .stage_id = "composition",
            .component_kind = "lui",
            .task_class = .leaf,
            .parallel_eligible = true,
            .contribution_range = .{ .start = 0, .len = 1 },
            .submitted = true,
            .started = true,
            .finished = true,
            .submitted_ns = 0,
            .ready_ns = 0,
            .start_ns = 10,
            .finish_ns = 30,
            .configured_workers = 2,
            .worker_slot = 0,
            .worker_kind = .helper,
            .queue_wait_ns = 10,
            .run_ns = 20,
            .bytes = .{
                .final_output_bytes = 64,
                .exclusive_scratch_bytes = 64,
            },
            .terminal_status = .completed,
            .cleanup_complete = true,
            .work_estimate = 4,
            .planned_rows = 4,
            .planned_tiles = 1,
            .completed_rows = 4,
            .completed_tiles = 1,
        };
        self.contributions[0] = .{
            .component_registry_index = 7,
            .component_kind = "lui",
            .role = .exclusive,
            .work_estimate = 4,
            .planned_rows = 4,
            .planned_tiles = 1,
            .completed_rows = 4,
            .completed_tiles = 1,
        };
        self.component_work[0] = .{
            .component_registry_index = 7,
            .component_kind = "lui",
            .role = .exclusive,
            .task_count = 1,
            .work_estimate = 4,
            .planned_rows = 4,
            .planned_tiles = 1,
            .completed_rows = 4,
            .completed_tiles = 1,
        };
        self.graphs[0] = .{
            .graph_id = "tree1-components",
            .events = self.events[0..],
            .contributions = self.contributions[0..],
            .component_work = self.component_work[0..],
            .summary = .{
                .requested_workers = 2,
                .admitted_workers = 2,
                .pool_capacity = 2,
                .worker_stack_bytes = 4096,
                .peak_active_tasks = 1,
                .peak_active_workers = 1,
                .planned_tasks = 1,
                .submitted_tasks = 1,
                .completed_tasks = 1,
                .started_tasks = 1,
                .finished_tasks = 1,
                .useful_task_work_ns = 20,
                .critical_path_ns = 20,
                .queue_wait_ns = 10,
                .task_run_ns = 20,
                .worker_busy_ns = 20,
                .worker_capacity_ns = 200,
                .graph_elapsed_ns = 100,
                .parallel_eligible_ns = 20,
                .peak_reserved_bytes = 128,
                .total_work_estimate = 4,
                .completed_rows = 4,
                .completed_tiles = 1,
            },
        };
    }

    fn stageProfile(self: *Fixture) StageProfile {
        return .{
            .runtime = "cpu",
            .example = "typed-air-runtime-fixture",
            .stages = self.roots[0..],
        };
    }

    fn taskProfile(self: *Fixture) task.TaskProfile {
        return .{
            .runtime = "cpu",
            .example = "typed-air-runtime-fixture",
            .graphs = self.graphs[0..],
        };
    }
};

fn exactObservation() runtime_profile.Observation {
    return .{
        .identity = .{
            .implementation = digest("implementation"),
            .workload = digest("workload"),
            .protocol = digest("protocol"),
            .proof = digest("proof"),
        },
        .backend = .cpu,
        .optimize = .release_fast,
        .configured_workers = 2,
        .independently_verified = true,
        .timings = .{
            .input_and_execution_ns = 100,
            .prove_ns = 600,
            .encode_ns = 50,
            .verify_ns = 150,
            .request_ns = 1000,
        },
        .proof_bytes = 4096,
        .committed_trace_cells = 65_536,
        .resources = .{
            .peak_rss_bytes = 1_048_576,
            .instructions = 90_000,
            .cycles = 50_000,
            .energy_nanojoules = 1_000,
        },
        .work = .{
            .authority = .instrumented_exact,
            .field_additions = 1_000,
            .field_multiplications = 800,
            .field_inversions = 10,
            .fft_butterflies = 256,
            .fri_folds = 128,
            .merkle_compressions = 64,
        },
    };
}

test "runtime profile: exact static, stage, task, and hardware evidence joins deterministically" {
    const static = try static_registry.collect(std.testing.allocator);
    var fixture = Fixture{};
    fixture.init();
    const stages = fixture.stageProfile();
    const tasks = fixture.taskProfile();

    const profile = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        exactObservation(),
    );
    try profile.validate();
    try profile.validateAgainstSources(&static, &stages, &tasks);
    try std.testing.expect(profile.evidenceComplete());
    try std.testing.expectEqual(@as(u32, 2), profile.stages.stage_count);
    try std.testing.expectEqual(@as(u16, 2), profile.stages.maximum_depth);
    try std.testing.expectEqual(@as(u64, 100), profile.stages.root_elapsed_ns);
    try std.testing.expectEqual(@as(u64, 120), profile.stages.nested_node_elapsed_ns);
    try std.testing.expectEqual(@as(u64, 1), profile.tasks.task_count);
    try std.testing.expectEqual(@as(?u64, 20), profile.tasks.critical_path_ns);
    try std.testing.expectEqualStrings(
        "bceaa2fa4607a9fc488a48700ecc7c8ac2fc99e05f9ba2cbe5e76c7d30dac6f0",
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );

    const replay = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        exactObservation(),
    );
    try std.testing.expectEqualDeep(profile, replay);
}

test "runtime profile: complete source records are bound beyond their aggregates" {
    const static = try static_registry.collect(std.testing.allocator);
    var fixture = Fixture{};
    fixture.init();
    var stages = fixture.stageProfile();
    var tasks = fixture.taskProfile();
    const baseline = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        exactObservation(),
    );

    fixture.child[0].seconds =
        21.0 / @as(f64, @floatFromInt(std.time.ns_per_s));
    try std.testing.expectError(
        error.InvalidRuntimeProfile,
        baseline.validateAgainstSources(&static, &stages, &tasks),
    );
    const stage_mutation = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        exactObservation(),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline.stages.source_digest,
        &stage_mutation.stages.source_digest,
    ));

    fixture.events[0].finish_ns = 31;
    fixture.events[0].run_ns = 21;
    fixture.graphs[0].summary.useful_task_work_ns = 21;
    fixture.graphs[0].summary.critical_path_ns = 21;
    fixture.graphs[0].summary.task_run_ns = 21;
    fixture.graphs[0].summary.worker_busy_ns = 21;
    fixture.graphs[0].summary.parallel_eligible_ns = 21;
    const task_mutation = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        exactObservation(),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &stage_mutation.tasks.source_digest,
        &task_mutation.tasks.source_digest,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline.profile_digest,
        &task_mutation.profile_digest,
    ));
}

test "runtime profile: estimates and missing hardware counters stay non-promotable" {
    const static = try static_registry.collect(std.testing.allocator);
    var fixture = Fixture{};
    fixture.init();
    const stages = fixture.stageProfile();
    const tasks = fixture.taskProfile();
    var observation = exactObservation();
    observation.independently_verified = false;
    observation.resources = .{};
    observation.work = .{};

    const profile = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        observation,
    );
    try profile.validate();
    try std.testing.expect(!profile.evidenceComplete());

    observation.work = .{
        .authority = .structural_estimate,
        .field_additions = 1,
        .field_multiplications = 1,
        .field_inversions = 1,
        .fft_butterflies = 1,
        .fri_folds = 1,
        .merkle_compressions = 1,
    };
    const estimated = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        observation,
    );
    try std.testing.expect(!estimated.evidenceComplete());
}

test "runtime profile: malformed source and receipt mutations fail closed" {
    const static = try static_registry.collect(std.testing.allocator);
    var fixture = Fixture{};
    fixture.init();
    const stages = fixture.stageProfile();
    const tasks = fixture.taskProfile();

    fixture.graphs[0].summary.useful_task_work_ns += 1;
    try std.testing.expectError(
        error.InvalidRuntimeProfileInput,
        runtime_profile.join(&static, &stages, &tasks, exactObservation()),
    );
    fixture.graphs[0].summary.useful_task_work_ns -= 1;

    var profile = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        exactObservation(),
    );
    profile.proof_bytes += 1;
    try std.testing.expectError(error.InvalidRuntimeProfile, profile.validate());

    var invalid_observation = exactObservation();
    invalid_observation.work.authority = .unavailable;
    try std.testing.expectError(
        error.InvalidRuntimeProfileInput,
        runtime_profile.join(&static, &stages, &tasks, invalid_observation),
    );
}

test "runtime profile: canonical JSON is deterministic and validates before output" {
    const static = try static_registry.collect(std.testing.allocator);
    var fixture = Fixture{};
    fixture.init();
    const stages = fixture.stageProfile();
    const tasks = fixture.taskProfile();
    var profile = try runtime_profile.join(
        &static,
        &stages,
        &tasks,
        exactObservation(),
    );

    var first_storage: [16 * 1024]u8 = undefined;
    var first = std.Io.Writer.fixed(&first_storage);
    try runtime_profile.writeJson(&first, &profile);
    var replay_storage: [16 * 1024]u8 = undefined;
    var replay = std.Io.Writer.fixed(&replay_storage);
    try runtime_profile.writeJson(&replay, &profile);
    try std.testing.expectEqualStrings(first.buffered(), replay.buffered());
    try std.testing.expect(std.mem.indexOf(
        u8,
        first.buffered(),
        "\"evidence_complete\":true",
    ) != null);

    profile.tasks.completed_rows += 1;
    var rejected_storage: [256]u8 = undefined;
    var rejected = std.Io.Writer.fixed(&rejected_storage);
    try std.testing.expectError(
        error.InvalidRuntimeProfile,
        runtime_profile.writeJson(&rejected, &profile),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected.buffered().len);
}

fn digest(bytes: []const u8) runtime_profile.Digest {
    var result: runtime_profile.Digest = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}
