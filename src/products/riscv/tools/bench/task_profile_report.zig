//! Deterministic console projection of the flat prover task profile.

const std = @import("std");
const task_profile = @import("stwo_prover_api").task_profile;

/// Writes only schema-authoritative integers, booleans, enums, and identities.
/// Ratios and floating-point interpretations belong in an explicit report
/// layer, not in this diagnostic console projection.
pub fn write(writer: anytype, profile: task_profile.TaskProfile) !void {
    try writer.print(
        "Task profile: schema_version={d} runtime={s} example={s} graphs={d}\n",
        .{ profile.schema_version, profile.runtime, profile.example, profile.graphs.len },
    );
    for (profile.graphs) |graph| {
        const summary = graph.summary;
        try writer.print(
            "  graph id={s} events={d} contributions={d} components={d}\n",
            .{
                graph.graph_id,
                graph.events.len,
                graph.contributions.len,
                graph.component_work.len,
            },
        );
        try writer.print(
            "    scheduler kind={s} steal_count={d}\n",
            .{ @tagName(summary.scheduler), summary.steal_count },
        );
        try writer.print(
            "    workers requested={d} admitted={d} pool_capacity={d}" ++
                " worker_stack_bytes={d} peak_active_tasks={d}" ++
                " peak_active_workers=",
            .{
                summary.requested_workers,
                summary.admitted_workers,
                summary.pool_capacity,
                summary.worker_stack_bytes,
                summary.peak_active_tasks,
            },
        );
        try writeOptionalU32(writer, summary.peak_active_workers);
        try writer.writeByte('\n');
        try writer.print(
            "    tasks planned={d} submitted={d} completed={d} failed={d}" ++
                " cancelled={d} unsubmitted_cancelled={d} started={d}" ++
                " finished={d} duplicate_starts={d} duplicate_finishes={d}\n",
            .{
                summary.planned_tasks,
                summary.submitted_tasks,
                summary.completed_tasks,
                summary.failed_tasks,
                summary.cancelled_tasks,
                summary.unsubmitted_cancelled_tasks,
                summary.started_tasks,
                summary.finished_tasks,
                summary.duplicate_starts,
                summary.duplicate_finishes,
            },
        );
        try writer.print(
            "    timing useful_task_work_ns={d} critical_path_ns=",
            .{summary.useful_task_work_ns},
        );
        try writeOptionalU64(writer, summary.critical_path_ns);
        try writer.print(
            " admission_wait_ns={d} queue_wait_ns={d} resource_wait_ns={d}" ++
                " task_run_ns={d} worker_busy_ns=",
            .{
                summary.admission_wait_ns,
                summary.queue_wait_ns,
                summary.resource_wait_ns,
                summary.task_run_ns,
            },
        );
        try writeOptionalU64(writer, summary.worker_busy_ns);
        try writer.print(
            " worker_capacity_ns={d} graph_elapsed_ns={d}" ++
                " parallel_eligible_ns={d} cancellation_latency_ns=",
            .{
                summary.worker_capacity_ns,
                summary.graph_elapsed_ns,
                summary.parallel_eligible_ns,
            },
        );
        try writeOptionalU64(writer, summary.cancellation_latency_ns);
        try writer.writeByte('\n');
        try writer.print(
            "    resources peak_reserved_bytes={d}\n" ++
                "    work estimate={d} completed_rows={d} completed_tiles={d}\n",
            .{
                summary.peak_reserved_bytes,
                summary.total_work_estimate,
                summary.completed_rows,
                summary.completed_tiles,
            },
        );

        for (graph.component_work) |component| try writeComponent(writer, component);
        for (graph.contributions, 0..) |contribution, index|
            try writeContribution(writer, index, contribution);

        // The producer publishes this slice in canonical TaskKey order. Keep
        // that order visible instead of sorting or grouping for presentation.
        for (graph.events) |event| try writeEvent(writer, event);
    }
}

fn writeComponent(writer: anytype, component: task_profile.ComponentWork) !void {
    try writer.print(
        "    component index={d} kind={s} role={s} tasks={d}" ++
            " estimate={d} planned_rows={d} planned_tiles={d}" ++
            " completed_rows=",
        .{
            component.component_registry_index,
            component.component_kind,
            @tagName(component.role),
            component.task_count,
            component.work_estimate,
            component.planned_rows,
            component.planned_tiles,
        },
    );
    try writeOptionalU64(writer, component.completed_rows);
    try writer.writeAll(" completed_tiles=");
    try writeOptionalU64(writer, component.completed_tiles);
    try writer.writeByte('\n');
}

fn writeContribution(
    writer: anytype,
    index: usize,
    contribution: task_profile.Contribution,
) !void {
    try writer.print(
        "    contribution index={d} component_index={d} kind={s}" ++
            " role={s} estimate={d} planned_rows={d}" ++
            " planned_tiles={d} completed_rows=",
        .{
            index,
            contribution.component_registry_index,
            contribution.component_kind,
            @tagName(contribution.role),
            contribution.work_estimate,
            contribution.planned_rows,
            contribution.planned_tiles,
        },
    );
    try writeOptionalU64(writer, contribution.completed_rows);
    try writer.writeAll(" completed_tiles=");
    try writeOptionalU64(writer, contribution.completed_tiles);
    try writer.writeByte('\n');
}

fn writeEvent(writer: anytype, event: task_profile.TaskEvent) !void {
    try writer.writeAll("    event key=");
    try writeTaskKey(writer, event.key);
    try writer.print(
        " stage={s} component={s} class={s} parallel_eligible={} contributions={d}+{d} deps=[",
        .{
            event.stage_id,
            event.component_kind,
            @tagName(event.task_class),
            event.parallel_eligible,
            event.contribution_range.start,
            event.contribution_range.len,
        },
    );
    for (event.dependencySlice(), 0..) |dependency, index| {
        if (index != 0) try writer.writeByte(',');
        try writeTaskKey(writer, dependency);
    }
    try writer.writeAll("]\n");

    try writer.print(
        "      state submitted={} started={} finished={} cleanup_complete={}\n",
        .{ event.submitted, event.started, event.finished, event.cleanup_complete },
    );
    try writer.writeAll("      timestamps submitted_ns=");
    try writeOptionalU64(writer, event.submitted_ns);
    try writer.writeAll(" ready_ns=");
    try writeOptionalU64(writer, event.ready_ns);
    try writer.writeAll(" start_ns=");
    try writeOptionalU64(writer, event.start_ns);
    try writer.writeAll(" cancellation_requested_ns=");
    try writeOptionalU64(writer, event.cancellation_requested_ns);
    try writer.writeAll(" finish_ns=");
    try writeOptionalU64(writer, event.finish_ns);
    try writer.writeByte('\n');

    try writer.print(
        "      execution configured_workers={d} worker_slot=",
        .{event.configured_workers},
    );
    try writeOptionalU32(writer, event.worker_slot);
    try writer.writeAll(" worker_kind=");
    try writeOptionalEnum(writer, event.worker_kind);
    try writer.print(
        " admission_wait_ns={d} queue_wait_ns={d} run_ns={d}" ++
            " resource_wait_ns={d}\n",
        .{
            event.admission_wait_ns,
            event.queue_wait_ns,
            event.run_ns,
            event.resource_wait_ns,
        },
    );
    try writer.print(
        "      bytes final_output={d} exclusive_scratch={d}" ++
            " shared_resident={d} device_resident={d} worker_stack={d}\n",
        .{
            event.bytes.final_output_bytes,
            event.bytes.exclusive_scratch_bytes,
            event.bytes.shared_resident_bytes,
            event.bytes.device_resident_bytes,
            event.bytes.worker_stack_bytes,
        },
    );
    try writer.print(
        "      terminal status={s} error=",
        .{@tagName(event.terminal_status)},
    );
    try writeOptionalString(writer, event.error_name);
    try writer.writeAll(" cancellation_winner=");
    try writeOptionalTaskKey(writer, event.cancellation_winner);
    try writer.writeAll(" cancellation_reason=");
    try writeOptionalEnum(writer, event.cancellation_reason);
    try writer.writeByte('\n');
    try writer.print(
        "      work estimate={d} planned_rows={d} planned_tiles={d}" ++
            " completed_rows={d} completed_tiles={d}\n",
        .{
            event.work_estimate,
            event.planned_rows,
            event.planned_tiles,
            event.completed_rows,
            event.completed_tiles,
        },
    );
}

fn writeTaskKey(writer: anytype, key: task_profile.TaskKey) !void {
    try writer.print(
        "{d}:{d}:{d}:{d}",
        .{
            key.epoch,
            key.stage_rank,
            key.component_registry_index,
            key.shard_or_chunk_index,
        },
    );
}

fn writeOptionalTaskKey(writer: anytype, key: ?task_profile.TaskKey) !void {
    if (key) |present| return writeTaskKey(writer, present);
    try writer.writeAll("none");
}

fn writeOptionalU64(writer: anytype, value: ?u64) !void {
    if (value) |present| {
        try writer.print("{d}", .{present});
    } else {
        try writer.writeAll("none");
    }
}

fn writeOptionalU32(writer: anytype, value: ?u32) !void {
    if (value) |present| {
        try writer.print("{d}", .{present});
    } else {
        try writer.writeAll("none");
    }
}

fn writeOptionalEnum(writer: anytype, value: anytype) !void {
    if (value) |present| {
        try writer.writeAll(@tagName(present));
    } else {
        try writer.writeAll("none");
    }
}

fn writeOptionalString(writer: anytype, value: ?[]const u8) !void {
    if (value) |present| {
        try writer.print("{s}", .{present});
    } else {
        try writer.writeAll("none");
    }
}

test "raw task profile summary formatting is deterministic" {
    var no_events: [0]task_profile.TaskEvent = .{};
    var no_contributions: [0]task_profile.Contribution = .{};
    var no_components: [0]task_profile.ComponentWork = .{};
    var graphs = [_]task_profile.GraphRecord{.{
        .graph_id = "composition",
        .events = &no_events,
        .contributions = &no_contributions,
        .component_work = &no_components,
        .summary = .{
            .requested_workers = 4,
            .admitted_workers = 3,
            .pool_capacity = 8,
            .worker_stack_bytes = 1024,
            .peak_active_tasks = 2,
            .peak_active_workers = 2,
            .planned_tasks = 5,
            .submitted_tasks = 4,
            .completed_tasks = 3,
            .failed_tasks = 1,
            .unsubmitted_cancelled_tasks = 1,
            .started_tasks = 4,
            .finished_tasks = 4,
            .useful_task_work_ns = 11,
            .critical_path_ns = 17,
            .admission_wait_ns = 1,
            .queue_wait_ns = 2,
            .resource_wait_ns = 3,
            .task_run_ns = 19,
            .worker_busy_ns = 19,
            .worker_capacity_ns = 51,
            .graph_elapsed_ns = 23,
            .parallel_eligible_ns = 7,
            .peak_reserved_bytes = 4096,
            .total_work_estimate = 99,
            .completed_rows = 64,
            .completed_tiles = 2,
        },
    }};
    const profile = task_profile.TaskProfile{
        .runtime = "zig",
        .example = "riscv",
        .graphs = &graphs,
    };

    var output = std.ArrayList(u8).empty;
    defer output.deinit(std.testing.allocator);
    try write(output.writer(std.testing.allocator), profile);
    try std.testing.expectEqualStrings(
        \\Task profile: schema_version=2 runtime=zig example=riscv graphs=1
        \\  graph id=composition events=0 contributions=0 components=0
        \\    scheduler kind=central_queue_no_steal steal_count=0
        \\    workers requested=4 admitted=3 pool_capacity=8 worker_stack_bytes=1024 peak_active_tasks=2 peak_active_workers=2
        \\    tasks planned=5 submitted=4 completed=3 failed=1 cancelled=0 unsubmitted_cancelled=1 started=4 finished=4 duplicate_starts=0 duplicate_finishes=0
        \\    timing useful_task_work_ns=11 critical_path_ns=17 admission_wait_ns=1 queue_wait_ns=2 resource_wait_ns=3 task_run_ns=19 worker_busy_ns=19 worker_capacity_ns=51 graph_elapsed_ns=23 parallel_eligible_ns=7 cancellation_latency_ns=none
        \\    resources peak_reserved_bytes=4096
        \\    work estimate=99 completed_rows=64 completed_tiles=2
        \\
    , output.items);
}

test "raw task event formatting preserves canonical identities" {
    var event = task_profile.TaskEvent{
        .key = .{
            .epoch = 2,
            .stage_rank = 3,
            .component_registry_index = 5,
            .shard_or_chunk_index = 7,
        },
        .stage_id = "interaction",
        .component_kind = "poseidon2",
        .contribution_range = .{ .start = 8, .len = 2 },
        .task_class = .pool_exclusive,
        .dependency_count = 1,
        .parallel_eligible = true,
        .submitted = true,
        .started = true,
        .finished = true,
        .submitted_ns = 10,
        .ready_ns = 8,
        .start_ns = 12,
        .finish_ns = 21,
        .configured_workers = 4,
        .worker_slot = 1,
        .worker_kind = .helper,
        .admission_wait_ns = 3,
        .queue_wait_ns = 4,
        .run_ns = 9,
        .resource_wait_ns = 2,
        .bytes = .{
            .final_output_bytes = 100,
            .exclusive_scratch_bytes = 200,
            .shared_resident_bytes = 300,
            .device_resident_bytes = 400,
            .worker_stack_bytes = 500,
        },
        .terminal_status = .cancelled,
        .error_name = "InjectedFailure",
        .cancellation_winner = .{
            .epoch = 2,
            .stage_rank = 3,
            .component_registry_index = 4,
            .shard_or_chunk_index = 0,
        },
        .cancellation_reason = .sibling_failure,
        .cleanup_complete = true,
        .work_estimate = 1024,
        .planned_rows = 512,
        .planned_tiles = 2,
        .completed_rows = 256,
        .completed_tiles = 1,
    };
    event.dependencies[0] = .{
        .epoch = 1,
        .stage_rank = 9,
        .component_registry_index = 4,
        .shard_or_chunk_index = 6,
    };

    var output = std.ArrayList(u8).empty;
    defer output.deinit(std.testing.allocator);
    try writeEvent(output.writer(std.testing.allocator), event);
    try std.testing.expectEqualStrings(
        \\    event key=2:3:5:7 stage=interaction component=poseidon2 class=pool_exclusive parallel_eligible=true contributions=8+2 deps=[1:9:4:6]
        \\      state submitted=true started=true finished=true cleanup_complete=true
        \\      timestamps submitted_ns=10 ready_ns=8 start_ns=12 cancellation_requested_ns=none finish_ns=21
        \\      execution configured_workers=4 worker_slot=1 worker_kind=helper admission_wait_ns=3 queue_wait_ns=4 run_ns=9 resource_wait_ns=2
        \\      bytes final_output=100 exclusive_scratch=200 shared_resident=300 device_resident=400 worker_stack=500
        \\      terminal status=cancelled error=InjectedFailure cancellation_winner=2:3:4:0 cancellation_reason=sibling_failure
        \\      work estimate=1024 planned_rows=512 planned_tiles=2 completed_rows=256 completed_tiles=1
        \\
    , output.items);
}

test "raw semantic attribution formatting keeps unknown completion explicit" {
    var output = std.ArrayList(u8).empty;
    defer output.deinit(std.testing.allocator);
    const writer = output.writer(std.testing.allocator);

    try writeComponent(writer, .{
        .component_registry_index = 11,
        .component_kind = "poseidon2",
        .role = .semantic_constraints,
        .task_count = 2,
        .work_estimate = 17,
        .planned_rows = 12,
        .planned_tiles = 3,
        .completed_rows = null,
        .completed_tiles = null,
    });
    try writeContribution(writer, 4, .{
        .component_registry_index = 12,
        .component_kind = "lookup",
        .role = .lookup_constraints,
        .work_estimate = 8,
        .planned_rows = 8,
        .completed_rows = 8,
    });

    try std.testing.expectEqualStrings(
        \\    component index=11 kind=poseidon2 role=semantic_constraints tasks=2 estimate=17 planned_rows=12 planned_tiles=3 completed_rows=none completed_tiles=none
        \\    contribution index=4 component_index=12 kind=lookup role=lookup_constraints estimate=8 planned_rows=8 planned_tiles=0 completed_rows=8 completed_tiles=0
        \\
    , output.items);
}
