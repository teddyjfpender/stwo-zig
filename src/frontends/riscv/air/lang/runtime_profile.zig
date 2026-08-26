//! Authenticated join between static typed-AIR geometry and runtime evidence.
//!
//! The static registry, hierarchical stage profile, and flat bounded-task
//! profile remain independent authorities. This module validates all three,
//! binds the complete runtime source records, and emits one allocation-free
//! fixed-shape receipt. Derived work is never presented as an exact hardware
//! counter: counter authority is explicit and promotion remains fail closed.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const static_registry = @import("static_profile_registry.zig");
const runtime_profile_json = @import("runtime_profile_json.zig");
const runtime_profile_support = @import("runtime_profile_support.zig");

const stage_profile = prover_api.stage_profile;
const task_profile = prover_api.task_profile;
const work_profile = prover_api.work_profile;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA = "stwo.typed-air.runtime-profile.v1";
pub const SCHEMA_VERSION: u16 = 1;
pub const DIGEST_DOMAIN = "stwo-zig/typed-air/runtime-profile/v1\x00";
const STAGE_DIGEST_DOMAIN = "stwo-zig/typed-air/stage-profile-source/v1\x00";
const TASK_DIGEST_DOMAIN = "stwo-zig/typed-air/task-profile-source/v2\x00";
const BYTE_STRING_DIGEST_DOMAIN = "stwo-zig/typed-air/runtime-string/v1\x00";
const MAX_STAGE_DEPTH: u16 = 64;
const MAX_STAGE_NODES: u32 = 100_000;

pub const Digest = [Sha256.digest_length]u8;
pub const Error = error{
    InvalidRuntimeProfileInput,
    InvalidRuntimeProfile,
};

pub const Backend = enum(u8) {
    cpu = 1,
    metal = 2,
    cuda = 3,
};

pub const OptimizeMode = enum(u8) {
    debug = 1,
    release_safe = 2,
    release_fast = 3,
    release_small = 4,
};

pub const CounterAuthority = work_profile.Authority;

pub const Identity = struct {
    implementation: Digest,
    workload: Digest,
    protocol: Digest,
    proof: Digest,
};

pub const Timings = struct {
    input_and_execution_ns: u64,
    prove_ns: u64,
    encode_ns: u64,
    verify_ns: u64,
    request_ns: u64,
};

pub const ResourceCounters = struct {
    peak_rss_bytes: ?u64 = null,
    instructions: ?u64 = null,
    cycles: ?u64 = null,
    energy_nanojoules: ?u64 = null,
};

/// Receipt transport is owned by the prover API work authority. The stronger
/// source-mask-authenticated Profile is converted only after complete capture.
pub const WorkCounters = work_profile.ReceiptCounters;

/// Caller-owned observations not already represented by the two prover API
/// telemetry schemas. Every digest is a SHA-256 identity supplied by the
/// capture harness; none is inferred from a filename or display label.
pub const Observation = struct {
    identity: Identity,
    backend: Backend,
    optimize: OptimizeMode,
    configured_workers: u32,
    independently_verified: bool,
    timings: Timings,
    proof_bytes: u64,
    committed_trace_cells: u64,
    resources: ResourceCounters = .{},
    work: WorkCounters = .{},

    fn validate(self: Observation) Error!void {
        if (digestEmpty(self.identity.implementation) or
            digestEmpty(self.identity.workload) or
            digestEmpty(self.identity.protocol) or
            digestEmpty(self.identity.proof) or
            self.configured_workers == 0 or
            self.timings.request_ns == 0 or
            self.proof_bytes == 0 or
            self.committed_trace_cells == 0)
        {
            return error.InvalidRuntimeProfileInput;
        }
        const input_and_prove = checkedAdd(
            self.timings.input_and_execution_ns,
            self.timings.prove_ns,
        ) orelse return error.InvalidRuntimeProfileInput;
        const through_encode = checkedAdd(
            input_and_prove,
            self.timings.encode_ns,
        ) orelse return error.InvalidRuntimeProfileInput;
        const accounted = checkedAdd(
            through_encode,
            self.timings.verify_ns,
        ) orelse return error.InvalidRuntimeProfileInput;
        if (accounted > self.timings.request_ns)
            return error.InvalidRuntimeProfileInput;
        self.work.validate() catch return error.InvalidRuntimeProfileInput;
    }
};

pub const StageFacts = struct {
    source_schema_version: u32,
    source_digest: Digest,
    stage_count: u32,
    maximum_depth: u16,
    root_elapsed_ns: u64,
    nested_node_elapsed_ns: u64,
};

pub const TaskFacts = struct {
    source_schema_version: u32,
    source_digest: Digest,
    graph_count: u32,
    task_count: u64,
    contribution_count: u64,
    component_work_count: u64,
    useful_task_work_ns: u64,
    critical_path_ns: ?u64,
    admission_wait_ns: u64,
    queue_wait_ns: u64,
    resource_wait_ns: u64,
    task_run_ns: u64,
    worker_busy_ns: ?u64,
    worker_capacity_ns: u64,
    graph_elapsed_ns: u64,
    parallel_eligible_ns: u64,
    peak_reserved_bytes: u64,
    total_work_estimate: u64,
    completed_rows: u64,
    completed_tiles: u64,
    maximum_active_tasks: u32,
    maximum_active_workers: ?u32,
    all_graphs_completed: bool,
};

/// Fixed-shape, allocation-free performance receipt. It owns no source slices;
/// runtime/example are represented by domain-separated digests.
pub const Profile = struct {
    schema_version: u16 = SCHEMA_VERSION,
    static_schema_version: u16,
    static_report_digest: Digest,
    static_totals: static_registry.Totals,
    runtime_digest: Digest,
    example_digest: Digest,
    identity: Identity,
    backend: Backend,
    optimize: OptimizeMode,
    configured_workers: u32,
    independently_verified: bool,
    timings: Timings,
    proof_bytes: u64,
    committed_trace_cells: u64,
    resources: ResourceCounters,
    work: WorkCounters,
    stages: StageFacts,
    tasks: TaskFacts,
    profile_digest: Digest,

    pub fn validate(self: *const Profile) Error!void {
        if (self.schema_version != SCHEMA_VERSION or
            self.static_schema_version != static_registry.SCHEMA_VERSION or
            digestEmpty(self.static_report_digest) or
            digestEmpty(self.runtime_digest) or
            digestEmpty(self.example_digest) or
            digestEmpty(self.stages.source_digest) or
            digestEmpty(self.tasks.source_digest) or
            self.stages.source_schema_version != stage_profile.SCHEMA_VERSION or
            self.tasks.source_schema_version !=
                task_profile.TASK_PROFILE_SCHEMA_VERSION or
            self.stages.maximum_depth > MAX_STAGE_DEPTH or
            self.stages.stage_count > MAX_STAGE_NODES or
            (self.stages.stage_count == 0) != (self.stages.maximum_depth == 0) or
            (self.tasks.graph_count == 0 and self.tasks.all_graphs_completed) or
            (self.tasks.all_graphs_completed !=
                (self.tasks.critical_path_ns != null)) or
            (self.tasks.worker_busy_ns == null) !=
                (self.tasks.maximum_active_workers == null))
        {
            return error.InvalidRuntimeProfile;
        }
        (Observation{
            .identity = self.identity,
            .backend = self.backend,
            .optimize = self.optimize,
            .configured_workers = self.configured_workers,
            .independently_verified = self.independently_verified,
            .timings = self.timings,
            .proof_bytes = self.proof_bytes,
            .committed_trace_cells = self.committed_trace_cells,
            .resources = self.resources,
            .work = self.work,
        }).validate() catch return error.InvalidRuntimeProfile;
        if (!std.mem.eql(u8, &computeDigest(self), &self.profile_digest))
            return error.InvalidRuntimeProfile;
    }

    /// A single receipt can be admitted to a comparative optimization corpus
    /// only when it has independent verification, complete exact work and
    /// hardware counters, non-empty stage/task capture, and successful graphs.
    /// Statistical promotion still belongs to the comparative corpus policy.
    pub fn evidenceComplete(self: *const Profile) bool {
        self.validate() catch return false;
        return self.independently_verified and
            self.work.authority == .instrumented_exact and
            self.work.complete() and
            self.resources.peak_rss_bytes != null and
            self.resources.instructions != null and
            self.resources.cycles != null and
            self.stages.stage_count != 0 and
            self.tasks.graph_count != 0 and
            self.tasks.task_count != 0 and
            self.tasks.all_graphs_completed and
            self.tasks.worker_busy_ns != null;
    }

    /// Independently regenerates the receipt from all three source authorities.
    /// Corpus admission must use this stronger check; `validate` alone proves
    /// only internal canonical-digest consistency of a transported receipt.
    pub fn validateAgainstSources(
        self: *const Profile,
        static_report: *const static_registry.Report,
        stages: *const stage_profile.StageProfile,
        tasks: *const task_profile.TaskProfile,
    ) Error!void {
        const replay = try join(
            static_report,
            stages,
            tasks,
            self.observation(),
        );
        if (!std.meta.eql(self.*, replay)) return error.InvalidRuntimeProfile;
    }

    fn observation(self: *const Profile) Observation {
        return .{
            .identity = self.identity,
            .backend = self.backend,
            .optimize = self.optimize,
            .configured_workers = self.configured_workers,
            .independently_verified = self.independently_verified,
            .timings = self.timings,
            .proof_bytes = self.proof_bytes,
            .committed_trace_cells = self.committed_trace_cells,
            .resources = self.resources,
            .work = self.work,
        };
    }
};

/// Validates and joins all authorities without allocation, clock sampling, or
/// mutation. Source slices need not outlive the returned receipt.
pub fn join(
    static_report: *const static_registry.Report,
    stages: *const stage_profile.StageProfile,
    tasks: *const task_profile.TaskProfile,
    observation: Observation,
) Error!Profile {
    static_report.validate() catch return error.InvalidRuntimeProfileInput;
    try observation.validate();
    if (!std.mem.eql(u8, stages.runtime, tasks.runtime) or
        !std.mem.eql(u8, stages.example, tasks.example) or
        stages.runtime.len == 0 or stages.example.len == 0)
    {
        return error.InvalidRuntimeProfileInput;
    }

    var result = Profile{
        .static_schema_version = static_report.schema_version,
        .static_report_digest = static_report.report_digest,
        .static_totals = static_report.totals,
        .runtime_digest = digestBytes(stages.runtime),
        .example_digest = digestBytes(stages.example),
        .identity = observation.identity,
        .backend = observation.backend,
        .optimize = observation.optimize,
        .configured_workers = observation.configured_workers,
        .independently_verified = observation.independently_verified,
        .timings = observation.timings,
        .proof_bytes = observation.proof_bytes,
        .committed_trace_cells = observation.committed_trace_cells,
        .resources = observation.resources,
        .work = observation.work,
        .stages = try stageFacts(stages),
        .tasks = try taskFacts(tasks),
        .profile_digest = undefined,
    };
    result.profile_digest = computeDigest(&result);
    try result.validate();
    return result;
}

/// Canonical single-line JSON. It emits only fixed-schema integers, enum tags,
/// booleans, and digests, so no borrowed display string needs JSON escaping.
pub fn writeJson(
    writer: *std.Io.Writer,
    profile: *const Profile,
) (Error || std.Io.Writer.Error)!void {
    try profile.validate();
    try runtime_profile_json.write(writer, profile, SCHEMA);
}

const StageAccumulator = struct {
    count: u32 = 0,
    maximum_depth: u16 = 0,
    root_elapsed_ns: u64 = 0,
    nested_node_elapsed_ns: u64 = 0,
};

fn stageFacts(profile: *const stage_profile.StageProfile) Error!StageFacts {
    if (profile.schema_version != stage_profile.SCHEMA_VERSION)
        return error.InvalidRuntimeProfileInput;
    var accumulator = StageAccumulator{};
    try accumulateStages(profile.stages, 1, true, &accumulator);
    return .{
        .source_schema_version = profile.schema_version,
        .source_digest = digestSource(STAGE_DIGEST_DOMAIN, profile.*),
        .stage_count = accumulator.count,
        .maximum_depth = accumulator.maximum_depth,
        .root_elapsed_ns = accumulator.root_elapsed_ns,
        .nested_node_elapsed_ns = accumulator.nested_node_elapsed_ns,
    };
}

fn accumulateStages(
    nodes: []const stage_profile.StageNode,
    depth: u16,
    roots: bool,
    accumulator: *StageAccumulator,
) Error!void {
    if (nodes.len == 0) return;
    if (depth > MAX_STAGE_DEPTH) return error.InvalidRuntimeProfileInput;
    for (nodes) |node| {
        if (node.id.len == 0 or node.label.len == 0)
            return error.InvalidRuntimeProfileInput;
        const elapsed_ns = try secondsToNanoseconds(node.seconds);
        accumulator.count = std.math.add(u32, accumulator.count, 1) catch
            return error.InvalidRuntimeProfileInput;
        if (accumulator.count > MAX_STAGE_NODES)
            return error.InvalidRuntimeProfileInput;
        accumulator.maximum_depth = @max(accumulator.maximum_depth, depth);
        accumulator.nested_node_elapsed_ns = checkedAdd(
            accumulator.nested_node_elapsed_ns,
            elapsed_ns,
        ) orelse return error.InvalidRuntimeProfileInput;
        if (roots) {
            accumulator.root_elapsed_ns = checkedAdd(
                accumulator.root_elapsed_ns,
                elapsed_ns,
            ) orelse return error.InvalidRuntimeProfileInput;
        }
        if (node.children) |children| {
            try accumulateStages(children, depth + 1, false, accumulator);
        }
    }
}

fn taskFacts(profile: *const task_profile.TaskProfile) Error!TaskFacts {
    if (profile.schema_version != task_profile.TASK_PROFILE_SCHEMA_VERSION)
        return error.InvalidRuntimeProfileInput;
    var facts = TaskFacts{
        .source_schema_version = profile.schema_version,
        .source_digest = undefined,
        .graph_count = std.math.cast(u32, profile.graphs.len) orelse
            return error.InvalidRuntimeProfileInput,
        .task_count = 0,
        .contribution_count = 0,
        .component_work_count = 0,
        .useful_task_work_ns = 0,
        .critical_path_ns = if (profile.graphs.len == 0) null else 0,
        .admission_wait_ns = 0,
        .queue_wait_ns = 0,
        .resource_wait_ns = 0,
        .task_run_ns = 0,
        .worker_busy_ns = if (profile.graphs.len == 0) null else 0,
        .worker_capacity_ns = 0,
        .graph_elapsed_ns = 0,
        .parallel_eligible_ns = 0,
        .peak_reserved_bytes = 0,
        .total_work_estimate = 0,
        .completed_rows = 0,
        .completed_tiles = 0,
        .maximum_active_tasks = 0,
        .maximum_active_workers = if (profile.graphs.len == 0) null else 0,
        .all_graphs_completed = profile.graphs.len != 0,
    };
    for (profile.graphs, 0..) |*graph, graph_index| {
        if (graph.graph_id.len == 0) return error.InvalidRuntimeProfileInput;
        for (profile.graphs[0..graph_index]) |prior| {
            if (std.mem.eql(u8, prior.graph_id, graph.graph_id))
                return error.InvalidRuntimeProfileInput;
        }
        try validateGraph(graph);
        facts.task_count = try addInput(facts.task_count, graph.events.len);
        facts.contribution_count = try addInput(
            facts.contribution_count,
            graph.contributions.len,
        );
        facts.component_work_count = try addInput(
            facts.component_work_count,
            graph.component_work.len,
        );
        try addSummary(&facts, graph.summary);
    }
    facts.source_digest = digestSource(TASK_DIGEST_DOMAIN, profile.*);
    return facts;
}

fn validateGraph(graph: *const task_profile.GraphRecord) Error!void {
    const summary = graph.summary;
    if (summary.planned_tasks != graph.events.len or
        summary.scheduler != .central_queue_no_steal or
        summary.steal_count != 0 or
        summary.requested_workers == 0 or
        summary.admitted_workers == 0 or
        summary.pool_capacity == 0 or
        summary.admitted_workers > summary.requested_workers or
        summary.admitted_workers > summary.pool_capacity or
        summary.peak_active_tasks > summary.admitted_workers or
        summary.duplicate_starts != 0 or
        summary.duplicate_finishes != 0)
    {
        return error.InvalidRuntimeProfileInput;
    }
    if (summary.peak_active_workers) |peak| {
        if (peak > summary.admitted_workers or summary.worker_busy_ns == null)
            return error.InvalidRuntimeProfileInput;
    } else if (summary.worker_busy_ns != null) {
        return error.InvalidRuntimeProfileInput;
    }
    const expected_capacity = std.math.mul(
        u64,
        summary.admitted_workers,
        summary.graph_elapsed_ns,
    ) catch return error.InvalidRuntimeProfileInput;
    if (summary.worker_capacity_ns != expected_capacity)
        return error.InvalidRuntimeProfileInput;
    if (summary.worker_busy_ns) |busy| {
        if (busy < summary.task_run_ns or busy > summary.worker_capacity_ns)
            return error.InvalidRuntimeProfileInput;
    }

    var observed = task_profile.RequestSummary{};
    observed.planned_tasks = graph.events.len;
    var all_completed = graph.events.len != 0;
    var maximum_run_ns: u64 = 0;
    for (graph.events, 0..) |*event, index| {
        if (event.dependency_count > task_profile.MAX_DEPENDENCIES or
            event.stage_id.len == 0 or event.component_kind.len == 0 or
            event.configured_workers == 0 or
            event.completed_rows > event.planned_rows or
            event.completed_tiles > event.planned_tiles)
        {
            return error.InvalidRuntimeProfileInput;
        }
        if (index != 0 and !graph.events[index - 1].key.lessThan(event.key))
            return error.InvalidRuntimeProfileInput;
        for (event.dependencySlice()) |dependency| {
            if (dependency.eql(event.key) or !containsTaskKey(graph.events, dependency))
                return error.InvalidRuntimeProfileInput;
        }
        try validateEventTimes(event, summary.graph_elapsed_ns);
        if (event.submitted) observed.submitted_tasks += 1;
        if (event.started) observed.started_tasks += 1;
        if (event.finished and event.submitted) observed.finished_tasks += 1;
        if (event.submitted) switch (event.terminal_status) {
            .completed => observed.completed_tasks += 1,
            .failed => observed.failed_tasks += 1,
            .cancelled => observed.cancelled_tasks += 1,
        } else if (event.terminal_status == .cancelled) {
            observed.unsubmitted_cancelled_tasks += 1;
        } else {
            return error.InvalidRuntimeProfileInput;
        }
        if (event.terminal_status != .completed) all_completed = false;
        observed.admission_wait_ns = try addInput(
            observed.admission_wait_ns,
            event.admission_wait_ns,
        );
        observed.queue_wait_ns = try addInput(
            observed.queue_wait_ns,
            event.queue_wait_ns,
        );
        observed.resource_wait_ns = try addInput(
            observed.resource_wait_ns,
            event.resource_wait_ns,
        );
        observed.task_run_ns = try addInput(observed.task_run_ns, event.run_ns);
        if (event.terminal_status == .completed) {
            observed.useful_task_work_ns = try addInput(
                observed.useful_task_work_ns,
                event.run_ns,
            );
            if (event.parallel_eligible and event.ready_ns != null) {
                observed.parallel_eligible_ns = try addInput(
                    observed.parallel_eligible_ns,
                    event.run_ns,
                );
            }
        }
        observed.total_work_estimate = try addInput(
            observed.total_work_estimate,
            event.work_estimate,
        );
        observed.completed_rows = try addInput(
            observed.completed_rows,
            event.completed_rows,
        );
        observed.completed_tiles = try addInput(
            observed.completed_tiles,
            event.completed_tiles,
        );
        maximum_run_ns = @max(maximum_run_ns, event.run_ns);
    }
    inline for (.{
        "planned_tasks",
        "submitted_tasks",
        "completed_tasks",
        "failed_tasks",
        "cancelled_tasks",
        "unsubmitted_cancelled_tasks",
        "started_tasks",
        "finished_tasks",
        "useful_task_work_ns",
        "admission_wait_ns",
        "queue_wait_ns",
        "resource_wait_ns",
        "task_run_ns",
        "parallel_eligible_ns",
        "total_work_estimate",
        "completed_rows",
        "completed_tiles",
    }) |field| {
        if (@field(summary, field) != @field(observed, field))
            return error.InvalidRuntimeProfileInput;
    }
    if (all_completed != (summary.critical_path_ns != null))
        return error.InvalidRuntimeProfileInput;
    if (summary.critical_path_ns) |critical| {
        if (critical < maximum_run_ns or critical > summary.useful_task_work_ns)
            return error.InvalidRuntimeProfileInput;
    }
    try validateAttribution(graph);
}

fn validateEventTimes(
    event: *const task_profile.TaskEvent,
    graph_elapsed_ns: u64,
) Error!void {
    inline for (.{
        event.submitted_ns,
        event.ready_ns,
        event.start_ns,
        event.cancellation_requested_ns,
        event.finish_ns,
    }) |timestamp| {
        if (timestamp) |value| if (value > graph_elapsed_ns)
            return error.InvalidRuntimeProfileInput;
    }
    if (event.submitted) {
        const ready = event.ready_ns orelse return error.InvalidRuntimeProfileInput;
        const submitted = event.submitted_ns orelse
            return error.InvalidRuntimeProfileInput;
        const finish = event.finish_ns orelse return error.InvalidRuntimeProfileInput;
        if (!event.finished or ready > submitted or submitted > finish or
            event.admission_wait_ns != submitted - ready)
        {
            return error.InvalidRuntimeProfileInput;
        }
        const queue_finish = event.start_ns orelse finish;
        if (queue_finish < submitted or
            event.queue_wait_ns != queue_finish - submitted)
        {
            return error.InvalidRuntimeProfileInput;
        }
    } else if (event.started or event.admission_wait_ns != 0 or
        event.queue_wait_ns != 0)
    {
        return error.InvalidRuntimeProfileInput;
    }
    if (event.started) {
        const start = event.start_ns orelse return error.InvalidRuntimeProfileInput;
        const finish = event.finish_ns orelse return error.InvalidRuntimeProfileInput;
        if (start > finish or event.run_ns != finish - start)
            return error.InvalidRuntimeProfileInput;
    } else if (event.run_ns != 0) {
        return error.InvalidRuntimeProfileInput;
    }
    switch (event.terminal_status) {
        .completed => if (!event.submitted or !event.started or !event.finished or
            !event.cleanup_complete or event.error_name != null or
            event.cancellation_reason != null)
        {
            return error.InvalidRuntimeProfileInput;
        },
        .failed => if (!event.submitted or !event.started or
            event.error_name == null)
        {
            return error.InvalidRuntimeProfileInput;
        },
        .cancelled => {},
    }
}

fn validateAttribution(graph: *const task_profile.GraphRecord) Error!void {
    var cursor: usize = 0;
    for (graph.events) |*event| {
        const start: usize = event.contribution_range.start;
        const len: usize = event.contribution_range.len;
        if (start != cursor) return error.InvalidRuntimeProfileInput;
        const end = std.math.add(usize, start, len) catch
            return error.InvalidRuntimeProfileInput;
        if (end > graph.contributions.len)
            return error.InvalidRuntimeProfileInput;
        const contributions = graph.contributions[start..end];
        if (contributions.len != 1) {
            for (contributions) |contribution| if (contribution.role == .exclusive)
                return error.InvalidRuntimeProfileInput;
        }
        for (contributions, 0..) |contribution, index| {
            for (contributions[0..index]) |prior| {
                if (prior.component_registry_index ==
                    contribution.component_registry_index)
                {
                    return error.InvalidRuntimeProfileInput;
                }
            }
            try validateContribution(event, contribution);
        }
        cursor = end;
    }
    if (cursor != graph.contributions.len)
        return error.InvalidRuntimeProfileInput;

    var component_cursor: usize = 0;
    for (graph.contributions, 0..) |contribution, index| {
        var first = true;
        for (graph.contributions[0..index]) |prior| {
            if (prior.component_registry_index == contribution.component_registry_index) {
                first = false;
                break;
            }
        }
        if (!first) continue;
        if (component_cursor >= graph.component_work.len)
            return error.InvalidRuntimeProfileInput;
        try validateComponentAggregate(
            graph.contributions,
            contribution,
            graph.component_work[component_cursor],
        );
        component_cursor += 1;
    }
    if (component_cursor != graph.component_work.len)
        return error.InvalidRuntimeProfileInput;
}

fn validateContribution(
    event: *const task_profile.TaskEvent,
    contribution: task_profile.Contribution,
) Error!void {
    if (contribution.component_kind.len == 0 or
        contribution.completed_rows != null and
            contribution.completed_rows.? > contribution.planned_rows or
        contribution.completed_tiles != null and
            contribution.completed_tiles.? > contribution.planned_tiles)
    {
        return error.InvalidRuntimeProfileInput;
    }
    if (!event.started) {
        if (contribution.completed_rows == null or
            contribution.completed_rows.? != 0 or
            contribution.completed_tiles == null or
            contribution.completed_tiles.? != 0)
        {
            return error.InvalidRuntimeProfileInput;
        }
    } else switch (event.terminal_status) {
        .completed => if (contribution.completed_rows == null or
            contribution.completed_tiles == null)
        {
            return error.InvalidRuntimeProfileInput;
        },
        .failed, .cancelled => if (contribution.completed_rows != null or
            contribution.completed_tiles != null)
        {
            return error.InvalidRuntimeProfileInput;
        },
    }
}

fn validateComponentAggregate(
    contributions: []const task_profile.Contribution,
    first: task_profile.Contribution,
    actual: task_profile.ComponentWork,
) Error!void {
    if (actual.component_registry_index != first.component_registry_index or
        !std.mem.eql(u8, actual.component_kind, first.component_kind) or
        actual.role != first.role)
    {
        return error.InvalidRuntimeProfileInput;
    }
    var tasks: u64 = 0;
    var work: u64 = 0;
    var planned_rows: u64 = 0;
    var planned_tiles: u64 = 0;
    var completed_rows: ?u64 = 0;
    var completed_tiles: ?u64 = 0;
    for (contributions) |contribution| {
        if (contribution.component_registry_index != first.component_registry_index)
            continue;
        if (!std.mem.eql(u8, contribution.component_kind, first.component_kind) or
            contribution.role != first.role)
        {
            return error.InvalidRuntimeProfileInput;
        }
        tasks = try addInput(tasks, 1);
        work = try addInput(work, contribution.work_estimate);
        planned_rows = try addInput(planned_rows, contribution.planned_rows);
        planned_tiles = try addInput(planned_tiles, contribution.planned_tiles);
        completed_rows = try addOptionalInput(
            completed_rows,
            contribution.completed_rows,
        );
        completed_tiles = try addOptionalInput(
            completed_tiles,
            contribution.completed_tiles,
        );
    }
    if (actual.task_count != tasks or actual.work_estimate != work or
        actual.planned_rows != planned_rows or
        actual.planned_tiles != planned_tiles or
        actual.completed_rows != completed_rows or
        actual.completed_tiles != completed_tiles)
    {
        return error.InvalidRuntimeProfileInput;
    }
}

fn addSummary(facts: *TaskFacts, summary: task_profile.RequestSummary) Error!void {
    facts.useful_task_work_ns = try addInput(
        facts.useful_task_work_ns,
        summary.useful_task_work_ns,
    );
    facts.admission_wait_ns = try addInput(
        facts.admission_wait_ns,
        summary.admission_wait_ns,
    );
    facts.queue_wait_ns = try addInput(facts.queue_wait_ns, summary.queue_wait_ns);
    facts.resource_wait_ns = try addInput(
        facts.resource_wait_ns,
        summary.resource_wait_ns,
    );
    facts.task_run_ns = try addInput(facts.task_run_ns, summary.task_run_ns);
    facts.worker_capacity_ns = try addInput(
        facts.worker_capacity_ns,
        summary.worker_capacity_ns,
    );
    facts.graph_elapsed_ns = try addInput(
        facts.graph_elapsed_ns,
        summary.graph_elapsed_ns,
    );
    facts.parallel_eligible_ns = try addInput(
        facts.parallel_eligible_ns,
        summary.parallel_eligible_ns,
    );
    facts.peak_reserved_bytes = @max(
        facts.peak_reserved_bytes,
        summary.peak_reserved_bytes,
    );
    facts.total_work_estimate = try addInput(
        facts.total_work_estimate,
        summary.total_work_estimate,
    );
    facts.completed_rows = try addInput(facts.completed_rows, summary.completed_rows);
    facts.completed_tiles = try addInput(
        facts.completed_tiles,
        summary.completed_tiles,
    );
    facts.maximum_active_tasks = @max(
        facts.maximum_active_tasks,
        summary.peak_active_tasks,
    );
    facts.critical_path_ns = try addOptionalInput(
        facts.critical_path_ns,
        summary.critical_path_ns,
    );
    facts.worker_busy_ns = try addOptionalInput(
        facts.worker_busy_ns,
        summary.worker_busy_ns,
    );
    if (facts.maximum_active_workers) |current| {
        if (summary.peak_active_workers) |peak| {
            facts.maximum_active_workers = @max(current, peak);
        } else {
            facts.maximum_active_workers = null;
        }
    }
    facts.all_graphs_completed = facts.all_graphs_completed and
        summary.critical_path_ns != null;
}

const containsTaskKey = runtime_profile_support.containsTaskKey;
const secondsToNanoseconds = runtime_profile_support.secondsToNanoseconds;
const addInput = runtime_profile_support.addInput;
const addOptionalInput = runtime_profile_support.addOptionalInput;
const checkedAdd = runtime_profile_support.checkedAdd;
fn computeDigest(profile: *const Profile) Digest {
    return runtime_profile_support.computeDigest(profile, DIGEST_DOMAIN);
}
const digestSource = runtime_profile_support.digestSource;
fn digestBytes(bytes: []const u8) Digest {
    return runtime_profile_support.digestBytes(bytes, BYTE_STRING_DIGEST_DOMAIN);
}
const digestEmpty = runtime_profile_support.digestEmpty;
