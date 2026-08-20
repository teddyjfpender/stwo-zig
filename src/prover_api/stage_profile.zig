//! Stable hierarchical prover-stage telemetry schema and recorder.

const std = @import("std");
const task_profile = @import("task_profile.zig");
const work_profile = @import("work_profile.zig");

pub const SCHEMA_VERSION: u32 = 1;

pub const RecorderOptions = struct {
    /// Flat task capture is opt-in independently from hierarchical stage
    /// timing. Disabling it keeps stage boundaries available while ensuring
    /// bounded graphs receive no recorder and therefore allocate or sample no
    /// task-profile state.
    capture_tasks: bool = true,
    /// Exact logical work is a separate opt-in capability. The ordinary
    /// recorder path never exposes its state to prover operation boundaries.
    capture_work: bool = false,
};

pub const StageNode = struct {
    id: []const u8,
    label: []const u8,
    seconds: f64,
    children: ?[]StageNode = null,

    pub fn deinit(self: *StageNode, allocator: std.mem.Allocator) void {
        if (self.children) |children| {
            for (children) |*child| child.deinit(allocator);
            allocator.free(children);
        }
        self.* = undefined;
    }

    pub fn deinitSlice(allocator: std.mem.Allocator, nodes: []StageNode) void {
        for (nodes) |*node| node.deinit(allocator);
        allocator.free(nodes);
    }
};

pub const StageProfile = struct {
    schema_version: u32 = SCHEMA_VERSION,
    runtime: []const u8,
    example: []const u8,
    stages: []StageNode,

    pub fn deinit(self: *StageProfile, allocator: std.mem.Allocator) void {
        StageNode.deinitSlice(allocator, self.stages);
        self.* = undefined;
    }
};

const MutableNode = struct {
    id: []const u8,
    label: []const u8,
    start_ns: i128,
    seconds: f64,
    children: std.ArrayList(*MutableNode),

    fn init(id: []const u8, label: []const u8) MutableNode {
        return .{
            .id = id,
            .label = label,
            .start_ns = std.time.nanoTimestamp(),
            .seconds = 0.0,
            .children = std.ArrayList(*MutableNode).empty,
        };
    }

    fn deinit(self: *MutableNode, allocator: std.mem.Allocator) void {
        for (self.children.items) |child| {
            child.deinit(allocator);
            allocator.destroy(child);
        }
        self.children.deinit(allocator);
        self.* = undefined;
    }
};

pub const Recorder = struct {
    allocator: std.mem.Allocator,
    runtime: []const u8,
    example: []const u8,
    roots: std.ArrayList(*MutableNode),
    stack: std.ArrayList(*MutableNode),
    task_recorder: task_profile.Recorder,
    work_recorder: work_profile.Recorder(true),
    capture_tasks: bool,
    capture_work: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        runtime: []const u8,
        example: []const u8,
    ) Recorder {
        return initWithOptions(allocator, runtime, example, .{});
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        runtime: []const u8,
        example: []const u8,
        options: RecorderOptions,
    ) Recorder {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .example = example,
            .roots = std.ArrayList(*MutableNode).empty,
            .stack = std.ArrayList(*MutableNode).empty,
            .task_recorder = task_profile.Recorder.init(allocator, runtime, example),
            .work_recorder = .{},
            .capture_tasks = options.capture_tasks,
            .capture_work = options.capture_work,
        };
    }

    pub fn deinit(self: *Recorder) void {
        for (self.roots.items) |root| {
            root.deinit(self.allocator);
            self.allocator.destroy(root);
        }
        self.roots.deinit(self.allocator);
        self.stack.deinit(self.allocator);
        self.task_recorder.deinit();
        self.* = undefined;
    }

    pub fn snapshot(self: *const Recorder, allocator: std.mem.Allocator) !StageProfile {
        std.debug.assert(self.stack.items.len == 0);
        return .{
            .runtime = self.runtime,
            .example = self.example,
            .stages = try snapshotNodes(allocator, self.roots.items),
        };
    }

    /// Compatibility reservation for producers without semantic attribution.
    /// Existing stage timing remains independent from this reservation.
    pub fn reserveTaskGraph(
        self: *Recorder,
        event_count: usize,
        component_work_count: usize,
    ) !task_profile.PendingGraph {
        return self.task_recorder.reserveTaskGraph(event_count, component_work_count);
    }

    /// Reserves exact schema-v2 event, contribution, and aggregate storage
    /// before launch.
    pub fn reserveTaskGraphShape(
        self: *Recorder,
        shape: task_profile.ReservationShape,
    ) !task_profile.PendingGraph {
        return self.task_recorder.reserveTaskGraphShape(shape);
    }

    /// Moves a fully joined task graph into the separate flat recorder without
    /// allocation or event copying.
    pub fn publishTaskGraphAfterJoin(
        self: *Recorder,
        pending: *task_profile.PendingGraph,
        header: task_profile.GraphHeader,
        summary: task_profile.RequestSummary,
    ) !void {
        try self.task_recorder.publishTaskGraphAfterJoin(pending, header, summary);
    }

    pub fn taskSnapshot(
        self: *const Recorder,
        allocator: std.mem.Allocator,
    ) !task_profile.TaskProfile {
        return self.task_recorder.snapshot(allocator);
    }

    /// Returns the recorder only when flat task capture is enabled. Prover
    /// orchestration calls this once before composition dispatch; workers and
    /// disabled graph execution never branch on the option.
    pub fn taskCaptureRecorder(self: *Recorder) ?*Recorder {
        return if (self.capture_tasks) self else null;
    }

    /// Returns one request-scoped exact-work capability only on the explicitly
    /// profiled path. Callers cache this pointer at a whole-operation boundary;
    /// no field/SIMD inner loop observes the option.
    pub fn workCaptureRecorder(
        self: *Recorder,
    ) ?*work_profile.Recorder(true) {
        return if (self.capture_work) &self.work_recorder else null;
    }

    /// Produces an unavailable receipt for the ordinary path and for an opted-
    /// in request before any source boundary has published completed work.
    pub fn workSnapshot(self: *Recorder) work_profile.Error!work_profile.Profile {
        if (!self.capture_work) return work_profile.Profile.unavailable();
        return self.work_recorder.snapshot();
    }

    fn pushStage(self: *Recorder, id: []const u8, label: []const u8) !*MutableNode {
        const node = try self.allocator.create(MutableNode);
        node.* = MutableNode.init(id, label);
        errdefer self.allocator.destroy(node);

        if (self.stack.items.len == 0) {
            try self.roots.append(self.allocator, node);
        } else {
            try self.stack.items[self.stack.items.len - 1].children.append(self.allocator, node);
        }
        try self.stack.append(self.allocator, node);
        return node;
    }

    fn popStage(self: *Recorder, node: *MutableNode) void {
        std.debug.assert(self.stack.items.len > 0);
        std.debug.assert(self.stack.items[self.stack.items.len - 1] == node);
        _ = self.stack.pop();
        const elapsed_ns = std.time.nanoTimestamp() - node.start_ns;
        node.seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    }
};

pub const StageScope = struct {
    recorder: ?*Recorder = null,
    node: ?*MutableNode = null,
    ended: bool = false,

    pub fn begin(
        recorder: ?*Recorder,
        id: []const u8,
        label: []const u8,
    ) !StageScope {
        if (recorder) |active| {
            return .{
                .recorder = active,
                .node = try active.pushStage(id, label),
            };
        }
        return .{};
    }

    pub fn end(self: *StageScope) void {
        if (self.ended) return;
        if (self.recorder) |recorder| {
            recorder.popStage(self.node.?);
        }
        self.ended = true;
    }
};

fn snapshotNodes(
    allocator: std.mem.Allocator,
    nodes: []const *MutableNode,
) ![]StageNode {
    const out = try allocator.alloc(StageNode, nodes.len);
    errdefer allocator.free(out);

    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |*node| node.deinit(allocator);
    }

    for (nodes, 0..) |node, i| {
        out[i] = .{
            .id = node.id,
            .label = node.label,
            .seconds = node.seconds,
            .children = if (node.children.items.len == 0)
                null
            else
                try snapshotNodes(allocator, node.children.items),
        };
        initialized += 1;
    }
    return out;
}

test "prover stage profile: preserves nested order" {
    const alloc = std.testing.allocator;
    var recorder = Recorder.init(alloc, "zig", "wide_fibonacci");
    defer recorder.deinit();

    var outer = try StageScope.begin(&recorder, "outer", "Outer");
    defer outer.end();
    {
        var inner_a = try StageScope.begin(&recorder, "inner_a", "Inner A");
        defer inner_a.end();
    }
    {
        var inner_b = try StageScope.begin(&recorder, "inner_b", "Inner B");
        defer inner_b.end();
    }
    outer.end();

    var profile = try recorder.snapshot(alloc);
    defer profile.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), profile.stages.len);
    try std.testing.expectEqualStrings("outer", profile.stages[0].id);
    const children = profile.stages[0].children orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2), children.len);
    try std.testing.expectEqualStrings("inner_a", children[0].id);
    try std.testing.expectEqualStrings("inner_b", children[1].id);
}

test "prover stage profile: task publication propagates capability errors" {
    const allocator = std.testing.allocator;
    var owner = Recorder.init(allocator, "zig", "owner");
    defer owner.deinit();
    var other = Recorder.init(allocator, "zig", "other");
    defer other.deinit();

    var pending = try owner.reserveTaskGraph(0, 0);
    defer pending.deinit();
    try std.testing.expectError(
        error.TaskGraphReservationWrongRecorder,
        other.publishTaskGraphAfterJoin(
            &pending,
            .{ .graph_id = "wrong" },
            .{},
        ),
    );
    try owner.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "owner" },
        .{},
    );
}

test "prover stage profile: stage-only recorder suppresses flat task capture" {
    const allocator = std.testing.allocator;
    var recorder = Recorder.initWithOptions(
        allocator,
        "zig",
        "stage-only",
        .{ .capture_tasks = false },
    );
    defer recorder.deinit();

    try std.testing.expect(recorder.taskCaptureRecorder() == null);
    var scope = try StageScope.begin(&recorder, "outer", "Outer");
    scope.end();

    var stages = try recorder.snapshot(allocator);
    defer stages.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), stages.stages.len);

    var tasks = try recorder.taskSnapshot(allocator);
    defer tasks.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), tasks.graphs.len);
    try std.testing.expect(recorder.workCaptureRecorder() == null);
    const work = try recorder.workSnapshot();
    try work.validate();
    try std.testing.expect(!work.completeExact());
}

test "prover stage profile: exact work capability is independently opt in" {
    const allocator = std.testing.allocator;
    var recorder = Recorder.initWithOptions(
        allocator,
        "zig",
        "work-profile",
        .{ .capture_tasks = false, .capture_work = true },
    );
    defer recorder.deinit();

    const work = recorder.workCaptureRecorder() orelse unreachable;
    try work.record(.{
        .producer = .column_preparation_fft,
        .source_mask = work_profile.SourceMask.one(.fft_butterflies),
        .counters = .{ .fft_butterflies = 32 },
    });
    const snapshot = try recorder.workSnapshot();
    try snapshot.validate();
    try std.testing.expectEqual(@as(u64, 32), snapshot.counters.fft_butterflies);
    try std.testing.expect(!snapshot.completeExact());
}

test {
    _ = @import("task_profile_reservation_test.zig");
}
