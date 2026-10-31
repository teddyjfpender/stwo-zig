//! Stable hierarchical prover-stage telemetry schema and recorder.

const std = @import("std");
const builtin = @import("builtin");
const task_profile = @import("task_profile.zig");
const work_profile = @import("work_profile.zig");
pub const process_usage = @import("stage_process_usage.zig");

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
    /// Whole-process counters across all threads; overlapping stages are not additive.
    capture_process_usage: bool = false,
};

pub const StageNode = struct {
    id: []const u8,
    label: []const u8,
    seconds: f64,
    children: ?[]StageNode = null,
    process_usage: ?process_usage.ProcessUsage = null,

    /// Preserve the original field order and null children in disabled profiles.
    pub fn jsonStringify(self: StageNode, writer: anytype) !void {
        try writer.beginObject();
        try writer.objectField("id");
        try writer.write(self.id);
        try writer.objectField("label");
        try writer.write(self.label);
        try writer.objectField("seconds");
        try writer.write(self.seconds);
        if (self.children != null or writer.options.emit_null_optional_fields) {
            try writer.objectField("children");
            try writer.write(self.children);
        }
        if (self.process_usage) |usage| {
            try writer.objectField("process_usage");
            try writer.write(usage);
        }
        try writer.endObject();
    }

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
    usage_start: ?process_usage.Snapshot = null,
    usage: ?process_usage.ProcessUsage = null,

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

/// A Recorder has one serial owner and is NOT thread-safe. Never share one
/// mutable stage stack between concurrent callbacks, even with a thread-safe
/// allocator. Give each concurrent component a private recorder; after joining
/// every writer, its coordinator adopts completed trees with adoptJoinedStages
/// (or adoptJoined when completed task graphs must move too). Locking a shared
/// stack would not make overlapping callbacks a valid nested hierarchy.
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
    capture_process_usage: bool,

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
            .capture_process_usage = options.capture_process_usage,
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

    /// Moves completed stage trees and task graphs from a joined coordinator.
    /// Both owners must use the same allocator. All admission and reservation
    /// happen before ownership moves; the child remains independently reusable.
    /// Exact-work capture uses the serial coordinator instead of this seam.
    pub fn adoptJoined(self: *Recorder, child: *Recorder) !void {
        if (self == child or !sameAllocator(self.allocator, child.allocator) or
            self.capture_tasks != child.capture_tasks or self.capture_work or child.capture_work)
            return error.IncompatibleJoinedRecorder;
        if (child.stack.items.len != 0 or self.task_recorder.active_reservation != null or
            child.task_recorder.active_reservation != null)
            return error.JoinedRecorderStillActive;
        const destination = if (self.stack.items.len == 0)
            &self.roots
        else
            &self.stack.items[self.stack.items.len - 1].children;
        try destination.ensureUnusedCapacity(self.allocator, child.roots.items.len);
        try self.task_recorder.graphs.ensureUnusedCapacity(self.allocator, child.task_recorder.graphs.items.len);
        destination.appendSliceAssumeCapacity(child.roots.items);
        self.task_recorder.graphs.appendSliceAssumeCapacity(child.task_recorder.graphs.items);
        child.roots.clearRetainingCapacity();
        child.task_recorder.graphs.clearRetainingCapacity();
    }

    /// Moves only completed hierarchical stage trees from a private, joined
    /// recorder. The coordinator calls this after every child writer returns.
    /// Parent task reservations and exact-work capture remain untouched; child
    /// task graphs, reservations and exact-work capture cannot cross this seam.
    /// Matching allocators let the parent reclaim the moved nodes directly.
    pub fn adoptJoinedStages(self: *Recorder, child: *Recorder) !void {
        if (self == child or !sameAllocator(self.allocator, child.allocator) or child.capture_work or
            child.task_recorder.graphs.items.len != 0)
            return error.IncompatibleJoinedRecorder;
        if (child.stack.items.len != 0 or child.task_recorder.active_reservation != null)
            return error.JoinedRecorderStillActive;
        const destination = if (self.stack.items.len == 0)
            &self.roots
        else
            &self.stack.items[self.stack.items.len - 1].children;
        // Reserve before moving any ownership. Failure leaves both logical
        // trees unchanged, and a partially adopted set of siblings remains
        // independently reclaimable by its two original recorder owners.
        try destination.ensureUnusedCapacity(self.allocator, child.roots.items.len);
        destination.appendSliceAssumeCapacity(child.roots.items);
        child.roots.clearRetainingCapacity();
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
        if (self.capture_process_usage) node.usage_start = process_usage.read();
        errdefer self.allocator.destroy(node);

        const destination = if (self.stack.items.len == 0)
            &self.roots
        else
            &self.stack.items[self.stack.items.len - 1].children;
        // Reserve both lists before publishing. A failed stack allocation must
        // not leave a root/child pointer to the node freed by this errdefer.
        try self.stack.ensureUnusedCapacity(self.allocator, 1);
        try destination.ensureUnusedCapacity(self.allocator, 1);
        destination.appendAssumeCapacity(node);
        self.stack.appendAssumeCapacity(node);
        return node;
    }

    fn popStage(self: *Recorder, node: *MutableNode) void {
        std.debug.assert(self.stack.items.len > 0);
        std.debug.assert(self.stack.items[self.stack.items.len - 1] == node);
        _ = self.stack.pop();
        if (node.usage_start) |start| {
            if (process_usage.read()) |end| node.usage = process_usage.delta(start, end);
        }
        const elapsed_ns = std.time.nanoTimestamp() - node.start_ns;
        node.seconds = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    }
};

// Stateless std allocators intentionally carry an undefined context pointer.
// Recognize their concrete implementations before reading ptr. Do not compare
// page_allocator's alias: a root.os.heap override may instead be stateful.
fn sameAllocator(a: std.mem.Allocator, b: std.mem.Allocator) bool {
    if (a.vtable != b.vtable) return false;
    if (comptime !builtin.single_threaded) if (a.vtable == &std.heap.SmpAllocator.vtable) return true;
    if (comptime !builtin.cpu.arch.isWasm() and builtin.os.tag != .plan9) if (a.vtable == &std.heap.PageAllocator.vtable) return true;
    if (comptime builtin.link_libc) if (a.vtable == std.heap.c_allocator.vtable or a.vtable == std.heap.raw_c_allocator.vtable) return true;
    if (comptime builtin.cpu.arch.isWasm() and builtin.single_threaded) if (a.vtable == std.heap.wasm_allocator.vtable) return true;
    if (comptime builtin.os.tag == .plan9) if (a.vtable == &std.heap.SbrkAllocator(std.os.plan9.sbrk).vtable) return true;
    return a.ptr == b.ptr;
}

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
            .process_usage = node.usage,
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

test "joined recorder retains nested stages and completed task graph ownership" {
    const allocator = std.testing.allocator;
    var parent = Recorder.init(allocator, "zig", "joined");
    defer parent.deinit();
    var child = Recorder.init(allocator, "zig", "joined");
    defer child.deinit();
    var child_stage = try StageScope.begin(&child, "parallel", "Parallel");
    child_stage.end();
    var pending = try child.reserveTaskGraph(0, 0);
    defer pending.deinit();
    try child.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "parallel-graph" }, .{});
    var outer = try StageScope.begin(&parent, "parent", "Parent");
    try parent.adoptJoined(&child);
    outer.end();
    try std.testing.expectEqual(@as(usize, 0), child.roots.items.len);
    try std.testing.expectEqual(@as(usize, 0), child.task_recorder.graphs.items.len);
    var stages = try parent.snapshot(allocator);
    defer stages.deinit(allocator);
    try std.testing.expectEqualStrings("parallel", stages.stages[0].children.?[0].id);
    var tasks = try parent.taskSnapshot(allocator);
    defer tasks.deinit(allocator);
    try std.testing.expectEqualStrings("parallel-graph", tasks.graphs[0].graph_id);
}

test "joined recorder rejects live stages and reservations before transfer" {
    const allocator = std.testing.allocator;
    var parent = Recorder.init(allocator, "zig", "joined");
    defer parent.deinit();
    var child = Recorder.init(allocator, "zig", "joined");
    defer child.deinit();
    var stage = try StageScope.begin(&child, "active", "Active");
    try std.testing.expectError(error.JoinedRecorderStillActive, parent.adoptJoined(&child));
    stage.end();
    var pending = try child.reserveTaskGraph(0, 0);
    defer pending.deinit();
    try std.testing.expectError(error.JoinedRecorderStillActive, parent.adoptJoined(&child));
    try std.testing.expectEqual(@as(usize, 1), child.roots.items.len);
    try std.testing.expectEqual(@as(usize, 0), parent.roots.items.len);
    try pending.abort();
    try parent.adoptJoined(&child);
    try std.testing.expectError(error.IncompatibleJoinedRecorder, parent.adoptJoined(&parent));
}

fn exerciseJoinedAllocationFailure(allocator: std.mem.Allocator) !void {
    var parent = Recorder.init(allocator, "zig", "joined");
    defer parent.deinit();
    var child = Recorder.init(allocator, "zig", "joined");
    defer child.deinit();
    var stage = try StageScope.begin(&child, "child", "Child");
    stage.end();
    var pending = try child.reserveTaskGraph(0, 0);
    defer pending.deinit();
    try child.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "child" }, .{});
    try parent.adoptJoined(&child);
    try std.testing.expectEqual(@as(usize, 1), parent.roots.items.len);
    try std.testing.expectEqual(@as(usize, 0), child.roots.items.len);
    try std.testing.expectEqual(@as(usize, 1), parent.task_recorder.graphs.items.len);
}

test "joined recorder allocation failures leave every owner reclaimable" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseJoinedAllocationFailure, .{});
}

const JoinedStagesThread = struct {
    recorder: *Recorder,
    gate: *std.Thread.ResetEvent,
    entered: *std.atomic.Value(usize),
    id: []const u8,
    failure: ?anyerror = null,
    fn run(self: *JoinedStagesThread) void {
        self.capture() catch |err| {
            self.failure = err;
            self.gate.set();
        };
    }
    fn capture(self: *JoinedStagesThread) !void {
        var outer = try StageScope.begin(self.recorder, self.id, self.id);
        defer outer.end();
        var inner = try StageScope.begin(self.recorder, "inner", "Inner");
        defer inner.end();
        if (self.entered.fetchAdd(1, .acq_rel) + 1 == 2) self.gate.set();
        self.gate.wait();
    }
};
test "joined stages privately record concurrent children and attach in coordinator order" {
    if (comptime builtin.single_threaded) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var parent = Recorder.initWithOptions(allocator, "rv64", "parent", .{ .capture_tasks = true, .capture_work = true });
    defer parent.deinit();
    var children: [2]Recorder = undefined;
    for (&children) |*child| child.* = Recorder.initWithOptions(allocator, "rv64", "component", .{ .capture_tasks = false });
    defer for (&children) |*child| child.deinit();
    var gate: std.Thread.ResetEvent = .{};
    var entered: std.atomic.Value(usize) = .init(0);
    var jobs = [_]JoinedStagesThread{
        .{ .recorder = &children[0], .gate = &gate, .entered = &entered, .id = "left" },
        .{ .recorder = &children[1], .gate = &gate, .entered = &entered, .id = "right" },
    };
    {
        const first = try std.Thread.spawn(.{}, JoinedStagesThread.run, .{&jobs[0]});
        errdefer {
            gate.set();
            first.join();
        }
        const second = try std.Thread.spawn(.{}, JoinedStagesThread.run, .{&jobs[1]});
        second.join();
        first.join();
    }
    for (jobs) |job| if (job.failure) |err| return err;
    var pending = try parent.reserveTaskGraph(0, 0);
    defer pending.deinit();
    const reservation = parent.task_recorder.active_reservation;
    const work = parent.workCaptureRecorder().?;
    try work.record(.{ .producer = .column_preparation_fft, .source_mask = work_profile.SourceMask.one(.fft_butterflies), .counters = .{ .fft_butterflies = 19 } });
    const work_before = (try parent.workSnapshot()).counters;
    var outer = try StageScope.begin(&parent, "components", "Joined components");
    defer outer.end();
    for (&children) |*child| try parent.adoptJoinedStages(child);
    try std.testing.expect(parent.capture_tasks and parent.capture_work);
    try std.testing.expectEqualDeep(reservation, parent.task_recorder.active_reservation);
    try std.testing.expectEqualDeep(work_before, (try parent.workSnapshot()).counters);
    try std.testing.expectEqual(@as(usize, 0), parent.task_recorder.graphs.items.len);
    for (&children) |*child| try std.testing.expectEqual(@as(usize, 0), child.roots.items.len);
    outer.end();
    var profile = try parent.snapshot(allocator);
    defer profile.deinit(allocator);
    const nodes = profile.stages[0].children.?;
    try std.testing.expectEqual(@as(usize, 2), nodes.len);
    try std.testing.expectEqualStrings("left", nodes[0].id);
    try std.testing.expectEqualStrings("right", nodes[1].id);
    for (nodes) |node| try std.testing.expectEqualStrings("inner", node.children.?[0].id);
    try pending.abort();
}

test "joined stages reject live or incompatible child ownership without moving roots" {
    const allocator = std.testing.allocator;
    var parent = Recorder.initWithOptions(allocator, "rv64", "parent", .{ .capture_tasks = false });
    defer parent.deinit();
    var child = Recorder.initWithOptions(allocator, "rv64", "child", .{ .capture_tasks = false });
    defer child.deinit();
    var stage = try StageScope.begin(&child, "child", "Child");
    defer stage.end();
    try std.testing.expectError(error.JoinedRecorderStillActive, parent.adoptJoinedStages(&child));
    stage.end();
    var pending = try child.reserveTaskGraph(0, 0);
    defer pending.deinit();
    try std.testing.expectError(error.JoinedRecorderStillActive, parent.adoptJoinedStages(&child));
    try pending.abort();
    try std.testing.expectEqual(@as(usize, 1), child.roots.items.len);
    var other_arena = std.heap.ArenaAllocator.init(allocator);
    defer other_arena.deinit();
    var other_parent = Recorder.init(other_arena.allocator(), "rv64", "other");
    defer other_parent.deinit();
    try std.testing.expectError(error.IncompatibleJoinedRecorder, other_parent.adoptJoinedStages(&child));
    try std.testing.expectError(error.IncompatibleJoinedRecorder, child.adoptJoinedStages(&child));
    try std.testing.expectEqual(@as(usize, 1), child.roots.items.len);
    try std.testing.expectEqual(@as(usize, 0), parent.roots.items.len);
    var graph = try child.reserveTaskGraph(0, 0);
    defer graph.deinit();
    try child.publishTaskGraphAfterJoin(&graph, .{ .graph_id = "child-task" }, .{});
    try std.testing.expectError(error.IncompatibleJoinedRecorder, parent.adoptJoinedStages(&child));
    try std.testing.expectEqual(@as(usize, 1), child.roots.items.len);
    var work_child = Recorder.initWithOptions(allocator, "rv64", "work", .{ .capture_work = true });
    defer work_child.deinit();
    try std.testing.expectError(error.IncompatibleJoinedRecorder, parent.adoptJoinedStages(&work_child));
}

fn exerciseJoinedStagesAllocationFailure(allocator: std.mem.Allocator) !void {
    var parent = Recorder.initWithOptions(allocator, "rv64", "parent", .{ .capture_tasks = true, .capture_work = true });
    defer parent.deinit();
    var child = Recorder.initWithOptions(allocator, "rv64", "child", .{ .capture_tasks = false });
    defer child.deinit();
    var parent_scope = try StageScope.begin(&parent, "outer", "Outer");
    defer parent_scope.end();
    var child_scope = try StageScope.begin(&child, "child", "Child");
    child_scope.end();
    parent.adoptJoinedStages(&child) catch |err| {
        try std.testing.expectEqual(@as(usize, 1), child.roots.items.len);
        try std.testing.expectEqual(@as(usize, 0), parent_scope.node.?.children.items.len);
        return err;
    };
    try std.testing.expectEqual(@as(usize, 0), child.roots.items.len);
    try std.testing.expectEqual(@as(usize, 1), parent_scope.node.?.children.items.len);
    // The emptied child remains reusable without invalidating the moved tree.
    var again = try StageScope.begin(&child, "again", "Again");
    again.end();
    try parent.adoptJoinedStages(&child);
}
test "joined stages allocation failures preserve child ownership and parent cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseJoinedStagesAllocationFailure, .{});
}

fn exerciseStatelessStageAdoption(allocator: std.mem.Allocator) !void {
    var parent = Recorder.initWithOptions(allocator, "rv64", "parent", .{ .capture_tasks = false });
    defer parent.deinit();
    var child = Recorder.initWithOptions(allocator, "rv64", "child", .{ .capture_tasks = false });
    defer child.deinit();
    var first = try StageScope.begin(&child, "first", "First");
    first.end();
    try parent.adoptJoinedStages(&child);
    var second = try StageScope.begin(&child, "second", "Second");
    second.end();
    try parent.adoptJoined(&child);
    try std.testing.expectEqual(@as(usize, 2), parent.roots.items.len);
    try std.testing.expectEqual(@as(usize, 0), child.roots.items.len);
}
test "joined adoption recognizes stateless allocator identities without reading undefined context" {
    try exerciseStatelessStageAdoption(std.heap.page_allocator);
    if (comptime !builtin.single_threaded) try exerciseStatelessStageAdoption(std.heap.smp_allocator);
    if (comptime builtin.link_libc) {
        try exerciseStatelessStageAdoption(std.heap.c_allocator);
        // raw_c_allocator cannot allocate MutableNode when its required
        // alignment exceeds max_align_t; identity itself is still stateless.
        try std.testing.expect(sameAllocator(std.heap.raw_c_allocator, std.heap.raw_c_allocator));
    }
}

test "stage process usage: disabled JSON preserves old schema bytes" {
    const a = std.testing.allocator;
    const Old = struct { id: []const u8, label: []const u8, seconds: f64, children: ?[]StageNode = null };
    const old = try std.json.Stringify.valueAlloc(a, Old{ .id = "x", .label = "X", .seconds = 1.25 }, .{});
    defer a.free(old);
    const current = try std.json.Stringify.valueAlloc(a, StageNode{ .id = "x", .label = "X", .seconds = 1.25 }, .{});
    defer a.free(current);
    try std.testing.expectEqualStrings(old, current);
    const options: std.json.Stringify.Options = .{ .whitespace = .indent_2, .emit_null_optional_fields = false };
    const old_pretty = try std.json.Stringify.valueAlloc(a, Old{ .id = "x", .label = "X", .seconds = 1.25 }, options);
    defer a.free(old_pretty);
    const current_pretty = try std.json.Stringify.valueAlloc(a, StageNode{ .id = "x", .label = "X", .seconds = 1.25 }, options);
    defer a.free(current_pretty);
    try std.testing.expectEqualStrings(old_pretty, current_pretty);
    var recorder = Recorder.init(a, "test", "disabled");
    defer recorder.deinit();
    var stage = try StageScope.begin(&recorder, "x", "X");
    try std.testing.expect(stage.node.?.usage_start == null);
    stage.end();
    try std.testing.expect(stage.node.?.usage == null);
}

fn exerciseProcessStages(a: std.mem.Allocator) !void {
    var parent = Recorder.initWithOptions(a, "test", "enabled", .{ .capture_process_usage = true });
    defer parent.deinit();
    var outer = try StageScope.begin(&parent, "outer", "Outer");
    defer outer.end();
    var inner = try StageScope.begin(&parent, "inner", "Inner");
    inner.end();
    var child = Recorder.initWithOptions(a, "test", "joined", .{ .capture_tasks = false, .capture_process_usage = true });
    defer child.deinit();
    var joined = try StageScope.begin(&child, "joined", "Joined");
    joined.end();
    try parent.adoptJoinedStages(&child);
    outer.end();
    try std.testing.expectEqual(@as(usize, 0), parent.stack.items.len);
    var profile = try parent.snapshot(a);
    defer profile.deinit(a);
    if (process_usage.read() != null) {
        const root = profile.stages[0];
        try std.testing.expect(root.process_usage != null);
        try std.testing.expectEqual(@as(usize, 2), root.children.?.len);
        for (root.children.?) |node| try std.testing.expect(node.process_usage != null);
        const json = try std.json.Stringify.valueAlloc(a, profile, .{});
        defer a.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"process_usage\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, process_usage.SCOPE) != null);
    }
}

test "stage process usage: nested and adopted intervals survive snapshot and OOM" {
    try exerciseProcessStages(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseProcessStages, .{});
}
