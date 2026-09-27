//! Provisional parallel dyadic forest. Independent ready parents may prove on
//! separate bounded lanes; canonical task indices and file names never depend
//! on worker completion order. The final receiver still verifies every proof.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const folder_mod = @import("../recursion/blake3_stream_prover.zig");
const serial = @import("block_v4_cpu_incremental_forest_stage.zig");
const leaf_stage = @import("block_v4_cpu_incremental_leaf_stage.zig");
const dag_mod = @import("block_v4_cpu_parallel_forest_plan.zig");
const queue_mod = @import("block_v4_cpu_parallel_forest_queue.zig");

const MAX_PROOF_BYTES: usize = 256 * 1024 * 1024;
const Folder = folder_mod.ForBackend(Cpu);
const Budget = engine.host_budget_allocator.SharedHostBudget;

pub const Options = struct {
    profile: parent.protocol.Profile,
    lane_count: usize,
    total_host_limit: usize,
    preparation_limit_per_lane: usize,
    parent_worker_options: @import("../recursion/blake3_native_parent_worker.zig").Options,
    preparation_pool_workers_per_lane: usize = 1,
    metrics: ?*Metrics = null,
};

pub const Metrics = struct {
    lane_count: usize,
    parent_count: usize,
    tracked_peak_bytes: usize,
};

const Shared = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    leaves: *const leaf_stage.Capture,
    dag: *const dag_mod.Plan,
    pins: []serial.ParentPin,
    queue: *queue_mod.Queue,
};

const Lane = struct {
    shared: *Shared,
    pool: engine.work_pool.WorkPool = undefined,
    folder: Folder = undefined,

    fn run(self: *Lane) void {
        while (self.shared.queue.take()) |index| {
            self.proveOne(index) catch |err| {
                self.shared.queue.cancel(index, err);
                return;
            };
            self.shared.queue.complete(index) catch unreachable;
        }
    }

    fn proveOne(self: *Lane, index: u32) !void {
        const shared = self.shared;
        const task = shared.dag.tasks[index];
        var left = try loadNode(shared, task.left);
        defer left.deinit();
        var right = try loadNode(shared, task.right);
        defer right.deinit();
        const expected = try spans.SpanStatement.fold(left.statement, right.statement);
        if (!std.meta.eql(expected.slots, task.slots)) return error.ParallelParentSpanMismatch;
        var node = try self.folder.fold(&left, &right);
        defer node.deinit();
        if (!std.meta.eql(node.statement, expected)) return error.ParallelParentStatementMismatch;
        const bytes = node.transport_bytes orelse return error.MissingDyadicParentTransport;
        if (bytes.len == 0 or bytes.len > MAX_PROOF_BYTES)
            return error.InvalidStagedDyadicParentSize;
        var buffer: [80]u8 = undefined;
        const name = try serial.parentPath(task.slots, &buffer);
        var file = try shared.dir.createFile(name, .{ .exclusive = true });
        errdefer shared.dir.deleteFile(name) catch {};
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        shared.pins[index] = .{
            .statement = node.statement,
            .admission = node.admission,
            .left = left.statement.slots,
            .right = right.statement.slots,
            .byte_len = bytes.len,
            .sha256 = digest,
        };
        // Queue.complete publishes the pin to all dependent lanes under its
        // mutex. No dependent may open this file before the sync above.
    }
};

fn loadNode(shared: *const Shared, ref: dag_mod.Ref) !parent.tree.Node {
    const Source = struct { admission: parent.protocol.Admission, statement: spans.SpanStatement, bytes: []u8 };
    const source: Source = switch (ref) {
        .leaf => |index| blk: {
            const entry = shared.leaves.entries[index];
            if (entry.admission.key.profile != shared.leaves.profile or
                !std.meta.eql(entry.admission, entry.descriptor.admission))
                return error.UntrustedStagedDyadicLeaf;
            var buffer: [64]u8 = undefined;
            break :blk .{ .admission = entry.admission, .statement = entry.descriptor.statement, .bytes = try loadPinned(shared.a, shared.leaves.dir, try leaf_stage.Capture.path(index, &buffer), entry.byte_len, entry.sha256) };
        },
        .parent => |index| blk: {
            const pin = shared.pins[index];
            var buffer: [80]u8 = undefined;
            break :blk .{ .admission = pin.admission, .statement = pin.statement, .bytes = try loadPinned(shared.a, shared.dir, try serial.parentPath(pin.statement.slots, &buffer), pin.byte_len, pin.sha256) };
        },
    };
    defer shared.a.free(source.bytes);
    var artifact = try parent.codec.decode(shared.a, source.bytes, &source.admission);
    return parent.tree.Node.verifyOwned(&artifact, source.admission, source.admission.expected_id, source.statement);
}

fn loadPinned(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, byte_len: usize, expected: [32]u8) ![]u8 {
    if (byte_len == 0 or byte_len > MAX_PROOF_BYTES) return error.InvalidStagedDyadicSourceSize;
    var file = try dir.openFile(name, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(a, byte_len);
    errdefer a.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (bytes.len != byte_len or !std.meta.eql(digest, expected))
        return error.TamperedStagedDyadicSource;
    return bytes;
}

/// Uses a shared hard host cap and one persistent Folder/Worker per lane.
/// Leaf and parent files are opened one task at a time and hash checked.
/// This produces the same Stage wire as the serial forest implementation.
pub fn prove(a: std.mem.Allocator, dir: std.fs.Dir, leaves: *const leaf_stage.Capture, job: spans.JobContext, options: Options) !serial.Stage {
    try job.validate();
    if (leaves.next != job.segment_count or leaves.entries.len != job.segment_count or
        leaves.profile != options.profile or options.lane_count == 0 or options.lane_count > 8 or
        options.total_host_limit == 0 or options.preparation_limit_per_lane == 0 or
        options.parent_worker_options.host_byte_limit == 0 or options.preparation_pool_workers_per_lane == 0)
        return error.InvalidParallelForestOptions;
    const per_lane = std.math.add(usize, options.preparation_limit_per_lane, options.parent_worker_options.host_byte_limit) catch return error.InvalidParallelForestOptions;
    const reserved = std.math.mul(usize, per_lane, options.lane_count) catch return error.InvalidParallelForestOptions;
    if (reserved > options.total_host_limit)
        return error.InvalidParallelForestOptions;
    var dag = try dag_mod.plan(a, job.segment_count);
    defer dag.deinit();
    const pins = try a.alloc(serial.ParentPin, dag.tasks.len);
    errdefer a.free(pins);
    const budget = try Budget.create(a, options.total_host_limit);
    defer budget.destroy();
    const work = budget.allocator();
    var queue = try queue_mod.Queue.init(a, &dag, options.lane_count);
    defer queue.deinit();
    errdefer for (queue.completed, 0..) |done, index| if (done) {
        var buffer: [80]u8 = undefined;
        dir.deleteFile(serial.parentPath(dag.tasks[index].slots, &buffer) catch unreachable) catch {};
    };
    var shared = Shared{ .a = work, .dir = dir, .leaves = leaves, .dag = &dag, .pins = pins, .queue = &queue };
    const lane_count = @min(options.lane_count, @max(1, dag.tasks.len));
    const lanes = try a.alloc(Lane, lane_count);
    defer a.free(lanes);
    var initialized: usize = 0;
    defer {
        for (lanes[0..initialized]) |*lane| {
            lane.folder.deinit();
            lane.pool.deinit();
        }
    }
    for (lanes) |*lane| {
        lane.* = .{ .shared = &shared };
        try lane.pool.initInPlaceWithOptions(.{
            .worker_count = options.preparation_pool_workers_per_lane,
            .backing_allocator = work,
        });
        lane.folder = .{
            .allocator = work,
            .pool = &lane.pool,
            .preparation_limit = options.preparation_limit_per_lane,
            .worker_options = options.parent_worker_options,
            .profile = options.profile,
            .retain_exact_forest_artifacts = true,
        };
        initialized += 1;
    }
    const threads = try a.alloc(std.Thread, lane_count);
    defer a.free(threads);
    var started: usize = 0;
    for (lanes, 0..) |*lane, index| {
        threads[index] = std.Thread.spawn(.{ .stack_size = 8 * 1024 * 1024 }, Lane.run, .{lane}) catch |err| {
            queue.stop(err);
            for (threads[0..started]) |thread| thread.join();
            return err;
        };
        started += 1;
    }
    for (threads[0..started]) |thread| thread.join();
    try queue.result();
    const roots = try a.alloc(serial.RootPin, dag.roots.len);
    errdefer a.free(roots);
    var descriptors: [spans.MAX_SLOT_HEIGHT + 1]linked.Descriptor = undefined;
    for (dag.roots, roots, 0..) |root, *pin, index| {
        const source: serial.RootPin = switch (root.node) {
            .leaf => |leaf_index| blk: {
                const entry = leaves.entries[leaf_index];
                // Singleton roots would otherwise never be read by a parent.
                var node = try loadNode(&shared, root.node);
                node.deinit();
                break :blk .{ .statement = entry.descriptor.statement, .admission = entry.admission, .file = .{ .leaf = leaf_index } };
            },
            .parent => |parent_index| blk: {
                const entry = pins[parent_index];
                break :blk .{ .statement = entry.statement, .admission = entry.admission, .file = .{ .parent = parent_index } };
            },
        };
        if (!std.meta.eql(source.statement.slots, root.slots)) return error.InvalidParallelForestRootSpan;
        pin.* = source;
        descriptors[index] = .{ .statement = source.statement, .admission = source.admission };
    }
    const digest = try linked.verifiedForestDigest(job, descriptors[0..roots.len]);
    if (options.metrics) |metrics| metrics.* = .{
        .lane_count = lane_count,
        .parent_count = pins.len,
        .tracked_peak_bytes = budget.snapshot().peak_live_bytes,
    };
    return .{ .a = a, .dir = dir, .parents = pins, .roots = roots, .digest = digest };
}
