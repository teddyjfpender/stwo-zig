//! Bounded parallel producer for the exact four-child/binary forest. Each
//! worker has its own prover pool and folder under one shared host budget.
//! The queue publishes SHA-pinned proof files before releasing dependents;
//! completion order cannot alter the canonical parent roster.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const quad = @import("../recursion/blake3_local_quad_aggregate.zig");
const folder_mod = @import("../recursion/blake3_stream_prover.zig");
const leaves_mod = @import("block_v4_cpu_incremental_leaf_stage.zig");
const mixed = @import("block_v4_cpu_mixed_forest_plan.zig");
const serial = @import("block_v4_cpu_mixed_forest_stage.zig");
const queue_mod = @import("block_v5_mixed_forest_queue_v1.zig");

const MAX_PROOF_BYTES: usize = 256 * 1024 * 1024;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Folder = folder_mod.ForBackend(Cpu);

pub const Options = struct {
    profile: parent.protocol.Profile,
    lane_count: usize,
    total_host_limit: usize,
    preparation_limit_per_lane: usize,
    worker_options: @import("../recursion/blake3_native_parent_worker.zig").Options,
    preparation_pool_workers_per_lane: usize = 1,
};

const Shared = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    leaves: *const leaves_mod.Capture,
    dag: *const mixed.Plan,
    pins: []serial.ParentPin,
    queue: *queue_mod.Queue,
    profile: parent.protocol.Profile,
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
        var children: [4]parent.tree.Node = undefined;
        var child_count: usize = 0;
        defer for (children[0..child_count]) |*node| node.deinit();
        for (task.children[0..task.childCount()]) |child| {
            children[child_count] = try loadNode(shared, child);
            child_count += 1;
        }
        var node: parent.tree.Node = undefined;
        var quartet_bytes: ?[]u8 = null;
        defer if (quartet_bytes) |bytes| shared.a.free(bytes);
        if (task.kind == .pair) {
            node = try self.folder.fold(&children[0], &children[1]);
        } else {
            var folded = try quad.prepare(shared.a, .{ &children[0], &children[1], &children[2], &children[3] }, 2, shared.profile);
            defer folded.deinit();
            const Api = parent.ForBackend(Cpu);
            const key = try Api.deriveKeyWithProfileAndPool(shared.a, &folded.prepared, shared.profile, &self.pool);
            const admission = try parent.protocol.Admission.init(key, try key.identity());
            const plan = try Api.Plan.init(shared.a, &folded.prepared.rows, admission);
            defer plan.deinit();
            var proof = try plan.prove(shared.a, &folded.prepared.rows);
            {
                errdefer proof.deinit();
                quartet_bytes = try parent.codec.encode(shared.a, &proof, &admission);
            }
            node = try parent.tree.Node.verifyOwned(&proof, admission, admission.expected_id, folded.statement);
        }
        defer node.deinit();
        if (!std.meta.eql(node.statement.slots, task.slots)) return error.MixedParentSpanMismatch;
        const bytes = if (task.kind == .pair)
            node.transport_bytes orelse return error.MissingMixedParentTransport
        else
            quartet_bytes.?;
        if (bytes.len == 0 or bytes.len > MAX_PROOF_BYTES) return error.InvalidMixedParentTransport;
        var name_buffer: [80]u8 = undefined;
        const name = try serial.parentPath(task.kind, task.slots, &name_buffer);
        var file = try shared.dir.createFile(name, .{ .exclusive = true });
        errdefer shared.dir.deleteFile(name) catch {};
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        const unused = spans.SlotSpan{ .first = 0, .height = 0 };
        var slots: [4]spans.SlotSpan = @splat(unused);
        for (task.children[0..task.childCount()], 0..) |child, edge| slots[edge] = child.slots;
        shared.pins[index] = .{ .kind = task.kind, .statement = node.statement, .admission = node.admission, .children = slots, .byte_len = bytes.len, .sha256 = digest };
    }
};

fn loadNode(shared: *const Shared, child: mixed.Child) !parent.tree.Node {
    const Source = struct { admission: parent.protocol.Admission, statement: spans.SpanStatement, bytes: []u8 };
    const source: Source = switch (child.node) {
        .leaf => |index| blk: {
            const entry = shared.leaves.entries[index];
            if (entry.admission.key.profile != shared.profile or
                !std.meta.eql(entry.admission, entry.descriptor.admission))
                return error.UntrustedMixedLeaf;
            var name_buffer: [64]u8 = undefined;
            break :blk .{ .admission = entry.admission, .statement = entry.descriptor.statement, .bytes = try openPinned(shared.a, shared.leaves.dir, try leaves_mod.Capture.path(index, &name_buffer), entry.byte_len, entry.sha256) };
        },
        .parent => |index| blk: {
            const pin = shared.pins[index];
            var name_buffer: [80]u8 = undefined;
            break :blk .{ .admission = pin.admission, .statement = pin.statement, .bytes = try openPinned(shared.a, shared.dir, try serial.parentPath(pin.kind, pin.statement.slots, &name_buffer), pin.byte_len, pin.sha256) };
        },
    };
    defer shared.a.free(source.bytes);
    if (!std.meta.eql(source.statement.slots, child.slots) or source.admission.key.profile != shared.profile)
        return error.UntrustedMixedParentEdge;
    var artifact = try parent.codec.decode(shared.a, source.bytes, &source.admission);
    return parent.tree.Node.verifyOwned(&artifact, source.admission, source.admission.expected_id, source.statement);
}

fn openPinned(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, byte_len: usize, digest: [32]u8) ![]u8 {
    if (byte_len == 0 or byte_len > MAX_PROOF_BYTES) return error.InvalidMixedProofSize;
    var file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != byte_len) return error.TamperedMixedProof;
    const bytes = try file.readToEndAlloc(a, byte_len);
    errdefer a.free(bytes);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    if (bytes.len != byte_len or !std.meta.eql(actual, digest)) return error.TamperedMixedProof;
    return bytes;
}

pub fn prove(a: std.mem.Allocator, dir: std.fs.Dir, leaves: *const leaves_mod.Capture, job: spans.JobContext, options: Options) !serial.Stage {
    try job.validate();
    if (leaves.next != job.segment_count or leaves.entries.len != job.segment_count or
        leaves.profile != options.profile or options.lane_count == 0 or options.lane_count > 8 or
        options.total_host_limit == 0 or options.preparation_limit_per_lane == 0 or
        options.worker_options.host_byte_limit == 0 or options.preparation_pool_workers_per_lane == 0)
        return error.InvalidParallelMixedForestOptions;
    const per_lane = std.math.add(usize, options.preparation_limit_per_lane, options.worker_options.host_byte_limit) catch
        return error.InvalidParallelMixedForestOptions;
    const reserved = std.math.mul(usize, per_lane, options.lane_count) catch
        return error.InvalidParallelMixedForestOptions;
    if (reserved > options.total_host_limit)
        return error.InvalidParallelMixedForestOptions;
    var dag = try mixed.plan(a, job.segment_count);
    defer dag.deinit();
    const pins = try a.alloc(serial.ParentPin, dag.tasks.len);
    errdefer a.free(pins);
    const budget = try Budget.create(a, options.total_host_limit);
    defer budget.destroy();
    const work = budget.allocator();
    var queue = try queue_mod.Queue.init(a, &dag, options.lane_count);
    defer queue.deinit();
    errdefer for (queue.completed, 0..) |done, index| if (done) {
        var name_buffer: [80]u8 = undefined;
        dir.deleteFile(serial.parentPath(dag.tasks[index].kind, dag.tasks[index].slots, &name_buffer) catch unreachable) catch {};
    };
    var shared = Shared{ .a = work, .dir = dir, .leaves = leaves, .dag = &dag, .pins = pins, .queue = &queue, .profile = options.profile };
    const lane_count = @min(options.lane_count, @max(1, dag.tasks.len));
    const lanes = try a.alloc(Lane, lane_count);
    defer a.free(lanes);
    var initialized: usize = 0;
    defer for (lanes[0..initialized]) |*lane| {
        lane.folder.deinit();
        lane.pool.deinit();
    };
    for (lanes) |*lane| {
        lane.* = .{ .shared = &shared };
        try lane.pool.initInPlaceWithOptions(.{
            .worker_count = options.preparation_pool_workers_per_lane,
            .backing_allocator = work,
        });
        lane.folder = .{ .allocator = work, .pool = &lane.pool, .preparation_limit = options.preparation_limit_per_lane, .worker_options = options.worker_options, .profile = options.profile, .retain_exact_forest_artifacts = true };
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
        pin.* = switch (root.node) {
            .leaf => |leaf_index| blk: {
                var node = try loadNode(&shared, root);
                node.deinit();
                const entry = leaves.entries[leaf_index];
                break :blk .{ .statement = entry.descriptor.statement, .admission = entry.admission, .file = .{ .leaf = leaf_index } };
            },
            .parent => |parent_index| blk: {
                const entry = pins[parent_index];
                break :blk .{ .statement = entry.statement, .admission = entry.admission, .file = .{ .parent = parent_index } };
            },
        };
        if (!std.meta.eql(pin.statement.slots, root.slots)) return error.InvalidMixedForestRoot;
        descriptors[index] = .{ .statement = pin.statement, .admission = pin.admission };
    }
    const digest = try linked.verifiedForestDigest(job, descriptors[0..roots.len]);
    return .{ .a = a, .dir = dir, .parents = pins, .roots = roots, .digest = digest, .tracked_peak_bytes = budget.snapshot().peak_live_bytes };
}
