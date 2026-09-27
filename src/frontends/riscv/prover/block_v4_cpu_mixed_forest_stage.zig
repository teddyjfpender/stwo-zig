//! Provisional radix-four forest from genuine staged recursive leaves.
//! Quartet tasks prove all four child STARK verifiers; residual pairs use the
//! existing binary parent. Transport is hash-pinned but grants no final policy.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const quad = @import("../recursion/blake3_local_quad_aggregate.zig");
const folder_mod = @import("../recursion/blake3_stream_prover.zig");
const leaf_stage = @import("block_v4_cpu_incremental_leaf_stage.zig");
const mixed = @import("block_v4_cpu_mixed_forest_plan.zig");

const MAX_PROOF_BYTES: usize = 256 * 1024 * 1024;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Folder = folder_mod.ForBackend(Cpu);

pub const Options = struct {
    profile: parent.protocol.Profile,
    total_host_limit: usize,
    preparation_limit: usize,
    worker_options: @import("../recursion/blake3_native_parent_worker.zig").Options,
};
pub const ParentPin = struct {
    kind: mixed.Kind,
    statement: spans.SpanStatement,
    admission: parent.protocol.Admission,
    children: [4]spans.SlotSpan,
    byte_len: usize,
    sha256: [32]u8,
};
pub const RootPin = struct {
    statement: spans.SpanStatement,
    admission: parent.protocol.Admission,
    file: union(enum) { leaf: u32, parent: usize },
};
pub const Stage = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    parents: []ParentPin,
    roots: []RootPin,
    digest: [32]u8,
    tracked_peak_bytes: usize,

    pub fn deinit(self: *Stage) void {
        self.a.free(self.parents);
        self.a.free(self.roots);
        self.* = undefined;
    }
    pub fn rootDescriptors(self: *const Stage, a: std.mem.Allocator) ![]linked.Descriptor {
        const result = try a.alloc(linked.Descriptor, self.roots.len);
        for (self.roots, result) |pin, *descriptor| descriptor.* = .{ .statement = pin.statement, .admission = pin.admission };
        return result;
    }
    pub fn loadParent(self: *const Stage, index: usize) ![]u8 {
        if (index >= self.parents.len) return error.MissingMixedParent;
        const pin = self.parents[index];
        var buffer: [80]u8 = undefined;
        return loadPinned(self.a, self.dir, try parentPath(pin.kind, pin.statement.slots, &buffer), pin.byte_len, pin.sha256);
    }
};

pub fn parentPath(kind: mixed.Kind, slots: spans.SlotSpan, buffer: *[80]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "block-v4-{s}-{d}-{d}.proof", .{ if (kind == .pair) "pair" else "quad", slots.first, slots.height });
}

fn loadPinned(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, length: usize, expected: [32]u8) ![]u8 {
    if (length == 0 or length > MAX_PROOF_BYTES) return error.InvalidMixedProofSize;
    var file = try dir.openFile(name, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(a, length);
    errdefer a.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (bytes.len != length or !std.meta.eql(digest, expected)) return error.TamperedMixedProof;
    return bytes;
}

fn loadNode(a: std.mem.Allocator, leaves: *const leaf_stage.Capture, dir: std.fs.Dir, pins: []const ParentPin, child: mixed.Child, profile: parent.protocol.Profile) !parent.tree.Node {
    const Source = struct { admission: parent.protocol.Admission, statement: spans.SpanStatement, bytes: []u8 };
    const source: Source = switch (child.node) {
        .leaf => |index| blk: {
            const entry = leaves.entries[index];
            var buffer: [64]u8 = undefined;
            break :blk .{ .admission = entry.admission, .statement = entry.descriptor.statement, .bytes = try loadPinned(a, leaves.dir, try leaf_stage.Capture.path(index, &buffer), entry.byte_len, entry.sha256) };
        },
        .parent => |index| blk: {
            const pin = pins[index];
            var buffer: [80]u8 = undefined;
            break :blk .{ .admission = pin.admission, .statement = pin.statement, .bytes = try loadPinned(a, dir, try parentPath(pin.kind, pin.statement.slots, &buffer), pin.byte_len, pin.sha256) };
        },
    };
    defer a.free(source.bytes);
    if (!std.meta.eql(source.statement.slots, child.slots) or source.admission.key.profile != profile)
        return error.UntrustedMixedChild;
    var artifact = try parent.codec.decode(a, source.bytes, &source.admission);
    return parent.tree.Node.verifyOwned(&artifact, source.admission, source.admission.expected_id, source.statement);
}

pub fn prove(a: std.mem.Allocator, dir: std.fs.Dir, leaves: *const leaf_stage.Capture, job: spans.JobContext, pool: *engine.work_pool.WorkPool, options: Options) !Stage {
    try job.validate();
    if (leaves.next != job.segment_count or leaves.entries.len != job.segment_count or
        leaves.profile != options.profile or options.total_host_limit == 0 or
        options.preparation_limit == 0 or options.worker_options.host_byte_limit == 0)
        return error.InvalidMixedForestInput;
    for (leaves.entries, 0..) |entry, index| {
        if (entry.admission.key.profile != options.profile or
            !std.meta.eql(entry.admission, entry.descriptor.admission) or
            !std.meta.eql(entry.descriptor.statement.job, job) or
            entry.descriptor.statement.slots.height != 0 or
            entry.descriptor.statement.slots.first != index)
            return error.UntrustedMixedForestLeaf;
    }
    var dag = try mixed.plan(a, job.segment_count);
    defer dag.deinit();
    const pins = try a.alloc(ParentPin, dag.tasks.len);
    errdefer a.free(pins);
    const budget = try Budget.create(a, options.total_host_limit);
    defer budget.destroy();
    const work = budget.allocator();
    var folder = Folder{
        .allocator = work,
        .pool = pool,
        .preparation_limit = options.preparation_limit,
        .worker_options = options.worker_options,
        .profile = options.profile,
        .retain_exact_forest_artifacts = true,
    };
    defer folder.deinit();
    var completed: usize = 0;
    errdefer for (pins[0..completed]) |pin| {
        var buffer: [80]u8 = undefined;
        dir.deleteFile(parentPath(pin.kind, pin.statement.slots, &buffer) catch unreachable) catch {};
    };
    for (dag.tasks) |task| {
        var children: [4]parent.tree.Node = undefined;
        var child_count: usize = 0;
        defer for (children[0..child_count]) |*node| node.deinit();
        for (task.children[0..task.childCount()]) |child| {
            children[child_count] = try loadNode(work, leaves, dir, pins[0..completed], child, options.profile);
            child_count += 1;
        }
        var node: parent.tree.Node = undefined;
        var quad_bytes: ?[]u8 = null;
        defer if (quad_bytes) |bytes| work.free(bytes);
        if (task.kind == .pair) {
            node = try folder.fold(&children[0], &children[1]);
        } else {
            var folded = try quad.prepare(work, .{ &children[0], &children[1], &children[2], &children[3] }, 2, options.profile);
            defer folded.deinit();
            const Api = parent.ForBackend(Cpu);
            const key = try Api.deriveKeyWithProfileAndPool(work, &folded.prepared, options.profile, pool);
            const admission = try parent.protocol.Admission.init(key, try key.identity());
            const plan = try Api.Plan.init(work, &folded.prepared.rows, admission);
            defer plan.deinit();
            var proof = try plan.prove(work, &folded.prepared.rows);
            {
                errdefer proof.deinit();
                quad_bytes = try parent.codec.encode(work, &proof, &admission);
            }
            node = try parent.tree.Node.verifyOwned(&proof, admission, admission.expected_id, folded.statement);
        }
        defer node.deinit();
        if (!std.meta.eql(node.statement.slots, task.slots)) return error.MixedParentSpanMismatch;
        const bytes = if (task.kind == .pair) node.transport_bytes orelse return error.MissingMixedParentTransport else quad_bytes.?;
        if (bytes.len == 0 or bytes.len > MAX_PROOF_BYTES) return error.InvalidMixedProofSize;
        var buffer: [80]u8 = undefined;
        const path = try parentPath(task.kind, task.slots, &buffer);
        var file = try dir.createFile(path, .{ .exclusive = true });
        errdefer dir.deleteFile(path) catch {};
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        const unused_child = spans.SlotSpan{ .first = 0, .height = 0 };
        var child_slots: [4]spans.SlotSpan = @splat(unused_child);
        for (task.children[0..task.childCount()], 0..) |child, index| child_slots[index] = child.slots;
        pins[completed] = .{ .kind = task.kind, .statement = node.statement, .admission = node.admission, .children = child_slots, .byte_len = bytes.len, .sha256 = digest };
        completed += 1;
    }
    const roots = try a.alloc(RootPin, dag.roots.len);
    errdefer a.free(roots);
    var descriptors: [spans.MAX_SLOT_HEIGHT + 1]linked.Descriptor = undefined;
    for (dag.roots, roots, 0..) |root, *pin, index| {
        pin.* = switch (root.node) {
            .leaf => |leaf_index| blk: {
                var node = try loadNode(work, leaves, dir, pins, root, options.profile);
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
