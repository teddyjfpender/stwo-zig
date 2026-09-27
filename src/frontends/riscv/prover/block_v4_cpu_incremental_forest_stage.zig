//! Provisional exact-count dyadic forest from hash-pinned recursive leaves.
//! The frontier retains O(log segment_count) verified nodes. Every folded
//! parent proof is persisted and its transport bytes released immediately.
//! The returned digest is a roster commitment, not outer-root authority.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const frontier_mod = @import("../recursion/blake3_stream_frontier.zig");
const folder_mod = @import("../recursion/blake3_stream_prover.zig");
const worker = @import("../recursion/blake3_native_parent_worker.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const leaf_stage = @import("block_v4_cpu_incremental_leaf_stage.zig");

const MAX_PARENT_BYTES: usize = 256 * 1024 * 1024;
pub const Options = struct {
    profile: parent.protocol.Profile,
    preparation_limit: usize,
    worker_options: worker.Options,
};
pub const ParentPin = struct {
    statement: spans.SpanStatement,
    admission: parent.protocol.Admission,
    left: spans.SlotSpan,
    right: spans.SlotSpan,
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
        if (index >= self.parents.len) return error.MissingStagedDyadicParent;
        const pin = self.parents[index];
        if (pin.byte_len == 0 or pin.byte_len > MAX_PARENT_BYTES)
            return error.InvalidStagedDyadicParentSize;
        var buffer: [80]u8 = undefined;
        var file = try self.dir.openFile(try parentPath(pin.statement.slots, &buffer), .{});
        defer file.close();
        const bytes = try file.readToEndAlloc(self.a, pin.byte_len);
        errdefer self.a.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (bytes.len != pin.byte_len or !std.meta.eql(digest, pin.sha256))
            return error.TamperedStagedDyadicParent;
        return bytes;
    }
};

const Folder = folder_mod.ForBackend(Cpu);
const Context = struct {
    dir: std.fs.Dir,
    folder: *Folder,
    pins: []ParentPin,
    next: usize = 0,

    pub fn fold(self: *Context, left: *const parent.tree.Node, right: *const parent.tree.Node) !parent.tree.Node {
        if (self.next >= self.pins.len) return error.TooManyDyadicParents;
        var node = try self.folder.fold(left, right);
        errdefer node.deinit();
        const bytes = node.transport_bytes orelse return error.MissingDyadicParentTransport;
        if (bytes.len == 0 or bytes.len > MAX_PARENT_BYTES)
            return error.InvalidStagedDyadicParentSize;
        const slots = node.statement.slots;
        var buffer: [80]u8 = undefined;
        const name = try parentPath(slots, &buffer);
        var file = try self.dir.createFile(name, .{ .exclusive = true });
        errdefer self.dir.deleteFile(name) catch {};
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        self.pins[self.next] = .{
            .statement = node.statement,
            .admission = node.admission,
            .left = left.statement.slots,
            .right = right.statement.slots,
            .byte_len = bytes.len,
            .sha256 = digest,
        };
        self.next += 1;
        node.transport_allocator.?.free(bytes);
        node.transport_bytes = null;
        node.transport_allocator = null;
        return node;
    }
};

/// Each input leaf is decoded from its hash-pinned file and independently
/// verified before entering the bounded frontier. All parent proofs are
/// staged under exclusive names. No complete manifest or outer proof is made.
pub fn prove(a: std.mem.Allocator, dir: std.fs.Dir, leaves: *const leaf_stage.Capture, job: spans.JobContext, pool: *engine.work_pool.WorkPool, options: Options) !Stage {
    try job.validate();
    if (job.segment_count == 0 or leaves.next != job.segment_count or
        leaves.entries.len != job.segment_count or options.preparation_limit == 0)
        return error.InvalidStagedDyadicLeafCensus;
    const parent_count = @as(usize, job.segment_count) - @as(usize, @popCount(job.segment_count));
    const pins = try a.alloc(ParentPin, parent_count);
    errdefer a.free(pins);
    var folder = Folder{
        .allocator = a,
        .pool = pool,
        .preparation_limit = options.preparation_limit,
        .worker_options = options.worker_options,
        .profile = options.profile,
        .retain_exact_forest_artifacts = true,
    };
    defer folder.deinit();
    var context = Context{ .dir = dir, .folder = &folder, .pins = pins };
    errdefer for (pins[0..context.next]) |pin| {
        var buffer: [80]u8 = undefined;
        dir.deleteFile(parentPath(pin.statement.slots, &buffer) catch unreachable) catch {};
    };
    var frontier = try frontier_mod.Frontier.init(job);
    defer frontier.deinit();
    for (leaves.entries[0..leaves.next], 0..) |entry, index| {
        if (entry.admission.key.profile != options.profile or
            !std.meta.eql(entry.admission, entry.descriptor.admission) or
            !std.meta.eql(entry.descriptor.statement.job, job))
            return error.UntrustedStagedDyadicLeaf;
        const bytes = try leaves.load(index);
        defer leaves.a.free(bytes);
        var artifact = try parent.codec.decode(a, bytes, &entry.admission);
        var node = try parent.tree.Node.verifyOwned(&artifact, entry.admission, entry.admission.expected_id, entry.descriptor.statement);
        errdefer node.deinit();
        try frontier.push(&node, &context);
    }
    if (context.next != parent_count) return error.IncompleteStagedDyadicParents;
    var forest = try frontier.takeExactForest();
    defer forest.deinit();
    const digest = try forest.rosterDigest();
    const roots = try a.alloc(RootPin, forest.count);
    errdefer a.free(roots);
    for (forest.nodes[0..forest.count], roots) |node, *root| {
        root.* = .{
            .statement = node.statement,
            .admission = node.admission,
            .file = if (node.statement.slots.height == 0)
                .{ .leaf = @intCast(node.statement.slots.first) }
            else
                .{ .parent = try findParent(pins, node.statement.slots) },
        };
    }
    return .{ .a = a, .dir = dir, .parents = pins, .roots = roots, .digest = digest };
}

fn findParent(pins: []const ParentPin, slots: spans.SlotSpan) !usize {
    for (pins, 0..) |pin, index| if (std.meta.eql(pin.statement.slots, slots)) return index;
    return error.MissingStagedDyadicParent;
}

pub fn parentPath(slots: spans.SlotSpan, buffer: *[80]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "block-v4-parent-{d}-{d}.proof", .{ slots.first, slots.height });
}

test "staged dyadic forest rejects an incomplete exact leaf roster" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const entries = try a.alloc(leaf_stage.Entry, 0);
    var leaves = leaf_stage.Capture{ .a = a, .dir = tmp.dir, .profile = .diagnostic_q8_pow0, .entries = entries };
    defer leaves.deinit();
    const job = try @import("../recursion/span_statement_blake3_test_fixture.zig").job(2);
    try std.testing.expectError(error.InvalidStagedDyadicLeafCensus, prove(a, tmp.dir, &leaves, job, undefined, .{
        .profile = .diagnostic_q8_pow0,
        .preparation_limit = 1,
        .worker_options = .{ .worker_count = 1, .host_byte_limit = 1, .retained_scratch_limit = 0 },
    }));
}
