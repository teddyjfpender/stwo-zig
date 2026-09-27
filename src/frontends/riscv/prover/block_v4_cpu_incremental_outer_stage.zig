//! Provisional exact-count outer proof from hash-pinned forest members.
//! Only O(log segment_count) verified member captures are live. The resulting
//! bytes/admission have no complete-block authority until independent final
//! pins and the file-backed receiver admit them.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const exact = @import("../recursion/blake3_exact_root_aggregate.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const leaf_stage = @import("block_v4_cpu_incremental_leaf_stage.zig");
const forest_stage = @import("block_v4_cpu_incremental_forest_stage.zig");

const MAX_OUTER_BYTES: usize = 256 * 1024 * 1024;
pub const OUTER_FILE = "block-v4-outer.proof";

pub const Stage = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    statement: spans.RootStatement,
    admission: parent.protocol.Admission,
    forest_digest: [32]u8,
    byte_len: usize,
    sha256: [32]u8,
    /// Peak live bytes within the outer proof's own preparation budget.
    preparation_peak_bytes: usize,

    pub fn load(self: *const Stage) ![]u8 {
        if (self.byte_len == 0 or self.byte_len > MAX_OUTER_BYTES)
            return error.InvalidStagedOuterSize;
        var file = try self.dir.openFile(OUTER_FILE, .{});
        defer file.close();
        const bytes = try file.readToEndAlloc(self.a, self.byte_len);
        errdefer self.a.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (bytes.len != self.byte_len or !std.meta.eql(digest, self.sha256))
            return error.TamperedStagedOuter;
        return bytes;
    }
};

pub const Options = struct {
    profile: parent.protocol.Profile,
    preparation_limit: usize,
};

/// The forest source may be the binary v1 stage or the versioned mixed
/// pair/quartet stage. Both expose hash-pinned exact roots and loadParent.
pub fn prove(a: std.mem.Allocator, dir: std.fs.Dir, leaves: *const leaf_stage.Capture, forest: anytype, job: spans.JobContext, options: Options) !Stage {
    try job.validate();
    if (options.preparation_limit == 0 or forest.roots.len == 0 or
        forest.roots.len != @popCount(job.segment_count))
        return error.InvalidStagedOuterForest;
    const descriptors = try forest.rootDescriptors(a);
    defer a.free(descriptors);
    if (!std.meta.eql(try linked.verifiedForestDigest(job, descriptors), forest.digest))
        return error.UntrustedStagedOuterForest;
    const budget = try Budget.create(a, options.preparation_limit);
    defer budget.destroy();
    const work = budget.allocator();
    const nodes = try work.alloc(parent.tree.Node, forest.roots.len);
    defer work.free(nodes);
    var node_count: usize = 0;
    defer for (nodes[0..node_count]) |*node| node.deinit();
    const pointers = try work.alloc(*const parent.tree.Node, forest.roots.len);
    defer work.free(pointers);
    for (forest.roots, 0..) |root, index| {
        if (root.admission.key.profile != options.profile or
            !std.meta.eql(root.statement.job, job))
            return error.UntrustedStagedOuterMember;
        const bytes = switch (root.file) {
            .leaf => |leaf_index| try leaves.load(leaf_index),
            .parent => |parent_index| try forest.loadParent(parent_index),
        };
        defer switch (root.file) {
            .leaf => leaves.a.free(bytes),
            .parent => forest.a.free(bytes),
        };
        var artifact = try parent.codec.decode(work, bytes, &root.admission);
        nodes[index] = try parent.tree.Node.verifyOwned(&artifact, root.admission, root.admission.expected_id, root.statement);
        node_count += 1;
        pointers[index] = &nodes[index];
    }
    var folded = if (options.profile == .diagnostic_q8_pow0)
        try exact.prepareDiagnostic(work, job, pointers, forest.digest, 2)
    else
        try exact.prepare(work, job, pointers, forest.digest, 2);
    defer folded.deinit();
    const Api = parent.ForBackend(Cpu);
    const key = try Api.deriveKeyWithProfile(work, &folded.prepared, options.profile);
    const admission = try parent.protocol.Admission.init(key, try key.identity());
    const plan = try Api.Plan.init(work, &folded.prepared.rows, admission);
    defer plan.deinit();
    var proof = try plan.prove(work, &folded.prepared.rows);
    defer proof.deinit();
    const bytes = try parent.codec.encode(work, &proof, &admission);
    defer work.free(bytes);
    if (bytes.len == 0 or bytes.len > MAX_OUTER_BYTES)
        return error.InvalidStagedOuterSize;
    var verified = if (options.profile == .diagnostic_q8_pow0)
        try linked.verifyDiagnosticExactBytes(work, bytes, admission, admission.expected_id, job, descriptors)
    else
        try linked.verifyExactBytes(work, bytes, admission, admission.expected_id, job, descriptors);
    defer verified.deinit();
    _ = try verified.root();
    var file = try dir.createFile(OUTER_FILE, .{ .exclusive = true });
    errdefer dir.deleteFile(OUTER_FILE) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .a = a, .dir = dir, .statement = folded.statement, .admission = admission, .forest_digest = forest.digest, .byte_len = bytes.len, .sha256 = digest, .preparation_peak_bytes = budget.snapshot().peak_live_bytes };
}

test "outer staging rejects an incomplete exact forest before proving" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const leaf_entries = try a.alloc(leaf_stage.Entry, 0);
    var leaves = leaf_stage.Capture{ .a = a, .dir = tmp.dir, .profile = .diagnostic_q8_pow0, .entries = leaf_entries };
    defer leaves.deinit();
    const parents = try a.alloc(forest_stage.ParentPin, 0);
    const roots = try a.alloc(forest_stage.RootPin, 0);
    var forest = forest_stage.Stage{ .a = a, .dir = tmp.dir, .parents = parents, .roots = roots, .digest = @splat(0) };
    defer forest.deinit();
    const job = try @import("../recursion/span_statement_blake3_test_fixture.zig").job(2);
    try std.testing.expectError(error.InvalidStagedOuterForest, prove(a, tmp.dir, &leaves, &forest, job, .{ .profile = .diagnostic_q8_pow0, .preparation_limit = 1 }));
}
