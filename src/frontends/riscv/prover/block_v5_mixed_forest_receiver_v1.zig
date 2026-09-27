//! Detached exact mixed-radix forest verification. The leaf descriptors must
//! already come from fresh native, sidecar, and recursive-leaf verification;
//! transport metadata never supplies execution authority. This receiver
//! replays the topology and freshly verifies every binary or four-child
//! parent against its exact previously verified child edges.
const std = @import("std");
const spans = @import("../recursion/span_statement_blake3.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const quad = @import("../recursion/blake3_local_quad_aggregate.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const topology = @import("block_v4_cpu_mixed_forest_plan.zig");
const stage = @import("block_v4_cpu_mixed_forest_stage.zig");

pub const MAX_PARENT_BYTES: usize = 256 * 1024 * 1024;

/// `expected_forest_digest` and `leaves` are receiver-side policy/results,
/// not values copied from the untrusted bundle being opened here.
pub fn verify(
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    job: spans.JobContext,
    profile: parent.Profile,
    leaves: []const linked.Descriptor,
    parents: []const stage.ParentPin,
    roots: []const stage.RootPin,
    expected_forest_digest: [32]u8,
) ![]linked.Descriptor {
    try job.validate();
    if (leaves.len == 0 or leaves.len != job.segment_count) return error.InvalidMixedLeafCensus;
    var dag = try topology.plan(a, job.segment_count);
    defer dag.deinit();
    if (parents.len != dag.tasks.len or roots.len != dag.roots.len)
        return error.InvalidMixedForestCensus;
    for (leaves, 0..) |leaf, index| {
        try leaf.admission.validate();
        if (leaf.admission.key.profile != profile or
            !std.meta.eql(leaf.statement.job, job) or
            leaf.statement.slots.height != 0 or leaf.statement.slots.first != index)
            return error.UntrustedMixedLeaf;
    }
    const verified = try a.alloc(linked.Descriptor, parents.len);
    defer a.free(verified);
    for (dag.tasks, parents, 0..) |task, pin, index| {
        if (pin.kind != task.kind or pin.admission.key.profile != profile or
            pin.byte_len == 0 or pin.byte_len > MAX_PARENT_BYTES)
            return error.UntrustedMixedParentPin;
        for (pin.children[task.childCount()..]) |unused| {
            if (unused.first != 0 or unused.height != 0)
                return error.NoncanonicalMixedParentTail;
        }
        var children: [4]linked.Descriptor = undefined;
        for (task.children[0..task.childCount()], 0..) |child, edge| {
            const descriptor = switch (child.node) {
                .leaf => |at| leaves[at],
                .parent => |at| blk: {
                    if (at >= index) return error.ForwardMixedParentEdge;
                    break :blk verified[at];
                },
            };
            if (!std.meta.eql(descriptor.statement.slots, child.slots) or
                !std.meta.eql(pin.children[edge], child.slots))
                return error.UntrustedMixedParentEdge;
            children[edge] = descriptor;
        }
        var name_buffer: [80]u8 = undefined;
        const name = try stage.parentPath(task.kind, task.slots, &name_buffer);
        const bytes = try openPinned(a, dir, name, pin.byte_len, pin.sha256);
        defer a.free(bytes);
        const descriptor = if (task.kind == .pair)
            try linked.verifyDyadicBytes(a, bytes, pin.admission, pin.admission.expected_id, children[0], children[1])
        else blk: {
            var quartet: [4]quad.Child = undefined;
            for (children, &quartet) |child, *out| out.* = .{ .statement = child.statement, .admission = child.admission };
            var node = try quad.verifyBytes(a, bytes, pin.admission, pin.admission.expected_id, quartet);
            defer node.deinit();
            break :blk linked.Descriptor{ .statement = node.statement, .admission = node.admission };
        };
        if (!std.meta.eql(descriptor.statement, pin.statement) or
            !std.meta.eql(descriptor.statement.slots, task.slots) or
            !std.meta.eql(descriptor.admission, pin.admission))
            return error.UntrustedMixedParentStatement;
        verified[index] = descriptor;
    }
    const result = try a.alloc(linked.Descriptor, dag.roots.len);
    errdefer a.free(result);
    for (dag.roots, roots, result) |expected, pin, *out| {
        const descriptor = switch (expected.node) {
            .leaf => |index| blk: {
                if (pin.file != .leaf or pin.file.leaf != index)
                    return error.UntrustedMixedRootFile;
                break :blk leaves[index];
            },
            .parent => |index| blk: {
                if (pin.file != .parent or pin.file.parent != index)
                    return error.UntrustedMixedRootFile;
                break :blk verified[index];
            },
        };
        if (!std.meta.eql(pin.statement, descriptor.statement) or
            !std.meta.eql(pin.admission, descriptor.admission) or
            !std.meta.eql(descriptor.statement.slots, expected.slots))
            return error.UntrustedMixedRoot;
        out.* = descriptor;
    }
    if (!std.meta.eql(try linked.verifiedForestDigest(job, result), expected_forest_digest))
        return error.UntrustedMixedForestDigest;
    return result;
}

fn openPinned(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, length: usize, expected: [32]u8) ![]u8 {
    if (length == 0 or length > MAX_PARENT_BYTES) return error.InvalidMixedParentLength;
    var file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != length) return error.TamperedMixedParentFile;
    const bytes = try file.readToEndAlloc(a, length);
    errdefer a.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (bytes.len != length or !std.meta.eql(digest, expected))
        return error.TamperedMixedParentFile;
    return bytes;
}
