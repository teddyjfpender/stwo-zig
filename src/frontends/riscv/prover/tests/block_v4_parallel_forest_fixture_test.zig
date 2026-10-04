//! Reuses independently verified block-v3 leaves to compare serial and
//! parallel exact-forest staging. This is a q8 proving regression, not a
//! complete block receiver or a q70 performance qualification.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const spans = @import("../../recursion/span_statement_blake3.zig");
const linked = @import("../../recursion/blake3_exact_root_receiver_v3.zig");
const leaves_mod = @import("../block_v4_cpu_incremental_leaf_stage.zig");
const serial = @import("../block_v4_cpu_incremental_forest_stage.zig");
const parallel = @import("../block_v4_cpu_parallel_forest_stage.zig");
const mixed = @import("../block_v4_cpu_mixed_forest_stage.zig");
const parallel_mixed = @import("../block_v5_parallel_mixed_forest_stage_v1.zig");
const quad = @import("../../recursion/blake3_local_quad_aggregate.zig");
const outer = @import("../block_v4_cpu_incremental_outer_stage.zig");
const detached_mixed = @import("../block_v5_mixed_forest_receiver_v1.zig");
const mixed_manifest = @import("../block_v5_mixed_forest_manifest_v1.zig");
const mixed_outer_receiver = @import("../block_v5_mixed_outer_receiver_v1.zig");

pub fn compare(a: std.mem.Allocator, job: spans.JobContext, nodes: []const parent.tree.Node) !void {
    return compareMode(a, job, nodes, false);
}

pub fn compareMixedOnly(a: std.mem.Allocator, job: spans.JobContext, nodes: []const parent.tree.Node) !void {
    return compareMode(a, job, nodes, true);
}

fn compareMode(a: std.mem.Allocator, job: spans.JobContext, nodes: []const parent.tree.Node, mixed_only: bool) !void {
    var leaf_tmp = std.testing.tmpDir(.{});
    defer leaf_tmp.cleanup();
    var serial_tmp = std.testing.tmpDir(.{});
    defer serial_tmp.cleanup();
    var parallel_tmp = std.testing.tmpDir(.{});
    defer parallel_tmp.cleanup();
    var mixed_tmp = std.testing.tmpDir(.{});
    defer mixed_tmp.cleanup();
    const entries = try a.alloc(leaves_mod.Entry, nodes.len);
    var leaves = leaves_mod.Capture{
        .a = a,
        .dir = leaf_tmp.dir,
        .profile = .diagnostic_q8_pow0,
        .entries = entries,
        .next = nodes.len,
    };
    defer leaves.deinit();
    for (nodes, entries, 0..) |node, *entry, index| {
        const bytes = node.transport_bytes orelse return error.MissingStagedRecursiveLeaf;
        var name: [64]u8 = undefined;
        var file = try leaf_tmp.dir.createFile(try leaves_mod.Capture.path(index, &name), .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        entry.* = .{
            .byte_len = bytes.len,
            .sha256 = digest,
            .admission = node.admission,
            .descriptor = .{ .statement = node.statement, .admission = node.admission },
        };
    }
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = a });
    defer pool.deinit();
    if (!mixed_only) {
        var timer = try std.time.Timer.start();
        var standard = try serial.prove(a, serial_tmp.dir, &leaves, job, &pool, .{
            .profile = .diagnostic_q8_pow0,
            .preparation_limit = 16 * 1024 * 1024 * 1024,
            .worker_options = .{ .worker_count = 1, .host_byte_limit = 16 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 },
        });
        defer standard.deinit();
        const serial_ns = timer.read();
        timer.reset();
        var metrics: parallel.Metrics = undefined;
        var concurrent = try parallel.prove(a, parallel_tmp.dir, &leaves, job, .{
            .profile = .diagnostic_q8_pow0,
            .lane_count = 2,
            .total_host_limit = 32 * 1024 * 1024 * 1024,
            .preparation_limit_per_lane = 8 * 1024 * 1024 * 1024,
            .parent_worker_options = .{ .worker_count = 1, .host_byte_limit = 8 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 },
            .metrics = &metrics,
        });
        defer concurrent.deinit();
        const parallel_ns = timer.read();
        try std.testing.expectEqual(standard.parents.len, concurrent.parents.len);
        try std.testing.expectEqual(standard.roots.len, concurrent.roots.len);
        try std.testing.expectEqualSlices(u8, &standard.digest, &concurrent.digest);
        for (standard.parents, concurrent.parents) |expected, actual| {
            try std.testing.expectEqualDeep(expected.statement, actual.statement);
            try std.testing.expectEqualDeep(expected.admission, actual.admission);
            try std.testing.expectEqualDeep(expected.left, actual.left);
            try std.testing.expectEqualDeep(expected.right, actual.right);
        }
        for (standard.roots, concurrent.roots) |expected, actual| {
            try std.testing.expectEqualDeep(expected.statement, actual.statement);
            try std.testing.expectEqualDeep(expected.admission, actual.admission);
            try std.testing.expectEqualDeep(expected.file, actual.file);
        }
        const parent_descriptors = try a.alloc(linked.Descriptor, concurrent.parents.len);
        defer a.free(parent_descriptors);
        for (concurrent.parents, parent_descriptors, 0..) |pin, *descriptor, index| {
            const left = try childDescriptor(&leaves, concurrent.parents[0..index], parent_descriptors[0..index], pin.left);
            const right = try childDescriptor(&leaves, concurrent.parents[0..index], parent_descriptors[0..index], pin.right);
            const bytes = try concurrent.loadParent(index);
            defer a.free(bytes);
            descriptor.* = try linked.verifyDyadicBytes(a, bytes, pin.admission, pin.admission.expected_id, left, right);
        }
        var fresh: [spans.MAX_SLOT_HEIGHT + 1]linked.Descriptor = undefined;
        for (concurrent.roots, 0..) |root, index| fresh[index] = switch (root.file) {
            .leaf => |leaf_index| leaves.entries[leaf_index].descriptor,
            .parent => |parent_index| parent_descriptors[parent_index],
        };
        const fresh_digest = try linked.verifiedForestDigest(job, fresh[0..concurrent.roots.len]);
        try std.testing.expectEqualSlices(u8, &concurrent.digest, &fresh_digest);
        std.debug.print("BLOCK_V4_PARALLEL_FOREST_PARITY verified=true leaves={d} parents={d} roots={d} lanes={d} serial_ns={d} parallel_ns={d} tracked_peak_bytes={d}\n", .{ nodes.len, concurrent.parents.len, concurrent.roots.len, metrics.lane_count, serial_ns, parallel_ns, metrics.tracked_peak_bytes });
    }

    // A quartet has a distinct, versioned key and digest, so semantic root
    // coverage is checked against the same job instead of comparing its bytes
    // with the binary-only roster.
    if (nodes.len >= 4) {
        var combined = if (mixed_only)
            try parallel_mixed.prove(a, mixed_tmp.dir, &leaves, job, .{
                .profile = .diagnostic_q8_pow0,
                .lane_count = 2,
                .total_host_limit = 32 * 1024 * 1024 * 1024,
                .preparation_limit_per_lane = 8 * 1024 * 1024 * 1024,
                .worker_options = .{ .worker_count = 1, .host_byte_limit = 8 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 },
            })
        else
            try mixed.prove(a, mixed_tmp.dir, &leaves, job, &pool, .{
                .profile = .diagnostic_q8_pow0,
                .total_host_limit = 16 * 1024 * 1024 * 1024,
                .preparation_limit = 12 * 1024 * 1024 * 1024,
                .worker_options = .{ .worker_count = 1, .host_byte_limit = 12 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 },
            });
        defer combined.deinit();
        const verified_parents = try a.alloc(linked.Descriptor, combined.parents.len);
        defer a.free(verified_parents);
        var quartet_count: usize = 0;
        for (combined.parents, verified_parents, 0..) |pin, *descriptor, index| {
            const bytes = try combined.loadParent(index);
            defer a.free(bytes);
            if (pin.kind == .pair) {
                const left = try mixedChildDescriptor(&leaves, combined.parents[0..index], verified_parents[0..index], pin.children[0]);
                const right = try mixedChildDescriptor(&leaves, combined.parents[0..index], verified_parents[0..index], pin.children[1]);
                descriptor.* = try linked.verifyDyadicBytes(a, bytes, pin.admission, pin.admission.expected_id, left, right);
            } else {
                var children: [4]quad.Child = undefined;
                for (pin.children, &children) |slots, *child| {
                    const found = try mixedChildDescriptor(&leaves, combined.parents[0..index], verified_parents[0..index], slots);
                    child.* = .{ .statement = found.statement, .admission = found.admission };
                }
                var verified = try quad.verifyBytes(a, bytes, pin.admission, pin.admission.expected_id, children);
                defer verified.deinit();
                descriptor.* = .{ .statement = verified.statement, .admission = verified.admission };
                quartet_count += 1;
            }
            try std.testing.expectEqualDeep(pin.statement, descriptor.statement);
        }
        var root_descriptors: [spans.MAX_SLOT_HEIGHT + 1]linked.Descriptor = undefined;
        for (combined.roots, 0..) |root, index| root_descriptors[index] = switch (root.file) {
            .leaf => |leaf_index| leaves.entries[leaf_index].descriptor,
            .parent => |parent_index| verified_parents[parent_index],
        };
        const mixed_digest = try linked.verifiedForestDigest(job, root_descriptors[0..combined.roots.len]);
        try std.testing.expectEqualSlices(u8, &combined.digest, &mixed_digest);
        const fresh_leaves = try a.alloc(linked.Descriptor, leaves.entries.len);
        defer a.free(fresh_leaves);
        for (leaves.entries, fresh_leaves) |entry, *descriptor| descriptor.* = entry.descriptor;
        const detached_roots = try detached_mixed.verify(a, mixed_tmp.dir, job, .diagnostic_q8_pow0, fresh_leaves, combined.parents, combined.roots, combined.digest);
        defer a.free(detached_roots);
        try std.testing.expectEqualDeep(root_descriptors[0..combined.roots.len], detached_roots);
        const manifest_sha = try mixed_manifest.write(a, mixed_tmp.dir, &combined, job.segment_count);
        const manifest_roots = try mixed_manifest.verifyCanonical(a, mixed_tmp.dir, manifest_sha, combined.digest, job, .diagnostic_q8_pow0, fresh_leaves);
        defer a.free(manifest_roots);
        try std.testing.expectEqualDeep(detached_roots, manifest_roots);
        var wrong_manifest_sha = manifest_sha;
        wrong_manifest_sha[0] ^= 1;
        try std.testing.expectError(error.ChangedMixedForestManifest, mixed_manifest.verifyCanonical(a, mixed_tmp.dir, wrong_manifest_sha, combined.digest, job, .diagnostic_q8_pow0, fresh_leaves));
        if (combined.parents.len != 0) {
            const bad_pins = try a.dupe(mixed.ParentPin, combined.parents);
            defer a.free(bad_pins);
            bad_pins[0].kind = if (bad_pins[0].kind == .quartet) .pair else .quartet;
            try std.testing.expectError(error.UntrustedMixedParentPin, detached_mixed.verify(a, mixed_tmp.dir, job, .diagnostic_q8_pow0, fresh_leaves, bad_pins, combined.roots, combined.digest));
            bad_pins[0] = combined.parents[0];
            bad_pins[0].children[0].first += 1;
            try std.testing.expectError(error.UntrustedMixedParentEdge, detached_mixed.verify(a, mixed_tmp.dir, job, .diagnostic_q8_pow0, fresh_leaves, bad_pins, combined.roots, combined.digest));
            bad_pins[0] = combined.parents[0];
            bad_pins[0].sha256[0] ^= 1;
            try std.testing.expectError(error.TamperedMixedParentFile, detached_mixed.verify(a, mixed_tmp.dir, job, .diagnostic_q8_pow0, fresh_leaves, bad_pins, combined.roots, combined.digest));
        }
        var bad_digest = combined.digest;
        bad_digest[0] ^= 1;
        try std.testing.expectError(error.UntrustedMixedForestDigest, detached_mixed.verify(a, mixed_tmp.dir, job, .diagnostic_q8_pow0, fresh_leaves, combined.parents, combined.roots, bad_digest));
        try std.testing.expectError(error.UntrustedMixedForestManifest, mixed_manifest.verifyCanonical(a, mixed_tmp.dir, manifest_sha, bad_digest, job, .diagnostic_q8_pow0, fresh_leaves));
        if (nodes.len == 5) {
            try std.testing.expectEqual(@as(usize, 1), quartet_count);
            try std.testing.expectEqual(@as(usize, 0), combined.parents.len - quartet_count);
            try std.testing.expectEqual(@as(usize, 2), combined.roots.len);
        }
        const exact = try outer.prove(a, mixed_tmp.dir, &leaves, &combined, job, .{
            .profile = .diagnostic_q8_pow0,
            .preparation_limit = 12 * 1024 * 1024 * 1024,
        });
        const outer_bytes = try exact.load();
        defer a.free(outer_bytes);
        try std.testing.expectEqualSlices(u8, &combined.digest, &exact.forest_digest);
        const outer_pin = mixed_outer_receiver.Pin{
            .admission = exact.admission,
            .statement = exact.statement,
            .byte_len = exact.byte_len,
            .sha256 = exact.sha256,
        };
        var complete_root = try mixed_outer_receiver.verifyCanonical(a, mixed_tmp.dir, manifest_sha, combined.digest, job, .diagnostic_q8_pow0, fresh_leaves, exact.admission.expected_id, outer_pin);
        defer complete_root.deinit();
        _ = try complete_root.root();
        var wrong_outer_key = exact.admission.expected_id;
        wrong_outer_key[0] ^= 1;
        try std.testing.expectError(error.UntrustedMixedOuterPin, mixed_outer_receiver.verifyCanonical(a, mixed_tmp.dir, manifest_sha, combined.digest, job, .diagnostic_q8_pow0, fresh_leaves, wrong_outer_key, outer_pin));
        std.debug.print("BLOCK_V4_MIXED_FOREST verified=true leaves={d} pair_parents={d} quartet_parents={d} roots={d} outer_bytes={d} tracked_peak_bytes={d}\n", .{
            nodes.len, combined.parents.len - quartet_count, quartet_count, combined.roots.len, outer_bytes.len, combined.tracked_peak_bytes,
        });
    }
}

fn childDescriptor(leaves: *const leaves_mod.Capture, pins: []const serial.ParentPin, descriptors: []const linked.Descriptor, slots: spans.SlotSpan) !linked.Descriptor {
    if (slots.height == 0) {
        const index: usize = @intCast(slots.first);
        if (index >= leaves.entries.len) return error.InvalidParallelForestLeaf;
        return leaves.entries[index].descriptor;
    }
    for (pins, descriptors) |pin, descriptor| if (std.meta.eql(pin.statement.slots, slots)) return descriptor;
    return error.MissingParallelForestDependency;
}

fn mixedChildDescriptor(leaves: *const leaves_mod.Capture, pins: []const mixed.ParentPin, descriptors: []const linked.Descriptor, slots: spans.SlotSpan) !linked.Descriptor {
    if (slots.height == 0) {
        const index: usize = @intCast(slots.first);
        if (index >= leaves.entries.len) return error.InvalidMixedForestLeaf;
        return leaves.entries[index].descriptor;
    }
    for (pins, descriptors) |pin, descriptor| if (std.meta.eql(pin.statement.slots, slots)) return descriptor;
    return error.MissingMixedForestDependency;
}
