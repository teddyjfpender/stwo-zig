//! Canonical complete-block admission from hash-pinned staged proof files.
//! Both public manifests are selected by caller-supplied SHA-256 pins before
//! any proof bytes are opened. Core and recursion are freshly verified here.
const std = @import("std");
const batch = @import("block_memory_batch_verify_v2.zig");
const manifest_mod = @import("block_v4_cpu_trusted_manifest_v1.zig");
const rebind = @import("block_v4_cpu_complete_pin_rebind_v1.zig");
const incremental = @import("block_v4_cpu_incremental_core_receiver.zig");
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const leaf_stage = @import("block_v4_cpu_incremental_leaf_stage.zig");
const forest_stage = @import("block_v4_cpu_incremental_forest_stage.zig");
const pins_mod = @import("block_memory_complete_receiver_v3.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const runner = @import("block_v4_cpu_runner_source.zig");

const MAX_OUTER_BYTES: usize = 256 * 1024 * 1024;

pub const ManifestFile = struct {
    dir: std.fs.Dir,
    path: []const u8,
    expected_sha256: [32]u8,
};

pub const OuterFile = struct {
    dir: std.fs.Dir,
    path: []const u8,
    byte_len: usize,
    sha256: [32]u8,
};

pub const Files = struct {
    leaves: *const leaf_stage.Capture,
    forest: *const forest_stage.Stage,
    outer: OuterFile,
};

/// `candidate` binds the already-sealed first-round core. `final` pins the
/// same job/source plus the independently admitted forest and outer key.
/// `pins` are caller policy; staged metadata only supplies transport hashes.
pub fn verifyCanonical(
    a: std.mem.Allocator,
    product: product_mod.Product,
    candidate_file: ManifestFile,
    final_file: ManifestFile,
    schedule_json: []const u8,
    pins: pins_mod.RecursionPins,
    files: Files,
) !batch.CompleteBlock {
    var candidate = try manifest_mod.read(a, candidate_file.dir, candidate_file.path, candidate_file.expected_sha256);
    defer candidate.deinit();
    var final = try manifest_mod.read(a, final_file.dir, final_file.path, final_file.expected_sha256);
    defer final.deinit();
    try admitSource(a, product.source, schedule_json, &candidate, &final);
    try preflightFiles(pins, files, candidate.trusted().job.segment_count);
    if (!std.meta.eql(pins.outer.expected_key_id, final.trusted().outer_key_id) or
        !std.meta.eql(files.forest.digest, final.trusted().forest_roster_digest))
        return error.UntrustedStagedFinalPins;

    var verifier_source = try freshSource(a, product.source, schedule_json, candidate.sourcePins());
    defer verifier_source.deinit();
    var verifier_product = product;
    verifier_product.source = &verifier_source;
    var closed = try incremental.verify(a, verifier_product, candidate.trusted(), parent.Profile.csp_q70_pow26.config());
    defer closed.deinit(a);
    const proposed_roots = try files.forest.rootDescriptors(a);
    defer a.free(proposed_roots);
    const rebound = try rebind.finalizeCompletePins(a, verifier_product, &candidate, &final, &closed, proposed_roots, pins.outer.admission);
    const complete = try rebound.product.statement.requireCompletePins(rebound.product.public.pin.initial_rw_root.bytes);
    if (!std.meta.eql(rebound.trusted.job, complete.expected_job)) return error.UntrustedStagedCompleteJob;

    const count = pins.leaf.len;
    const descriptors = try a.alloc(linked.Descriptor, count + pins.dyadic.len);
    defer a.free(descriptors);
    for (pins.leaf, descriptors[0..count], 0..) |pin, *descriptor, index| {
        const bytes = try files.leaves.load(index);
        defer files.leaves.a.free(bytes);
        const receipt = &closed.core.executions[index];
        descriptor.* = try linked.verifyLeafBytes(a, bytes, pin.admission, pin.expected_key_id, closed.leaves[index], &closed.public_data[index].data, parent.Profile.csp_q70_pow26.config(), rebound.product.statement.seal, rebound.trusted.native_key_ids[index], receipt.native_roots, receipt.witness_root, receipt);
    }
    for (pins.dyadic, descriptors[count..], 0..) |pin, *descriptor, index| {
        const bytes = try files.forest.loadParent(index);
        defer files.forest.a.free(bytes);
        descriptor.* = try linked.verifyDyadicBytes(a, bytes, pin.proof.admission, pin.proof.expected_key_id, descriptors[pin.left_index], descriptors[pin.right_index]);
        if (!std.meta.eql(descriptor.statement, files.forest.parents[index].statement))
            return error.UntrustedStagedDyadicStatement;
    }
    const roots = try a.alloc(linked.Descriptor, pins.root_indices.len);
    defer a.free(roots);
    for (pins.root_indices, roots, files.forest.roots) |index, *root, staged| {
        root.* = descriptors[index];
        if (!std.meta.eql(root.statement, staged.statement) or
            !std.meta.eql(root.admission, staged.admission))
            return error.UntrustedStagedForestRoot;
    }
    const digest = try linked.verifiedForestDigest(complete.expected_job, roots);
    if (!std.meta.eql(digest, complete.forest_roster_digest) or
        !std.meta.eql(digest, files.forest.digest))
        return error.UntrustedStagedForestRoster;
    const outer_bytes = try loadOuter(a, files.outer);
    defer a.free(outer_bytes);
    var outer = try linked.verifyExactBytes(a, outer_bytes, pins.outer.admission, pins.outer.expected_key_id, complete.expected_job, roots);
    defer outer.deinit();
    _ = try outer.root();
    return .complete_block_verified;
}

fn admitSource(a: std.mem.Allocator, source: *const runner.Source, schedule_json: []const u8, candidate: *const manifest_mod.Owned, final: *const manifest_mod.Owned) !void {
    try candidate.admitInputs(source.elf, source.input, source.oracle, schedule_json);
    try final.admitInputs(source.elf, source.input, source.oracle, schedule_json);
    if (!std.meta.eql(source.job, candidate.trusted().job) or
        !std.meta.eql(source.job, final.trusted().job))
        return error.UntrustedStagedRunnerJob;
    const expected = source.owned_budgets orelse return error.MissingStagedRunnerSchedule;
    var parsed = try std.json.parseFromSlice([]u32, a, schedule_json, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    if (!std.mem.eql(u32, parsed.value, expected)) return error.UntrustedStagedRunnerSchedule;
}

/// A detached receiver cannot reuse the producer's already-consumed replay
/// cursor. Reconstruct its boundary map from independently pinned inputs in
/// two bounded host passes, then run the fresh proof-verification pass.
fn freshSource(a: std.mem.Allocator, source: *const runner.Source, schedule_json: []const u8, pins: runner.Pins) !runner.Source {
    var maximum: u32 = 0;
    const budgets = source.owned_budgets orelse return error.MissingStagedRunnerSchedule;
    for (budgets) |budget| maximum = @max(maximum, budget);
    var fresh = try runner.Source.initWithSchedule(a, source.elf, source.input, source.oracle, maximum, parent.Profile.csp_q70_pow26.config(), pins, schedule_json);
    errdefer fresh.deinit();
    try drainPass(&fresh, .first);
    try drainPass(&fresh, .second);
    return fresh;
}

fn drainPass(source: *runner.Source, pass: runner.Pass) !void {
    var reader = try source.openPass(pass);
    defer reader.deinit();
    while (try reader.next()) |owned| {
        var segment = owned;
        segment.deinit();
    }
}

fn preflightFiles(pins: pins_mod.RecursionPins, files: Files, segment_count: u32) !void {
    const count: usize = segment_count;
    const roots_expected: usize = @popCount(segment_count);
    if (count == 0 or pins.leaf.len != count or files.leaves.next != count or
        files.leaves.entries.len != count or pins.dyadic.len != count - roots_expected or
        files.forest.parents.len != pins.dyadic.len or pins.root_indices.len != roots_expected or
        files.forest.roots.len != roots_expected)
        return error.InvalidStagedRecursiveCensus;
    try pins.outer.admission.validate();
    if (pins.outer.admission.key.profile != .csp_q70_pow26 or
        !std.meta.eql(pins.outer.admission.expected_id, pins.outer.expected_key_id))
        return error.UntrustedStagedOuterKey;
    for (pins.leaf, files.leaves.entries) |pin, staged| {
        try pin.admission.validate();
        if (pin.admission.key.profile != .csp_q70_pow26 or
            !std.meta.eql(pin.admission.expected_id, pin.expected_key_id) or
            !std.meta.eql(pin.admission, staged.admission))
            return error.UntrustedStagedLeafKey;
    }
    for (pins.dyadic, files.forest.parents, 0..) |pin, staged, index| {
        try pin.proof.admission.validate();
        if (pin.proof.admission.key.profile != .csp_q70_pow26 or
            !std.meta.eql(pin.proof.admission.expected_id, pin.proof.expected_key_id) or
            !std.meta.eql(pin.proof.admission, staged.admission) or
            pin.left_index >= count + index or pin.right_index >= count + index or
            pin.left_index == pin.right_index)
            return error.UntrustedStagedDyadicKey;
    }
    for (pins.root_indices) |index| if (index >= count + pins.dyadic.len)
        return error.InvalidStagedRootIndex;
}

fn loadOuter(a: std.mem.Allocator, pin: OuterFile) ![]u8 {
    if (pin.byte_len == 0 or pin.byte_len > MAX_OUTER_BYTES or pin.path.len == 0)
        return error.InvalidStagedOuterSize;
    var file = try pin.dir.openFile(pin.path, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(a, pin.byte_len);
    errdefer a.free(bytes);
    if (bytes.len != pin.byte_len or !std.meta.eql(runner.sha256(bytes), pin.sha256))
        return error.TamperedStagedOuterProof;
    return bytes;
}

test "file-backed complete receiver rejects an unpinned manifest before proof files" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "candidate.json", .data = "{}" });
    try std.testing.expectError(error.UntrustedBlockManifestHash, verifyCanonical(a, undefined, .{
        .dir = tmp.dir,
        .path = "candidate.json",
        .expected_sha256 = @splat(0),
    }, undefined, undefined, undefined, undefined));
}
