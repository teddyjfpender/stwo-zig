//! Canonical two-segment file-backed receiver fixture over real public I/O.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const batch = @import("../block_memory_batch_verify_v2.zig");
const product_mod = @import("../block_v4_cpu_streaming_produce.zig");
const trusted_mod = @import("../block_v4_cpu_multi_segment_assembly.zig");
const manifest = @import("../block_v4_cpu_trusted_manifest_v1.zig");
const leaves_mod = @import("../block_v4_cpu_incremental_leaf_stage.zig");
const forest_mod = @import("../block_v4_cpu_incremental_forest_stage.zig");
const outer_mod = @import("../block_v4_cpu_incremental_outer_stage.zig");
const receiver = @import("../block_v4_cpu_streaming_file_receiver_v1.zig");
const rebind = @import("../block_v4_cpu_complete_pin_rebind_v1.zig");
const bundle_snapshot = @import("../block_v4_cpu_bundle_snapshot_v1.zig");
const detached = @import("../block_v4_cpu_bundle_rehydrate_v1.zig");
const recursion_policy = @import("../block_v4_cpu_trusted_recursion_v1.zig");
const parent = @import("../../recursion/blake3_execution_parent_protocol.zig");
const runner = @import("../block_v4_cpu_runner_source.zig");

pub fn run(
    a: std.mem.Allocator,
    product: product_mod.Product,
    candidate: trusted_mod.Trusted,
    pool: *engine.work_pool.WorkPool,
    outer_binding: *engine.work_pool.ScopedPoolBinding,
    binding_active: *bool,
    schedule_json: []const u8,
) !void {
    const dir = product.memories.dir;
    const config = parent.Profile.csp_q70_pow26.config();
    var timer = try std.time.Timer.start();
    var leaves = try leaves_mod.verifyAndStage(a, product, candidate, config, dir, .csp_q70_pow26);
    defer leaves.deinit(a);
    const leaf_ns = timer.read();
    try std.testing.expectEqual(@as(usize, 2), leaves.staged.next);
    try std.testing.expectEqual(product.statement.expected_events, leaves.verified_core.core.summary.event_count);

    outer_binding.deinit();
    binding_active.* = false;
    timer.reset();
    var forest = try forest_mod.prove(a, dir, &leaves.staged, candidate.job, pool, .{
        .profile = .csp_q70_pow26,
        .preparation_limit = 24 * 1024 * 1024 * 1024,
        .worker_options = .{ .worker_count = 4, .host_byte_limit = 24 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 },
    });
    defer forest.deinit();
    const forest_ns = timer.read();
    try std.testing.expectEqual(@as(usize, 1), forest.parents.len);
    try std.testing.expectEqual(@as(usize, 1), forest.roots.len);

    timer.reset();
    const outer = try outer_mod.prove(a, dir, &leaves.staged, &forest, candidate.job, .{
        .profile = .csp_q70_pow26,
        .preparation_limit = 24 * 1024 * 1024 * 1024,
    });
    const outer_ns = timer.read();
    try std.testing.expectEqualSlices(u8, &forest.digest, &outer.forest_digest);

    const source_pins = runner.Pins{
        .elf_sha256 = runner.sha256(product.source.elf),
        .input_sha256 = runner.sha256(product.source.input),
        .oracle_sha256 = runner.sha256(product.source.oracle),
        .initial_rw_root = candidate.job.complete.initial_state.rw_memory,
        .program_root = candidate.job.complete.program,
        .schedule_json_sha256 = runner.sha256(schedule_json),
        .expected_job = candidate.job,
    };
    const candidate_manifest = manifest.Wire{ .format_version = manifest.FORMAT_VERSION, .trusted = candidate, .source = source_pins };
    var final_trusted = candidate;
    final_trusted.outer_key_id = outer.admission.expected_id;
    final_trusted.forest_roster_digest = forest.digest;
    const final_manifest = manifest.Wire{ .format_version = manifest.FORMAT_VERSION, .trusted = final_trusted, .source = source_pins };
    const candidate_json = try std.json.Stringify.valueAlloc(a, candidate_manifest, .{});
    defer a.free(candidate_json);
    const final_json = try std.json.Stringify.valueAlloc(a, final_manifest, .{});
    defer a.free(final_json);
    try dir.writeFile(.{ .sub_path = "candidate.json", .data = candidate_json });
    try dir.writeFile(.{ .sub_path = "final.json", .data = final_json });
    const candidate_file = receiver.ManifestFile{ .dir = dir, .path = "candidate.json", .expected_sha256 = runner.sha256(candidate_json) };
    const final_file = receiver.ManifestFile{ .dir = dir, .path = "final.json", .expected_sha256 = runner.sha256(final_json) };

    const policy_hash = try recursion_policy.writeProposed(a, dir, candidate.job, &leaves.staged, &forest, &outer);
    var policy = try recursion_policy.read(a, dir, policy_hash);
    defer policy.deinit();
    var wrong_policy_hash = policy_hash;
    wrong_policy_hash[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV4RecursionPolicyHash, recursion_policy.read(a, dir, wrong_policy_hash));
    const pins = policy.view().pins();
    var candidate_owned = try manifest.read(a, dir, candidate_file.path, candidate_file.expected_sha256);
    defer candidate_owned.deinit();
    var final_owned = try manifest.read(a, dir, final_file.path, final_file.expected_sha256);
    defer final_owned.deinit();
    const roots = try forest.rootDescriptors(a);
    defer a.free(roots);
    const rebound = try rebind.finalizeCompletePins(a, product, &candidate_owned, &final_owned, &leaves.verified_core, roots, outer.admission);
    const bundle_hash = try bundle_snapshot.write(a, dir, rebound.product, &leaves.staged, &forest, &outer, candidate_file.expected_sha256, final_file.expected_sha256);
    timer.reset();
    try std.testing.expectEqual(batch.CompleteBlock.complete_block_verified, try detached.verifyCanonical(a, dir, bundle_hash, candidate_file, final_file, .{
        .elf = product.source.elf,
        .input = product.source.input,
        .oracle = product.source.oracle,
        .schedule_json = schedule_json,
        .max_segment_cycles = 1 << 22,
    }, pins));
    const fresh_ns = timer.read();
    var wrong_final = final_file;
    wrong_final.expected_sha256[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV4BundlePolicyHashes, detached.verifyCanonical(a, dir, bundle_hash, candidate_file, wrong_final, undefined, pins));
    var wrong_bundle = bundle_hash;
    wrong_bundle[0] ^= 1;
    try std.testing.expectError(error.ChangedBlockV4BundleManifest, detached.verifyCanonical(a, dir, wrong_bundle, candidate_file, final_file, undefined, pins));
    std.debug.print("BLOCK_V4_FILE_COMPLETE verified=true core_leaf_ns={d} forest_ns={d} outer_ns={d} detached_receiver_ns={d} leaf_bytes={d}+{d} parent_bytes={d} outer_bytes={d} bundle_and_manifest_tamper_rejected=true recursion_policy_tamper_rejected=true\n", .{ leaf_ns, forest_ns, outer_ns, fresh_ns, leaves.staged.entries[0].byte_len, leaves.staged.entries[1].byte_len, forest.parents[0].byte_len, outer.byte_len });
}
