//! Saved canonical q70 originals/roots only. No source or parent proving.
//! Written while the retained run is live; qualification must wait for release.
const std = @import("std");
const E = @import("stwo_prover_engine");
const C = @import("../block_v7_real_window_capture_v1.zig");
const Pipeline = @import("../block_v8_full_block_pipeline_v1.zig");
const Fixture = @import("block_v8_full_boundary_test.zig");
const Wire = @import("../../recursion/block_v8_window_root_wire_v1.zig");
const evidence = "campaign/qualification/new-full-block-depth2-driver-q70-v1";
fn seed(a: std.mem.Allocator, target: std.fs.Dir) !void {
    var source = try std.fs.cwd().openDir(evidence, .{});
    defer source.close();
    for ([_][]const u8{ "root.proof", "report.json", "catalog.json", "node-0.public", "node-0.proof", "node-1.public", "node-1.proof", "node-2.public", "node-2.proof", "node-3.proof", "node-3.proving.json", "node-3.timing.json", "node-4.proof", "node-4.proving.json", "node-4.timing.json" }) |name| {
        const bytes = try source.readFileAlloc(a, name, 64 << 20);
        defer a.free(bytes);
        try target.writeFile(.{ .sub_path = name, .data = bytes });
    }
}
fn expectNoProving(directory: std.fs.Dir) !void {
    for ([_][]const u8{ "window-0", "window-1", "window-2", "node-0.recursion.json", "node-1.recursion.json", "node-2.recursion.json" }) |name| try std.testing.expectError(error.FileNotFound, directory.access(name, .{}));
}
test "immutable admission cache resumes three canonical windows and two folds with uncached full receiving" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const pins = C.Pins{ .elf = C.sha(&Fixture.elf), .input = C.sha(&.{}) };
    var left = try C.capture(a, &Fixture.elf, &.{}, pins, .{ .skip_cycles = 0, .cycles = 4 }, .{});
    defer left.deinit();
    left.releaseExecution();
    var middle = try C.capture(a, &Fixture.elf, &.{}, pins, .{ .skip_cycles = 4, .cycles = 2 }, .{});
    defer middle.deinit();
    middle.releaseExecution();
    var right = try C.capture(a, &Fixture.elf, &.{}, pins, .{ .skip_cycles = 6, .cycles = 1 }, .{});
    defer right.deinit();
    right.releaseExecution();
    const snapshots = [_]struct { incoming: C.Snapshot, outgoing: C.Snapshot, skip: u64, cycles: u32 }{
        .{ .incoming = left.incoming, .outgoing = left.outgoing, .skip = 0, .cycles = 4 },
        .{ .incoming = middle.incoming, .outgoing = middle.outgoing, .skip = 4, .cycles = 2 },
        .{ .incoming = right.incoming, .outgoing = right.outgoing, .skip = 6, .cycles = 1 },
    };
    var jobs: [3]Pipeline.Job = undefined;
    for (&jobs, snapshots) |*job, snapshot| job.* = .{ .kind = .native, .request = .{ .elf = &Fixture.elf, .elf_sha256 = pins.elf, .config = config, .incoming = snapshot.incoming, .outgoing = snapshot.outgoing, .trusted_window = .{ .elf_sha256 = pins.elf, .incoming_sha256 = snapshot.incoming.identity(), .outgoing_sha256 = snapshot.outgoing.identity(), .window = .{ .skip_cycles = snapshot.skip, .cycles = snapshot.cycles } } } };
    var expected: [43]u8 = @splat(0);
    expected[32] = 1;
    const input = Pipeline.Input{ .elf = &Fixture.elf, .private_input = &.{}, .trusted = .{ .elf_sha256 = pins.elf, .input_sha256 = pins.input, .total_cycles = 7, .expected_output = expected, .config = config }, .jobs = &jobs };
    const options = Pipeline.Options{ .resume_saved = true, .immutable_admission_cache = true };
    var positive = std.testing.tmpDir(.{ .iterate = true });
    defer positive.cleanup();
    try seed(a, positive.dir);
    const original_root = try positive.dir.readFileAlloc(a, "root.proof", 64 << 20);
    defer a.free(original_root);
    const old_proving = try positive.dir.readFileAlloc(a, "node-3.proving.json", 1 << 20);
    defer a.free(old_proving);
    const old_timing = try positive.dir.readFileAlloc(a, "node-3.timing.json", 1 << 20);
    defer a.free(old_timing);
    const summary = try Pipeline.run(budget, &pool, positive.dir, input, options);
    try std.testing.expect(summary.proof_verified and !summary.fresh_complete_run);
    try std.testing.expectEqual(@as(u32, 3), summary.resumed_windows);
    try std.testing.expectEqual(@as(u32, 2), summary.resumed_folds);
    try std.testing.expectEqual(@as(u32, 0), summary.resumed_original_bundles);
    try std.testing.expectEqual(@as(u64, 0), summary.originals_ns);
    try std.testing.expectEqual(@as(u64, 0), summary.window_roots_ns);
    try std.testing.expect(summary.resume_fold_verification_ns > 0);
    try std.testing.expectEqual(@as(usize, 5), summary.admission_cache.?.independent_derivations);
    try std.testing.expectEqual(@as(usize, 2), summary.admission_cache.?.temporary_fold_derivations);
    try std.testing.expectEqualStrings("resume invocation; previously completed proving excluded", summary.timing_scope);
    const current_root = try positive.dir.readFileAlloc(a, "root.proof", 64 << 20);
    defer a.free(current_root);
    try std.testing.expectEqualSlices(u8, original_root, current_root);
    const current_proving = try positive.dir.readFileAlloc(a, "node-3.proving.json", 1 << 20);
    defer a.free(current_proving);
    const current_timing = try positive.dir.readFileAlloc(a, "node-3.timing.json", 1 << 20);
    defer a.free(current_timing);
    try std.testing.expectEqualSlices(u8, old_proving, current_proving);
    try std.testing.expectEqualSlices(u8, old_timing, current_timing);
    try positive.dir.access("node-3.resume.json", .{});
    try positive.dir.access("node-4.resume.json", .{});
    try expectNoProving(positive.dir);

    var wrong_main = std.testing.tmpDir(.{ .iterate = true });
    defer wrong_main.cleanup();
    try seed(a, wrong_main.dir);
    const metadata = try wrong_main.dir.readFileAlloc(a, "node-0.public", 16 << 20);
    defer a.free(metadata);
    var leaf = try Wire.decodeNativeLeafOwned(a, metadata, .{});
    defer leaf.deinit();
    leaf.value.main_root[0] ^= 1;
    const changed = try Wire.encodeNativeLeaf(a, leaf.value);
    defer a.free(changed);
    try wrong_main.dir.writeFile(.{ .sub_path = "node-0.public", .data = changed });
    try std.testing.expectError(error.UntrustedB8WindowRootCapture, Pipeline.run(budget, &pool, wrong_main.dir, input, options));
    try expectNoProving(wrong_main.dir);

    var wrong_fold = std.testing.tmpDir(.{ .iterate = true });
    defer wrong_fold.cleanup();
    try seed(a, wrong_fold.dir);
    const proof = try wrong_fold.dir.readFileAlloc(a, "node-3.proof", 64 << 20);
    defer a.free(proof);
    proof[12] ^= 1; // Change expected-ID transport field; it cannot select a VK.
    try wrong_fold.dir.writeFile(.{ .sub_path = "node-3.proof", .data = proof });
    try std.testing.expectError(error.UntrustedBlake3ParentKey, Pipeline.run(budget, &pool, wrong_fold.dir, input, options));
    try expectNoProving(wrong_fold.dir);

    var wrong_roster = std.testing.tmpDir(.{ .iterate = true });
    defer wrong_roster.cleanup();
    try seed(a, wrong_roster.dir);
    try wrong_roster.dir.writeFile(.{ .sub_path = "node-3.timing.json", .data = "{\"fold_ns\":0,\"children\":[1,0],\"index\":3}" });
    try std.testing.expectError(error.UntrustedSavedFoldRoster, Pipeline.run(budget, &pool, wrong_roster.dir, input, options));
    try expectNoProving(wrong_roster.dir);

    var incomplete = std.testing.tmpDir(.{ .iterate = true });
    defer incomplete.cleanup();
    try seed(a, incomplete.dir);
    try incomplete.dir.deleteFile("node-3.timing.json");
    try std.testing.expectError(error.IncompleteSavedFoldRoot, Pipeline.run(budget, &pool, incomplete.dir, input, options));
    try expectNoProving(incomplete.dir);
    std.debug.print("B8_CACHE_RESUME windows=3 folds=2 parent_proofs=0 source_proofs=0 root_bytes_identical=true historical_proving_timing_unchanged=true final_uncached_full_receiver=true retained_profile_peak_bytes={d} key_derivation_peak_bytes={d}\n", .{ summary.admission_cache.?.retained_profile_peak_bytes, summary.admission_cache.?.key_derivation_peak_bytes });
}
