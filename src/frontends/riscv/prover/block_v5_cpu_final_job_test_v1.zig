//! Nonproving transport, lifecycle and ordinary-storage checks. Proposal bytes
//! and lifecycle state never substitute for a genuine Fresh or derived key.
const std = @import("std");
const Job = @import("block_v5_cpu_final_job_v1.zig");
const Manifest = @import("block_v5_cpu_final_job_manifest_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Windows = @import("block_v5_register_windows_v1.zig");
const Live = @import("block_v5_memory_source_page_forest_live_budget_v1.zig");
const PublicBus = @import("../recursion/block_v5_requester_public_bus_v1.zig");
pub const behavioral_test_count: usize = 12;
fn proposal() Manifest.Proposal {
    return .{ .bindings = .{ .requester_context = @splat(1), .source_seal = @splat(2), .memory_plan = @splat(3), .memory_public = @splat(4), .register_windows = @splat(5) }, .records = .{ .{ .file = .{ .byte_len = 7, .sha256 = @splat(6) }, .expected_id = @splat(7) }, .{ .file = .{ .byte_len = 11, .sha256 = @splat(8) }, .expected_id = @splat(9) } } };
}
test "CPU final job: exact two typed records and independent source bindings round trip" {
    const expected = proposal();
    const raw = try Manifest.encode(expected, .{});
    try std.testing.expectEqual(@as(usize, 320), raw.len);
    try std.testing.expectEqualDeep(expected, try Manifest.decode(&raw, .{}));
    try Manifest.requireBindings(expected, expected.bindings);
    try Manifest.requireKey(expected.records[0], expected.records[0].expected_id);
    try std.testing.expect(!Job.complete_block_authority);
    try std.testing.expect(!Job.Built.complete_block_authority);
}
test "CPU final job: re-sealed manifest key and swapped typed records reject original expected setup" {
    const expected = proposal();
    var changed = expected;
    changed.records[0].expected_id[2] ^= 1;
    var raw = try Manifest.encode(changed, .{});
    const parsed = try Manifest.decode(&raw, .{});
    try std.testing.expectError(error.UntrustedFinalJobExpectedKey, Manifest.requireKey(parsed.records[0], expected.records[0].expected_id));
    changed.records = .{ expected.records[1], expected.records[0] };
    raw = try Manifest.encode(changed, .{});
    const swapped = try Manifest.decode(&raw, .{});
    try std.testing.expectError(error.UntrustedFinalJobExpectedKey, Manifest.requireKey(swapped.records[0], expected.records[0].expected_id));
    try std.testing.expectError(error.UntrustedFinalJobExpectedKey, Manifest.requireKey(swapped.records[1], expected.records[1].expected_id));
}
test "CPU final job: every independently pinned requester memory source and window identity rejects resealing" {
    const expected = proposal();
    inline for (std.meta.fields(Manifest.Bindings)) |field| {
        var changed = expected;
        @field(changed.bindings, field.name)[13] ^= 1;
        const raw = try Manifest.encode(changed, .{});
        try std.testing.expectError(error.UnpairedFinalJobManifest, Manifest.requireBindings(try Manifest.decode(&raw, .{}), expected.bindings));
    }
}
test "CPU final job: fixed version count length reserved grammar and zero identities reject" {
    const expected = proposal();
    const raw = try Manifest.encode(expected, .{});
    try std.testing.expectError(error.UntrustedFinalJobManifest, Manifest.decode(raw[0..319], .{}));
    var changed = raw;
    changed[0] ^= 1;
    try std.testing.expectError(error.UntrustedFinalJobManifest, Manifest.decode(&changed, .{}));
    changed = raw;
    std.mem.writeInt(u32, changed[8..12], 2, .little);
    try std.testing.expectError(error.UntrustedFinalJobManifest, Manifest.decode(&changed, .{}));
    changed = raw;
    std.mem.writeInt(u32, changed[12..16], 3, .little);
    try std.testing.expectError(error.UntrustedFinalJobManifest, Manifest.decode(&changed, .{}));
    var zero = expected;
    zero.records[1].file.byte_len = 0;
    try std.testing.expectError(error.UntrustedFinalJobManifest, Manifest.encode(zero, .{}));
    zero = expected;
    zero.records[1].expected_id = @splat(0);
    try std.testing.expectError(error.UntrustedFinalJobManifest, Manifest.encode(zero, .{}));
    zero = expected;
    zero.bindings.source_seal = @splat(0);
    try std.testing.expectError(error.UntrustedFinalJobManifest, Manifest.encode(zero, .{}));
}
test "CPU final job: exact metadata per-proof aggregate and local fan-in caps reject" {
    const expected = proposal();
    try std.testing.expectError(error.FinalJobManifestLimit, Manifest.encode(expected, .{ .max_manifest_bytes = 319 }));
    try std.testing.expectError(error.UntrustedFinalJobManifest, Manifest.encode(expected, .{ .max_proof_bytes = 10 }));
    try std.testing.expectError(error.FinalJobManifestLimit, Manifest.encode(expected, .{ .max_total_proof_bytes = 17 }));
    try std.testing.expectError(error.FinalJobResourceLimit, (Job.Limits{ .final_public = .{ .max_children = 3 } }).validate());
    try std.testing.expectError(error.FinalJobResourceLimit, (Job.Limits{ .max_live_bytes = 0 }).validate());
    try std.testing.expectError(error.FinalJobResourceLimit, (Job.Limits{ .max_schedule_terms = (16 << 20) + 1 }).validate());
}
fn rejectBeforeSource(dir: std.fs.Dir, raw: []const u8, hash: [32]u8, expected_error: anyerror) !void {
    try dir.writeFile(.{ .sub_path = Manifest.NAME, .data = raw });
    // Only rejecting transport may see these absent capabilities. A successful
    // path must receive actual requester and memory proof owners.
    const selection = Job.Selection{ .requester = undefined, .memory = undefined, .windows = undefined, .profile = .diagnostic_q8_pow0 };
    try std.testing.expectError(expected_error, Job.reconstruct(std.testing.allocator, dir, selection, .{ .byte_len = raw.len, .sha256 = hash }));
}
test "CPU final job: pinned transport rejects before touching original proof capabilities" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const raw = try Manifest.encode(proposal(), .{});
    var wrong = Files.hash(&raw);
    wrong[1] ^= 1;
    try rejectBeforeSource(directory.dir, &raw, wrong, error.TamperedV5BundleFileHash);
    try rejectBeforeSource(directory.dir, raw[0..319], Files.hash(raw[0..319]), error.UntrustedFinalJobManifest);
    var invalid = raw;
    invalid[12] = 3;
    try rejectBeforeSource(directory.dir, &invalid, Files.hash(&invalid), error.UntrustedFinalJobManifest);
    const selection = Job.Selection{ .requester = undefined, .memory = undefined, .windows = undefined, .profile = .diagnostic_q8_pow0, .limits = .{ .transcript_capacity = 0 } };
    try std.testing.expectError(error.FinalJobResourceLimit, Job.publish(std.testing.failing_allocator, directory.dir, selection));
}
fn readAllocations(a: std.mem.Allocator, dir: std.fs.Dir, pin: Manifest.FilePin) !void {
    try std.testing.expectEqualDeep(proposal(), try Manifest.read(a, dir, pin, .{}));
}
test "CPU final job: bounded proposal loader releases every allocation failure" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const raw = try Manifest.encode(proposal(), .{});
    try directory.dir.writeFile(.{ .sub_path = Manifest.NAME, .data = &raw });
    try std.testing.checkAllAllocationFailures(std.testing.allocator, readAllocations, .{ directory.dir, Manifest.FilePin{ .byte_len = raw.len, .sha256 = Files.hash(&raw) } });
}
test "CPU final job: rollback removes only newly published roots and preserves preexisting destinations" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try Files.publish(directory.dir, Manifest.PUBLIC_PROOF, "existing requester");
    try Files.publish(directory.dir, Manifest.NAME, "existing manifest");
    try std.testing.expectError(error.ExistingV5BundleArtifact, Files.publish(directory.dir, Manifest.PUBLIC_PROOF, "replacement"));
    Manifest.removePublished(directory.dir, false, false);
    var public_file = try directory.dir.openFile(Manifest.PUBLIC_PROOF, .{});
    public_file.close();
    try Files.publish(directory.dir, Manifest.FINAL_PROOF, "new final");
    Manifest.removePublished(directory.dir, false, true);
    try std.testing.expectError(error.FileNotFound, directory.dir.openFile(Manifest.FINAL_PROOF, .{}));
    var manifest_file = try directory.dir.openFile(Manifest.NAME, .{});
    manifest_file.close();
}
test "CPU final job: lifecycle callback runs once and grants no proof or setup authority" {
    const Counter = struct {
        count: usize = 0,
        fn release(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.count += 1;
        }
    };
    var counter = Counter{};
    var lifecycle = Job.CaptureRelease{ .callback = .{ .context = &counter, .call = Counter.release } };
    try lifecycle.afterPreparation();
    try std.testing.expectEqual(@as(usize, 1), counter.count);
    try std.testing.expectError(error.RequesterCaptureAlreadyReleased, lifecycle.afterPreparation());
    try std.testing.expectEqual(@as(usize, 1), counter.count);
    var absent = Job.CaptureRelease{ .callback = null };
    try absent.afterPreparation();
    try std.testing.expectError(error.RequesterCaptureAlreadyReleased, absent.afterPreparation());
}
fn originalWindows() [2]Windows.Window {
    return .{ .{ .index = 0, .first_cycle = 1, .cycle_count = 2, .initial_registers = @splat(0), .final_registers = @splat(0), .final_clocks = @splat(0) }, .{ .index = 1, .first_cycle = 3, .cycle_count = 3, .initial_registers = @splat(0), .final_registers = @splat(0), .final_clocks = @splat(0) } };
}
fn copiedWindows(a: std.mem.Allocator) !void {
    var upstream = originalWindows();
    const plan = Windows.Plan{ .initial_registers = @splat(0), .final_registers = @splat(0), .windows = &upstream };
    const digest = try plan.digest();
    const owned = try Job.cloneWindows(a, plan);
    defer a.free(owned.windows);
    upstream = undefined;
    try owned.validate();
    try std.testing.expectEqual(digest, try owned.digest());
    try std.testing.expectEqual(@as(u64, 3), owned.windows[1].first_cycle);
}
test "CPU final job: copied original public windows outlive upstream buffers with OOM parity" {
    try copiedWindows(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, copiedWindows, .{});
    var upstream = originalWindows();
    upstream[1].first_cycle = 4;
    const bad = Windows.Plan{ .initial_registers = @splat(0), .final_registers = @splat(0), .windows = &upstream };
    try std.testing.expectError(error.InvalidV5RegisterWindowPlan, Job.cloneWindows(std.testing.failing_allocator, bad));
}
fn schedule() [2]PublicBus.Wire {
    return .{ .{ .circuit = 4_600_001, .wire = 0, .uses = 1, .source = .{ .original = .{ .child = 1, .kind = .frame_cell, .coordinate = 0 } } }, .{ .circuit = 4_600_001, .wire = 1, .uses = 2, .negative = true, .source = .{ .original = .{ .child = 1, .kind = .pairing_coordinate, .coordinate = 1, .part = 3 } } } };
}
fn copiedSchedule(a: std.mem.Allocator) !void {
    var upstream = schedule();
    const identity = try PublicBus.scheduleDigest(&upstream);
    const owned = try Job.cloneSchedule(a, &upstream, 2);
    defer a.free(owned);
    upstream = undefined;
    try std.testing.expectEqual(identity, try PublicBus.scheduleDigest(owned));
    try std.testing.expect(owned[1].negative);
    try std.testing.expectEqual(@as(u32, 2), owned[1].uses);
}
test "CPU final job: copied signed public descriptors remain exact after upstream rows release with OOM parity" {
    try copiedSchedule(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, copiedSchedule, .{});
    var upstream = schedule();
    try std.testing.expectError(error.FinalJobResourceLimit, Job.cloneSchedule(std.testing.failing_allocator, &upstream, 1));
    upstream[1].wire = 0;
    try std.testing.expectError(error.InvalidGlobalPublicSchedule, Job.cloneSchedule(std.testing.failing_allocator, &upstream, 2));
}
fn escapingCustody(a: std.mem.Allocator) !void {
    const aggregate = try Live.Budget.create(a, 128 << 10);
    var aggregate_owned = true;
    defer if (aggregate_owned) aggregate.destroy();
    const metadata = try Live.Budget.createRetainingParent(aggregate.allocator(), 8 << 10);
    defer metadata.destroy();
    const live = try Live.create(aggregate.allocator(), metadata, 64 << 10);
    var live_owned = true;
    defer if (live_owned) live.destroy();
    const retained = live.retain();
    defer retained.destroy();
    const scratch = live.allocator();
    const bytes = try scratch.alloc(u8, 32 << 10);
    defer scratch.free(bytes);
    @memset(bytes, 93);
    live.destroy();
    live_owned = false;
    aggregate.destroy();
    aggregate_owned = false;
    try std.testing.expectEqual(@as(usize, 0), metadata.snapshot().live_bytes);
    try std.testing.expect(live.snapshot().live_bytes > metadata.snapshot().limit);
    try std.testing.expectEqual(@as(u8, 93), bytes[bytes.len - 1]);
    try std.testing.expectError(error.OutOfMemory, scratch.alloc(u8, (32 << 10) + 1));
}
test "CPU final job: independent metadata live and aggregate lanes retain escaping control storage across OOM" {
    try escapingCustody(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, escapingCustody, .{});
}
