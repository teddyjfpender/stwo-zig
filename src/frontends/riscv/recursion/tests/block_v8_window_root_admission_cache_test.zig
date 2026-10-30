//! Opt-in cache qualification. No production driver imports this module.
//! This gate is intentionally NOT run during the retained full-block campaign.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const CacheModule = @import("../block_v8_window_root_admission_cache_v1.zig");
const Upper = @import("../block_v8_window_root_receiver_v1.zig");
const Full = @import("../../prover/block_v8_full_boundary_policy_v1.zig");
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Fixture = @import("../../prover/tests/block_v8_full_boundary_test.zig");
const Wire = @import("../block_v8_window_root_wire_v1.zig");
const evidence = "campaign/qualification/new-full-block-depth2-driver-q70-v1/";
const SavedNative = struct {
    arena: std.heap.ArenaAllocator,
    context: CacheModule.InputContext,
    trees: [2]Upper.Tree,
    fn init(a: std.mem.Allocator) !@This() {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const t = arena.allocator();
        const config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
        var output: [43]u8 = @splat(0);
        output[32] = 1;
        const context = CacheModule.InputContext{ .elf = &Fixture.elf, .private_input = &.{}, .trusted = .{ .elf_sha256 = Capture.sha(&Fixture.elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 7, .expected_output = output, .config = config } };
        var boundary = try Full.Owned.derive(a, context.elf, context.private_input, context.trusted, .{});
        defer boundary.deinit();
        var snapshots: [3]Capture.Snapshot = undefined;
        for (&snapshots, [3][]const u8{ "state-0.b7win", "state-4.b7win", "state-6.b7win" }, [3][]const u8{ "9622bb5065631fa73247fd68c9d2e228f9f1b7705eda60b2c7a3db6e44b73769", "9c0f70ab01d38890cf69bd756b6098b921bba3b4bea9744404089e39eb10cc48", "97bcd2f45f4bf84350a0ea14df0e00f9b24796a8e8161d83721b2ca65590b100" }) |*snapshot, name, pin| {
            var path: [256]u8 = undefined;
            const bytes = try std.fs.cwd().readFileAlloc(t, try std.fmt.bufPrint(&path, "{s}{s}", .{ evidence, name }), 1 << 20);
            var id: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&id, pin);
            snapshot.* = try Capture.Snapshot.decode(t, bytes, id, .{});
        }
        var trees: [2]Upper.Tree = undefined;
        for (&trees, [2]u32{ 4, 2 }, [2]u64{ 0, 4 }, 0..) |*tree, cycles, skip, i| {
            var path: [256]u8 = undefined;
            const bytes = try std.fs.cwd().readFileAlloc(t, try std.fmt.bufPrint(&path, "{s}node-{d}.public", .{ evidence, i }), 1 << 20);
            tree.* = .{ .leaf = .{ .external = .{ .elf = context.elf, .incoming = snapshots[i], .outgoing = snapshots[i + 1], .trusted = .{ .elf_sha256 = context.trusted.elf_sha256, .incoming_sha256 = snapshots[i].identity(), .outgoing_sha256 = snapshots[i + 1].identity(), .window = .{ .skip_cycles = skip, .cycles = cycles } }, .config = config, .boundary = try boundary.windowOptions(skip, cycles) }, .input = try Wire.decodeNativeLeafLeaky(t, bytes, .{}) } };
        }
        return .{ .arena = arena, .context = context, .trees = trees };
    }
    fn deinit(self: *@This()) void {
        self.arena.deinit();
    }
};

fn expectRejected(cache: *const CacheModule.Cache, node: CacheModule.Node) !void {
    if (cache.profile(node)) |_| return error.AcceptedMutatedAdmissionCache else |_| {}
}

test "immutable admission cache derives each canonical node once and detects profile mutation" {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var saved = try SavedNative.init(a);
    defer saved.deinit();
    // Expected-admission parity only: no new source or recursive proof.
    const parent = Upper.Tree{ .branch = .{ .children = &saved.trees, .main_root = @splat(17) } };
    const forest = [_]Upper.Tree{ saved.trees[0], saved.trees[1], parent };
    const context = saved.context;
    const frozen = try CacheModule.Frozen.clone(a, context, &forest, .{ .max_nodes = 3 });
    var frozen_live = true;
    defer if (frozen_live) frozen.deinit();
    try std.testing.expectEqual(@as(usize, 3), frozen.nodeCount());
    // All borrowed input buffers may change after freezing. The cache must
    // derive the original statements from its own copies, not reread them.
    const borrowed = @constCast(saved.trees[0].leaf.external.incoming.words);
    try std.testing.expect(borrowed.len != 0);
    const saved_value = borrowed[0].value;
    borrowed[0].value ^= 1;
    defer borrowed[0].value = saved_value;
    const cache = try CacheModule.Cache.create(a, frozen);
    defer cache.deinit();
    frozen.deinit();
    frozen_live = false; // Cache retains the complete frozen context.
    const l = try cache.root(0);
    const r = try cache.root(1);
    const p = try cache.root(2);
    try std.testing.expectEqual(@as(usize, 3), cache.stats().independent_derivations);
    // Existing parent is a hit even at the exact unique-node resource cap.
    const hit = try cache.appendFold(&.{ l, r }, @splat(17));
    try std.testing.expectEqualDeep(p, hit);
    try std.testing.expectEqual(@as(usize, 3), cache.stats().independent_derivations);
    try std.testing.expectEqual(@as(usize, 1), cache.stats().hits);
    try std.testing.expectEqual(@as(usize, 3), cache.stats().frozen_snapshot_count);
    var forged = p;
    forged.context_id[0] ^= 1;
    try expectRejected(cache, forged);
    forged = p;
    forged.descriptor_id[0] ^= 1;
    try expectRejected(cache, forged);
    const profile = @constCast(try cache.profile(p));
    profile.fixed_root[0] ^= 1;
    try expectRejected(cache, p);
    // A cached-parent hit must also validate the parent, not just its children.
    if (cache.appendFold(&.{ l, r }, @splat(17))) |_| return error.AcceptedMutatedAdmissionCache else |_| {}
    profile.fixed_root[0] ^= 1;
    profile.span.cycles += 1;
    try expectRejected(cache, p);
    profile.span.cycles -= 1;
    @constCast(profile.shape.widths)[0] += 1;
    try expectRejected(cache, p);
    @constCast(profile.shape.widths)[0] -= 1;
    profile.admission.expected_id[0] ^= 1;
    try expectRejected(cache, p);
    profile.admission.expected_id[0] ^= 1;
    const ChildSpan = @import("../block_v5_pc_clock_span_v1.zig").Span;
    const spans = [_]ChildSpan{.{ .job_id = @splat(1), .source_image_digest = @splat(2), .sealed_digest = @splat(3), .job_segment_count = 1, .first_index = 0, .segment_count = 1, .first_cycle = 1, .last_cycle = 1, .initial_pc = 0x1000, .final_pc = 0x1004 }};
    const original_spans = profile.admission.pc_clock_children;
    profile.admission.pc_clock_children = &spans;
    // Existing profile identity omits this semantic field. Cache seals it too.
    try profile.validate();
    try expectRejected(cache, p);
    profile.admission.pc_clock_children = original_spans;
    try cache.validateAll();
    borrowed[0].value = saved_value;
    // Compare with the unchanged, independent recursive factory. This checks
    // every key/profile identity without accepting the cache as a VK authority.
    const fresh = try parent.derive(a);
    defer fresh.deinit();
    try std.testing.expectEqualDeep(fresh.admission.key, profile.admission.key);
    try std.testing.expectEqualDeep(fresh.span, profile.span);
    try std.testing.expectEqualDeep(fresh.fixed_root, profile.fixed_root);
    try std.testing.expectEqualDeep(fresh.seal, profile.seal);
    try std.testing.expect(cache.stats().retained_profile_peak_bytes >= cache.stats().profile_live_bytes);
    try std.testing.expect(cache.stats().key_derivation_peak_bytes >= cache.stats().retained_profile_peak_bytes);
    std.debug.print("B8_ADMISSION_CACHE unique=3 independently_derived=3 duplicate_fold_hits=1 retained_profile_bytes={d} retained_profile_peak_bytes={d} key_derivation_peak_bytes={d} frozen_snapshot_bytes={d} frozen_snapshots=3 final_receiver_unchanged=true\n", .{ cache.stats().profile_live_bytes, cache.stats().retained_profile_peak_bytes, cache.stats().key_derivation_peak_bytes, cache.stats().frozen_snapshot_bytes });
}

fn expectFrozenRejected(context: CacheModule.InputContext, forest: []const Upper.Tree, limits: CacheModule.Limits) !void {
    if (CacheModule.Frozen.clone(std.testing.allocator, context, forest, limits)) |frozen| {
        frozen.deinit();
        return error.AcceptedInvalidFrozenContext;
    } else |_| {}
}
test "immutable cache frozen context rejects scope and bounds mutations without any proving" {
    var saved = try SavedNative.init(std.testing.allocator);
    defer saved.deinit();
    var context = saved.context;
    context.trusted.elf_sha256[0] ^= 1;
    try expectFrozenRejected(context, &saved.trees, .{});
    var bad = saved.trees;
    bad[0].leaf.external.trusted.incoming_sha256[0] ^= 1;
    try expectFrozenRejected(saved.context, &bad, .{});
    bad = saved.trees;
    bad[0].leaf.external.boundary.initial = null;
    try expectFrozenRejected(saved.context, &bad, .{});
    bad = saved.trees;
    const copied_words = try std.testing.allocator.dupe(Capture.Word, bad[0].leaf.external.incoming.words);
    defer std.testing.allocator.free(copied_words);
    copied_words[0].value ^= 1;
    bad[0].leaf.external.incoming.words = copied_words;
    try expectFrozenRejected(saved.context, &bad, .{});
    const parent = Upper.Tree{ .branch = .{ .children = &saved.trees, .main_root = @splat(17) } };
    try expectFrozenRejected(saved.context, &.{parent}, .{ .max_nodes = 1 });
    try expectFrozenRejected(saved.context, &.{parent}, .{ .max_depth = 0 });
    try expectFrozenRejected(saved.context, &.{parent}, .{ .max_tree_visits = 1 });
    try expectFrozenRejected(saved.context, &saved.trees, .{ .max_snapshots = 1 });
    try expectFrozenRejected(saved.context, &saved.trees, .{ .max_snapshot_words = 0 });
    try expectFrozenRejected(saved.context, &saved.trees, .{ .max_frozen_snapshot_bytes = 1 });
    try expectFrozenRejected(saved.context, &saved.trees, .{ .max_metadata_bytes = 1 });
    try expectFrozenRejected(saved.context, &saved.trees, .{ .max_metadata_items = 1 });
}
fn frozenOnly(a: std.mem.Allocator, context: CacheModule.InputContext, forest: []const Upper.Tree) !void {
    const frozen = try CacheModule.Frozen.clone(a, context, forest, .{});
    frozen.deinit();
}
test "immutable cache targeted allocation failures release frozen ownership and early key construction" {
    var saved = try SavedNative.init(std.testing.allocator);
    defer saved.deinit();
    var baseline = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try frozenOnly(baseline.allocator(), saved.context, &saved.trees);
    try std.testing.expectEqual(baseline.allocated_bytes, baseline.freed_bytes);
    const count = baseline.alloc_index;
    // Exercise constructor start, quarter points and every final allocation,
    // including the transferred arena/metadata/descriptor ownership paths.
    var probes: usize = 0;
    for (0..count) |index| {
        if (index >= 4 and index + 12 < count and index != count / 4 and index != count / 2 and index != 3 * count / 4) continue;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        if (frozenOnly(failing.allocator(), saved.context, &saved.trees)) |_| {} else |err| try std.testing.expectEqual(error.OutOfMemory, err);
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        probes += 1;
    }
    const frozen = try CacheModule.Frozen.clone(std.testing.allocator, saved.context, &saved.trees, .{});
    defer frozen.deinit();
    for (0..8) |index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        if (CacheModule.Cache.create(failing.allocator(), frozen)) |cache| cache.deinit() else |err| try std.testing.expectEqual(error.OutOfMemory, err);
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        try std.testing.expectEqual(@as(usize, 2), frozen.nodeCount());
    }
    std.debug.print("B8_CACHE_OOM frozen_targeted_points={d} total_frozen_allocations={d} early_key_points=8 no_proving=true\n", .{ probes, count });
}
test "immutable cache key derivation and retained profile budgets reject without leaking owners" {
    var saved = try SavedNative.init(std.testing.allocator);
    defer saved.deinit();
    const tiny_key = try CacheModule.Frozen.clone(std.testing.allocator, saved.context, &saved.trees, .{ .max_key_derivation_live_bytes = 1 });
    defer tiny_key.deinit();
    try std.testing.expectError(error.OutOfMemory, CacheModule.Cache.create(std.testing.allocator, tiny_key));
    try std.testing.expectEqual(@as(usize, 2), tiny_key.nodeCount());
    const tiny_retained = try CacheModule.Frozen.clone(std.testing.allocator, saved.context, &saved.trees, .{ .max_retained_profile_bytes = 1 });
    defer tiny_retained.deinit();
    try std.testing.expectError(error.AdmissionCacheRetainedLimit, CacheModule.Cache.create(std.testing.allocator, tiny_retained));
    try std.testing.expectEqual(@as(usize, 2), tiny_retained.nodeCount());
}
