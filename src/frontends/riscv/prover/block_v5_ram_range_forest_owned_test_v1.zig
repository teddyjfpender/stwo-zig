//! Genuine independent original pin/admission ownership plus bounded proposal
//! transport. No successful capture/proof/recursive key is manufactured here.
const std = @import("std");
const Catalogue = @import("block_v5_ram_range_forest_catalogue_v1.zig");
const Manifest = @import("block_v5_ram_range_forest_manifest_v1.zig");
const Owned = @import("block_v5_ram_range_forest_policy_owner_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
fn header() Manifest.Header {
    return .{ .ram = 1, .range = 1, .nodes = 1, .seal = @splat(1), .memory_plan = @splat(2), .page_owner = @splat(3) };
}
fn records() [4]Manifest.Record {
    var out: [4]Manifest.Record = undefined;
    for (&out, 0..) |*record, i| record.* = .{ .file = .{ .byte_len = i + 1, .sha256 = @splat(@intCast(i + 4)) }, .expected_id = @splat(@intCast(i + 8)) };
    return out;
}
test "RAM durable catalogue: exact typed manifest order and final join record round trip" {
    const original = records();
    const bytes = try Manifest.encode(std.testing.allocator, header(), &original, .{});
    defer std.testing.allocator.free(bytes);
    var proposal = try Manifest.decode(std.testing.allocator, bytes, .{});
    defer proposal.deinit();
    try std.testing.expectEqualDeep(header(), proposal.header);
    const expected: []const Manifest.Record = &original;
    try std.testing.expectEqualDeep(expected, proposal.records);
    try std.testing.expectEqual(@as(usize, 408), bytes.len);
    try std.testing.expectError(error.RamForestManifestLimit, Manifest.require(header(), original[0..3], .{}));
    var empty = header();
    empty.ram = 0;
    empty.range = 0;
    empty.nodes = 0;
    try Manifest.require(empty, original[0..1], .{});
    try std.testing.expectError(error.RamForestManifestLimit, Manifest.require(empty, &.{}, .{}));
}
test "RAM durable catalogue: resealed received key proposal rejects original derived identity" {
    const original = records();
    var changed = original;
    changed[2].expected_id[7] ^= 1;
    const bytes = try Manifest.encode(std.testing.allocator, header(), &changed, .{});
    defer std.testing.allocator.free(bytes);
    var parsed = try Manifest.decode(std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    try std.testing.expectError(error.UntrustedRamForestExpectedKey, Manifest.requireDerived(parsed.records[2], original[2].expected_id));
    try Manifest.requireDerived(parsed.records[0], original[0].expected_id);
}
test "RAM durable catalogue: framing truncation excess version and zero identities reject" {
    const original = records();
    const bytes = try Manifest.encode(std.testing.allocator, header(), &original, .{});
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(error.UntrustedRamForestManifest, Manifest.decode(std.testing.failing_allocator, bytes[0..8], .{}));
    try std.testing.expectError(error.RamForestManifestLimit, Manifest.decode(std.testing.failing_allocator, bytes[0 .. bytes.len - 1], .{}));
    const copy = try std.testing.allocator.dupe(u8, bytes);
    defer std.testing.allocator.free(copy);
    copy[8] = 2;
    try std.testing.expectError(error.UntrustedRamForestManifest, Manifest.decode(std.testing.failing_allocator, copy, .{}));
    var changed = original;
    changed[0].file.byte_len = 0;
    try std.testing.expectError(error.UntrustedRamForestManifest, Manifest.require(header(), &changed, .{}));
    changed = original;
    changed[3].expected_id = @splat(0);
    try std.testing.expectError(error.UntrustedRamForestManifest, Manifest.require(header(), &changed, .{}));
}
test "RAM durable catalogue: independent metadata proof and aggregate resource caps" {
    const original = records();
    try std.testing.expectError(error.RamForestManifestLimit, Manifest.require(header(), &original, .{ .max_records = 3 }));
    try std.testing.expectError(error.RamForestManifestLimit, Manifest.require(header(), &original, .{ .max_bytes = 407 }));
    try std.testing.expectError(error.UntrustedRamForestManifest, Manifest.require(header(), &original, .{ .max_proof_bytes = 3 }));
    try std.testing.expectError(error.RamForestManifestLimit, Manifest.require(header(), &original, .{ .max_total_proof_bytes = 9 }));
}
fn manifestAllocations(a: std.mem.Allocator) !void {
    const original = records();
    const bytes = try Manifest.encode(a, header(), &original, .{});
    defer a.free(bytes);
    var parsed = try Manifest.decode(a, bytes, .{});
    defer parsed.deinit();
    const expected: []const Manifest.Record = &original;
    try std.testing.expectEqualDeep(expected, parsed.records);
}
test "RAM durable catalogue: every manifest encode decode allocation releases" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, manifestAllocations, .{});
}
const Seal = @import("block_v5_source_seal_v1.zig");
const Lane = @import("block_v5_ram_lanes_receiver_v1.zig");
const LaneProof = @import("block_v5_ram_lanes_proof_v1.zig");
const Plans = @import("block_v5_ram_lanes_plan_v1.zig");
const RangeProof = @import("block_v5_range16_proof_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    memory: Lane.Pins,
    sealed: Seal.Sealed,
    fn init(a: std.mem.Allocator) !Fixture {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const scratch = arena.allocator();
        const pins = try scratch.alloc(LaneProof.Pin, 1);
        const first = Event{ .space = 1, .address = 0x8000_0000, .clock = (@as(u64, 1) << 40) + 1, .before = 7, .after = 7 };
        var last = first;
        last.clock += 3;
        pins[0] = .{ .claim = .{ .first_event = 0, .total_events = 4, .events = 4, .row_log = 2, .first = first, .last = last, .preceding = null }, .index = 0, .roots = .{ @splat(8), @splat(9) }, .request_count = 52, .counter_digest = @splat(10), .config = Base.PCS_CONFIG };
        const roots = try scratch.alloc([2][32]u8, 1);
        roots[0] = .{ @splat(51), @splat(52) };
        const digest = try Plans.digest(scratch, pins, 4, roots, .{});
        var plan = try Plans.rangePlan(scratch, pins, 4, .{});
        defer plan.deinit(scratch);
        const entries = try scratch.alloc(Seal.Entry, 6);
        entries[0] = .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } };
        entries[1] = .{ .family = .execution, .index = 0, .instance_id = @splat(20), .roots = .{ @splat(21), @splat(22) } };
        entries[2] = .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } };
        entries[3] = .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } };
        entries[4] = try pins[0].entry();
        entries[5] = .{ .family = .memory_range, .index = 0, .instance_id = RangeProof.instanceId(plan.digest, 0), .roots = roots[0] };
        const sha = Initial.sha256("");
        const empty = @import("block_v5_memory_source_batch_defaults_v1.zig").get().defaults[0].bytes;
        const source = Endpoint.Pins{ .initial = .{ .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 }, .initial_rw_root = empty, .initial_registers = @splat(0), .public_input_sha256 = sha, .public_input_len = 0, .input_words = .{ .sha256 = sha, .records = 0 }, .rw_words = .{ .sha256 = sha, .records = 0 }, .first_touches = .{ .sha256 = sha, .records = 0 } }, .memory_plan_digest = digest, .expected_final_rw_root = empty, .endpoints = .{ .sha256 = sha, .records = 0 } };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        const seal_pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = digest, .initial_source_plan_digest = try source.initial.digest(), .register_endpoint_plan_digest = @splat(8), .register_custody_mode = 1, .expected_final_rw_root = empty, .rw_endpoint_plan_digest = try source.digest(), .config = Base.PCS_CONFIG, .counts = counts };
        const sealed = try Seal.seal(seal_pins, entries);
        const memory = Lane.Pins{ .seal = seal_pins, .expected_seal_digest = sealed.digest, .first_round = entries, .pins = pins, .range_roots = roots, .expected_total_events = 4, .source = source };
        try Lane.admit(scratch, memory, sealed, memory.limits);
        return .{ .arena = arena, .memory = memory, .sealed = sealed };
    }
};
fn cloneAdmissions(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var owned = try Catalogue.Owned.init(a, fixture.memory, fixture.sealed, .{});
    defer owned.deinit();
    try owned.ram[0].validate(owned.ram[0].template_id);
    try owned.range[0].validate(owned.range[0].template_id);
    try std.testing.expectEqualDeep(fixture.memory.first_round, owned.memory.first_round);
    try std.testing.expect(@intFromPtr(fixture.memory.first_round.ptr) != @intFromPtr(owned.memory.first_round.ptr));
}
test "RAM durable catalogue: original independent admission remains usable after upstream buffers release" {
    var fixture = try Fixture.init(std.testing.allocator);
    var held = true;
    defer if (held) fixture.arena.deinit();
    var owned = try Catalogue.Owned.init(std.testing.allocator, fixture.memory, fixture.sealed, .{});
    defer owned.deinit();
    const digest = owned.memory.seal.memory_plan_digest;
    fixture.arena.deinit();
    held = false;
    try owned.ram[0].validate(owned.ram[0].template_id);
    try owned.range[0].validate(owned.range[0].template_id);
    try Lane.admit(std.testing.allocator, owned.memory, owned.sealed, owned.memory.limits);
    try std.testing.expectEqualDeep(digest, owned.memory.seal.memory_plan_digest);
    try std.testing.expect(owned.ram[0].pin.claim.first.clock > (@as(u64, 1) << 30));
}
test "RAM durable catalogue: transfer allocations fail atomically with upstream admitted once" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.arena.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cloneAdmissions, .{&fixture});
}
test "RAM durable catalogue: exact independent source roster mutations reject before recursive proof" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.arena.deinit();
    var changed = fixture.memory;
    changed.expected_total_events = 5;
    if (Catalogue.Owned.init(std.testing.allocator, changed, fixture.sealed, .{})) |value| {
        var copy = value;
        copy.deinit();
        return error.MutatedOriginalRosterAdmitted;
    } else |_| {}
    changed = fixture.memory;
    changed.expected_seal_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5RamLanesReceiver, Catalogue.Owned.init(std.testing.allocator, changed, fixture.sealed, .{}));
    try std.testing.expectError(error.RamForestCatalogueLimit, Catalogue.Owned.init(std.testing.failing_allocator, undefined, undefined, .{ .max_leaves = 0 }));
}
test "RAM durable catalogue: canonical minimum forest uses exact original counts and bounded children" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.arena.deinit();
    var plan = try Plans.rangePlan(std.testing.allocator, fixture.memory.pins, fixture.memory.expected_total_events, .{});
    defer plan.deinit(std.testing.allocator);
    const Geometry = @import("../recursion/block_v5_ram_range_forest_plan_v1.zig");
    var geometry = try Geometry.derive(std.testing.allocator, fixture.memory.pins, &plan, .{});
    defer geometry.deinit();
    try std.testing.expectEqual(try Geometry.requiredNodes(plan.shards), geometry.nodes.len);
    try std.testing.expectEqual(@as(usize, 1), geometry.nodes.len);
    try std.testing.expectEqual(@as(u32, 2), geometry.nodes[0].child_count);
    try std.testing.expectEqual(@as(u64, 4), geometry.nodes[0].events);
}
test "RAM durable catalogue: rollback removes only successfully new recursive outputs" {
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var ram: [96]u8 = undefined;
    var range: [96]u8 = undefined;
    const ram_name = try Owned.filename(&ram, .ram, 0);
    const range_name = try Owned.filename(&range, .range, 0);
    try Files.publish(temp.dir, range_name, "old");
    try Files.publish(temp.dir, ram_name, "new");
    try std.testing.expectError(error.ExistingV5BundleArtifact, Files.publish(temp.dir, range_name, "replacement"));
    Owned.removePublished(temp.dir, 1, 0, 0, false);
    try std.testing.expectError(error.FileNotFound, temp.dir.openFile(ram_name, .{}));
    const bytes = try Files.readPinned(std.testing.allocator, temp.dir, range_name, 3, Files.hash("old"), 3);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("old", bytes);
}
test "RAM durable catalogue: independent cap admission precedes undefined source capabilities" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    var limits = Owned.Limits{};
    limits.max_live_bytes = 0;
    try std.testing.expectError(error.InvalidRamForestOwnerLimits, Owned.ForBackend(Cpu).build(std.testing.failing_allocator, undefined, undefined, undefined, undefined, undefined, undefined, limits, .publish));
    limits = .{};
    limits.provider.max_proof_bytes -= 1;
    try std.testing.expectError(error.InvalidRamForestOwnerLimits, limits.validate());
}
test "RAM durable catalogue: memory scratch cap is independent and retains aggregate backing" {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const live_lane = @import("block_v5_memory_source_page_forest_live_budget_v1.zig");
    const aggregate = try Budget.create(std.testing.allocator, 1 << 20);
    var held = true;
    defer if (held) aggregate.destroy();
    const metadata = try Budget.createRetainingParent(aggregate.allocator(), 32 << 10);
    defer metadata.destroy();
    const live = try live_lane.create(aggregate.allocator(), metadata, 128 << 10);
    defer live.destroy();
    const bytes = try live.allocator().alloc(u8, 64 << 10);
    defer live.allocator().free(bytes);
    @memset(bytes, 19);
    aggregate.destroy();
    held = false;
    try std.testing.expectEqual(@as(u8, 19), bytes[bytes.len - 1]);
    try std.testing.expect(live.snapshot().live_bytes > metadata.snapshot().limit);
    try std.testing.expectError(error.OutOfMemory, live.allocator().alloc(u8, (64 << 10) + 1));
}
