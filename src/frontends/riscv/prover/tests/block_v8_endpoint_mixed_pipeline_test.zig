const std = @import("std");
const E = @import("stwo_prover_engine");
const Fixture = @import("block_v8_endpoint_mixed_fixture.zig");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Pipeline = @import("../block_v8_endpoint_mixed_pipeline_v1.zig");

fn run(kind: Fixture.Kind, wide: bool) !void {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 16 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const fixture = try Fixture.Owned.initForGlobal(a, kind, config);
    const elf = a.dupe(u8, fixture.elf) catch |err| {
        fixture.deinit();
        return err;
    };
    defer a.free(elf);
    // Preserve external input data only; no fixture witness enters production.
    const ib = try fixture.incoming.?.encode(a);
    defer a.free(ib);
    const ob = try fixture.outgoing.?.encode(a);
    defer a.free(ob);
    const in_pin = fixture.incoming.?.identity();
    const out_pin = fixture.outgoing.?.identity();
    const cycles = fixture.current.?.segment.base.cycle_count;
    fixture.deinit();
    var incoming = try Capture.Snapshot.decode(a, ib, in_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, ob, out_pin, .{});
    defer outgoing.deinit(a);
    var output = std.testing.tmpDir(.{ .iterate = true });
    defer output.cleanup();
    const result = try Pipeline.produceDirectory(a, .{
        .elf = elf,
        .elf_sha256 = Capture.sha(elf),
        .config = config,
        .incoming = incoming,
        .outgoing = outgoing,
        .trusted_window = .{ .elf_sha256 = Capture.sha(elf), .incoming_sha256 = in_pin, .outgoing_sha256 = out_pin, .window = .{ .skip_cycles = 0, .cycles = @intCast(cycles) } },
    }, output.dir, .{ .source = .{ .native_wide_shards = wide } });
    try std.testing.expectEqual(.declared_window_originals_closed, result.verified.scope);
    try std.testing.expectEqual(cycles, result.verified.cycles);
    try std.testing.expect(result.verified.external_retirements != 0);
    try std.testing.expect(result.stats.whole_ns >= result.stats.original_ns + result.stats.bridge_ns + result.stats.global_memory_ns);
    const metadata = try output.dir.readFileAlloc(a, "local-0.json", 16 << 20);
    defer a.free(metadata);
    const public = try @import("../block_v8_endpoint_mixed_statement_wire_v1.zig").decode(a, metadata, .{ .elf = elf, .elf_sha256 = Capture.sha(elf), .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 }, .{});
    defer public.deinit();
    try std.testing.expectEqual(@as(u32, @intFromBool(wide)), public.input.shape.native_shard_version);
}
test "real mixed pipeline reexecutes SHA Keccak input and freshly closes durable originals" {
    try run(.sha_keccak, true);
}
test "real mixed pipeline reexecutes recovery input and freshly closes durable originals" {
    try run(.recovery, false);
}
