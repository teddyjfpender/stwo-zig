const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Full = @import("../block_v8_full_boundary_policy_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const code = [_]u32{ 0x001000b7, 0x10008093, 0x02b00113, 0x0020a223, 0x00100113, 0x0220a423, 0x0020a023, 0x0000006f };
pub const elf = blk: {
    var bytes = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1);
    const data_offset = std.mem.readInt(u32, bytes[88..92], .little);
    @memset(bytes[data_offset..][0..256], 0);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([_]usize{ 2, 3, 7, 8, 9, 10, 11, 12 }, [_]u32{ 0x100100, 256, 0x100300, 0x100310, 0x100100, 0x100104, 0x100108, 0x100200 }) |index, value| std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};
fn expectedOutput() [43]u8 {
    var out: [43]u8 = @splat(0);
    out[32] = 1;
    return out;
}
test "full initial through terminal genuine q70 originals bind FIRST instruction halt and output" {
    try qualifyWithObserver(struct {});
}
pub fn qualifyWithObserver(comptime Observer: type) !void {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, if (@hasDecl(Observer, "budget_bytes")) Observer.budget_bytes else 16 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var full = try Full.Owned.derive(a, &elf, &.{}, .{ .elf_sha256 = Capture.sha(&elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 7, .expected_output = expectedOutput(), .config = config }, .{});
    defer full.deinit();
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, .{ .skip_cycles = 0, .cycles = 7 }, .{});
    defer captured.deinit();
    try full.requireInitial(captured.incoming, 1);
    try std.testing.expectError(error.UntrustedFullInitialBoundary, full.requireInitial(captured.incoming, 2));
    try std.testing.expectEqual(.halt_flag, captured.segment.base.completion_reason.?);
    captured.releaseExecution();
    const trusted = Window.Trusted{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = .{ .skip_cycles = 0, .cycles = 7 } };
    const ports = try full.windowOptions(0, 7);
    var policy = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, &elf, captured.incoming, captured.outgoing, trusted, .{ .cohort_count = 2, .max_cohort_cycles = 4 }, &.{}, ports, .{});
    defer policy.deinit();
    try std.testing.expect(policy.selection.?.addresses.len >= 13);
    try std.testing.expectError(error.NonterminalWindowHalted, Window.Owned.deriveCohorts(a, &elf, captured.incoming, captured.outgoing, trusted, .{ .cohort_count = 2, .max_cohort_cycles = 4 }, .{}));
    // Expected output is an independent public requirement: changing it cannot
    // be authorized by the captured host result or its snapshot digest.
    var wrong = ports;
    wrong.terminal.?.policy.output[0] = 9;
    try std.testing.expectError(error.UntrustedFullTerminalOutput, Window.Owned.deriveCohortsForAddressesWithBoundary(a, &elf, captured.incoming, captured.outgoing, trusted, .{ .cohort_count = 2, .max_cohort_cycles = 4 }, &.{}, wrong, .{}));
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var files = std.testing.tmpDir(.{ .iterate = true });
    defer files.cleanup();
    const Run = @import("../block_v8_endpoint_local_compact_execution_v1.zig");
    const result = try Run.run(budget, &pool, files.dir, .{ .elf = &elf, .elf_sha256 = Capture.sha(&elf), .config = config, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted_window = trusted }, .{ .boundary = ports, .program_flavor = .sparse_elf, .cohort_cycles = 4, .memory_rows_per_shard = 4, .proof_workers = 4 });
    const events: u32 = @intCast(result.verified.endpoint_events);
    try std.testing.expectEqual(@as(u64, 7), result.verified.cycles);
    try std.testing.expectEqual(@as(u64, 8), result.verified.program_fetches); // 4+one unretired +3 terminal (no terminal ROM fetch).
    try std.testing.expect(result.selected_initial_addresses.len >= 13);
    result.deinit();
    // Every source/native/endpoint/bridge/global producer is now gone.
    const External = @import("../block_v8_endpoint_local_bundle_v1.zig").External;
    const external = External{ .elf = &elf, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = trusted, .config = config, .boundary = ports };
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    if (@hasDecl(Observer, "observeFiles")) try Observer.observeFiles(a, files.dir, external, &full);
    const Directory = @import("../block_v8_endpoint_local_directory_v1.zig");
    const verified = try Directory.verifyDirectoryCompact(a, files.dir, external, .{ .endpoint_events_nomination = events }, .{});
    try std.testing.expectEqual(@as(u64, 7), verified.cycles);
    var denied = external;
    denied.boundary = .{};
    try std.testing.expectError(error.NonterminalWindowHalted, Directory.verifyDirectoryCompact(a, files.dir, denied, .{ .endpoint_events_nomination = events }, .{}));
    std.debug.print("B8_FULL_BOUNDARY q70=70 pow=26 skip=0 cycles=7 source_originals=2 terminal_halt=1 output_bytes=43 compact_ram_authenticated=true freshly_file_verified=true\n", .{});
}
