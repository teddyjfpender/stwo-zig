//! Genuine caller-containing fresh execution, including its native final halt.
//! This support module has no standalone tests or proof authority.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Full = @import("../block_v8_full_boundary_policy_v1.zig");
const Pipeline = @import("../block_v8_endpoint_mixed_pipeline_v1.zig");
const code = [_]u32{ 0x001000b7, 0x14008093, @import("../../isa/custom0.zig").encodeKeccakf(1), 0xfc008093, 0x02b00113, 0x0020a223, 0x00100113, 0x0220a423, 0x0020a023, 0x0000006f };
pub const elf = blk: {
    var bytes = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_ethereum_sha_v1);
    const data_offset = std.mem.readInt(u32, bytes[88..92], .little);
    @memset(bytes[data_offset..][0..512], 0);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([_]usize{ 2, 3, 7, 8, 9, 10, 11, 12 }, [_]u32{ 0x100100, 512, 0x100500, 0x100510, 0x100100, 0x100104, 0x100108, 0x100400 }) |index, value| std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};
pub fn expectedOutput() [43]u8 {
    var out: [43]u8 = @splat(0);
    out[32] = 1;
    return out;
}
pub fn qualifyWithObserver(comptime Observer: type) !void {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, if (@hasDecl(Observer, "budget_bytes")) Observer.budget_bytes else 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var full = try Full.Owned.derive(a, &elf, &.{}, .{ .elf_sha256 = Capture.sha(&elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 9, .expected_output = expectedOutput(), .config = config }, .{});
    defer full.deinit();
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, .{ .skip_cycles = 0, .cycles = 9 }, .{});
    defer captured.deinit();
    try full.requireInitial(captured.incoming, 1);
    try std.testing.expectEqual(@as(usize, 1), captured.segment.extension.keccakf_calls.records().len);
    try std.testing.expectEqual(.halt_flag, captured.segment.base.completion_reason.?);
    captured.releaseExecution();
    const trusted = @import("../block_v7_real_window_policy_v2.zig").Trusted{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = .{ .skip_cycles = 0, .cycles = 9 } };
    const ports = try full.windowOptions(0, 9);
    var files = std.testing.tmpDir(.{ .iterate = true });
    defer files.cleanup();
    const result = try Pipeline.produceDirectory(a, .{ .elf = &elf, .elf_sha256 = Capture.sha(&elf), .config = config, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted_window = trusted }, files.dir, .{ .source = .{ .boundary = ports, .native_wide_shards = true } });
    try std.testing.expectEqual(@as(u64, 9), result.verified.cycles);
    try std.testing.expectEqual(@as(u64, 1), result.verified.external_retirements);
    try std.testing.expectEqual(@as(u32, 1), result.verified.cohorts);
    const external = @import("../block_v8_endpoint_local_bundle_v1.zig").External{ .elf = &elf, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = trusted, .config = config, .boundary = ports };
    // Pipeline returned after original/endpoint/native/caller producers were
    // all destroyed and the durable bundle was freshly checked from files.
    if (@hasDecl(Observer, "observeFiles")) try Observer.observeFiles(a, files.dir, external, &full);
    std.debug.print("B8_TERMINAL_MIXED_FIXTURE queries=70 pow=26 first_cycle=1 cycles=9 keccak_calls=1 final_native_halt=1 caller_halt_zero=true output43_ram_authenticated=true\n", .{});
}
