const std = @import("std");
const E = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const code = [_]u32{ 0x001000b7, 0x20008093, 0x0000a103, 0x00110113, 0x0020a023, 0xff5ff06f };
const elf = blk: {
    var bytes = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 256, .rv32im_zkvm_ethereum_sha_v1);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 256, 0x100300, 0x100310 }) |index, value| std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};
const Run = @import("../block_v8_endpoint_group_execution_v1.zig");
test "group execution prepares actual continuous cohorts once and receives shared original" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 16 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const pin = Capture.sha(&elf);
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = pin, .input = Capture.sha(&.{}) }, .{ .skip_cycles = 2, .cycles = 8 }, .{});
    defer captured.deinit();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    const result = try Run.run(budget, &pool, .{ .elf = &elf, .elf_sha256 = pin, .config = config, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted_window = .{ .elf_sha256 = pin, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = .{ .skip_cycles = 2, .cycles = 8 } } }, .{ .cohort_cycles = 4 });
    defer result.deinit();
    try std.testing.expectEqual(@as(u32, 2), result.stats.cohorts);
    try std.testing.expectEqual(@as(usize, 15), result.stats.trace_trees);
    try std.testing.expectEqual(@as(u32, 2), result.verified.summary.cohorts);
    try std.testing.expectEqual(@as(u64, 8), result.verified.summary.cycles);
    try std.testing.expectEqual(.group_execution_global_ram_open, result.verified.summary.scope);
    try std.testing.expectEqual(@as(usize, 2), result.endpoints.len);
    for (result.leases, result.verified.summary.sources) |lease, source| {
        try std.testing.expect(lease != null);
        try std.testing.expectEqual(source.endpoint_root, lease.?.tree.root());
    }
    try std.testing.expect(result.stats.fresh_verification_ns > 0);
    try std.testing.expect(result.stats.original.core_ns > 0);
    try std.testing.expect(result.stats.program_selected_pcs <= 6);
}

test "group late RAM pipeline closes three originals with one group verification and no producers" {
    try qualifyPipelineWithObserver(.compact_v1, struct {});
}
test "explicit native wide group profile closes genuine originals and rejects compact relabeling" {
    try qualifyPipelineWithObserver(.native_wide_v2, struct {});
}
pub fn qualifyPipelineWithObserver(profile: @import("../block_v8_endpoint_group_layout_v1.zig").Profile, comptime Observer: type) !void {
    const Pipeline = @import("../block_v8_endpoint_group_pipeline_v1.zig");
    const Directory = @import("../block_v8_endpoint_group_directory_v1.zig");
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, if (@hasDecl(Observer, "budget_bytes")) Observer.budget_bytes else 16 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const pin = Capture.sha(&elf);
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = pin, .input = Capture.sha(&.{}) }, .{ .skip_cycles = 2, .cycles = 8 }, .{});
    defer captured.deinit();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var files = std.testing.tmpDir(.{ .iterate = true });
    defer files.cleanup();
    const request = Run.Request{ .elf = &elf, .elf_sha256 = pin, .config = config, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted_window = .{ .elf_sha256 = pin, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = .{ .skip_cycles = 2, .cycles = 8 } } };
    const result = try Pipeline.run(budget, &pool, files.dir, request, .{ .source = .{ .profile = profile, .cohort_cycles = 4 } });
    try std.testing.expectEqual(.declared_window_originals_closed, result.verified.scope);
    try std.testing.expectEqual(@as(u32, 2), result.verified.cohorts);
    try std.testing.expectEqual(@as(u32, 1), result.verified.groups);
    try std.testing.expectEqual(@as(u32, 1), result.verified.group_original_verifications);
    try std.testing.expectEqual(@as(u64, 8), result.verified.cycles);
    try std.testing.expectEqual(@as(u64, 0), result.stats.source.fresh_verification_ns);
    for ([_][]const u8{ "group-0.proof", "group-0.json", "bridge-0.proof", "global-memory.proof", "global-public.json" }) |name| try std.testing.expect((try files.dir.statFile(name)).size > 0);
    // Invalid Group coverage is rejected by file admission before re-running
    // any STARK. The positive pipeline verified exactly one Group original.
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    if (@hasDecl(Observer, "observeFiles")) try Observer.observeFiles(a, files.dir, @import("../block_v8_endpoint_group_bundle_v1.zig").External{ .elf = &elf, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = request.trusted_window, .config = config });
    const group_metadata = try files.dir.readFileAlloc(a, "group-0.json", 1 << 20);
    defer a.free(group_metadata);
    const public = try @import("../block_v8_endpoint_group_statement_wire_v1.zig").decode(a, group_metadata, .{ .elf = &elf, .elf_sha256 = pin, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 2 }, .{});
    defer public.deinit();
    try std.testing.expectEqual(profile, public.input.profile);
    const group_bytes = try files.dir.readFileAlloc(a, "group-0.proof", 128 << 20);
    defer a.free(group_bytes);
    var relabeled = public.input;
    relabeled.profile = if (profile == .compact_v1) .native_wide_v2 else .compact_v1;
    try std.testing.expectError(error.UntrustedEndpointEnvelope, @import("../block_v8_endpoint_group_codec_v1.zig").decode(a, group_bytes, public.trusted, relabeled, .{}));
    const metadata = try files.dir.readFileAlloc(a, "global-public.json", 1 << 20);
    defer a.free(metadata);
    const bad = try a.dupe(u8, metadata);
    defer a.free(bad);
    const marker = std.mem.indexOf(u8, bad, "\"group_count\":1") orelse return error.MissingGroupCountFixture;
    bad[marker + "\"group_count\":".len] = '0';
    try files.dir.writeFile(.{ .sub_path = "global-public.json", .data = bad });
    try std.testing.expectError(error.UntrustedGroupDirectoryMetadata, Directory.verify(a, files.dir, .{ .elf = &elf, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = request.trusted_window, .config = config }, .{}));
}
