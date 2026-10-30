//! Exercise the actual full driver mixed branch, not just its source helpers.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Pipeline = @import("../block_v8_full_block_pipeline_v1.zig");
const Fixture = @import("block_v8_terminal_mixed_fixture.zig");

test "full driver mixed Keccak FIRST terminal output fresh serialized complete root q70" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const pins = Capture.Pins{ .elf = Capture.sha(&Fixture.elf), .input = Capture.sha(&.{}) };
    var captured = try Capture.capture(a, &Fixture.elf, &.{}, pins, .{ .skip_cycles = 0, .cycles = 9 }, .{});
    defer captured.deinit();
    try std.testing.expectEqual(@as(usize, 1), captured.segment.extension.keccakf_calls.records().len);
    captured.releaseExecution();
    const trusted = @import("../block_v8_full_boundary_policy_v1.zig").Trusted{ .elf_sha256 = pins.elf, .input_sha256 = pins.input, .total_cycles = 9, .expected_output = Fixture.expectedOutput(), .config = config };
    const jobs = [_]Pipeline.Job{.{ .kind = .mixed, .request = .{ .elf = &Fixture.elf, .elf_sha256 = pins.elf, .config = config, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted_window = .{ .elf_sha256 = pins.elf, .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = .{ .skip_cycles = 0, .cycles = 9 } } } }};
    var output = std.testing.tmpDir(.{ .iterate = true });
    defer output.cleanup();
    const summary = try Pipeline.run(budget, &pool, output.dir, .{ .elf = &Fixture.elf, .private_input = &.{}, .trusted = trusted, .jobs = &jobs }, .{});
    try std.testing.expect(summary.proof_verified);
    try std.testing.expectEqual(@as(u64, 9), summary.cycles);
    try std.testing.expectEqual(@as(u32, 1), summary.windows);
    try std.testing.expectEqual(@as(u32, 0), summary.folds);
    const proof = try output.dir.readFileAlloc(a, "root.proof", 64 << 20);
    defer a.free(proof);
    try std.testing.expectEqual(summary.root_bytes, proof.len);
    try std.testing.expectEqualDeep(summary.root_sha256, std.fmt.bytesToHex(Capture.sha(proof), .lower));
    const catalog_bytes = try output.dir.readFileAlloc(a, "catalog.json", 16 << 20);
    defer a.free(catalog_bytes);
    const catalog = try std.json.parseFromSlice(Pipeline.Catalog, a, catalog_bytes, .{});
    defer catalog.deinit();
    try catalog.value.validate(a, &jobs);
    try std.testing.expectEqual(@as(usize, 1), catalog.value.nodes.len);
    try std.testing.expectEqual(@as(u8, 1), catalog.value.nodes[0].kind);
    std.debug.print("B8_COMPLETE_MIXED_DRIVER q=70 pow=26 cycles=9 windows=1 keccak=1 folds=0 initial=true terminal_output=true fresh_serialized_root=true bytes={d} sha256={s}\n", .{ proof.len, summary.root_sha256 });
    if (std.posix.getenv("STWO_B8_MIXED_DRIVER_ARTIFACT_DIR")) |path| {
        try std.fs.cwd().makePath(path);
        var archive = try std.fs.cwd().openDir(path, .{});
        defer archive.close();
        if (archive.access("root.proof", .{})) |_| return error.RefuseOverwriteMixedDriverRoot else |err| if (err != error.FileNotFound) return err;
        try archive.writeFile(.{ .sub_path = "root.proof", .data = proof });
        try archive.writeFile(.{ .sub_path = "catalog.json", .data = catalog_bytes });
        for ([_][]const u8{ "node-0.public", "node-0.recursion.json", "window-0-original.json", "report.json" }) |name| {
            const bytes = try output.dir.readFileAlloc(a, name, 16 << 20);
            defer a.free(bytes);
            try archive.writeFile(.{ .sub_path = name, .data = bytes });
        }
    }
}
