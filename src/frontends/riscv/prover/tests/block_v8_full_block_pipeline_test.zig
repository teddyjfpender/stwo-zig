//! Complete production driver exercised with two real windows and a bounded
//! fold, including independently selected initialization and terminal output.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Pipeline = @import("../block_v8_full_block_pipeline_v1.zig");
const elf = @import("block_v8_full_boundary_test.zig").elf;
test "full block driver proves FIRST through terminal three-window depth-two chain and serialized upper root q70" {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const pins = Capture.Pins{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) };
    var left = try Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 0, .cycles = 4 }, .{});
    defer left.deinit();
    left.releaseExecution();
    var middle = try Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 4, .cycles = 2 }, .{});
    defer middle.deinit();
    middle.releaseExecution();
    var right = try Capture.capture(a, &elf, &.{}, pins, .{ .skip_cycles = 6, .cycles = 1 }, .{});
    defer right.deinit();
    right.releaseExecution();
    try std.testing.expectEqualDeep(left.outgoing.identity(), middle.incoming.identity());
    try std.testing.expectEqualDeep(middle.outgoing.identity(), right.incoming.identity());
    var expected: [43]u8 = @splat(0);
    expected[32] = 1;
    const trusted = @import("../block_v8_full_boundary_policy_v1.zig").Trusted{ .elf_sha256 = pins.elf, .input_sha256 = pins.input, .total_cycles = 7, .expected_output = expected, .config = config };
    const snapshots = [_]struct { incoming: Capture.Snapshot, outgoing: Capture.Snapshot, skip: u64, cycles: u32 }{ .{ .incoming = left.incoming, .outgoing = left.outgoing, .skip = 0, .cycles = 4 }, .{ .incoming = middle.incoming, .outgoing = middle.outgoing, .skip = 4, .cycles = 2 }, .{ .incoming = right.incoming, .outgoing = right.outgoing, .skip = 6, .cycles = 1 } };
    var jobs: [3]Pipeline.Job = undefined;
    for (&jobs, snapshots) |*job, snapshot| job.* = .{ .kind = .native, .request = .{ .elf = &elf, .elf_sha256 = pins.elf, .config = config, .incoming = snapshot.incoming, .outgoing = snapshot.outgoing, .trusted_window = .{ .elf_sha256 = pins.elf, .incoming_sha256 = snapshot.incoming.identity(), .outgoing_sha256 = snapshot.outgoing.identity(), .window = .{ .skip_cycles = snapshot.skip, .cycles = snapshot.cycles } } } };
    var output = std.testing.tmpDir(.{ .iterate = true });
    defer output.cleanup();
    var durable: ?std.fs.Dir = if (std.posix.getenv("STWO_B8_FULL_DRIVER_QUALIFICATION_DIR")) |path| try std.fs.cwd().makeOpenPath(path, .{ .iterate = true }) else null;
    defer if (durable) |*directory| directory.close();
    const target = durable orelse output.dir;
    try std.testing.expectError(error.IncompleteFullBlockCoverage, Pipeline.run(budget, &pool, target, .{ .elf = &elf, .private_input = &.{}, .trusted = trusted, .jobs = jobs[0..1] }, .{}));
    var wrong = jobs;
    wrong[1].request.trusted_window.window.skip_cycles = 3;
    try std.testing.expectError(error.InvalidFullBlockCoverage, Pipeline.run(budget, &pool, target, .{ .elf = &elf, .private_input = &.{}, .trusted = trusted, .jobs = &wrong }, .{}));
    const summary = try Pipeline.run(budget, &pool, target, .{ .elf = &elf, .private_input = &.{}, .trusted = trusted, .jobs = &jobs }, .{});
    try std.testing.expect(summary.proof_verified);
    try std.testing.expectEqual(@as(u64, 7), summary.cycles);
    try std.testing.expectEqual(@as(u32, 3), summary.windows);
    try std.testing.expectEqual(@as(u32, 2), summary.folds);
    const root = try target.readFileAlloc(a, "root.proof", 64 << 20);
    defer a.free(root);
    try std.testing.expectEqual(summary.root_bytes, root.len);
    try std.testing.expectEqualDeep(summary.root_sha256, std.fmt.bytesToHex(Capture.sha(root), .lower));
    if (durable != null) {
        try target.writeFile(.{ .sub_path = "guest.elf", .data = &elf });
        try target.writeFile(.{ .sub_path = "input.bin", .data = &.{} });
        try target.writeFile(.{ .sub_path = "expected-output.bin", .data = &expected });
        for ([4]Capture.Snapshot{ left.incoming, left.outgoing, middle.outgoing, right.outgoing }, [4]u64{ 0, 4, 6, 7 }) |snapshot, cycle| {
            const bytes = try snapshot.encode(a);
            defer a.free(bytes);
            var name: [64]u8 = undefined;
            try target.writeFile(.{ .sub_path = try std.fmt.bufPrint(&name, "state-{d}.b7win", .{cycle}), .data = bytes });
        }
        const info = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-three-window-depth2-full-driver-qualification-v1", .scope = "tiny genuine RV32 test ELF, initial/middle/terminal and oddcarry; not retained Ethereum block", .queries = @as(u32, 70), .pow_bits = @as(u32, 26), .windows = [_]u32{ 4, 2, 1 }, .folds = @as(u32, 2), .depth = @as(u32, 2), .root_sha256 = summary.root_sha256, .fresh_serialized_full_receiver = true }, .{ .whitespace = .indent_2 });
        defer a.free(info);
        try target.writeFile(.{ .sub_path = "qualification.json", .data = info });
    }
    std.debug.print("B8_COMPLETE_DRIVER q70=70 pow=26 cycles=7 windows=3 folds=2 depth=2 initial_authenticated=true terminal_output_authenticated=true fresh_serialized_root=true bytes={d}\n", .{root.len});
}
