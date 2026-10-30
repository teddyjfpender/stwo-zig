//! Genuine nonterminal captured machine transition for original/recursive consumers.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const Run = @import("block_v7_real_window_execution_v2.zig");
const Guest = @import("tests/block_v7_keccak_execution_test_support.zig");
pub fn runTiny(comptime Selected: type) !void {
    return runTinyWithSparse(Selected, false);
}
pub fn runTinyWithSparse(comptime Selected: type, sparse: bool) !void {
    return runTinySpan(Selected, sparse, .{ .skip_cycles = 6, .cycles = 3 });
}
pub fn runNativeTail(comptime Selected: type) !void {
    return runTinySpan(Selected, true, .{ .skip_cycles = 9, .cycles = 4 });
}
fn runTinySpan(comptime Selected: type, sparse: bool, span: Capture.Window) !void {
    const config = if (comptime @hasDecl(Selected, "config")) Selected.config else @import("../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    const backing = std.testing.allocator;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(backing, 12 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scope = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scope.deinit();
    const elf = Guest.elf();
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, span, .{});
    defer captured.deinit();
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const result = try Run.run(budget, temporary.dir, .{
        .elf = &elf,
        .elf_sha256 = Capture.sha(&elf),
        .cycles = span.cycles,
        .config = config,
        .state = .{ .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span } },
    }, .{ .segment_cycles = 2, .active_callers = true, .sparse_window_initialization = sparse }, &pool, Selected);
    try std.testing.expectEqual(@as(u64, span.cycles), result.stats.cycles);
    try std.testing.expectEqual(@as(u32, 2), result.stats.segments);
    try std.testing.expectEqual(@as(u32, if (span.skip_cycles == 9) 0 else 1), result.stats.callers);
    var remaining = temporary.dir.iterate();
    try std.testing.expect((try remaining.next()) == null);
    if (comptime @hasDecl(Selected, "consumeStagedWindow")) {
        defer Selected.discardStagedResult(result.value);
        if (comptime @hasDecl(Selected, "OracleConsumer")) {
            const oracle = try Run.run(budget, temporary.dir, .{
                .elf = &elf,
                .elf_sha256 = Capture.sha(&elf),
                .cycles = span.cycles,
                .config = config,
                .state = .{ .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span } },
            }, .{ .segment_cycles = 2, .active_callers = true, .sparse_window_initialization = sparse }, &pool, Selected.OracleConsumer);
            try Selected.compareOriginal(result.value, oracle.value);
        }
        if (comptime @hasDecl(Selected, "verifyAfterProducersDestroyedWithExternal")) {
            try Selected.verifyAfterProducersDestroyedWithExternal(result.value, @import("block_v7_window_union_loader_v1.zig").External{
                .elf = &elf,
                .incoming = captured.incoming,
                .outgoing = captured.outgoing,
                .trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span },
                .config = config,
            });
        } else try Selected.verifyAfterProducersDestroyed(result.value);
    }
}
