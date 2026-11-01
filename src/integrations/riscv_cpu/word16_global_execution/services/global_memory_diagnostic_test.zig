const std = @import("std");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const D = @import("global_memory_diagnostic.zig");
const a = std.testing.allocator;

test "global RAM diagnostic consumes the actual mixed Keccak secp and LS collector with correct predecessor chains" {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    const report = try D.auditCaptured(&captured.advice, F.image());
    try std.testing.expectEqual(@as(u16, 2), report.epochs);
    try std.testing.expectEqual(@as(usize, 25), report.touched_words);
    try std.testing.expectEqual(@as(usize, 1), report.ordinary_accesses);
    try std.testing.expectEqual(@as(usize, 25), report.keccak_word_accesses);
    try std.testing.expectEqual(@as(usize, 36), report.secp_word_accesses);
    try std.testing.expectEqual(@as(usize, 62), report.total_transitions);
    try std.testing.expect(!D.Report.physical_origin_join_verified);

    const saved = captured.advice.terminal[0].state.value;
    captured.advice.terminal[0].state.value ^= 1;
    try std.testing.expectError(error.MemoryTerminalMismatch, D.auditCaptured(&captured.advice, F.image()));
    captured.advice.terminal[0].state.value = saved;
    const before = captured.advice.keccak[0][0].before[1];
    captured.advice.keccak[0][0].before[1] ^= 1;
    try std.testing.expectError(error.InconsistentCapturedServiceBefore, D.auditCaptured(&captured.advice, F.image()));
    captured.advice.keccak[0][0].before[1] = before;
    const root = captured.advice.initial[0].state.value;
    captured.advice.initial[0].state.value ^= 1;
    try std.testing.expectError(error.UntrustedGlobalDiagnosticGenesis, D.auditCaptured(&captured.advice, F.image()));
    captured.advice.initial[0].state.value = root;
    _ = try D.auditCaptured(&captured.advice, F.image());
}

test "mixed-service native acceptance and diagnostic flow both pass but require a separate physical event-source join" {
    var c = try F.Case.init(a);
    defer c.deinit();
    try E.verify(a, &c.keys(), &c.truths(), c.expected(), &c.bundle);
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    const report = try D.auditCaptured(&captured.advice, F.image());
    try std.testing.expectEqual(@as(usize, 62), report.total_transitions);
    // Neither independent native verification nor this host diagnostic proves
    // equality of the captured advice and the original committed CPU tuples.
    try std.testing.expect(!D.Report.physical_origin_join_verified);
}
