//! Top-endpoint routing checks over a genuine baseline proof. These mutations
//! specifically exercise public admission before transcript verification; the
//! separate hostile-prover fixtures qualify malformed-list physical proofs.
const std = @import("std");
const Memory = @import("../word16_execution/memory/statement.zig");
pub const Probe = struct {
    context: *anyopaque,
    verify: *const fn (*anyopaque) anyerror!void,
};
pub fn check(first: *Memory.Statement, last: *Memory.Statement, probe: Probe) !void {
    const initial = first.initial;
    const terminal = last.terminal;
    std.debug.assert(initial.len != 0 and terminal.len == initial.len);
    defer {
        first.initial = initial;
        last.terminal = terminal;
    }
    var before = [2]Memory.Cell{ initial[0], initial[0] };
    var after = [2]Memory.Cell{ terminal[0], terminal[0] };
    first.initial = &before;
    last.terminal = &after;
    try std.testing.expectError(error.GlobalTouchedSetMismatch, probe.verify(probe.context));
    before[0].address |= 1;
    after[0].address = before[0].address;
    first.initial = before[0..1];
    last.terminal = after[0..1];
    try std.testing.expectError(error.GlobalTouchedSetMismatch, probe.verify(probe.context));
    before[0] = initial[0];
    after[0] = terminal[0];
    before[0].state.value ^= 1;
    try std.testing.expectError(error.UntrustedGlobalMemoryInitialization, probe.verify(probe.context));
    if (initial.len >= 2) {
        before = .{ initial[1], initial[0] };
        after = .{ terminal[1], terminal[0] };
        first.initial = &before;
        last.terminal = &after;
        try std.testing.expectError(error.GlobalTouchedSetMismatch, probe.verify(probe.context));
    }
}
