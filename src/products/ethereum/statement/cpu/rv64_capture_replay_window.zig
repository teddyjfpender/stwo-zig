//! Bounded producer-only replay launch policy. Speculation starts only later
//! checkpoint waiters; the next required checkpoint retains ordered admission.
const std = @import("std");
pub fn enabled() bool {
    return false;
}
pub const Decision = enum { launch, wait_checkpoint, stop };
pub const State = struct {
    next: u32,
    launched: u32,
    workers: u8,
    checkpoints: usize,
    bound: u32,
    done: bool,
    ahead: bool,
};
pub fn decide(state: State) Decision {
    // Subtraction after the order check avoids overflow near an index limit.
    if (state.launched < state.next or state.launched - state.next >= state.workers or state.launched >= state.bound) return .stop;
    if (state.launched < state.checkpoints) return .launch;
    if (state.done) return .stop;
    if (state.launched == state.next) return .wait_checkpoint;
    return if (state.ahead) .launch else .stop;
}

test "replay speculation fills the bounded window before later checkpoints publish" {
    var state = State{ .next = 0, .launched = 0, .workers = 4, .checkpoints = 1, .bound = std.math.maxInt(u32), .done = false, .ahead = true };
    for (0..4) |_| {
        try std.testing.expectEqual(Decision.launch, decide(state));
        state.launched += 1;
    }
    try std.testing.expectEqual(Decision.stop, decide(state));
    // Releasing one ordered result permits exactly one additional waiter.
    state.next += 1;
    try std.testing.expectEqual(Decision.launch, decide(state));
    state.launched += 1;
    try std.testing.expectEqual(Decision.stop, decide(state));
}

test "both schedules retain the required checkpoint wait and terminal failure boundary" {
    var state = State{ .next = 7, .launched = 7, .workers = 4, .checkpoints = 7, .bound = std.math.maxInt(u32), .done = false, .ahead = false };
    for ([_]bool{ false, true }) |ahead| {
        state.ahead = ahead;
        try std.testing.expectEqual(Decision.wait_checkpoint, decide(state));
        state.done = true;
        try std.testing.expectEqual(Decision.stop, decide(state));
        state.done = false;
        state.bound = 7;
        try std.testing.expectEqual(Decision.stop, decide(state));
        state.bound = std.math.maxInt(u32);
    }
}

test "default schedule stops at an unpublished later checkpoint and bounds never speculate" {
    var state = State{ .next = 0, .launched = 1, .workers = 4, .checkpoints = 1, .bound = 3, .done = false, .ahead = false };
    try std.testing.expectEqual(Decision.stop, decide(state));
    state.ahead = true;
    try std.testing.expectEqual(Decision.launch, decide(state));
    state.launched = 3;
    state.checkpoints = 4;
    try std.testing.expectEqual(Decision.stop, decide(state));
    state.next = std.math.maxInt(u32) - 1;
    state.launched = std.math.maxInt(u32);
    state.bound = std.math.maxInt(u32);
    try std.testing.expectEqual(Decision.stop, decide(state));
}
