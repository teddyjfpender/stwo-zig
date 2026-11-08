//! Optional producer diagnostics. Inputs only; observers never supply a digest.
//! Phase and listener are scoped to one host worker thread.
pub const Phase = enum { none, sampled_values_mix };
pub const Event = struct { h: [8]u32, message: [16]u32, t0: u32, t1: u32, final_word: u32 };
pub const Observer = struct { context: *anyopaque, before_compress: *const fn (*anyopaque, Event) void };
pub threadlocal var observer: ?Observer = null;
pub threadlocal var phase: Phase = .none;

pub inline fn observe(h: *const [8]u32, message: *const [16]u32, t0: u32, t1: u32, final_word: u32) void {
    if (observer) |listener| if (phase == .sampled_values_mix) {
        listener.before_compress(listener.context, .{ .h = h.*, .message = message.*, .t0 = t0, .t1 = t1, .final_word = final_word });
    };
}
