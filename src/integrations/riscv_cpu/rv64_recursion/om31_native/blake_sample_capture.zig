//! Native sampled-values hash inputs for a producer-only GPU shadow check.
const std = @import("std");
const Observer = @import("stwo_core").crypto.blake2s_observer;
pub const Record = [26]u32;
pub fn prefillEnabled() !bool {
    const value = std.posix.getenv("STWO_RV64_BLAKE_SAMPLE_PREFILL") orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidBlakeSamplePrefillOption;
}
pub fn enabled() !bool {
    if (try prefillEnabled()) return true;
    const value = std.posix.getenv("STWO_RV64_BLAKE_SAMPLE_CHECK") orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidBlakeSampleCheckOption;
}
pub const Recorder = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayListUnmanaged(Record) = .empty,
    failure: ?anyerror = null,
    pub const Saved = struct { listener: ?Observer.Observer, phase: Observer.Phase };
    pub fn install(self: *Recorder) Saved {
        const saved = Saved{ .listener = Observer.observer, .phase = Observer.phase };
        Observer.observer = .{ .context = self, .before_compress = record };
        Observer.phase = .none;
        return saved;
    }
    pub fn restore(saved: Saved) void {
        Observer.observer = saved.listener;
        Observer.phase = saved.phase;
    }
    fn record(raw: *anyopaque, event: Observer.Event) void {
        const self: *Recorder = @ptrCast(@alignCast(raw));
        if (self.failure != null) return;
        if (event.t1 != 0 or (event.final_word != 0 and event.final_word != std.math.maxInt(u32))) {
            self.failure = error.UnsupportedBlakeSampleCounter;
            return;
        }
        var words: Record = undefined;
        @memcpy(words[0..8], &event.h);
        @memcpy(words[8..24], &event.message);
        words[24] = event.t0;
        words[25] = @intFromBool(event.final_word != 0);
        self.records.append(self.allocator, words) catch |err| {
            self.failure = err;
        };
    }
    pub fn take(self: *Recorder) ![]Record {
        if (self.failure) |err| return err;
        if (self.records.items.len == 0) return error.MissingBlakeSampleInputs;
        return self.records.toOwnedSlice(self.allocator);
    }
    pub fn deinit(self: *Recorder) void {
        self.records.deinit(self.allocator);
    }
};
