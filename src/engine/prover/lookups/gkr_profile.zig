//! Opt-in coordinator-only GKR phase telemetry. No new proof/prover options.
//! Helper threads inherit no recorder and never mutate its serial stage stack.
const std = @import("std");
const P = @import("stwo_prover_api").stage_profile;
threadlocal var active: ?*P.Recorder = null;
pub const Scope = struct {
    previous: ?*P.Recorder,
    recorder: ?*P.Recorder,
    pub fn init(recorder: ?*P.Recorder) Scope {
        const previous = active;
        active = recorder;
        return .{ .previous = previous, .recorder = recorder };
    }
    pub fn deinit(self: *Scope) void {
        std.debug.assert(active == self.recorder);
        active = self.previous;
        self.* = undefined;
    }
};
/// Disabled scopes delegate to the existing null-recorder fast path, which
/// reads no clock and allocates no node. Enabled OOM preserves normal unwind.
pub fn begin(id: []const u8, label: []const u8) !P.StageScope {
    return P.StageScope.begin(active, id, label);
}
