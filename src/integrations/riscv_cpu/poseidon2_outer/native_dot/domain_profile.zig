//! Optional coordinator-only phase timings. Scopes borrow an existing recorder;
//! helpers inherit neither the pointer nor any ownership. Null scopes read no clock.
const std = @import("std");
const E = @import("stwo_prover_engine");
threadlocal var active: ?*E.stage_profile.Recorder = null;
pub const Scope = struct {
    previous: ?*E.stage_profile.Recorder,
    recorder: ?*E.stage_profile.Recorder,
    pub fn init(recorder: ?*E.stage_profile.Recorder) Scope {
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
pub fn begin(id: []const u8, label: []const u8) !E.stage_profile.StageScope {
    return E.stage_profile.StageScope.begin(active, id, label);
}
