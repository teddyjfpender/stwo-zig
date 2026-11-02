//! Optional local OM31 implementation timings. No transcript or allocation state.
const std = @import("std");
const core = @import("stwo_core");
pub const Scope = struct {
    timer: ?std.time.Timer = null,
    label: []const u8,
    count: usize,
    pub fn begin(comptime S: type, label: []const u8, count: usize) Scope {
        return .{ .label = label, .count = count, .timer = if (S == core.fields.om31.OM31 and std.process.hasEnvVarConstant("STWO_ZIG_PROFILE_WIDE_QUOTIENT")) std.time.Timer.start() catch null else null };
    }
    pub fn end(self: *Scope) void {
        if (self.timer) |*timer| {
            const elapsed = timer.read();
            self.timer = null;
            std.debug.print("OM_DEEP_PHASE phase={s} count={d} ns={d}\n", .{ self.label, self.count, elapsed });
        }
    }
};

test "wide phase scope leaves the QM31 control inert and end is idempotent" {
    var scope = Scope.begin(core.fields.qm31.QM31, "control", 4);
    try std.testing.expect(scope.timer == null);
    scope.end();
    scope.end();
    try std.testing.expect(scope.timer == null);
}
