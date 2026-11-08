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
    pub fn readNs(self: *Scope) u64 {
        return if (self.timer) |*timer| timer.read() else 0;
    }
    pub fn endRows(self: *Scope, points_ns: u64, inverse_ns: u64, finalize_ns: u64) void {
        if (self.timer != null) {
            self.timer = null;
            std.debug.print("OM_DEEP_ROWS rows={d} points_ns={d} inverse_ns={d} finalize_ns={d}\n", .{ self.count, points_ns, inverse_ns, finalize_ns });
        }
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
