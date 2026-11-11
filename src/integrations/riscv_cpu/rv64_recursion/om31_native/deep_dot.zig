//! Explicit whole-numerator lowering. No scope means the historical DEEP
//! arithmetic remains unchanged; this never intercepts generic mulInner calls.
const C = @import("common.zig");
pub const Hook = *const fn (*C.Context, []const C.F, []const C.Var) anyerror!C.F;
threadlocal var active: ?Hook = null;
pub const Scope = struct {
    previous: ?Hook,
    pub fn init(hook: Hook) Scope {
        const previous = active;
        active = hook;
        return .{ .previous = previous };
    }
    pub fn deinit(self: *Scope) void {
        active = self.previous;
    }
};
pub fn current() ?Hook {
    return active;
}
