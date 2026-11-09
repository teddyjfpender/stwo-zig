//! Optional synchronous admission custody, not cryptographic authority. The
//! original producer validates admission before binding. Clearing the slot
//! removes every prior dynamic public borrow; only separately owned template
//! key/fixed metadata may persist. No fabricated empty admission is installed.
pub fn For(comptime Admission: type) type {
    return struct {
        const Self = @This();
        current: ?Admission = null,
        pub fn bind(self: *Self, admission: Admission) void {
            self.current = admission;
        }
        pub fn require(self: *const Self) !*const Admission {
            if (self.current) |*admission| return admission;
            return error.ParentDynamicAdmissionNotBound;
        }
        pub fn release(self: *Self) void {
            self.current = null;
        }
    };
}
