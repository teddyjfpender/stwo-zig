//! Request-owned original PP evaluations. These are never immutable-cache aliases
//! or retained PCS coefficients: one exact native lease moves between owners.
const std = @import("std");
const N = @import("pcs_native_abi.zig");
pub const Ops = struct {
    session: *anyopaque,
    validate: N.LeaseValidate,
    rebind: N.LeaseRebind,
    release: N.LeaseRelease,
};
pub const Raw = struct {
    lease: N.Lease = .{},
    scope: [8]u32 = @splat(0),
    fn require(self: Raw, ops: Ops) !void {
        if (self.lease.words == null or self.lease.count == 0 or self.lease.kind != 0 or self.lease.reserved != 0 or self.lease.context_token == 0 or self.lease.generation == 0 or std.mem.allEqual(u32, &self.scope, 0)) return error.InvalidOuterFixedIngress;
        if (ops.validate(ops.session, &self.lease, &self.scope) != 0) return error.InvalidOuterFixedIngress;
    }
    pub fn promote(self: *Raw, next: [8]u32, ops: Ops) !void {
        try self.require(ops);
        if (std.mem.allEqual(u32, &next, 0) or std.mem.eql(u32, &self.scope, &next)) return error.InvalidOuterFixedIngressScope;
        // Native rebind validates the full descriptor before changing authority.
        // No allocation or fallible bookkeeping follows that mutation.
        if (ops.rebind(ops.session, &self.lease, &self.scope, &next) != 0) return error.OuterFixedIngressRebindFailed;
        self.scope = next;
    }
    pub fn transferTo(self: *Raw, target: *Raw, next: [8]u32, ops: Ops) !void {
        if (self == target or target.lease.words != null) return error.OuterFixedIngressAlreadyOwned;
        try self.promote(next, ops);
        target.* = self.*;
        self.* = .{};
    }
    pub fn release(self: *Raw, ops: Ops) !void {
        if (self.lease.words == null) return;
        try self.require(ops);
        // Failed release preserves custody for error cleanup/retry.
        if (ops.release(ops.session, &self.lease) != 0) return error.OuterFixedIngressReleaseFailed;
        self.* = .{};
    }
};

test "raw FIXED custody transfers once and failed rebind/release preserve exact authority" {
    const Fake = struct {
        scope: [8]u32 = @splat(1),
        generation: u64 = 7,
        live: bool = true,
        fail_rebind: bool = false,
        fail_release: bool = false,
        releases: usize = 0,
        fn validate(p: *anyopaque, l: *const N.Lease, s: *const [8]u32) callconv(.c) c_int {
            const f: *@This() = @ptrCast(@alignCast(p));
            return if (f.live and l.words == @as(?[*]u32, @ptrFromInt(4096)) and l.count == 128 and l.generation == f.generation and l.context_token == 3 and l.kind == 0 and l.reserved == 0 and std.mem.eql(u32, s, &f.scope)) 0 else 1;
        }
        fn rebind(p: *anyopaque, l: *const N.Lease, old: *const [8]u32, next: *const [8]u32) callconv(.c) c_int {
            const f: *@This() = @ptrCast(@alignCast(p));
            if (f.fail_rebind or validate(p, l, old) != 0) return 1;
            f.scope = next.*;
            return 0;
        }
        fn release(p: *anyopaque, l: *N.Lease) callconv(.c) c_int {
            const f: *@This() = @ptrCast(@alignCast(p));
            if (f.fail_release or validate(p, l, &f.scope) != 0) return 1;
            f.live = false;
            f.releases += 1;
            l.* = .{};
            return 0;
        }
    };
    var f = Fake{};
    const ops = Ops{ .session = &f, .validate = Fake.validate, .rebind = Fake.rebind, .release = Fake.release };
    var original = Raw{ .lease = .{ .words = @ptrFromInt(4096), .count = 128, .context_token = 3, .generation = 7, .kind = 0 }, .scope = @splat(1) };
    var destination = Raw{};
    f.fail_rebind = true;
    try std.testing.expectError(error.OuterFixedIngressRebindFailed, original.transferTo(&destination, @splat(2), ops));
    try std.testing.expect(original.lease.words != null and destination.lease.words == null);
    try std.testing.expectEqual(@as(u32, 1), original.scope[0]);
    f.fail_rebind = false;
    var altered = original;
    altered.lease.generation += 1;
    try std.testing.expectError(error.InvalidOuterFixedIngress, altered.transferTo(&destination, @splat(2), ops));
    altered = original;
    altered.lease.count -= 1;
    try std.testing.expectError(error.InvalidOuterFixedIngress, altered.transferTo(&destination, @splat(2), ops));
    try original.transferTo(&destination, @splat(2), ops);
    try std.testing.expect(original.lease.words == null and destination.lease.words != null);
    try std.testing.expectError(error.OuterFixedIngressAlreadyOwned, original.transferTo(&destination, @splat(3), ops));
    f.fail_rebind = true;
    try std.testing.expectError(error.OuterFixedIngressRebindFailed, destination.promote(@splat(3), ops));
    try std.testing.expectEqual(@as(u32, 2), destination.scope[0]);
    f.fail_rebind = false;
    try destination.promote(@splat(3), ops);
    f.fail_release = true;
    try std.testing.expectError(error.OuterFixedIngressReleaseFailed, destination.release(ops));
    try std.testing.expect(destination.lease.words != null);
    f.fail_release = false;
    try destination.release(ops);
    try original.release(ops);
    try destination.release(ops);
    try std.testing.expectEqual(@as(usize, 1), f.releases);
}
