//! Scoped ownership of an entirely device-generated MAIN. The flat ordering
//! is the admitted CpuSetup ordering; private formatter roles cannot rekey it.
const std = @import("std");
const D = @import("stwo_prover_api").device_pcs;
pub const Owner = struct {
    context: *anyopaque,
    scope: D.Scope,
    columns: []const D.TraceColumn,
    release_fn: *const fn (*anyopaque) void,
    pub fn validate(self: *const Owner, expected_scope: D.Scope, logs: []const u32) !void {
        if (!std.meta.eql(self.scope, expected_scope) or self.columns.len != logs.len or self.columns.len == 0) return error.DeviceMainAuthorityMismatch;
        var token: ?u64 = null;
        for (self.columns, logs) |column, log| {
            const device = column.device orelse return error.DeviceMainHostFallback;
            if (column.host.len != 0 or column.log_size != log or log < 5 or log > 28 or device.count != @as(u64, 1) << @intCast(log) or device.context_token == 0 or device.generation == 0) return error.DeviceMainShapeMismatch;
            if (token) |value| {
                if (value != device.context_token) return error.DeviceMainContextMismatch;
            } else token = device.context_token;
        }
    }
    pub fn release(self: *Owner) void {
        self.release_fn(self.context);
        self.* = undefined;
    }
};

test "device family witness MAIN rejects host gaps wrong shape and cross-context columns" {
    const Testing = struct {
        fn release(_: *anyopaque) void {}
    };
    const scope = D.Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(0), .ordinal = 3 };
    var columns = [_]D.TraceColumn{.{ .log_size = 5, .encoding = .evaluations, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 7, .generation = 9 } }};
    const owner = Owner{ .context = @ptrFromInt(8), .scope = scope, .columns = &columns, .release_fn = Testing.release };
    try owner.validate(scope, &.{5});
    var wrong = scope;
    wrong.ordinal += 1;
    try std.testing.expectError(error.DeviceMainAuthorityMismatch, owner.validate(wrong, &.{5}));
    columns[0].host = &.{@import("stwo_core").fields.m31.M31.zero()};
    try std.testing.expectError(error.DeviceMainShapeMismatch, owner.validate(scope, &.{5}));
    columns[0].host = &.{};
    columns[0].device = null;
    try std.testing.expectError(error.DeviceMainHostFallback, owner.validate(scope, &.{5}));
}
