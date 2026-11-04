//! Optional owner-thread phase trim; no field/transcript or allocation changes.
const std = @import("std");
pub const ENV = "STWO_RV64_COMPOSITION_POOL_TRIM";
// Observed normal arena12.464GB stays below this; worst16.844GB opts in.
pub const MIN_ARENA_BYTES: u64 = 12 << 30;
pub const Trim = *const fn (*anyopaque) callconv(.c) c_int;
pub fn parse(value: ?[]const u8) !bool {
    const text = value orelse return false;
    if (std.mem.eql(u8, text, "0")) return false;
    if (std.mem.eql(u8, text, "1")) return true;
    return error.InvalidCompositionPoolTrim;
}
pub fn fromEnv(a: std.mem.Allocator) !bool {
    const value = std.process.getEnvVarOwned(a, ENV) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer a.free(value);
    return parse(value);
}
pub const Policy = struct {
    enabled: bool = false,
    trim: ?Trim = null,
    pub fn init(enabled: bool, function: ?Trim) !Policy {
        if (enabled and function == null) return error.MissingCompositionPoolTrim;
        return .{ .enabled = enabled, .trim = function };
    }
    /// Caller runs inside the native session's owner callback. The native API
    /// independently validates ownership/device, rejects capture and joins.
    /// Only successful physical calls return true; OFF never invokes CUDA.
    pub fn beforeTransform(self: Policy, context: *anyopaque, arena_bytes: u64) !bool {
        if (!self.enabled or arena_bytes < MIN_ARENA_BYTES) return false;
        const function = self.trim orelse return error.MissingCompositionPoolTrim;
        const status = function(context);
        if (status != 0) {
            std.debug.print("GPU_COMPOSITION_POOL_TRIM native_status={} arena_bytes={}\n", .{ status, arena_bytes });
            return error.CudaCompositionPoolTrimFailed;
        }
        return true;
    }
};
test "phase trim strict opt-in and missing API fail before proving" {
    try std.testing.expect(!try parse(null));
    try std.testing.expect(!try parse("0"));
    try std.testing.expect(try parse("1"));
    for ([_][]const u8{ "", "true", "2", "01", " 1" }) |text| try std.testing.expectError(error.InvalidCompositionPoolTrim, parse(text));
    _ = try Policy.init(false, null);
    try std.testing.expectError(error.MissingCompositionPoolTrim, Policy.init(true, null));
}
test "phase trim preserves OFF and small arenas and propagates terminal failure" {
    const Fake = struct {
        calls: usize = 0,
        status: c_int = 0,
        lease_token: u64 = 7,
        generation: u64 = 9,
        fn run(raw: *anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            return self.status;
        }
    };
    var fake = Fake{};
    try std.testing.expect(!try (try Policy.init(false, Fake.run)).beforeTransform(&fake, MIN_ARENA_BYTES));
    const policy = try Policy.init(true, Fake.run);
    try std.testing.expect(!try policy.beforeTransform(&fake, MIN_ARENA_BYTES - 1));
    try std.testing.expect(!try policy.beforeTransform(&fake, 12_463_648_768));
    try std.testing.expectEqual(@as(usize, 0), fake.calls);
    try std.testing.expect(try policy.beforeTransform(&fake, MIN_ARENA_BYTES));
    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    fake.status = 13;
    try std.testing.expectError(error.CudaCompositionPoolTrimFailed, policy.beforeTransform(&fake, MIN_ARENA_BYTES));
    try std.testing.expectEqual(@as(usize, 2), fake.calls);
    try std.testing.expectEqual(@as(u64, 7), fake.lease_token);
    try std.testing.expectEqual(@as(u64, 9), fake.generation);
}
