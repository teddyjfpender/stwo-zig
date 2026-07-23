//! Exact host-side layouts used by the imported CUDA runtime boundary.

pub const DeviceSnapshot = extern struct {
    count: u32 = 0,
    current: u32 = 0,
    sm_major: u32 = 0,
    sm_minor: u32 = 0,

    pub fn sm(self: DeviceSnapshot) !u32 {
        if (self.sm_minor > 9) return error.InvalidDeviceArchitecture;
        const major = std.math.mul(u32, self.sm_major, 10) catch
            return error.InvalidDeviceArchitecture;
        return std.math.add(u32, major, self.sm_minor) catch
            return error.InvalidDeviceArchitecture;
    }
};

pub const NativeAotStats = extern struct {
    aot_loads: u64 = 0,
    aot_cache_hits: u64 = 0,
    aot_misses: u64 = 0,
    launches: u64 = 0,
    launch_failures: u64 = 0,

    pub fn isStrict(self: NativeAotStats) bool {
        return self.aot_misses == 0 and
            self.launch_failures == 0 and
            self.aot_loads != 0 and
            self.launches != 0;
    }
};

pub const NativeAotFunctionReceipt = extern struct {
    abi_version: u32 = 0,
    abi_schema: u32 = 0,
    device_ordinal: u32 = 0,
    sm_major: u32 = 0,
    sm_minor: u32 = 0,
    grid: [3]u32 = .{ 0, 0, 0 },
    block: [3]u32 = .{ 0, 0, 0 },
    dynamic_shared_bytes: u32 = 0,
    argument_count: u32 = 0,
    registers_per_thread: u32 = 0,
    max_threads_per_block: u32 = 0,
    binary_version: u32 = 0,
    cache_key: u64 = 0,
    context_token: u64 = 0,
    module_token: u64 = 0,
    function_token: u64 = 0,
    stream_token: u64 = 0,
};

const std = @import("std");

comptime {
    std.debug.assert(@sizeOf(NativeAotStats) == 40);
    std.debug.assert(@alignOf(NativeAotStats) == 8);
    std.debug.assert(@sizeOf(NativeAotFunctionReceipt) == 104);
    std.debug.assert(@alignOf(NativeAotFunctionReceipt) == 8);
    std.debug.assert(@offsetOf(NativeAotFunctionReceipt, "abi_schema") == 4);
    std.debug.assert(@offsetOf(NativeAotFunctionReceipt, "grid") == 20);
    std.debug.assert(@offsetOf(NativeAotFunctionReceipt, "cache_key") == 64);
}

test "strict AOT stats reject every non-AOT provenance" {
    const strict = NativeAotStats{ .aot_loads = 1, .launches = 7 };
    try std.testing.expect(strict.isStrict());
    var rejected = strict;
    rejected.aot_misses = 1;
    try std.testing.expect(!rejected.isStrict());
    rejected = strict;
    rejected.launch_failures = 1;
    try std.testing.expect(!rejected.isStrict());
    try std.testing.expect(!(NativeAotStats{}).isStrict());
}
