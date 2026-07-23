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

pub const AotStats = extern struct {
    aot_loads: u64 = 0,
    aot_cache_hits: u64 = 0,
    aot_misses: u64 = 0,
    runtime_loads: u64 = 0,
    runtime_cache_hits: u64 = 0,
    strict_rejections: u64 = 0,

    pub fn isStrict(self: AotStats) bool {
        return self.aot_misses == 0 and
            self.runtime_loads == 0 and
            self.runtime_cache_hits == 0 and
            self.strict_rejections == 0;
    }
};

const std = @import("std");

comptime {
    std.debug.assert(@sizeOf(AotStats) == 48);
    std.debug.assert(@alignOf(AotStats) == 8);
}

test "strict AOT stats reject every non-AOT provenance" {
    try std.testing.expect((AotStats{}).isStrict());
    inline for (.{
        "aot_misses",
        "runtime_loads",
        "runtime_cache_hits",
        "strict_rejections",
    }) |field| {
        var stats = AotStats{};
        @field(stats, field) = 1;
        try std.testing.expect(!stats.isStrict());
    }
}
