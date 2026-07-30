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

pub const PlatformSnapshot = extern struct {
    uuid: [16]u8 = [_]u8{0} ** 16,
    driver_version: u32 = 0,
    runtime_version: u32 = 0,
    toolkit_version: u32 = 0,
    device_ordinal: u32 = 0,
    total_global_memory: u64 = 0,
    multiprocessor_count: u32 = 0,
    warp_size: u32 = 0,
    max_threads_per_block: u32 = 0,
    reserved: u32 = 0,

    pub fn isSane(self: PlatformSnapshot) bool {
        return !std.mem.allEqual(u8, &self.uuid, 0) and
            self.driver_version != 0 and
            self.runtime_version != 0 and
            self.toolkit_version != 0 and
            self.total_global_memory != 0 and
            self.multiprocessor_count != 0 and
            self.warp_size != 0 and
            self.max_threads_per_block != 0 and
            self.reserved == 0;
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

pub const aot_verification_abi_version: u32 = 1;
pub const aot_verification_verified: u32 = 1;

pub const NativeAotVerificationReceipt = extern struct {
    abi_version: u32 = 0,
    verified: u32 = 0,
    cubin_bytes: u64 = 0,
    expected_sha256: [32]u8 = [_]u8{0} ** 32,
    observed_sha256: [32]u8 = [_]u8{0} ** 32,

    pub fn isVerified(self: NativeAotVerificationReceipt) bool {
        return self.abi_version == aot_verification_abi_version and
            self.verified == aot_verification_verified and
            self.cubin_bytes != 0 and
            !std.mem.allEqual(u8, &self.expected_sha256, 0) and
            std.mem.eql(u8, &self.expected_sha256, &self.observed_sha256);
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
    local_bytes: u64 = 0,
    static_shared_bytes: u64 = 0,
    cache_key: u64 = 0,
    context_token: u64 = 0,
    module_token: u64 = 0,
    function_token: u64 = 0,
    stream_token: u64 = 0,
    verification: NativeAotVerificationReceipt = .{},
};

pub const aot_module_globals_receipt_abi_version: u32 = 1;

pub const NativeAotModuleGlobalsReceipt = extern struct {
    abi_version: u32 = 0,
    verified: u32 = 0,
    module_globals: u32 = 0,
    column_count: u32 = 0,
    row_count: u32 = 0,
    reserved: u32 = 0,
    columns_symbol_bytes: u64 = 0,
    row_count_symbol_bytes: u64 = 0,
    module_token: u64 = 0,
    stream_token: u64 = 0,
    table_identity: [32]u8 = [_]u8{0} ** 32,
};

const std = @import("std");

comptime {
    std.debug.assert(@sizeOf(PlatformSnapshot) == 56);
    std.debug.assert(@alignOf(PlatformSnapshot) == 8);
    std.debug.assert(@offsetOf(PlatformSnapshot, "total_global_memory") == 32);
    std.debug.assert(@sizeOf(NativeAotStats) == 40);
    std.debug.assert(@alignOf(NativeAotStats) == 8);
    std.debug.assert(@sizeOf(NativeAotVerificationReceipt) == 80);
    std.debug.assert(@alignOf(NativeAotVerificationReceipt) == 8);
    std.debug.assert(@offsetOf(NativeAotVerificationReceipt, "cubin_bytes") == 8);
    std.debug.assert(@offsetOf(NativeAotVerificationReceipt, "expected_sha256") == 16);
    std.debug.assert(@offsetOf(NativeAotVerificationReceipt, "observed_sha256") == 48);
    std.debug.assert(@sizeOf(NativeAotFunctionReceipt) == 200);
    std.debug.assert(@alignOf(NativeAotFunctionReceipt) == 8);
    std.debug.assert(@offsetOf(NativeAotFunctionReceipt, "abi_schema") == 4);
    std.debug.assert(@offsetOf(NativeAotFunctionReceipt, "grid") == 20);
    std.debug.assert(@offsetOf(NativeAotFunctionReceipt, "local_bytes") == 64);
    std.debug.assert(@offsetOf(NativeAotFunctionReceipt, "cache_key") == 80);
    std.debug.assert(@offsetOf(NativeAotFunctionReceipt, "verification") == 120);
    std.debug.assert(@sizeOf(NativeAotModuleGlobalsReceipt) == 88);
    std.debug.assert(@alignOf(NativeAotModuleGlobalsReceipt) == 8);
    std.debug.assert(
        @offsetOf(NativeAotModuleGlobalsReceipt, "columns_symbol_bytes") == 24,
    );
    std.debug.assert(
        @offsetOf(NativeAotModuleGlobalsReceipt, "table_identity") == 56,
    );
}

test "platform snapshot rejects incomplete provenance" {
    const complete = PlatformSnapshot{
        .uuid = [_]u8{7} ** 16,
        .driver_version = 12080,
        .runtime_version = 12080,
        .toolkit_version = 12080,
        .total_global_memory = 24 * 1024 * 1024 * 1024,
        .multiprocessor_count = 128,
        .warp_size = 32,
        .max_threads_per_block = 1024,
    };
    try std.testing.expect(complete.isSane());
    var incomplete = complete;
    incomplete.uuid = [_]u8{0} ** 16;
    try std.testing.expect(!incomplete.isSane());
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

test "AOT verification receipt requires exact nonzero digest equality" {
    const verified = NativeAotVerificationReceipt{
        .abi_version = aot_verification_abi_version,
        .verified = aot_verification_verified,
        .cubin_bytes = 4096,
        .expected_sha256 = [_]u8{7} ** 32,
        .observed_sha256 = [_]u8{7} ** 32,
    };
    try std.testing.expect(verified.isVerified());
    var rejected = verified;
    rejected.observed_sha256[0] ^= 0xff;
    try std.testing.expect(!rejected.isVerified());
    rejected = verified;
    rejected.expected_sha256 = [_]u8{0} ** 32;
    rejected.observed_sha256 = [_]u8{0} ** 32;
    try std.testing.expect(!rejected.isVerified());
    rejected = verified;
    rejected.verified = 0;
    try std.testing.expect(!rejected.isVerified());
}
