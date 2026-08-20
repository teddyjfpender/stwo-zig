//! Process-owned resource counters for benchmark evidence.

const std = @import("std");
const builtin = @import("builtin");

pub const Source = enum {
    darwin_proc_pid_rusage_v6,
    unsupported,
};

pub const Snapshot = struct {
    source: Source,
    lifetime_peak_physical_footprint_bytes: ?u64,
    process_cpu_ns: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    cycles: ?u64,
    unavailable_reason: ?[]const u8,

    pub fn available(self: Snapshot) bool {
        return self.source != .unsupported and
            self.lifetime_peak_physical_footprint_bytes != null and
            self.process_cpu_ns != null and
            self.energy_nj != null and
            self.instructions != null and
            self.cycles != null;
    }
};

pub const Delta = struct {
    source: Source,
    lifetime_peak_physical_footprint_bytes: ?u64,
    process_cpu_ns: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    cycles: ?u64,
    unavailable_reason: ?[]const u8,

    pub fn available(self: Delta) bool {
        return self.source != .unsupported and
            self.lifetime_peak_physical_footprint_bytes != null and
            self.process_cpu_ns != null and
            self.energy_nj != null and
            self.instructions != null and
            self.cycles != null;
    }
};

pub const Error = error{
    ProcessUsageQueryFailed,
    ProcessTimebaseQueryFailed,
    InvalidProcessTimebase,
    ProcessUsageSourceChanged,
    ProcessCounterRegressed,
    ProcessCounterOverflow,
};

pub fn sample() Error!Snapshot {
    if (builtin.os.tag != .macos) return .{
        .source = .unsupported,
        .lifetime_peak_physical_footprint_bytes = null,
        .process_cpu_ns = null,
        .energy_nj = null,
        .instructions = null,
        .cycles = null,
        .unavailable_reason = "proc_pid_rusage_v6 is available only on Darwin",
    };
    return darwin.sample();
}

pub fn difference(before: Snapshot, after: Snapshot) Error!Delta {
    if (before.source != after.source) return error.ProcessUsageSourceChanged;
    if (before.source == .unsupported) return .{
        .source = .unsupported,
        .lifetime_peak_physical_footprint_bytes = null,
        .process_cpu_ns = null,
        .energy_nj = null,
        .instructions = null,
        .cycles = null,
        .unavailable_reason = after.unavailable_reason orelse before.unavailable_reason,
    };
    return .{
        .source = after.source,
        .lifetime_peak_physical_footprint_bytes = after.lifetime_peak_physical_footprint_bytes orelse
            return error.ProcessCounterRegressed,
        .process_cpu_ns = try subtractOptional(
            before.process_cpu_ns,
            after.process_cpu_ns,
        ),
        .energy_nj = try subtractOptional(before.energy_nj, after.energy_nj),
        .instructions = try subtractOptional(before.instructions, after.instructions),
        .cycles = try subtractOptional(before.cycles, after.cycles),
        .unavailable_reason = null,
    };
}

fn subtractOptional(before: ?u64, after: ?u64) Error!?u64 {
    const start = before orelse return null;
    const finish = after orelse return null;
    return std.math.sub(u64, finish, start) catch error.ProcessCounterRegressed;
}

const darwin = struct {
    const RUSAGE_INFO_V6: c_int = 6;

    // ABI from macOS SDK sys/resource.h. Keep the full v6 tail so the kernel
    // cannot overwrite a shorter buffer when the flavor is RUSAGE_INFO_V6.
    const RUsageInfoV6 = extern struct {
        uuid: [16]u8,
        user_time: u64,
        system_time: u64,
        package_idle_wakeups: u64,
        interrupt_wakeups: u64,
        pageins: u64,
        wired_size: u64,
        resident_size: u64,
        physical_footprint: u64,
        process_start_abstime: u64,
        process_exit_abstime: u64,
        child_user_time: u64,
        child_system_time: u64,
        child_package_idle_wakeups: u64,
        child_interrupt_wakeups: u64,
        child_pageins: u64,
        child_elapsed_abstime: u64,
        disk_bytes_read: u64,
        disk_bytes_written: u64,
        cpu_time_qos_default: u64,
        cpu_time_qos_maintenance: u64,
        cpu_time_qos_background: u64,
        cpu_time_qos_utility: u64,
        cpu_time_qos_legacy: u64,
        cpu_time_qos_user_initiated: u64,
        cpu_time_qos_user_interactive: u64,
        billed_system_time: u64,
        serviced_system_time: u64,
        logical_writes: u64,
        lifetime_max_physical_footprint: u64,
        instructions: u64,
        cycles: u64,
        billed_energy: u64,
        serviced_energy: u64,
        interval_max_physical_footprint: u64,
        runnable_time: u64,
        flags: u64,
        user_performance_time: u64,
        system_performance_time: u64,
        performance_instructions: u64,
        performance_cycles: u64,
        energy_nj: u64,
        performance_energy_nj: u64,
        secure_system_time: u64,
        secure_performance_system_time: u64,
        neural_footprint: u64,
        lifetime_max_neural_footprint: u64,
        interval_max_neural_footprint: u64,
        reserved: [9]u64,
    };

    extern "c" fn proc_pid_rusage(
        pid: c_int,
        flavor: c_int,
        buffer: *anyopaque,
    ) c_int;

    fn sample() Error!Snapshot {
        var usage: RUsageInfoV6 = std.mem.zeroes(RUsageInfoV6);
        if (proc_pid_rusage(std.c.getpid(), RUSAGE_INFO_V6, &usage) != 0)
            return error.ProcessUsageQueryFailed;
        var timebase: std.c.mach_timebase_info_data = undefined;
        if (std.c.mach_timebase_info(&timebase) != 0)
            return error.ProcessTimebaseQueryFailed;
        return .{
            .source = .darwin_proc_pid_rusage_v6,
            .lifetime_peak_physical_footprint_bytes = usage.lifetime_max_physical_footprint,
            .process_cpu_ns = try ticksToNanoseconds(
                usage.user_time,
                usage.system_time,
                timebase.numer,
                timebase.denom,
            ),
            .energy_nj = usage.energy_nj,
            .instructions = usage.instructions,
            .cycles = usage.cycles,
            .unavailable_reason = null,
        };
    }

    /// `ri_user_time` and `ri_system_time` use Mach absolute-time ticks.  Use
    /// one wide rational conversion after summing them so the receipt field is
    /// genuinely nanoseconds and cannot overflow during intermediate math.
    fn ticksToNanoseconds(
        user_ticks: u64,
        system_ticks: u64,
        numerator: u32,
        denominator: u32,
    ) Error!u64 {
        if (numerator == 0 or denominator == 0)
            return error.InvalidProcessTimebase;
        const total_ticks = @as(u128, user_ticks) + system_ticks;
        const scaled = total_ticks * numerator;
        return std.math.cast(u64, scaled / denominator) orelse
            error.ProcessCounterOverflow;
    }
};

test "process usage: Darwin v6 ABI has the SDK layout" {
    try std.testing.expectEqual(@as(usize, 464), @sizeOf(darwin.RUsageInfoV6));
    try std.testing.expectEqual(@as(usize, 8), @alignOf(darwin.RUsageInfoV6));
}

test "process usage: current process counters are monotonic" {
    const before = try sample();
    var digest: [32]u8 = undefined;
    var input: [4096]u8 = undefined;
    @memset(&input, 0xa5);
    for (0..1024) |_| std.crypto.hash.sha2.Sha256.hash(&input, &digest, .{});
    std.mem.doNotOptimizeAway(&digest);
    const after = try sample();
    const delta = try difference(before, after);
    if (builtin.os.tag == .macos) {
        try std.testing.expect(delta.available());
        try std.testing.expect(delta.lifetime_peak_physical_footprint_bytes.? > 0);
        try std.testing.expect(delta.process_cpu_ns.? > 0);
        try std.testing.expect(delta.energy_nj != null);
        try std.testing.expect(delta.instructions != null);
        try std.testing.expect(delta.cycles != null);
    } else {
        try std.testing.expect(!delta.available());
        try std.testing.expect(delta.unavailable_reason != null);
    }
}

test "process usage: CPU ticks convert to nanoseconds with wide arithmetic" {
    try std.testing.expectEqual(
        @as(u64, 208),
        try darwin.ticksToNanoseconds(3, 2, 125, 3),
    );
    try std.testing.expectError(
        error.InvalidProcessTimebase,
        darwin.ticksToNanoseconds(1, 1, 1, 0),
    );
    try std.testing.expectError(
        error.ProcessCounterOverflow,
        darwin.ticksToNanoseconds(std.math.maxInt(u64), 1, 2, 1),
    );
}

test "process usage: regressing counters fail closed" {
    const before = Snapshot{
        .source = .darwin_proc_pid_rusage_v6,
        .lifetime_peak_physical_footprint_bytes = 100,
        .process_cpu_ns = 40,
        .energy_nj = 10,
        .instructions = 20,
        .cycles = 30,
        .unavailable_reason = null,
    };
    var after = before;
    after.energy_nj = 9;
    try std.testing.expectError(
        error.ProcessCounterRegressed,
        difference(before, after),
    );
}
