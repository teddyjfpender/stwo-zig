//! Operational controls only; none select proof statements or transcript data.
const std = @import("std");
pub const Options = struct {
    count: usize,
    jobs: ?u8 = null,
    /// Explicit per-lane worker counts; implies the lane count.
    lane_workers: [4]u8 = @splat(0),
    lane_workers_len: u8 = 0,
    /// Estimated in-flight proof bytes admission cap; zero disables it.
    memory_cap: u64 = 0,
    memory_cap_set: bool = false,
    batch: u32 = 64,
    batch_set: bool = false,
    keep_capture_cache: bool = false,
    keep_fixed_witness: bool = false,
    fixed_native_cache_bytes: usize = 256 << 20,
    native_cache_set: bool = false,
    program_metadata_cache_bytes: usize = 64 << 20,
    metadata_cache_set: bool = false,
    park_retained_main: bool = false,
    prefetch_main_bytes: usize = 0,
    prefetch_main_set: bool = false,
    /// Producer planning only: keep every LD/SD in the LS32 instances instead
    /// of the v3 LS-D64 component (the receiver admits either declared shape).
    no_ls_dword: bool = false,
    /// Producer capture scheduling only: decode and capture up to this many
    /// job packets concurrently (consumed in index order). 1 = serial reader.
    capture_inflight: u8 = 1,
    capture_inflight_set: bool = false,
    /// Producer planning only: Keccak truths that take the throughput tables
    /// keep the triple batching (`throughput_v1`) instead of the v3 default
    /// quartet batching (`throughput_quartet_v1`). The profile word is
    /// published and transcript-bound; the receiver admits either.
    keccak_throughput_v1: bool = false,
    /// Producer planning only: throughput Keccak truths keep the 29-row slot
    /// (`throughput_quartet_v1`) instead of the v3 default 27-row slot
    /// (`throughput_r27_v1`). Published and transcript-bound like the others.
    keccak_pair29: bool = false,
    pub fn parse(args: []const [:0]u8) !Options {
        var out = Options{ .count = args.len };
        while (out.count > 1) {
            const arg = args[out.count - 1];
            if (std.mem.startsWith(u8, arg, "--proof-jobs=")) {
                if (out.jobs != null) return error.DuplicateOperationalOption;
                out.jobs = try std.fmt.parseUnsigned(u8, arg[13..], 10);
                if (out.jobs.? == 0 or out.jobs.? > 4) return error.InvalidServiceSchedule;
            } else if (std.mem.startsWith(u8, arg, "--lane-workers=")) {
                if (out.lane_workers_len != 0) return error.DuplicateOperationalOption;
                var parts = std.mem.splitScalar(u8, arg["--lane-workers=".len..], ',');
                while (parts.next()) |part| {
                    if (out.lane_workers_len == out.lane_workers.len) return error.InvalidServiceSchedule;
                    const w = try std.fmt.parseUnsigned(u8, part, 10);
                    if (w == 0 or w > 32) return error.InvalidServiceSchedule;
                    out.lane_workers[out.lane_workers_len] = w;
                    out.lane_workers_len += 1;
                }
            } else if (std.mem.startsWith(u8, arg, "--proof-memory-cap=")) {
                if (out.memory_cap_set) return error.DuplicateOperationalOption;
                out.memory_cap_set = true;
                out.memory_cap = try std.fmt.parseUnsigned(u64, arg["--proof-memory-cap=".len..], 10);
            } else if (std.mem.startsWith(u8, arg, "--commit-batch-columns=")) {
                if (out.batch_set) return error.DuplicateOperationalOption;
                out.batch_set = true;
                out.batch = try std.fmt.parseUnsigned(u32, arg[23..], 10);
                if (out.batch == 0) return error.InvalidStreamingBatchSize;
            } else if (std.mem.startsWith(u8, arg, "--fixed-native-cache-bytes=")) {
                if (out.native_cache_set) return error.DuplicateOperationalOption;
                out.native_cache_set = true;
                const prefix = "--fixed-native-cache-bytes=";
                out.fixed_native_cache_bytes = try std.fmt.parseUnsigned(usize, arg[prefix.len..], 10);
                if (out.fixed_native_cache_bytes > 1 << 30 or (out.fixed_native_cache_bytes != 0 and out.fixed_native_cache_bytes < 4096)) return error.InvalidFixedNativeCacheBudget;
            } else if (std.mem.startsWith(u8, arg, "--program-metadata-cache-bytes=")) {
                if (out.metadata_cache_set) return error.DuplicateOperationalOption;
                out.metadata_cache_set = true;
                const prefix = "--program-metadata-cache-bytes=";
                out.program_metadata_cache_bytes = try std.fmt.parseUnsigned(usize, arg[prefix.len..], 10);
                if (out.program_metadata_cache_bytes > 1 << 30 or (out.program_metadata_cache_bytes != 0 and out.program_metadata_cache_bytes < 4096)) return error.InvalidProgramMetadataBudget;
            } else if (std.mem.startsWith(u8, arg, "--prefetch-retained-main-bytes=")) {
                if (out.prefetch_main_set) return error.DuplicateOperationalOption;
                out.prefetch_main_set = true;
                const prefix = "--prefetch-retained-main-bytes=";
                out.prefetch_main_bytes = try std.fmt.parseUnsigned(usize, arg[prefix.len..], 10);
                if (out.prefetch_main_bytes > 4 << 30 or (out.prefetch_main_bytes != 0 and out.prefetch_main_bytes < std.heap.pageSize())) return error.InvalidRetainedMainPrefetchCap;
            } else if (std.mem.eql(u8, arg, "--park-retained-main")) {
                if (out.park_retained_main) return error.DuplicateOperationalOption;
                out.park_retained_main = true;
            } else if (std.mem.eql(u8, arg, "--keep-capture-cache")) {
                if (out.keep_capture_cache) return error.DuplicateOperationalOption;
                out.keep_capture_cache = true;
            } else if (std.mem.startsWith(u8, arg, "--capture-inflight=")) {
                if (out.capture_inflight_set) return error.DuplicateOperationalOption;
                out.capture_inflight_set = true;
                out.capture_inflight = try std.fmt.parseUnsigned(u8, arg["--capture-inflight=".len..], 10);
                if (out.capture_inflight == 0 or out.capture_inflight > @import("capture_prefetch.zig").MAX_INFLIGHT) return error.InvalidEthereumCaptureOptions;
            } else if (std.mem.eql(u8, arg, "--no-ls-dword")) {
                if (out.no_ls_dword) return error.DuplicateOperationalOption;
                out.no_ls_dword = true;
            } else if (std.mem.eql(u8, arg, "--keccak-throughput-v1")) {
                if (out.keccak_throughput_v1) return error.DuplicateOperationalOption;
                out.keccak_throughput_v1 = true;
            } else if (std.mem.eql(u8, arg, "--keccak-pair29")) {
                if (out.keccak_pair29) return error.DuplicateOperationalOption;
                out.keccak_pair29 = true;
            } else if (std.mem.eql(u8, arg, "--keep-fixed-witness")) {
                if (out.keep_fixed_witness) return error.DuplicateOperationalOption;
                out.keep_fixed_witness = true;
            } else break;
            out.count -= 1;
        }
        return out;
    }
    pub fn schedule(self: Options, workers: usize) !@import("../services/schedule.zig").Policy {
        if (workers == 0 or workers > 32) return error.InvalidWorkerBudget;
        const Policy = @import("../services/schedule.zig").Policy;
        if (self.lane_workers_len != 0) {
            // An explicit lane list is the whole lane budget (sum <= 32); it
            // is not derived from, and may differ from, the request workers.
            if (self.jobs) |jobs| if (jobs != self.lane_workers_len) return error.InvalidServiceSchedule;
            var policy = Policy{ .lanes = self.lane_workers_len, .workers_per_lane = self.lane_workers[0], .lane_workers = self.lane_workers, .memory_cap_bytes = self.memory_cap };
            if (self.lane_workers_len == 1) policy.lane_workers = @splat(0);
            try policy.validate();
            return policy;
        }
        const jobs = self.jobs orelse @as(u8, @intCast(@min(2, workers)));
        if (jobs > workers) return error.InvalidWorkerBudget;
        const policy = Policy{ .lanes = jobs, .workers_per_lane = @intCast(workers / jobs), .memory_cap_bytes = self.memory_cap };
        try policy.validate();
        return policy;
    }
    /// Capture options for `capture_inflight` packets: each slot keeps the
    /// default per-packet decoded heap cap and wire cap.
    pub fn captureOptions(self: Options) @import("capture_options.zig").Options {
        const D = @import("capture_options.zig").Options{};
        const n: usize = self.capture_inflight;
        return .{ .max_inflight_packets = self.capture_inflight, .packet_heap_bytes = D.packet_heap_bytes, .max_inflight_packet_heap_bytes = n * D.packet_heap_bytes, .max_inflight_wire_bytes = n * D.max_inflight_wire_bytes };
    }
    pub fn producerOnly(self: Options) bool {
        return self.jobs != null or self.batch_set or self.keep_capture_cache or self.lane_workers_len != 0 or self.memory_cap_set or self.park_retained_main or self.prefetch_main_set or self.no_ls_dword or self.capture_inflight_set or self.keccak_throughput_v1 or self.keccak_pair29;
    }
};
test "operational jobs and batch parsing cannot silently broaden the worker budget" {
    const args = [_][:0]const u8{ "tool", "produce", "--proof-jobs=2", "--commit-batch-columns=8" };
    var mutable: [args.len][:0]u8 = undefined;
    for (args, &mutable) |value, *target| target.* = @constCast(value);
    const options = try Options.parse(&mutable);
    try std.testing.expectEqual(@as(usize, 2), options.count);
    try std.testing.expectEqual(@as(u32, 8), options.batch);
    try std.testing.expectError(error.InvalidWorkerBudget, options.schedule(1));
    try std.testing.expectEqual(@as(u8, 8), (try options.schedule(16)).workers_per_lane);
}

test "fixed native cache is a bounded receiver operational budget with an explicit disabled control" {
    var defaults = [_][:0]u8{ @constCast("tool"), @constCast("verify"), @constCast("config"), @constCast("proof") };
    try std.testing.expectEqual(@as(usize, 256 << 20), (try Options.parse(&defaults)).fixed_native_cache_bytes);
    var disabled = [_][:0]u8{ @constCast("tool"), @constCast("verify"), @constCast("config"), @constCast("proof"), @constCast("--fixed-native-cache-bytes=0") };
    const options = try Options.parse(&disabled);
    try std.testing.expectEqual(@as(usize, 4), options.count);
    try std.testing.expectEqual(@as(usize, 0), options.fixed_native_cache_bytes);
    try std.testing.expect(!options.producerOnly());
}
test "fixed native cache refuses duplicate undersized and excessive budgets before loading input" {
    var args = [_][:0]u8{ @constCast("tool"), @constCast("--fixed-native-cache-bytes=0"), @constCast("--fixed-native-cache-bytes=4096") };
    try std.testing.expectError(error.DuplicateOperationalOption, Options.parse(&args));
    for ([_][:0]const u8{ "--fixed-native-cache-bytes=1", "--fixed-native-cache-bytes=1073741825" }) |bad| {
        var one = [_][:0]u8{ @constCast("tool"), @constCast(bad) };
        try std.testing.expectError(error.InvalidFixedNativeCacheBudget, Options.parse(&one));
    }
}

test "program metadata budget is bounded operational state independent of receiver authority" {
    var defaults = [_][:0]u8{ @constCast("tool"), @constCast("verify") };
    try std.testing.expectEqual(@as(usize, 64 << 20), (try Options.parse(&defaults)).program_metadata_cache_bytes);
    var args = [_][:0]u8{ @constCast("tool"), @constCast("verify"), @constCast("--program-metadata-cache-bytes=0") };
    const options = try Options.parse(&args);
    try std.testing.expectEqual(@as(usize, 2), options.count);
    try std.testing.expectEqual(@as(usize, 0), options.program_metadata_cache_bytes);
    try std.testing.expect(!options.producerOnly());
}
test "program metadata duplicate tiny and excessive cache budgets reject before input allocation" {
    var duplicate = [_][:0]u8{ @constCast("tool"), @constCast("--program-metadata-cache-bytes=0"), @constCast("--program-metadata-cache-bytes=4096") };
    try std.testing.expectError(error.DuplicateOperationalOption, Options.parse(&duplicate));
    for ([_][:0]const u8{ "--program-metadata-cache-bytes=1", "--program-metadata-cache-bytes=1073741825" }) |bad| {
        var args = [_][:0]u8{ @constCast("tool"), @constCast(bad) };
        try std.testing.expectError(error.InvalidProgramMetadataBudget, Options.parse(&args));
    }
}

test "lane list jobs up to four and memory cap are explicit producer-only schedule controls" {
    var defaults = [_][:0]u8{ @constCast("tool"), @constCast("produce") };
    const plain = try Options.parse(&defaults);
    const policy = try plain.schedule(16);
    try std.testing.expectEqual(@as(u8, 2), policy.lanes);
    try std.testing.expectEqual(@as(u8, 8), policy.workers_per_lane);
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, policy.lane_workers);
    try std.testing.expectEqual(@as(u64, 0), policy.memory_cap_bytes);
    var four = [_][:0]u8{ @constCast("tool"), @constCast("produce"), @constCast("--proof-jobs=4"), @constCast("--proof-memory-cap=1000") };
    const jobs = try Options.parse(&four);
    try std.testing.expect(jobs.producerOnly());
    const p4 = try jobs.schedule(24);
    try std.testing.expectEqual(@as(u8, 4), p4.lanes);
    try std.testing.expectEqual(@as(u8, 6), p4.workers_per_lane);
    try std.testing.expectEqual(@as(u64, 1000), p4.memory_cap_bytes);
    var listed = [_][:0]u8{ @constCast("tool"), @constCast("produce"), @constCast("--lane-workers=6,6,4") };
    const lanes = try Options.parse(&listed);
    try std.testing.expectEqual(@as(usize, 2), lanes.count);
    const p3 = try lanes.schedule(16);
    try std.testing.expectEqual(@as(u8, 3), p3.lanes);
    try std.testing.expectEqual(@as(u8, 4), p3.workers(2));
    var five = [_][:0]u8{ @constCast("tool"), @constCast("--proof-jobs=5") };
    try std.testing.expectError(error.InvalidServiceSchedule, Options.parse(&five));
    var too_many = [_][:0]u8{ @constCast("tool"), @constCast("--lane-workers=8,8,8,8,1") };
    try std.testing.expectError(error.InvalidServiceSchedule, Options.parse(&too_many));
    var over = [_][:0]u8{ @constCast("tool"), @constCast("--lane-workers=16,16,1") };
    try std.testing.expectError(error.InvalidServiceSchedule, (try Options.parse(&over)).schedule(16));
    var mismatch = [_][:0]u8{ @constCast("tool"), @constCast("--proof-jobs=2"), @constCast("--lane-workers=8,8,8") };
    try std.testing.expectError(error.InvalidServiceSchedule, (try Options.parse(&mismatch)).schedule(16));
    var zero = [_][:0]u8{ @constCast("tool"), @constCast("--lane-workers=8,0") };
    try std.testing.expectError(error.InvalidServiceSchedule, Options.parse(&zero));
}

test "retained MAIN parking is an explicit producer-only operational opt-in" {
    var defaults = [_][:0]u8{ @constCast("tool"), @constCast("produce") };
    try std.testing.expect(!(try Options.parse(&defaults)).park_retained_main);
    var enabled = [_][:0]u8{ @constCast("tool"), @constCast("produce"), @constCast("--park-retained-main") };
    const options = try Options.parse(&enabled);
    try std.testing.expect(options.park_retained_main and options.producerOnly());
    try std.testing.expectEqual(@as(usize, 2), options.count);
    var duplicate = [_][:0]u8{ @constCast("tool"), @constCast("--park-retained-main"), @constCast("--park-retained-main") };
    try std.testing.expectError(error.DuplicateOperationalOption, Options.parse(&duplicate));
}

test "Retained MAIN prefetch has an explicit bounded producer-only cap and is off by default" {
    var defaults = [_][:0]u8{ @constCast("tool"), @constCast("produce") };
    try std.testing.expectEqual(@as(usize, 0), (try Options.parse(&defaults)).prefetch_main_bytes);
    var flags = [_][:0]u8{ @constCast("tool"), @constCast("produce"), @constCast("--prefetch-retained-main-bytes=268435456") };
    const options = try Options.parse(&flags);
    try std.testing.expectEqual(@as(usize, 256 << 20), options.prefetch_main_bytes);
    try std.testing.expect(options.producerOnly());
    for ([_][:0]const u8{ "--prefetch-retained-main-bytes=1", "--prefetch-retained-main-bytes=4294967297" }) |bad| {
        var one = [_][:0]u8{ @constCast("tool"), @constCast(bad) };
        try std.testing.expectError(error.InvalidRetainedMainPrefetchCap, Options.parse(&one));
    }
    var duplicate = [_][:0]u8{ @constCast("tool"), @constCast("--prefetch-retained-main-bytes=0"), @constCast("--prefetch-retained-main-bytes=0") };
    try std.testing.expectError(error.DuplicateOperationalOption, Options.parse(&duplicate));
}

test "keccak throughput-v1 truth fallback is an explicit producer-only planning option" {
    var defaults = [_][:0]u8{ @constCast("tool"), @constCast("produce") };
    try std.testing.expect(!(try Options.parse(&defaults)).keccak_throughput_v1);
    var enabled = [_][:0]u8{ @constCast("tool"), @constCast("produce"), @constCast("--keccak-throughput-v1") };
    const options = try Options.parse(&enabled);
    try std.testing.expect(options.keccak_throughput_v1 and options.producerOnly());
    try std.testing.expectEqual(@as(usize, 2), options.count);
    var duplicate = [_][:0]u8{ @constCast("tool"), @constCast("--keccak-throughput-v1"), @constCast("--keccak-throughput-v1") };
    try std.testing.expectError(error.DuplicateOperationalOption, Options.parse(&duplicate));
}
test "keccak pair29 truth slot fallback is an explicit producer-only planning option" {
    var defaults = [_][:0]u8{ @constCast("tool"), @constCast("produce") };
    try std.testing.expect(!(try Options.parse(&defaults)).keccak_pair29);
    var enabled = [_][:0]u8{ @constCast("tool"), @constCast("produce"), @constCast("--keccak-pair29") };
    const options = try Options.parse(&enabled);
    try std.testing.expect(options.keccak_pair29 and options.producerOnly() and !options.keccak_throughput_v1);
    var duplicate = [_][:0]u8{ @constCast("tool"), @constCast("--keccak-pair29"), @constCast("--keccak-pair29") };
    try std.testing.expectError(error.DuplicateOperationalOption, Options.parse(&duplicate));
}
