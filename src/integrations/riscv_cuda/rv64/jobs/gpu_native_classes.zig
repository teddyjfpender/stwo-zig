//! Install-owned class plans and sealed request-time lookups.
const std = @import("std");
const Check = @import("gpu_native_protocol.zig").Check;
const DeviceBuffer = @import("resources.zig").DeviceBuffer;

pub const ClassKey = [32]u8;

pub const Phase = enum { warm, request };

/// One cached class: host plan (opaque, owned by the stream that built it)
/// plus device-resident regions on each GPU that kernels read.
pub const ClassEntry = struct {
    key: ClassKey,
    /// Stream-owned host plan (component Sets, mask points, PcsJob framing,
    /// composition/INTER plans, outer node tapes, ...). Never mutated after warm.
    plan: *anyopaque,
    destroy: *const fn (*anyopaque) void,
    /// Device-resident constants per GPU (twiddles, FIXED trees, class tapes,
    /// directory prefixes); `null` on a GPU the class never runs on.
    device: [max_devices]?DeviceBuffer = @splat(null),
    /// Proof spec constants the driver plans the slab from.
    max_encoded_bytes: usize = 0,
    extra_checks: []const Check = &.{},
    /// Captured whole-job CUDA graph executable per GPU (opaque; null = direct
    /// enqueue). A graph that bakes arena or main_resident addresses is
    /// captured in the factory's `installed` hook, never in `warm`.
    graph: [max_devices]?*anyopaque = @splat(null),
    /// Native segment classes: MAIN words kept resident witness -> PCS (the
    /// driver carves them from the main_resident region; 0 = none).
    main_resident_words: usize = 0,
    /// Measured arena peak of one job of this class (plan.zig sweep).
    arena_peak_words: usize = 0,
    /// Smaller pre-seal producer when a two-stage class completes in phase B.
    phase_a_peak_words: usize = 0,
    /// Native segment classes: secure-felt claim blocks this segment publishes.
    claims_per_segment: u32 = 0,
    /// Estimated device time of one job of this class (placement weight only).
    cost_us: u64 = 1,
    /// The class runs after the plan's phase flip (folds, root): its arena
    /// peak is budgeted against phase B (arena + main_resident), not phase A.
    phase_b: bool = false,
    /// Device words per GPU the factory holds for this class OUTSIDE
    /// `device` (FIXED trees, statics, tapes it allocated itself). The memory
    /// plan reserves them; a factory that holds device memory and reports 0
    /// here makes the plan overcommit the device.
    held_words: [max_devices]u64 = @splat(0),
    /// Native segment classes: pinned capture words one segment holds in the
    /// capture ring until its Stage1 runs (0 = no ring use). The driver
    /// refuses a request whose ring cannot hold one segment of the class
    /// (a segment larger than the ring would deadlock its own capture).
    capture_words: u64 = 0,
    /// Native segment classes: upper bound of this segment's share of the
    /// stage-one bytes (`stage-one.bin`) that the native seal job encodes
    /// into the request pseudo-proof's encoded region. The driver sizes that
    /// region as `stage_one_base_bytes` + the sum over the request's segments
    /// (D2 golden stage-one.bin: 487,244 B for 4 segments, 823,416 B for 7 [M]).
    stage_one_bytes: usize = 0,
    /// Install bound of the length-prefixed local-GKR child encoding.
    local_gkr_wire_words: usize = 0,
    /// Truth classes whose inputs (capture advice) are final only once the
    /// capture ends: the driver gates the job on the capture's `done`.
    needs_capture_end: bool = false,
};

/// Fixed part of the stage-one region capacity, added to the per-segment
/// `ClassEntry.stage_one_bytes` sum [default, a bound, not a measurement].
pub const stage_one_base_bytes: usize = 64 << 10;

pub const max_devices = 4;

/// Thread-safe map from class key to entry. In `.request` phase a miss is an
/// error (a class must be warmed at install time): that is how "never per
/// request" is enforced rather than hoped for.
pub const ClassCache = struct {
    a: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    map: std.AutoHashMapUnmanaged(ClassKey, *ClassEntry) = .empty,
    phase: Phase = .warm,
    builds: u64 = 0,
    request_misses: u64 = 0,

    pub const Builder = struct {
        ctx: *anyopaque,
        build: *const fn (*anyopaque, std.mem.Allocator, ClassKey) anyerror!ClassEntry,
    };

    pub fn init(a: std.mem.Allocator) ClassCache {
        return .{ .a = a };
    }
    pub fn deinit(self: *ClassCache) void {
        var it = self.map.valueIterator();
        while (it.next()) |e| {
            e.*.destroy(e.*.plan);
            self.a.destroy(e.*);
        }
        self.map.deinit(self.a);
    }
    /// Close the warm phase: from now on every lookup must hit.
    pub fn seal(self: *ClassCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.phase = .request;
    }
    /// Re-open warm (a new class mix discovered at install, never mid-request).
    pub fn reopen(self: *ClassCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.phase = .warm;
    }
    pub fn get(self: *ClassCache, key: ClassKey) !*const ClassEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.map.get(key)) |e| return e;
        self.request_misses += 1;
        return error.GpuNativeClassNotWarmed;
    }
    /// Warm phase only: build (once) and insert.
    pub fn warm(self: *ClassCache, key: ClassKey, builder: Builder) !*const ClassEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.map.get(key)) |e| return e;
        if (self.phase != .warm) {
            self.request_misses += 1;
            return error.GpuNativeClassBuildOnRequestPath;
        }
        const entry = try self.a.create(ClassEntry);
        errdefer self.a.destroy(entry);
        entry.* = try builder.build(builder.ctx, self.a, key);
        errdefer entry.destroy(entry.plan);
        if (!std.mem.eql(u8, &entry.key, &key)) return error.GpuNativeClassKeyMismatch;
        try self.map.put(self.a, key, entry);
        self.builds += 1;
        return entry;
    }
    pub fn count(self: *ClassCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.count();
    }
};

const Built = struct {
    var destroyed: u32 = 0;
    var mismatch = false;
    fn destroy(_: *anyopaque) void {
        destroyed += 1;
    }
    fn build(_: *anyopaque, _: std.mem.Allocator, key: ClassKey) anyerror!ClassEntry {
        var actual = key;
        if (mismatch) actual[0] ^= 1;
        return .{ .key = actual, .plan = @ptrFromInt(0x1000), .destroy = destroy, .max_encoded_bytes = 77 };
    }
};

test "class cache: built once at warm, a request-path miss fails closed" {
    var c = ClassCache.init(std.testing.allocator);
    Built.destroyed = 0;
    var dummy: u8 = 0;
    const b = ClassCache.Builder{ .ctx = &dummy, .build = Built.build };
    const k1: ClassKey = @splat(1);
    const k2: ClassKey = @splat(2);
    const e1 = try c.warm(k1, b);
    try std.testing.expectEqual(e1, try c.warm(k1, b));
    try std.testing.expectEqual(@as(u64, 1), c.builds);
    c.seal();
    try std.testing.expectEqual(e1, try c.get(k1));
    try std.testing.expectError(error.GpuNativeClassNotWarmed, c.get(k2));
    try std.testing.expectError(error.GpuNativeClassBuildOnRequestPath, c.warm(k2, b));
    try std.testing.expectEqual(@as(u64, 2), c.request_misses);
    c.deinit();
    try std.testing.expectEqual(@as(u32, 1), Built.destroyed);
}

test "class cache: failed insertion and key mismatch destroy the built plan once" {
    defer Built.mismatch = false;
    for ([_]bool{ false, true }) |mismatch| {
        Built.destroyed = 0;
        Built.mismatch = mismatch;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
        var cache = ClassCache.init(failing.allocator());
        const result = cache.warm(@splat(1), .{ .ctx = &Built.destroyed, .build = Built.build });
        try std.testing.expectError(if (mismatch) error.GpuNativeClassKeyMismatch else error.OutOfMemory, result);
        cache.deinit();
        try std.testing.expectEqual(@as(u32, 1), Built.destroyed);
    }
}
