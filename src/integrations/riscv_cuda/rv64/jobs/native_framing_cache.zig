//! M8 GPU-native per-class Stage-2 framing cache (rv64-m8-gpu-native.md §3.1,
//! inventory H9; stream native).
//!
//! Stage-2 host framing (component views -> mask points, PcsJob.prepare with
//! its FFT/FRI coordinate sections, the composition and INTER plans, the
//! global-interaction plans) was rebuilt for every segment of every request:
//! 0.27-1.21 s per segment [M] (native-hybrid diagnostic-timing.json). All of
//! it is a function of the segment's class geometry except a few request words
//! (composition role parameters/hc rows, global shared challenges, the PCS
//! scope identity and expected roots), which the owner rebinds on checkout.
//!
//! The pool hands out an instance EXCLUSIVELY (checkout ... checkin): a framing
//! carries per-job mutable state (staged device views, PCS column bindings), so
//! two jobs in flight never share one; a busy class builds another instance
//! (bounded per class). Instances are keyed by a SHA-256 class key the owner
//! derives from everything the framing builders read (`Key`).
//!
//! Policy (STWO_RV64_M8_NATIVE_FRAMING_CACHE, default off):
//!   unset / 0  build per segment (today's path, byte for byte)
//!   1          cache: build on a class miss, rebind on a hit
//!   check      cache AND build fresh on every hit, compare, fail closed on any
//!              difference (the N1 acceptance mode; host cost is not saved)
//!
//! Under the GPU-native driver (ClassCache phase `request`) a miss is an error
//! (`GpuNativeClassNotWarmed`): `Pool.seal` gives the same contract here.
//! Pure host; no device access; lint-clean (no owner-path imports).
const std = @import("std");

pub const Policy = enum { off, on, check };

pub fn policyFromEnv() !Policy {
    return .off;
}
pub fn parsePolicy(v: []const u8) !Policy {
    if (v.len == 0 or std.mem.eql(u8, v, "0")) return .off;
    if (std.mem.eql(u8, v, "1")) return .on;
    if (std.mem.eql(u8, v, "check")) return .check;
    return error.InvalidM8NativeFramingCacheEnvironment;
}

pub const ClassKey = [32]u8;

/// Incremental class-key builder: callers feed every input of the framing
/// builders (geometry only, never request values). Domain-separated, with
/// length-prefixed slices so adjacent fields cannot alias.
pub const Key = struct {
    h: std.crypto.hash.sha2.Sha256,
    pub fn init(domain: []const u8) Key {
        var k = Key{ .h = std.crypto.hash.sha2.Sha256.init(.{}) };
        k.bytes(domain);
        return k;
    }
    pub fn int(self: *Key, v: anytype) void {
        const x: u64 = @intCast(v);
        self.h.update(std.mem.asBytes(&x));
    }
    pub fn bytes(self: *Key, b: []const u8) void {
        self.int(b.len);
        self.h.update(b);
    }
    pub fn ints(self: *Key, comptime T: type, values: []const T) void {
        self.int(values.len);
        for (values) |v| self.int(v);
    }
    /// Deep hash of plain data (ints, bools, enums, structs, tagged unions,
    /// optionals, arrays, slices of those): field by field, never raw struct
    /// bytes (padding would make the key nondeterministic).
    pub fn value(self: *Key, v: anytype) void {
        const T = @TypeOf(v);
        switch (@typeInfo(T)) {
            .int, .comptime_int => self.int(v),
            .bool => self.int(@intFromBool(v)),
            .@"enum" => self.int(@intFromEnum(v)),
            .optional => if (v) |x| {
                self.int(1);
                self.value(x);
            } else self.int(0),
            .array => for (v) |x| self.value(x),
            .pointer => |p| {
                if (p.size != .slice) @compileError("Key.value: only slices are hashed, not pointers");
                self.int(v.len);
                for (v) |x| self.value(x);
            },
            .@"struct" => |s| inline for (s.fields) |f| self.value(@field(v, f.name)),
            .@"union" => |u| {
                if (u.tag_type == null) @compileError("Key.value: untagged union");
                self.int(@intFromEnum(std.meta.activeTag(v)));
                switch (v) {
                    inline else => |x| self.value(x),
                }
            },
            .void => {},
            else => @compileError("Key.value: unsupported type " ++ @typeName(T)),
        }
    }
    pub fn final(self: *Key) ClassKey {
        return self.h.finalResult();
    }
};

pub const Stats = struct {
    hits: u64 = 0,
    misses: u64 = 0,
    builds: u64 = 0,
    busy_builds: u64 = 0,
    evictions: u64 = 0,
    sealed_misses: u64 = 0,
};

/// Exclusive-checkout pool of `T` instances per class key. `T` must have
/// `fn destroy(*T) void` (frees the instance and its allocation).
pub fn Pool(comptime T: type) type {
    return struct {
        const Self = @This();
        const Slot = struct { key: ClassKey, value: *T, busy: bool, last_use: u64 };

        a: std.mem.Allocator,
        mutex: std.Thread.Mutex = .{},
        slots: std.ArrayListUnmanaged(Slot) = .empty,
        /// Bound on instances across all classes (idle ones are evicted LRU).
        max_instances: usize,
        /// Bound on instances of ONE class (jobs in flight per class).
        max_per_class: usize,
        sealed: bool = false,
        clock: u64 = 0,
        stats: Stats = .{},

        pub fn init(a: std.mem.Allocator, max_instances: usize, max_per_class: usize) Self {
            return .{ .a = a, .max_instances = @max(max_instances, 1), .max_per_class = @max(max_per_class, 1) };
        }
        pub fn deinit(self: *Self) void {
            for (self.slots.items) |s| s.value.destroy();
            self.slots.deinit(self.a);
            self.* = undefined;
        }
        /// After warm: a class miss is an error from now on (never a build on
        /// the request path).
        pub fn seal(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.sealed = true;
        }

        pub const Checkout = union(enum) {
            /// An idle cached instance, now exclusively the caller's.
            hit: *T,
            /// No idle instance: the caller builds one and `insert`s it.
            miss,
        };
        pub fn checkout(self: *Self, key: ClassKey) !Checkout {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.clock += 1;
            var known = false;
            for (self.slots.items) |*s| if (std.mem.eql(u8, &s.key, &key)) {
                known = true;
                if (!s.busy) {
                    s.busy = true;
                    s.last_use = self.clock;
                    self.stats.hits += 1;
                    return .{ .hit = s.value };
                }
            };
            if (self.sealed) {
                self.stats.sealed_misses += 1;
                return error.GpuNativeClassNotWarmed;
            }
            self.stats.misses += 1;
            if (known) self.stats.busy_builds += 1;
            return .miss;
        }
        /// Register a freshly built instance as checked out by the caller.
        /// When the pool is full, the least recently used idle instance is
        /// destroyed; when nothing is idle (or the class is at its bound), the
        /// instance is not cached: the caller keeps ownership (returns false)
        /// and destroys it after use.
        pub fn insert(self: *Self, key: ClassKey, value: *T) !bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.stats.builds += 1;
            var same: usize = 0;
            for (self.slots.items) |s| same += @intFromBool(std.mem.eql(u8, &s.key, &key));
            if (same >= self.max_per_class) return false;
            if (self.slots.items.len >= self.max_instances) {
                var victim: ?usize = null;
                for (self.slots.items, 0..) |s, i| if (!s.busy and (victim == null or s.last_use < self.slots.items[victim.?].last_use)) {
                    victim = i;
                };
                const v = victim orelse return false;
                self.slots.items[v].value.destroy();
                _ = self.slots.swapRemove(v);
                self.stats.evictions += 1;
            }
            self.clock += 1;
            try self.slots.append(self.a, .{ .key = key, .value = value, .busy = true, .last_use = self.clock });
            return true;
        }
        /// Return a checked-out instance (from `hit`, or an `insert`ed one).
        pub fn checkin(self: *Self, value: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (self.slots.items) |*s| if (s.value == value) {
                std.debug.assert(s.busy);
                s.busy = false;
                return;
            };
            unreachable; // not ours: the caller owns it (insert returned false)
        }
        /// Drop a checked-out instance that failed its rebind/check (it may be
        /// partially rebound): destroyed, never handed out again.
        pub fn discard(self: *Self, value: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (self.slots.items, 0..) |s, i| if (s.value == value) {
                _ = self.slots.swapRemove(i);
                value.destroy();
                return;
            };
            unreachable;
        }
        pub fn count(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.slots.items.len;
        }
        pub fn snapshot(self: *Self) Stats {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.stats;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests (host)

const Probe = struct {
    a: std.mem.Allocator,
    id: u32,
    destroyed: *u32,
    fn make(a: std.mem.Allocator, id: u32, destroyed: *u32) !*Probe {
        const p = try a.create(Probe);
        p.* = .{ .a = a, .id = id, .destroyed = destroyed };
        return p;
    }
    pub fn destroy(self: *Probe) void {
        self.destroyed.* += 1;
        self.a.destroy(self);
    }
};

fn keyOf(n: u8) ClassKey {
    var k = Key.init("test");
    k.int(n);
    return k.final();
}

test "policy parsing" {
    try std.testing.expectEqual(Policy.off, try parsePolicy("0"));
    try std.testing.expectEqual(Policy.off, try parsePolicy(""));
    try std.testing.expectEqual(Policy.on, try parsePolicy("1"));
    try std.testing.expectEqual(Policy.check, try parsePolicy("check"));
    try std.testing.expectError(error.InvalidM8NativeFramingCacheEnvironment, parsePolicy("yes"));
}

test "class key separates adjacent slices and domains" {
    var x = Key.init("d");
    x.ints(u32, &.{ 1, 2 });
    x.ints(u32, &.{3});
    var y = Key.init("d");
    y.ints(u32, &.{1});
    y.ints(u32, &.{ 2, 3 });
    var z = Key.init("e");
    z.ints(u32, &.{ 1, 2 });
    z.ints(u32, &.{3});
    const kx = x.final();
    try std.testing.expect(!std.mem.eql(u8, &kx, &y.final()));
    try std.testing.expect(!std.mem.eql(u8, &kx, &z.final()));
}

test "deep value hashing covers tagged unions, optionals and nested structs" {
    const Origin = union(enum) { core: enum { a, b }, dword: u1 };
    const Slot = struct { origin: Origin, log: u32, binding: ?usize };
    const slots_a = [_]Slot{ .{ .origin = .{ .core = .b }, .log = 5, .binding = null }, .{ .origin = .{ .dword = 1 }, .log = 6, .binding = 2 } };
    var slots_b = slots_a;
    var x = Key.init("v");
    x.value(@as([]const Slot, &slots_a));
    const kx = x.final();
    var y = Key.init("v");
    y.value(@as([]const Slot, &slots_b));
    try std.testing.expectEqualSlices(u8, &kx, &y.final());
    slots_b[1].binding = null;
    var z = Key.init("v");
    z.value(@as([]const Slot, &slots_b));
    try std.testing.expect(!std.mem.eql(u8, &kx, &z.final()));
    slots_b = slots_a;
    slots_b[0].origin = .{ .core = .a };
    var w = Key.init("v");
    w.value(@as([]const Slot, &slots_b));
    try std.testing.expect(!std.mem.eql(u8, &kx, &w.final()));
}

test "checkout is exclusive: a busy class builds a second instance" {
    const a = std.testing.allocator;
    var destroyed: u32 = 0;
    var pool = Pool(Probe).init(a, 8, 2);
    defer pool.deinit();
    const k = keyOf(1);
    try std.testing.expect((try pool.checkout(k)) == .miss);
    const p1 = try Probe.make(a, 1, &destroyed);
    try std.testing.expect(try pool.insert(k, p1));
    // p1 is busy: the same class misses again (second job in flight).
    try std.testing.expect((try pool.checkout(k)) == .miss);
    const p2 = try Probe.make(a, 2, &destroyed);
    try std.testing.expect(try pool.insert(k, p2));
    // Third concurrent instance exceeds the per-class bound: not cached.
    try std.testing.expect((try pool.checkout(k)) == .miss);
    const p3 = try Probe.make(a, 3, &destroyed);
    try std.testing.expect(!(try pool.insert(k, p3)));
    p3.destroy();
    pool.checkin(p1);
    const again = try pool.checkout(k);
    try std.testing.expect(again == .hit and again.hit == p1);
    pool.checkin(p1);
    pool.checkin(p2);
    const s = pool.snapshot();
    try std.testing.expectEqual(@as(u64, 1), s.hits);
    try std.testing.expectEqual(@as(u64, 3), s.misses);
    try std.testing.expectEqual(@as(u64, 2), s.busy_builds);
    try std.testing.expectEqual(@as(u32, 1), destroyed);
}

test "LRU eviction of idle instances; busy instances are never evicted" {
    const a = std.testing.allocator;
    var destroyed: u32 = 0;
    var pool = Pool(Probe).init(a, 2, 1);
    defer pool.deinit();
    for (0..2) |i| {
        _ = try pool.checkout(keyOf(@intCast(i)));
        const p = try Probe.make(a, @intCast(i), &destroyed);
        try std.testing.expect(try pool.insert(keyOf(@intCast(i)), p));
        pool.checkin(p);
    }
    // Touch class 0 so class 1 is the LRU victim.
    const h = try pool.checkout(keyOf(0));
    pool.checkin(h.hit);
    _ = try pool.checkout(keyOf(2));
    const p = try Probe.make(a, 2, &destroyed);
    try std.testing.expect(try pool.insert(keyOf(2), p));
    try std.testing.expectEqual(@as(u32, 1), destroyed);
    try std.testing.expect((try pool.checkout(keyOf(1))) == .miss);
    try std.testing.expect((try pool.checkout(keyOf(0))) == .hit);
    // Everything busy now (0 and 2): a new class is built but not cached.
    const q = try Probe.make(a, 9, &destroyed);
    try std.testing.expect(!(try pool.insert(keyOf(1), q)));
    q.destroy();
    for (pool.slots.items) |s| if (s.busy) pool.checkin(s.value);
}

test "sealed pool: a class miss is an error, a hit still works; discard drops an instance" {
    const a = std.testing.allocator;
    var destroyed: u32 = 0;
    var pool = Pool(Probe).init(a, 4, 1);
    defer pool.deinit();
    _ = try pool.checkout(keyOf(5));
    const p = try Probe.make(a, 5, &destroyed);
    _ = try pool.insert(keyOf(5), p);
    pool.checkin(p);
    pool.seal();
    try std.testing.expectError(error.GpuNativeClassNotWarmed, pool.checkout(keyOf(6)));
    const h = try pool.checkout(keyOf(5));
    pool.discard(h.hit);
    try std.testing.expectEqual(@as(u32, 1), destroyed);
    try std.testing.expectEqual(@as(usize, 0), pool.count());
    try std.testing.expectEqual(@as(u64, 1), pool.snapshot().sealed_misses);
}
