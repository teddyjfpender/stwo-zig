//! M8 GPU-native recursion (stream: recursion). Contract: gpu_native.zig
//! RecursionFactory; design: rv64-m8-gpu-native.md §3.3, §6.
//!
//! Landed: the class side. Every recursion class the request layer has
//! planned (a leaf/fold/root authority whose statics and whole-node plan sit
//! in an outer_class_plan.zig slot) is registered here with its proof ids;
//! `warm` publishes one gpu_native.ClassEntry per class into the driver's
//! ClassCache (plan = the class statics, borrowed: the statics cache owns
//! them for the process lifetime), and `class_of` answers from the registry,
//! so after `ClassCache.seal` a node of an unplanned class fails closed
//! (GpuNativeClassNotWarmed) instead of planning on the request path.
//!
//! Not landed (fail closed, error.M8GpuNativeRecursionNotLanded): `truth` and
//! `node` jobs. They need the device seed fill from the children's encoded
//! slab regions, device lookupSum / OODS checks and device om31 encoding; the
//! node body itself is today's OuterNodeJob (outer_job.zig).
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

pub const ClassInfo = struct {
    /// Borrowed class plan (outer_job_prestage Statics.public); never freed here.
    plan: *anyopaque,
    /// Upper bound of the class's encoded proof bytes (0: not yet measured).
    max_encoded_bytes: usize = 0,
    /// GPUs that hold this class's warm state (bit d = device d).
    devices: u8 = 0,
};

pub const Recursion = struct {
    a: std.mem.Allocator = std.heap.c_allocator,
    mutex: std.Thread.Mutex = .{},
    classes: std.AutoHashMapUnmanaged(G.ClassKey, ClassInfo) = .empty,
    ids: std.AutoHashMapUnmanaged(u64, G.ClassKey) = .empty,

    pub fn deinit(self: *Recursion) void {
        self.classes.deinit(self.a);
        self.ids.deinit(self.a);
    }
    fn idKey(id: G.ProofId) u64 {
        return (@as(u64, @intFromEnum(id.kind)) << 32) | id.ordinal;
    }
    /// Request planning / install: proof `id` is of class `key`. A class may be
    /// registered by many ids; its info merges (largest encoded bound, union
    /// of devices). Re-registering an id under another class is refused (a
    /// manifest that moves a proof between classes is a new class mix: warm
    /// again with a fresh registry).
    pub fn register(self: *Recursion, id: G.ProofId, key: G.ClassKey, info: ClassInfo) !void {
        if (id.kind == .request or id.kind == .native_segment) return error.GpuNativeNotARecursionProof;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.classes.get(key)) |known| if (known.plan != info.plan) return error.GpuNativeClassPlanConflict;
        if (self.ids.get(idKey(id))) |known| if (!std.mem.eql(u8, &known, &key)) return error.GpuNativeProofClassChanged;
        try self.ids.put(self.a, idKey(id), key);
        const c = try self.classes.getOrPut(self.a, key);
        if (!c.found_existing) {
            c.value_ptr.* = info;
            return;
        }
        c.value_ptr.max_encoded_bytes = @max(c.value_ptr.max_encoded_bytes, info.max_encoded_bytes);
        c.value_ptr.devices |= info.devices;
    }
    pub fn classCount(self: *Recursion) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.classes.count();
    }

    pub fn factory(self: *Recursion) G.RecursionFactory {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable = G.RecursionFactory.VTable{ .warm = warm, .class_of = classOf, .truth = truth, .node = node };
    fn of(raw: *anyopaque) *Recursion {
        return @ptrCast(@alignCast(raw));
    }

    const Build = struct {
        info: ClassInfo,
        fn build(raw: *anyopaque, _: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
            const self: *Build = @ptrCast(@alignCast(raw));
            return .{ .key = key, .plan = self.info.plan, .destroy = borrowed, .max_encoded_bytes = self.info.max_encoded_bytes };
        }
        fn borrowed(_: *anyopaque) void {}
    };
    fn warm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.classes.iterator();
        while (it.next()) |kv| {
            var b = Build{ .info = kv.value_ptr.* };
            const entry = try cache.warm(kv.key_ptr.*, .{ .ctx = &b, .build = Build.build });
            if (entry.plan != kv.value_ptr.plan) return error.GpuNativeClassPlanConflict;
        }
    }
    fn classOf(raw: *anyopaque, id: G.ProofId) anyerror!G.ClassKey {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ids.get(idKey(id)) orelse error.GpuNativeClassNotWarmed;
    }
    fn truth(_: *anyopaque, _: *const G.RequestContext, _: u32, _: u32) anyerror!api.Job {
        return error.M8GpuNativeRecursionNotLanded;
    }
    fn node(_: *anyopaque, _: *const G.RequestContext, _: G.ProofId, _: []const G.ProofId, _: u32) anyerror!api.Job {
        return error.M8GpuNativeRecursionNotLanded;
    }
};

test "recursion factory: unregistered ids and non-recursion proofs fail closed" {
    var r = Recursion{ .a = std.testing.allocator };
    defer r.deinit();
    const f = r.factory();
    try std.testing.expectError(error.GpuNativeClassNotWarmed, f.vtable.class_of(f.ctx, .{ .kind = .leaf, .ordinal = 0 }));
    try std.testing.expectError(error.GpuNativeNotARecursionProof, r.register(.{ .kind = .native_segment, .ordinal = 0 }, @splat(1), .{ .plan = @ptrCast(&r) }));
}

test "recursion factory warms one ClassEntry per class, then a sealed cache refuses new classes" {
    const t = std.testing;
    var plan_a: u32 = 1;
    var plan_b: u32 = 2;
    var r = Recursion{ .a = t.allocator };
    defer r.deinit();
    const ka: G.ClassKey = @splat(0xa);
    const kb: G.ClassKey = @splat(0xb);
    // Leaves 0..2 share class A, the fold and the root are class B.
    for (0..3) |i| try r.register(.{ .kind = .leaf, .ordinal = @intCast(i) }, ka, .{ .plan = @ptrCast(&plan_a), .max_encoded_bytes = 600_000 + i, .devices = @as(u8, 1) << @intCast(i % 2) });
    try r.register(.{ .kind = .fold, .ordinal = 3 }, kb, .{ .plan = @ptrCast(&plan_b), .max_encoded_bytes = 632_624, .devices = 1 });
    try r.register(.{ .kind = .root, .ordinal = 4 }, kb, .{ .plan = @ptrCast(&plan_b), .max_encoded_bytes = 749_688, .devices = 1 });
    try t.expectEqual(@as(usize, 2), r.classCount());
    // An id cannot move to another class; a class cannot change its plan.
    try t.expectError(error.GpuNativeProofClassChanged, r.register(.{ .kind = .leaf, .ordinal = 0 }, kb, .{ .plan = @ptrCast(&plan_b) }));
    try t.expectError(error.GpuNativeClassPlanConflict, r.register(.{ .kind = .leaf, .ordinal = 9 }, ka, .{ .plan = @ptrCast(&plan_b) }));

    var cache = G.ClassCache.init(t.allocator);
    defer cache.deinit();
    const f = r.factory();
    try f.vtable.warm(f.ctx, &cache);
    try f.vtable.warm(f.ctx, &cache); // idempotent: no second build
    try t.expectEqual(@as(usize, 2), cache.count());
    try t.expectEqual(@as(u64, 2), cache.builds);
    cache.seal();
    const ea = try cache.get(try f.vtable.class_of(f.ctx, .{ .kind = .leaf, .ordinal = 2 }));
    try t.expectEqual(@as(*anyopaque, @ptrCast(&plan_a)), ea.plan);
    try t.expectEqual(@as(usize, 600_002), ea.max_encoded_bytes);
    const eb = try cache.get(try f.vtable.class_of(f.ctx, .{ .kind = .root, .ordinal = 4 }));
    try t.expectEqual(@as(usize, 749_688), eb.max_encoded_bytes);
    // A class registered after the seal is never built on the request path.
    try r.register(.{ .kind = .fold, .ordinal = 7 }, @splat(0xc), .{ .plan = @ptrCast(&plan_a) });
    try t.expectError(error.GpuNativeClassBuildOnRequestPath, f.vtable.warm(f.ctx, &cache));
    try t.expectError(error.GpuNativeClassNotWarmed, cache.get(@splat(0xc)));
    // The job entries are not landed and fail closed.
    try t.expectError(error.M8GpuNativeRecursionNotLanded, f.vtable.node(f.ctx, undefined, .{ .kind = .fold, .ordinal = 3 }, &.{}, 0));
}
