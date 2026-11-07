const std = @import("std");
const Plan = @import("plan.zig");
const Task = Plan.Task;
const V4 = [4]u32;

/// Synthetic plan builder in the circuit gadget's variable discipline.
const Builder = struct {
    a: std.mem.Allocator,
    n_vars: u32 = 0,
    tasks: std.ArrayList(Task) = .empty,
    seeds: std.ArrayList(struct { v: u32, x: V4 }) = .empty,
    fn seed(self: *Builder, x: V4) !u32 {
        const v = self.n_vars;
        self.n_vars += 1;
        try self.seeds.append(self.a, .{ .v = v, .x = x });
        return v;
    }
    fn op(self: *Builder, kind: u32, args: []const u32, extra: u32) !u32 {
        const out = self.n_vars;
        self.n_vars += if (kind == 6) 4 else 1;
        var t = Task{ .kind = kind, .out = out };
        @memcpy(t.args[0..args.len], args);
        if (kind == 12 or kind == 13) t.args[1] = extra;
        try self.tasks.append(self.a, t);
        return out;
    }
    /// blake2sU32s over 16 message words (one block): returns 8 h words.
    fn compress(self: *Builder, h: [8]u32, iv: [8]u32, msg: [16]u32) ![8]u32 {
        var v: [16]u32 = undefined;
        @memcpy(v[0..8], &h);
        @memcpy(v[8..16], &iv);
        for (0..10) |r| for (0..8) |g| {
            const s = Plan.g_state[g];
            const out = try self.op(6, &.{ v[s[0]], v[s[1]], v[s[2]], v[s[3]], msg[Plan.sigma[r][2 * g]], msg[Plan.sigma[r][2 * g + 1]] }, 0);
            for (0..4) |j| v[s[j]] = out + @as(u32, @intCast(j));
        };
        var next: [8]u32 = undefined;
        for (0..8) |i| next[i] = try self.op(4, &.{ h[i], v[i], v[i + 8] }, 0);
        return next;
    }
    fn deinit(self: *Builder) void {
        self.tasks.deinit(self.a);
        self.seeds.deinit(self.a);
    }
};

/// Sorts records by longest-path level (the plan builder's order) and
/// returns the level ends.
fn levelize(a: std.mem.Allocator, b: *Builder) ![]u32 {
    const producer = try a.alloc(u32, b.n_vars);
    defer a.free(producer);
    @memset(producer, Plan.none);
    for (b.tasks.items, 0..) |t, i| {
        const n: u32 = if (t.kind == 6) 4 else 1;
        for (0..n) |j| producer[t.out + j] = @intCast(i);
    }
    const level = try a.alloc(u32, b.tasks.items.len);
    defer a.free(level);
    var max: u32 = 0;
    for (b.tasks.items, 0..) |t, i| {
        var l: u32 = 0;
        for (t.args[0..Plan.arity(t.kind)]) |v| if (producer[v] != Plan.none) {
            l = @max(l, level[producer[v]] + 1);
        };
        level[i] = l;
        max = @max(max, l);
    }
    const sorted = try a.alloc(Task, b.tasks.items.len);
    defer a.free(sorted);
    const ends = try a.alloc(u32, max + 1);
    var k: usize = 0;
    for (0..max + 1) |l| {
        for (b.tasks.items, 0..) |t, i| if (level[i] == l) {
            sorted[k] = t;
            k += 1;
        };
        ends[l] = @intCast(k);
    }
    @memcpy(b.tasks.items, sorted);
    return ends;
}

fn runBoth(a: std.mem.Allocator, b: *Builder, options: Plan.Options) !Plan.Stats {
    const ends = try levelize(a, b);
    defer a.free(ends);
    var plan = try Plan.build(a, b.tasks.items, &.{}, b.n_vars, ends, options);
    defer plan.deinit();
    const x = try a.alloc(V4, b.n_vars);
    defer a.free(x);
    const y = try a.alloc(V4, b.n_vars);
    defer a.free(y);
    @memset(x, .{ 0, 0, 0, 0 });
    for (b.seeds.items) |s| x[s.v] = s.x;
    @memcpy(y, x);
    var sx: u32 = 0;
    var sy: u32 = 0;
    Plan.executeDag(b.tasks.items, &.{}, x, &sx);
    Plan.execute(&plan, b.tasks.items, &.{}, y, &sy);
    try std.testing.expectEqual(sx, sy);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(x), std.mem.sliceAsBytes(y));
    return plan.stats;
}

test "rowpar: chained Blake2s compressions fuse to one strand, values identical" {
    const a = std.testing.allocator;
    var b = Builder{ .a = a };
    defer b.deinit();
    var rng = std.Random.DefaultPrng.init(7);
    const r = rng.random();
    var h: [8]u32 = undefined;
    var iv: [8]u32 = undefined;
    for (&h) |*w| w.* = try b.seed(.{ r.int(u16), r.int(u16), 0, 0 });
    for (&iv) |*w| w.* = try b.seed(.{ r.int(u16), r.int(u16), 0, 0 });
    // Four independent chains of 6 blocks (parallel hash chains).
    for (0..4) |_| {
        var state = h;
        for (0..6) |_| {
            var msg: [16]u32 = undefined;
            @memcpy(msg[0..8], &state);
            for (msg[8..]) |*w| w.* = try b.seed(.{ r.int(u16), r.int(u16), 0, 0 });
            state = try b.compress(state, iv, msg);
        }
    }
    const s = try runBoth(a, &b, .{});
    try std.testing.expectEqual(@as(usize, 24), s.blake_units);
    try std.testing.expectEqual(@as(usize, 21 * 6), s.dag_levels);
    // h feeds both the message and the finalisation of the same next unit.
    try std.testing.expectEqual(@as(usize, 4), s.strands);
    try std.testing.expectEqual(@as(usize, 1), s.levels);
}

test "rowpar: Horner accumulation chains become strands, fan-out stays layered" {
    const a = std.testing.allocator;
    var b = Builder{ .a = a };
    defer b.deinit();
    var rng = std.Random.DefaultPrng.init(11);
    const r = rng.random();
    const p = 0x7fffffff;
    const alpha = try b.seed(.{ r.uintLessThan(u32, p), r.uintLessThan(u32, p), r.uintLessThan(u32, p), r.uintLessThan(u32, p) });
    var accs: [16]u32 = undefined;
    for (&accs) |*acc| {
        acc.* = try b.seed(.{ 1, 0, 0, 0 });
        for (0..50) |_| {
            const c = try b.seed(.{ r.uintLessThan(u32, p), r.uintLessThan(u32, p), r.uintLessThan(u32, p), r.uintLessThan(u32, p) });
            const m = try b.op(2, &.{ acc.*, alpha }, 0);
            acc.* = try b.op(0, &.{ m, c }, 0);
        }
    }
    // A reduction over the 16 accumulators plus every hint kind.
    var sum = accs[0];
    for (accs[1..]) |x| sum = try b.op(0, &.{ sum, x }, 0);
    const inv = try b.op(8, &.{sum}, 0);
    const d = try b.op(9, &.{ inv, sum }, 0);
    _ = try b.op(1, &.{ d, alpha }, 0);
    _ = try b.op(3, &.{ inv, alpha }, 0);
    _ = try b.op(10, &.{sum}, 0);
    _ = try b.op(11, &.{sum}, 0);
    const w = try b.op(5, &.{sum}, 0);
    _ = try b.op(12, &.{w}, 2);
    _ = try b.op(13, &.{w}, 3);
    _ = try b.op(14, &.{sum}, 0);
    _ = try b.op(15, &.{}, 0);
    const s = try runBoth(a, &b, .{});
    try std.testing.expectEqual(@as(usize, 0), s.blake_units);
    try std.testing.expect(s.levels < s.dag_levels / 4);
}

test "rowpar: a failing inverse stores nothing and is never forwarded" {
    const a = std.testing.allocator;
    var b = Builder{ .a = a };
    defer b.deinit();
    const z = try b.seed(.{ 0, 0, 0, 0 });
    const one = try b.seed(.{ 1, 0, 0, 0 });
    const inv = try b.op(8, &.{z}, 0);
    _ = try b.op(0, &.{ inv, one }, 0);
    _ = try runBoth(a, &b, .{});
}

test "rowpar: refuses duplicate producers and static failures" {
    const a = std.testing.allocator;
    const tasks = [_]Task{ .{ .kind = 0, .out = 2, .args = .{ 0, 1, 0, 0, 0, 0 } }, .{ .kind = 1, .out = 2, .args = .{ 0, 1, 0, 0, 0, 0 } } };
    try std.testing.expectError(error.RowparDuplicateProducer, Plan.build(a, &tasks, &.{}, 3, &.{ 1, 2 }, .{}));
    const bad = [_]Task{.{ .kind = 6, .out = 1, .args = .{ 0, 0, 0, 0, 0, 0 } }};
    try std.testing.expectError(error.RowparStaticFailure, Plan.build(a, &bad, &.{}, 3, &.{1}, .{}));
    const byte = [_]Task{.{ .kind = 12, .out = 1, .args = .{ 0, 4, 0, 0, 0, 0 } }};
    try std.testing.expectError(error.RowparStaticFailure, Plan.build(a, &byte, &.{}, 3, &.{1}, .{}));
}

test "rowpar: a compression with one miswired G stays plain and exact" {
    const a = std.testing.allocator;
    var b = Builder{ .a = a };
    defer b.deinit();
    var h: [8]u32 = undefined;
    var iv: [8]u32 = undefined;
    var msg: [16]u32 = undefined;
    for (&h, 0..) |*w, i| w.* = try b.seed(.{ @intCast(i), 1, 0, 0 });
    for (&iv, 0..) |*w, i| w.* = try b.seed(.{ @intCast(i + 9), 2, 0, 0 });
    for (&msg, 0..) |*w, i| w.* = try b.seed(.{ @intCast(i + 99), 3, 0, 0 });
    _ = try b.compress(h, iv, msg);
    b.tasks.items[40].args[5] = msg[0] ^ 1; // wrong message word
    const s = try runBoth(a, &b, .{});
    try std.testing.expectEqual(@as(usize, 0), s.blake_units);
}
