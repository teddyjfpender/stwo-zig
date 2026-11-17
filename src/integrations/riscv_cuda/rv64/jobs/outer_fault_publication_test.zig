//! Actual Driver/Worker publication on host-model devices; no CUDA/proof claim.
const std = @import("std");
const T = @import("driver_fixture_test.zig");
const F = @import("fake.zig");
const G = @import("gpu_native.zig");
const api = @import("api.zig");
const Seed = @import("outer_seed_device.zig");
const Authority = @import("outer_fault_authority_test.zig");
const a = std.testing.allocator;

fn gnVerdict(inject: bool) !u32 {
    var c0: Seed.Synthetic = undefined;
    try c0.init(a, 1, 128);
    defer c0.deinit(a);
    var c1: Seed.Synthetic = undefined;
    try c1.init(a, 2, 128);
    defer c1.deinit(a);
    const classes = [_]Seed.ChildClass{
        .{ .shape = c0.shape, .wire_words = 128, .n_outputs = 2, .identity = @splat(7), .fixed_root = @splat(0) },
        .{ .shape = c1.shape, .wire_words = 128, .n_outputs = 2, .identity = @splat(7), .fixed_root = @splat(0) },
    };
    const tape = try Seed.tapeLength(&classes, 3, a);
    const vars = try a.alloc(u32, tape + 1);
    defer a.free(vars);
    for (vars, 0..) |*word, i| word.* = @intCast(1000 + i);
    const constants = [_][4]u32{.{ 1, 2, 3, 4 }};
    const program = try Seed.buildFold(a, &classes, 3, vars, &constants, null);
    defer program.deinit(a);
    const scratch = try a.alloc(u32, program.header(Seed.P.scratch_words) + 8);
    defer a.free(scratch);
    const output = try a.alloc(u32, 5 * vars.len);
    defer a.free(output);
    const regions = [_][]const u32{ c0.region, c1.region };
    try std.testing.expectEqual(@as(u32, 0), Seed.fillHost(program, &regions, scratch, output));
    if (inject) {
        const layout = try Seed.Layout.of(c0.shape);
        const at = 128 + layout.trees[1].paths; // exact retired runtime +0, not existing +3
        const before = c0.region[at];
        c0.region[at] ^= 1;
        try std.testing.expectEqual(before ^ 1, c0.region[at]);
    }
    const verdict = Seed.fillHost(program, &regions, scratch, output);
    if (inject) {
        const prefix = @as(u32, 0x0305) << 16;
        try std.testing.expect(verdict == prefix | @intFromEnum(Seed.SeedDetail.cap_mismatch) or verdict == prefix | @intFromEnum(Seed.SeedDetail.cap_root));
    }
    return verdict;
}

const Oracle = struct {
    family: enum { pcs, lookup, gn },
    inject: bool = true,
    pcs: Authority.Pcs,
    calls: usize = 0,
    fn run(raw: *anyopaque, e: *api.Enqueue, id: G.ProofId) !?T.NodeRejection {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (id.kind != .leaf or id.ordinal != 0) return null;
        self.calls += 1;
        const verdict = switch (self.family) {
            .pcs => try self.pcs.run(a, e, self.inject),
            .lookup => try Authority.lookup(self.inject),
            .gn => try gnVerdict(self.inject),
        };
        if (self.inject) try std.testing.expect(verdict != G.Verdict.accepted) else try std.testing.expectEqual(G.Verdict.accepted, verdict);
        return if (verdict == G.Verdict.accepted) null else .{
            .check = switch (self.family) {
                .pcs => .node_pcs_status,
                .lookup => .lookup_sum,
                .gn => .seed_tape,
            },
            .verdict = verdict,
        };
    }
};

fn expectEmpty(dir: std.fs.Dir) !void {
    var it = dir.iterate();
    try std.testing.expect(try it.next() == null);
}

fn runFamily(family: @FieldType(Oracle, "family"), request_id: u64) !void {
    F.reset();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var oracle = Oracle{ .family = family, .pcs = try Authority.Pcs.init(a) };
    defer oracle.pcs.deinit(a);
    var world = T.World{ .a = a, .node_oracle = .{ .ctx = &oracle, .run = Oracle.run } };
    {
        var rig = try T.Rig.init(&world);
        defer rig.deinit();
        var request = T.request(request_id);
        request.out = tmp.dir;
        try std.testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&request));
        try std.testing.expectEqual(@as(usize, 1), oracle.calls);
        try std.testing.expectEqual([2]usize{ 0, 0 }, world.published);
        try expectEmpty(tmp.dir);
        // An accepted retry through the same workers/slabs cannot inherit rejection.
        world.reset();
        oracle.inject = false;
        request.id += 1;
        var accepted = try rig.driver.serve(&request);
        defer accepted.deinit();
        try std.testing.expectEqual(@as(usize, 9), accepted.proofs.len);
        try std.testing.expectEqual(@as(usize, 2), oracle.calls);
        try std.testing.expectEqual([2]usize{ 1, 1 }, world.published);
        const file = try tmp.dir.openFile("recursion-om31/root.proof", .{});
        defer file.close();
        try std.testing.expect((try file.stat()).size != 0);
    }
    try std.testing.expectEqual(@as(usize, 0), F.counters.bad_frees);
    try std.testing.expectEqual(@as(usize, 0), F.counters.bad_event_destroys);
    try std.testing.expectEqual(@as(usize, 0), F.liveEvents());
}

test "D1 fault migration: real PCS mutation and host encoder refuse atomic publication then retry" {
    try runFamily(.pcs, 1901);
}
test "D1 fault migration: canonical lookup mutation refuses atomic publication then retry" {
    try runFamily(.lookup, 1911);
}
test "D1 fault migration: exact first MAIN path mutation refuses publication then retry" {
    try runFamily(.gn, 1921);
}

test "D1 fault migration: preflight refusal aborts owned jobs without publishing and permits retry" {
    F.reset();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var world = T.World{ .a = a, .refuse_node_ordinal = 0 };
    {
        var rig = try T.Rig.init(&world);
        defer rig.deinit();
        var request = T.request(1931);
        request.out = tmp.dir;
        try std.testing.expectError(error.M8OuterInjectedFault, rig.driver.serve(&request));
        try std.testing.expect(world.aborted > 0);
        try std.testing.expectEqual([2]usize{ 0, 0 }, world.published);
        try expectEmpty(tmp.dir);
        world.refuse_node_ordinal = 99; // a nonmatching typed ordinal cannot refuse this request
        world.reset();
        request.id += 1;
        var accepted = try rig.driver.serve(&request);
        defer accepted.deinit();
        try std.testing.expectEqual([2]usize{ 1, 1 }, world.published);
    }
    try std.testing.expectEqual(@as(usize, 0), F.counters.bad_frees);
    try std.testing.expectEqual(@as(usize, 0), F.liveEvents());
}

test "D1 fault migration: teardown cancels in-flight fault jobs and releases their lifetime" {
    F.reset();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var oracle = Oracle{ .family = .pcs, .pcs = try Authority.Pcs.init(a) };
    defer oracle.pcs.deinit(a);
    var world = T.World{ .a = a, .node_oracle = .{ .ctx = &oracle, .run = Oracle.run } };
    var rig = try T.Rig.init(&world);
    var request = T.request(1941);
    request.out = tmp.dir;
    _ = try rig.driver.begin(&request);
    rig.deinit();
    try std.testing.expectEqual(@as(usize, 13), world.aborted);
    try std.testing.expectEqual([2]usize{ 0, 0 }, world.published);
    try expectEmpty(tmp.dir);
    try std.testing.expectEqual(@as(usize, 0), F.counters.bad_frees);
    try std.testing.expectEqual(@as(usize, 0), F.counters.bad_event_destroys);
    try std.testing.expectEqual(@as(usize, 0), F.liveEvents());
}
