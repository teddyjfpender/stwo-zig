//! Enqueue-only PCS at native-segment scale on a REAL GPU worker versus the
//! base image's production in-process PCS service (stwo_rv64_pcs_native_prove)
//! on the same 17-section request: words must be identical. Records the job's
//! receipt (enqueue / wait / arena peak) next to the legacy device_ns.
//! Opt-in: STWO_RV64_M8_PCS_SCALE=1 plus the GPU env of native_commit_test.zig.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("api.zig");
const W = @import("worker.zig");
const N = @import("native_pcs.zig");
const Abi = @import("../pcs_native_abi.zig");
const Export = @import("../pcs_request_export.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const M = D.M;
const OM = D.O;
const Point = D.Point;

const Group = struct { count: u32, log: u32 };
const trees = [_][]const Group{
    &.{ .{ .count = 12, .log = 12 }, .{ .count = 12, .log = 15 }, .{ .count = 12, .log = 18 }, .{ .count = 12, .log = 21 } }, // FIXED
    &.{ .{ .count = 800, .log = 14 }, .{ .count = 80, .log = 18 }, .{ .count = 16, .log = 21 }, .{ .count = 4, .log = 23 } }, // MAIN
    &.{ .{ .count = 500, .log = 14 }, .{ .count = 90, .log = 18 }, .{ .count = 10, .log = 21 } }, // INTER
    &.{.{ .count = 16, .log = 23 }}, // composition
};
const lifting_log: u32 = 24;
fn masks(tree: usize, column: usize) []const isize {
    if (tree == 1 and column % 7 == 3) return &.{ 0, -1 };
    if (tree == 2 and column % 5 == 1) return &.{ -1, 0 };
    if (tree == 0 and column % 11 == 5) return &.{};
    return &.{0};
}
fn offset(mask: isize) core.circle.CirclePointM31 {
    return core.poly.circle.canonic.CanonicCoset.new(lifting_log - 1).step().mulSigned(mask);
}

const Probe = struct {
    pcs: *N.PcsJob,
    sym: N.Symbols,
    seed: []const u32,
    point: []const u32,
    columns: [trees.len][][]const M,
    staged_seed: ?api.DeviceBuffer = null,
    staged_point: ?api.DeviceBuffer = null,
    staged_columns: [trees.len][]api.DeviceBuffer = undefined,
    pinned: []u32 = &.{},
    coefficient_words: usize,
    result: []u32,
    receipt: api.Receipt = .{},
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(11);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        return .{ .device_words = 5 << 29, .staged_words = self.coefficient_words + 4096, .slab_words = @intCast(self.pcs.outputWords()), .pinned_words = @intCast(self.pcs.ingressWords() + self.coefficient_words + 4096) };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        const sd = try s.alloc(16);
        try s.upload(sd, self.seed);
        self.staged_seed = sd;
        const pt = try s.alloc(16);
        try s.upload(pt, self.point);
        self.staged_point = pt;
        for (self.columns, &self.staged_columns) |cols, *out| for (cols, out.*) |c, *b| {
            b.* = try s.alloc(c.len);
            try s.upload(b.*, @as([*]const u32, @ptrCast(c.ptr))[0..c.len]);
        };
        self.pinned = try s.pinned(@intCast(self.pcs.ingressWords()));
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        for (self.staged_columns, 0..) |bufs, t| for (bufs, 0..) |b, c| try self.pcs.bindColumn(t, c, b.ptr);
        try self.pcs.enqueue(self.sym, e, self.pinned, .{ .seed = self.staged_seed.?.ptr, .point = self.staged_point.?.ptr, .output = e.slab.device.ptr, .output_words = self.pcs.outputWords() });
    }
    pub fn finish(self: *Probe, v: api.SlabView) !void {
        @memcpy(self.result, v.words[0..self.result.len]);
        self.receipt = v.receipt;
    }
    pub fn abort(_: *Probe) void {}
};
const Done = struct {
    n: std.atomic.Value(usize) = .init(0),
    err: ?anyerror = null,
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        if (c.result) |_| {} else |err| self.err = err;
        _ = self.n.fetchAdd(1, .seq_cst);
    }
};

test "GPU scale: enqueue-only PCS equals the production PCS service on a native-segment-sized request" {
    if (std.posix.getenv("STWO_RV64_M8_PCS_SCALE") == null) return error.SkipZigTest;
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.openNamed("native_pcs_scale_test")) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const sym = try N.Symbols.load(&gpu.libs.addon);
    const config = core.pcs.PcsConfig{ .pow_bits = 20, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 54, .fold_step = 4 } };

    var prng = std.Random.DefaultPrng.init(0x7363616c65);
    var host_columns: [trees.len][][]const M = undefined;
    var d_trees: [trees.len]D.Tree = undefined;
    var placeholder_trees: [trees.len]D.Tree = undefined;
    var coefficient_words: usize = 0;
    for (trees, &host_columns, &d_trees, &placeholder_trees) |groups, *hc, *dt, *pt| {
        var n: usize = 0;
        for (groups) |g| n += g.count;
        const cols = try ar.alloc([]const M, n);
        const dcols = try ar.alloc(D.Column, n);
        const pcols = try ar.alloc(D.Column, n);
        var i: usize = 0;
        for (groups) |g| for (0..g.count) |_| {
            const values = try ar.alloc(M, @as(usize, 1) << @intCast(g.log));
            for (values) |*x| x.* = M.fromCanonical(prng.random().uintLessThan(u32, core.fields.m31.Modulus));
            cols[i] = values;
            dcols[i] = .{ .log_size = g.log, .coefficients = values };
            pcols[i] = N.placeholderColumn(g.log);
            coefficient_words += values.len;
            i += 1;
        };
        // Interleave heights (the PCS sorts by height per tree).
        prng.random().shuffle(D.Column, dcols);
        for (dcols, cols, pcols) |d, *c, *p| {
            c.* = d.coefficients;
            p.* = N.placeholderColumn(d.log_size);
        }
        hc.* = cols;
        dt.* = .{ .root = @splat(0), .columns = dcols };
        pt.* = .{ .root = @splat(0), .columns = pcols };
    }
    var channel = D.Channel.init();
    channel.mixU32s(&.{ 0x5343414c, 24 });
    const oods = try core.circle.secureFieldPointFromRandomSeedCheckedFor(OM, channel.drawSecureFelt());
    const placeholder = try N.placeholderPoint();
    const Pts = struct {
        fn make(alloc: std.mem.Allocator, o: Point) !core.pcs.TreeVec([][]Point) {
            const out = try alloc.alloc([][]Point, trees.len);
            for (trees, out, 0..) |groups, *cols, t| {
                var n: usize = 0;
                for (groups) |g| n += g.count;
                cols.* = try alloc.alloc([]Point, n);
                for (cols.*, 0..) |*p, c| {
                    p.* = try alloc.alloc(Point, masks(t, c).len);
                    for (masks(t, c), p.*) |m, *v| {
                        const s = offset(m);
                        v.* = o.add(.{ .x = OM.fromBase(s.x), .y = OM.fromBase(s.y) });
                    }
                }
            }
            return core.pcs.TreeVec([][]Point).initOwned(out);
        }
    };
    // Seed and imported base point exactly as the legacy request frames them.
    var framing = try Export.prepareRequestWithFraming(a, .{ .config = config, .lifting_log_size = lifting_log, .trees = &d_trees, .points = try Pts.make(ar, oods) }, channel, null, true);
    defer framing.deinit(a);
    // Job path.
    var pcs = try N.PcsJob.prepare(a, sym, .{ .config = config, .lifting_log_size = lifting_log, .trees = &placeholder_trees, .points = try Pts.make(ar, placeholder) }, placeholder, true);
    defer pcs.deinit(a);
    var seed: [16]u32 = @splat(0);
    @memcpy(seed[0..9], framing.section_storage[1]);
    var staged_columns: [trees.len][]api.DeviceBuffer = undefined;
    for (host_columns, &staged_columns) |cols, *out| out.* = try ar.alloc(api.DeviceBuffer, cols.len);
    const result = try ar.alloc(u32, @intCast(pcs.outputWords()));
    var probe = Probe{ .pcs = &pcs, .sym = sym, .seed = &seed, .point = framing.section_storage[2], .columns = host_columns, .coefficient_words = coefficient_words, .result = result };
    probe.staged_columns = staged_columns;
    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 3 << 30, .pinned_slot_words = @intCast(pcs.ingressWords() + coefficient_words + pcs.outputWords() + (1 << 16)), .max_outstanding = 2 });
    var receipts: [2]api.Receipt = undefined;
    var first: []u32 = &.{};
    for (&receipts) |*r| {
        var done: Done = .{};
        @memset(result, 0);
        try w.submit(api.Job.from(Probe, &probe), .{ .ctx = &done, .done = Done.onDone });
        while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
        if (done.err) |err| return err;
        r.* = probe.receipt;
        if (r == &receipts[0]) first = try ar.dupe(u32, result) else try std.testing.expectEqualSlices(u32, first, result);
    }
    w.destroy();
    // Legacy: the production service of the pinned base image, with the
    // PCS-rebuilt tree roots of the job run as its section-15 expected roots
    // (the legacy pipeline re-derives and checks them).
    for (&d_trees, 0..) |*tree, t| for (0..8) |i| std.mem.writeInt(u32, tree.root[i * 4 ..][0..4], first[31 + 8 * t + i], .little);
    var legacy_prepared = try Export.prepareRequestWithFraming(a, .{ .config = config, .lifting_log_size = lifting_log, .trees = &d_trees, .points = try Pts.make(ar, oods) }, channel, null, true);
    defer legacy_prepared.deinit(a);
    const descriptor = legacy_prepared.descriptor();
    const create = gpu.libs.base.lookup(Abi.Create, "stwo_rv64_pcs_native_create") orelse return error.MissingSymbol;
    const prove = gpu.libs.base.lookup(Abi.Prove, "stwo_rv64_pcs_native_prove") orelse return error.MissingSymbol;
    const release = gpu.libs.base.lookup(Abi.Release, "stwo_rv64_pcs_native_release") orelse return error.MissingSymbol;
    const destroy = gpu.libs.base.lookup(Abi.Destroy, "stwo_rv64_pcs_native_destroy") orelse return error.MissingSymbol;
    var session: ?*anyopaque = null;
    if (create(0, 24 << 30, &session) != 0) return error.LegacySessionCreate;
    var legacy: []u32 = undefined;
    var legacy_device_ns: [2]u64 = undefined;
    var legacy_wall_ns: [2]u64 = undefined;
    var legacy_requested_bytes: [2]u64 = undefined;
    for (0..2) |run| {
        var out: Abi.Result = .{};
        var timer = try std.time.Timer.start();
        if (prove(session.?, &descriptor, &out) != 0) {
            const message = gpu.libs.base.lookup(Abi.Error, "stwo_rv64_pcs_native_error") orelse return error.LegacyProve;
            std.debug.print("LEGACY_PCS error={s}\n", .{message(session.?)});
            return error.LegacyProve;
        }
        legacy_wall_ns[run] = timer.read();
        legacy_device_ns[run] = out.device_ns;
        legacy_requested_bytes[run] = out.requested_bytes;
        if (run == 0) legacy = try ar.dupe(u32, out.words.?[0..@intCast(out.count)]) else if (!std.mem.eql(u32, legacy, out.words.?[0..@intCast(out.count)])) return error.LegacyNotDeterministic;
        release(&out);
    }
    _ = destroy(session.?);

    try std.testing.expectEqualSlices(u32, legacy, first);
    var trees_columns: usize = 0;
    for (host_columns) |cols| trees_columns += cols.len;
    for (receipts, 0..) |r, run| std.debug.print("GPU_M8_PCS_SCALE run={} columns={} coefficient_words={} lifting_log={} q=54 pow_bits=20 pcs_words={} samples={} byte_identical=1 legacy_device_ns={} legacy_wall_ns={} legacy_requested_bytes={} job_stage_ns={} job_enqueue_ns={} job_wait_ns={} job_host_waits={} job_arena_peak_words={} job_staged_words={}\n", .{ run, trees_columns, coefficient_words, lifting_log, pcs.outputWords(), pcs.plan.samples, legacy_device_ns[run], legacy_wall_ns[run], legacy_requested_bytes[run], r.stage_ns, r.enqueue_ns, r.wait_ns, r.host_waits, r.arena_peak_words, r.staged_words });
}
