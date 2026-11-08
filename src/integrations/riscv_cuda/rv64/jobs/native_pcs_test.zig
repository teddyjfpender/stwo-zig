//! native_pcs on the runtime's host device model (fake.zig): the opening tail
//! drives the real DeviceWorker/Enqueue/DeviceChannel, with the addon symbols
//! replaced by host stand-ins that check what the CUDA side would receive.
const std = @import("std");
const api = @import("api.zig");
const W = @import("worker.zig");
const fake = @import("fake.zig");
const N = @import("native_pcs.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const core = @import("stwo_core");
const M = D.M;
const Point = D.Point;

const Seen = struct {
    var plan_calls: usize = 0;
    var oods_shift: [2]u32 = .{ 0, 0 };
    var oods_out: ?[*]u32 = null;
    var seed: ?[*]const u32 = null;
    var point: ?[*]const u32 = null;
    var draw_word: u32 = 0;
};
const output_words = 96;
fn fakePlan(_: *const @import("../pcs_native_abi.zig").Request, plan: *N.Plan) callconv(.c) c_int {
    Seen.plan_calls += 1;
    plan.* = .{ .output_words = output_words, .ingress_words = 32, .trees = 1, .layers = 1, .queries = 2, .steps = 7, .samples = 3 };
    return 0;
}
fn fakeEnqueue(_: *anyopaque, lane: u32, _: *const @import("../pcs_native_abi.zig").Request, memory: *const N.Memory, io: *const N.Io) callconv(.c) c_int {
    if (lane != 0 or io.output_words != output_words or memory.pinned_words < 32) return 1;
    // Exercise the arena bridge exactly as the C side does.
    const scratch = memory.alloc(memory.user, 128) orelse return 2;
    memory.release(memory.user, scratch, 128);
    Seen.seed = io.seed;
    Seen.point = io.point;
    // "PCS": record the seed digest word and the imported base point word.
    io.output[0] = io.seed[0];
    io.output[1] = io.point.?[0];
    return 0;
}
fn fakeError() callconv(.c) [*:0]const u8 {
    return "fake";
}
fn fakeOods(_: *anyopaque, lane: u32, draw: [*]const u32, sx: u32, sy: u32, out: [*]u32, status: [*]u32) callconv(.c) c_int {
    if (lane != 0) return 1;
    Seen.oods_shift = .{ sx, sy };
    Seen.oods_out = out;
    Seen.draw_word = draw[0];
    for (0..32) |i| out[i] = draw[i % 8] +% @as(u32, @intCast(i));
    status[0] = 0;
    return 0;
}
const symbols = N.Symbols{ .plan = fakePlan, .enqueue = fakeEnqueue, .last_error = fakeError, .oods = fakeOods };

const OpeningProbe = struct {
    pcs: *N.PcsJob,
    seed: [9]u32 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 0 },
    staged: ?api.DeviceBuffer = null,
    pinned: []u32 = &.{},
    state_ptr: ?[*]const u32 = null,
    slab_ptr: ?[*]const u32 = null,
    steps_after: u32 = 0,
    finished: bool = false,
    pub fn classKey(_: *OpeningProbe) [32]u8 {
        return @splat(3);
    }
    pub fn footprint(self: *OpeningProbe) api.Footprint {
        return .{ .device_words = 4096, .staged_words = 64, .slab_words = 64 + output_words, .pinned_words = @intCast(self.pcs.ingressWords()) };
    }
    pub fn stage(self: *OpeningProbe, s: *api.Stager) !void {
        const b = try s.alloc(9);
        try s.upload(b, &self.seed);
        self.staged = b;
        self.pinned = try s.pinned(@intCast(self.pcs.ingressWords()));
    }
    pub fn enqueue(self: *OpeningProbe, e: *api.Enqueue) !void {
        try e.channel.initFromCheckpoint(self.staged.?);
        const oods = try e.slab.device.slice(0, N.oods_field_words);
        const out = try e.slab.device.slice(64, output_words);
        try self.pcs.enqueueOpening(symbols, e, self.pinned, oods, out);
        self.state_ptr = e.channel.stateBuffer().ptr;
        self.slab_ptr = e.slab.device.ptr;
        self.steps_after = e.channel.step;
    }
    pub fn finish(self: *OpeningProbe, v: api.SlabView) !void {
        // The PCS saw the channel state AFTER the OODS draw, and the BASE point.
        try std.testing.expectEqual(v.words[0 + 16], v.words[64 + 1]);
        self.finished = true;
    }
    pub fn abort(_: *OpeningProbe) void {}
};

const Done = struct {
    n: std.atomic.Value(usize) = .init(0),
    err: ?anyerror = null,
    fn sink(self: *Done) W.Sink {
        return .{ .ctx = self, .done = onDone };
    }
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        if (c.result) |_| {} else |err| self.err = err;
        _ = self.n.fetchAdd(1, .seq_cst);
    }
};

test "opening tail: OODS draw on the device channel, base point and PCS seed come from device memory" {
    const a = std.testing.allocator;
    fake.reset();
    // A real framing request (pure host) so prepare() runs end to end.
    var coeff8 = [_]M{M.zero()} ** 8;
    var coeff16 = [_]M{M.zero()} ** 16;
    const oods = try N.placeholderPoint();
    const step = core.poly.circle.canonic.CanonicCoset.new(4).coset().step;
    const shift = Point{ .x = D.O.fromBase(step.x), .y = D.O.fromBase(step.y) };
    var samples0 = [_]Point{};
    var samples1 = [_]Point{ oods.add(shift), oods };
    var samples2 = [_]Point{oods};
    var points = [_][]Point{ &samples0, &samples1, &samples2 };
    var forest = [_][][]Point{&points};
    var columns = [_]D.Column{ .{ .log_size = 3, .coefficients = &coeff8 }, .{ .log_size = 4, .coefficients = &coeff16 }, .{ .log_size = 4, .coefficients = &coeff16 } };
    var trees = [_]D.Tree{.{ .root = @splat(0), .columns = &columns }};
    const request = D.Request{ .config = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 2, .fold_step = 2 } }, .lifting_log_size = 5, .trees = &trees, .points = core.pcs.TreeVec([][]Point).initOwned(&forest) };
    var pcs = try N.PcsJob.prepare(a, symbols, request, oods, true);
    defer pcs.deinit(a);
    try std.testing.expectEqual(@as(u64, output_words), pcs.outputWords());
    try std.testing.expect(pcs.base_shift.x.eql(step.x) and pcs.base_shift.y.eql(step.y));

    const w = try W.Worker.create(a, &fake.ops, .{ .device = 0, .arena_words = 1 << 16, .pinned_slot_words = 1 << 12, .max_outstanding = 2 });
    var probe = OpeningProbe{ .pcs = &pcs };
    var done: Done = .{};
    try w.submit(api.Job.from(OpeningProbe, &probe), done.sink());
    while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
    w.destroy();
    if (done.err) |err| return err;
    try std.testing.expect(probe.finished);
    try std.testing.expectEqual(@as(u32, 1), probe.steps_after); // exactly the OODS draw
    try std.testing.expectEqual(probe.state_ptr.?, Seen.seed.?);
    try std.testing.expectEqual(Seen.oods_out.? + 16, @constCast(Seen.point.?));
    try std.testing.expectEqual(probe.slab_ptr.?, @as([*]const u32, Seen.oods_out.?));
    try std.testing.expectEqual([2]u32{ step.x.v, step.y.v }, Seen.oods_shift);
    try std.testing.expectEqual(@as(usize, 1), fake.counters.host_waits);
}
