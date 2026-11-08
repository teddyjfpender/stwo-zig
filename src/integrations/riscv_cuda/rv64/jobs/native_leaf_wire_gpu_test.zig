//! Codec parity, not an end-to-end proof qualification.
const std = @import("std");
const L = @import("native_leaf_wire.zig");
const api = @import("api.zig");
const Worker = @import("worker.zig").Worker;
const Copy = @import("native_commit.zig").CopyD2d;
const Probe = struct {
    encode: L.EncodeFn,
    copy: Copy,
    program: *const L.Program,
    sources: L.Sources,
    initial: []const u32,
    output: []u32,
    prior_verdict: u32 = 0,
    shorten_region: bool = false,
    buffers: [8]api.DeviceBuffer = undefined,
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(0x9d);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        var n = self.program.words.len + self.initial.len + 1024;
        for (self.sources) |src| n += src.len;
        return .{ .device_words = n, .staged_words = n, .slab_words = self.output.len, .pinned_words = n };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        const inputs = [_][]const u32{ self.program.words, self.sources[1], self.sources[2], self.sources[3], self.sources[4], self.sources[5], self.initial, &.{self.prior_verdict} };
        for (inputs, &self.buffers) |src, *buf| {
            buf.* = try s.alloc(@max(src.len, 1));
            if (src.len != 0) try s.upload(buf.*, src);
        }
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        const region = e.slab.device;
        const n = self.program.regionWords();
        if (self.copy(e.ctx(), region.ptr, self.buffers[6].ptr, 4 * self.initial.len) != 0 or self.copy(e.ctx(), region.ptr + n, self.buffers[7].ptr, 4) != 0) return error.CudaEnqueueFailed;
        if (self.copy(e.ctx(), region.ptr + self.program.words[10], self.buffers[5].ptr, self.sources[5].len * 4) != 0) return error.CudaEnqueueFailed;
        var run = L.Run{ .program = self.buffers[0].ptr, .program_words = self.program.words.len, .sources = @splat(null), .source_words = @splat(0), .region = region.ptr, .region_words = n - @intFromBool(self.shorten_region), .verdict = region.ptr + n, .reject_code = 0x04020000 };
        for (1..6) |i| {
            if (self.sources[i].len != 0) run.sources[i] = self.buffers[i].ptr;
            run.source_words[i] = self.sources[i].len;
        }
        if (self.encode(e.ctx(), 0, &run) != 0) return error.CudaEnqueueFailed;
    }
    pub fn finish(self: *Probe, view: api.SlabView) !void {
        @memcpy(self.output, view.words[0..self.output.len]);
    }
    pub fn abort(_: *Probe) void {}
};
fn runProbe(worker: *Worker, probe: *Probe) !void {
    var done = struct {
        event: std.Thread.ResetEvent = .{},
        result: anyerror!void = {},
        fn call(raw: *anyopaque, c: api.Completion) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.result = c.result;
            self.event.set();
        }
    }{};
    try worker.submit(api.Job.from(Probe, probe), .{ .ctx = &done, .done = @TypeOf(done).call });
    done.event.wait();
    try done.result;
}

test "GPU leaf suffix equals host tape and public digest; rejects bad shape and coordinates" {
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.openNamed("native_leaf_suffix")) orelse return;
    defer gpu.close();
    const a = std.testing.allocator;
    const t = std.testing;
    const tail = [_]L.Op{ .{ .kind = .word, .source = .pool, .offset = 0, .count = 1 }, .{ .kind = .word, .source = .manifest, .offset = 0, .count = 8 }, .{ .kind = .polynomial, .source = .section, .offset = 0, .count = 2 }, .{ .kind = .felts, .source = .claims, .offset = 0, .count = 1 } };
    const frame = [_]L.Op{ .{ .kind = .word, .source = .pool, .offset = 0, .count = 1 }, .{ .kind = .word, .source = .receipt, .offset = 0, .count = 8 }, .{ .kind = .word, .source = .pcs, .offset = 1, .count = 8 }, .{ .kind = .felts, .source = .claims, .offset = 0, .count = 1 } };
    var p = try L.Program.build(a, .{ .wire_words = 10, .image_words = 9, .tail_seeds = 24 }, &.{0xfedcba98}, &tail, &frame);
    defer p.deinit();
    var section: [44]u32 = @splat(31);
    section[40] = 2;
    var claims = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const manifest = [_]u32{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const receipt = [_]u32{ 101, 102, 103, 104, 105, 106, 107, 108 };
    const pcs = [_]u32{ 0, 109, 110, 111, 112, 113, 114, 115, 116 };
    const sources: L.Sources = .{ &.{}, &section, &manifest, &receipt, &claims, &pcs };
    const initial = try a.alloc(u32, p.regionWords());
    defer a.free(initial);
    @memset(initial, 0);
    initial[0] = 3;
    initial[1] = 0x12345678;
    const expected = try a.dupe(u32, initial);
    defer a.free(expected);
    try L.reference(&p, sources, expected);
    const output = try a.alloc(u32, initial.len + 1);
    defer a.free(output);
    const copy = gpu.libs.base.lookup(Copy, "stwo_exec_context_memcpy_d2d_async") orelse return error.MissingTraceCommitSymbol;
    for (0..2) |device| {
        const worker = try Worker.create(a, &gpu.libs.ops, .{ .device = @intCast(device), .arena_words = 1 << 20, .pinned_slot_words = 1 << 17, .max_outstanding = 1 });
        defer worker.destroy();
        var probe = Probe{ .encode = try L.load(&gpu.libs.addon), .copy = copy, .program = &p, .sources = sources, .initial = initial, .output = output };
        try runProbe(worker, &probe);
        try t.expectEqual(@as(u32, 0), output[initial.len]);
        try t.expectEqualSlices(u32, expected, output[0..initial.len]);
        section[40] = 1;
        try runProbe(worker, &probe);
        section[40] = 2;
        try t.expectEqual(@as(u32, 0x04020005), output[initial.len]);
        try t.expectEqual(@as(u32, 0), output[0]);
        claims[0] = L.modulus;
        try runProbe(worker, &probe);
        claims[0] = 1;
        try t.expectEqual(@as(u32, 0x04020006), output[initial.len]);
        probe.shorten_region = true;
        try runProbe(worker, &probe);
        try t.expect(output[initial.len] != 0);
        probe.shorten_region = false;
        probe.prior_verdict = 0x04020003;
        try runProbe(worker, &probe);
        try t.expectEqual(@as(u32, 0x04020003), output[initial.len]);
        std.debug.print("GPU_M8_NATIVE_LEAF_SUFFIX_PARITY device={d} words={d} polynomial_shape_rejected=1 noncanonical_rejected=1 bounds_rejected=1 prior_rejection_preserved=1\n", .{ device, expected.len });
    }
}
