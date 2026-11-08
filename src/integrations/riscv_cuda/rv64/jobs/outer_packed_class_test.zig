//! Lossless resident decoder parity and fail-closed malformed images.
const std = @import("std");
const P = @import("outer_packed_class.zig");
const Codec = @import("stwo_circuit_cpu_integration").om31.cache_pack;
const api = @import("api.zig");
const W = @import("worker.zig").Worker;

test "packed ingress defaults on and keeps strict explicit overrides" {
    try std.testing.expect(try P.ingressEnabled(null));
    try std.testing.expect(try P.ingressEnabled("1"));
    try std.testing.expect(!try P.ingressEnabled("0"));
    try std.testing.expectError(error.InvalidPackedClassFlag, P.ingressEnabled("yes"));
}
const Probe = struct {
    launch: P.Launch,
    memset: *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int,
    class: *const P.Class,
    output: []u32,
    program: api.DeviceBuffer = undefined,
    scratch: api.DeviceBuffer = undefined,
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(0xa7);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        const n = self.class.words.len + 128;
        return .{ .device_words = n, .staged_words = n, .pinned_words = n, .slab_words = self.output.len };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        self.program = try s.alloc(self.class.words.len);
        try s.upload(self.program, self.class.words);
        self.scratch = try s.alloc(12);
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        if (self.memset(e.ctx(), e.slab.device.ptr, 0x5a, 4 * self.output.len) != 0) return error.CudaEnqueueFailed;
        const n = self.class.outputWords();
        try P.enqueue(self.launch, e.ctx(), self.class, self.program, try e.slab.device.slice(0, n), self.scratch, try e.slab.device.slice(n, 1), 0x03090000);
    }
    pub fn finish(self: *Probe, view: api.SlabView) !void {
        @memcpy(self.output, view.words[0..self.output.len]);
    }
    pub fn abort(_: *Probe) void {}
};
fn run(worker: *W, probe: *Probe) !void {
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
test "resident class image matches independent host unpack across block boundaries" {
    const a = std.testing.allocator;
    const n = 2 * P.block_words + 24;
    const raw = try a.alloc(u32, n);
    defer a.free(raw);
    var rng = std.Random.DefaultPrng.init(0x928fa);
    for (raw, 0..) |*word, i| word.* = if (i < P.block_words) @intCast(i / 7) else rng.random().int(u32);
    for ([_]u8{ 1, 8 }) |channels| {
        var encoded = try Codec.pack(a, raw, channels);
        defer encoded.deinit(a);
        if (encoded.encoding != .lz4_blocks) return error.SkipZigTest;
        const host = try a.alloc(u32, n);
        defer a.free(host);
        try encoded.unpack(host);
        try std.testing.expectEqualSlices(u32, raw, host);
        var image = try P.build(a, encoded, P.block_words, n - P.block_words);
        defer image.deinit(a);
        try std.testing.expectEqual(@as(u32, 3), image.blocks());
        var gpu = (try @import("native_gpu_support_test.zig").Gpu.openNamed("outer_resident_packed_class")) orelse return;
        defer gpu.close();
        const sym = gpu.libs.addon.lookup(P.Launch, "stwo_rv64_outer_packed_class_v2_on") orelse return error.PackedClassDecoderMissing;
        const fill = gpu.libs.base.lookup(@FieldType(Probe, "memset"), "stwo_exec_context_memset_async") orelse return error.MissingTraceCommitSymbol;
        const output = try a.alloc(u32, n + 17);
        defer a.free(output);
        for (0..2) |device| {
            const worker = try W.create(a, &gpu.libs.ops, .{ .device = @intCast(device), .arena_words = 1 << 20, .pinned_slot_words = 1 << 18, .max_outstanding = 1 });
            defer worker.destroy();
            var probe = Probe{ .launch = sym, .memset = fill, .class = &image, .output = output };
            try run(worker, &probe);
            try std.testing.expectEqual(@as(u32, 0), output[n]);
            try std.testing.expectEqualSlices(u32, host, output[0..n]);
            for (output[n + 1 ..]) |word| try std.testing.expectEqual(@as(u32, 0x5a5a5a5a), word);
            image.words[0] ^= 1;
            try run(worker, &probe);
            image.words[0] ^= 1;
            try std.testing.expectEqual(@as(u32, 0x03090001), output[n]);
            image.words[9] ^= 1;
            try run(worker, &probe);
            image.words[9] ^= 1;
            try std.testing.expectEqual(@as(u32, 0x03090001), output[n]);
            const off = image.words[16];
            image.words[16] = 0xffffffff;
            try run(worker, &probe);
            image.words[16] = off;
            try std.testing.expect(output[n] != 0 and output[n] >> 16 == 0x0309);
            const bytes = std.mem.sliceAsBytes(image.words);
            const data_at: usize = 4 * @as(usize, image.words[6]);
            const first_len: usize = encoded.blocks[0].bytes;
            const saved = try a.dupe(u8, bytes[data_at..][0..first_len]);
            defer a.free(saved);
            @memset(bytes[data_at..][0..first_len], 0);
            try run(worker, &probe);
            @memcpy(bytes[data_at..][0..first_len], saved);
            try std.testing.expect(output[n] != 0 and output[n] >> 16 == 0x0309);
            for (output[n + 1 ..]) |word| try std.testing.expectEqual(@as(u32, 0x5a5a5a5a), word);
            std.debug.print("GPU_M9_RESIDENT_PACKED_CLASS device={d} words={d} channels={d} parity=1 malformed_header=1 block_bounds=1 malformed_lz4=1 guards=1\n", .{ device, n, channels });
        }
    }
}
