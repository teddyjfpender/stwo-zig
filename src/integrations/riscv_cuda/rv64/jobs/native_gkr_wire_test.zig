//! Serialization parity only: these generated proofs test framing, not GKR
//! soundness. End-to-end acceptance remains the real-block request gates.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const NG = @import("native_gkr.zig");
const W = @import("native_gkr_wire.zig");
const Slab = @import("slab.zig");
const Results = @import("../gkr_result.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const api = @import("api.zig");
const Worker = @import("worker.zig").Worker;
const MW = @import("native_manifest_wire.zig");
const G = @import("gpu_native.zig");
const Commit = @import("native_commit.zig");

const Probe = struct {
    encode: W.EncodeFn,
    program: []const u32,
    section: []const u32,
    scope: []const u32,
    marginals: []const u32,
    wire_words: usize,
    output: []u32,
    buffers: [4]api.DeviceBuffer = undefined,
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(0x9b);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        const input = self.program.len + self.section.len + self.scope.len + self.marginals.len;
        return .{ .device_words = input + 1024, .staged_words = input + 1024, .slab_words = self.output.len, .pinned_words = input + 1024 };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        const inputs = [_][]const u32{ self.program, self.section, self.scope, self.marginals };
        for (inputs, &self.buffers) |input, *buffer| {
            buffer.* = try s.alloc(input.len);
            try s.upload(buffer.*, input);
        }
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        const args = W.Run{
            .program = self.buffers[0].ptr,
            .program_words = self.buffers[0].words,
            .section = self.buffers[1].ptr,
            .section_words = self.buffers[1].words,
            .scope = self.buffers[2].ptr,
            .marginals = self.buffers[3].ptr,
            .marginal_words = self.buffers[3].words,
            .receipt = e.slab.device.ptr,
            .wire = e.slab.device.ptr + 16,
            .wire_words = self.wire_words,
            .verdict = e.slab.device.ptr + 16 + self.wire_words,
            .reject_code = 0x02090000,
        };
        if (self.encode(e.ctx(), 0, &args) != 0) return error.CudaEnqueueFailed;
    }
    pub fn finish(self: *Probe, v: api.SlabView) !void {
        @memcpy(self.output, v.words[0..self.output.len]);
    }
    pub fn abort(_: *Probe) void {}
};
const Done = struct {
    count: std.atomic.Value(usize) = .init(0),
    err: ?anyerror = null,
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        if (c.result) |_| {} else |err| self.err = err;
        _ = self.count.fetchAdd(1, .seq_cst);
    }
};
fn run(worker: *Worker, probe: anytype) !void {
    var done: Done = .{};
    try worker.submit(api.Job.from(std.meta.Child(@TypeOf(probe)), probe), .{ .ctx = &done, .done = Done.onDone });
    while (done.count.load(.seq_cst) == 0) std.Thread.yield() catch {};
    if (done.err) |err| return err;
}

const ManifestProbe = struct {
    encode: MW.EncodeFn,
    copy: Commit.CopyD2d,
    program: []const u32,
    exchange: []const u32,
    tag: u32,
    output: []u32,
    prior_verdict: u32 = 0,
    buffers: [3]api.DeviceBuffer = undefined,
    pub fn classKey(_: *ManifestProbe) [32]u8 {
        return @splat(0x9c);
    }
    pub fn footprint(self: *ManifestProbe) api.Footprint {
        const n = self.program.len + self.exchange.len + 1024;
        return .{ .device_words = n, .staged_words = n, .slab_words = self.output.len, .pinned_words = n };
    }
    pub fn stage(self: *ManifestProbe, s: *api.Stager) !void {
        for ([_][]const u32{ self.program, self.exchange, &.{self.prior_verdict} }, &self.buffers) |input, *buffer| {
            buffer.* = try s.alloc(input.len);
            try s.upload(buffer.*, input);
        }
    }
    pub fn enqueue(self: *ManifestProbe, e: *api.Enqueue) !void {
        const verdict = e.slab.device.ptr + self.output.len - 1;
        if (self.copy(e.ctx(), verdict, self.buffers[2].ptr, 4) != 0) return error.CudaEnqueueFailed;
        const args = MW.Run{ .program = self.buffers[0].ptr, .program_words = self.buffers[0].words, .exchange = self.buffers[1].ptr, .exchange_words = self.buffers[1].words, .tag = self.tag, .encoded = e.slab.device.ptr, .encoded_words = self.output.len - 1, .verdict = verdict, .reject_code = 0x01030000 };
        if (self.encode(e.ctx(), 0, &args) != 0) return error.CudaEnqueueFailed;
    }
    pub fn finish(self: *ManifestProbe, v: api.SlabView) !void {
        @memcpy(self.output, v.words[0..self.output.len]);
    }
    pub fn abort(_: *ManifestProbe) void {}
};

fn manifestParity(a: std.mem.Allocator, instances: []const NG.Instance, proof: anytype, child_bytes: []const u8, digest: [32]u8, scope: [25]u32) !void {
    const ex = G.Exchange{ .segments = 1, .claims_per_segment = @intCast(2 * instances.len), .devices = 2, .truths = 1, .receipts = true, .child_wire_words = 1 + (child_bytes.len + 3) / 4 };
    const exchange = try a.alloc(u32, ex.words());
    @memset(exchange, 0);
    const tag = G.Exchange.flagTag(71);
    @memset(exchange[0..ex.flagCapacity()], tag);
    const root = try ex.root(0);
    const truth = try ex.truthRoot(0);
    const receipt = try ex.receipt(0);
    const child = try ex.childWire(0);
    @memcpy(exchange[root.offset..][0..8], scope[16..24]);
    @memset(exchange[truth.offset..][0..8], 0x12345678);
    @memcpy(std.mem.sliceAsBytes(exchange[receipt.offset..][0..8]), &digest);
    exchange[child.offset] = @intCast(child_bytes.len);
    @memcpy(std.mem.sliceAsBytes(exchange[child.offset + 1 ..])[0..child_bytes.len], child_bytes);
    const Entry = struct { ordinal: u32, segment: ?u32 = null, truth: ?u32 = null, main: [32]u8 = @splat(0), local_instances: ?u32 = null };
    const entries = [_]Entry{ .{ .ordinal = 0, .segment = 0, .local_instances = @intCast(instances.len) }, .{ .ordinal = 1, .truth = 0 } };
    const workers = [_]CPU.rv64_gkr_manifest.ExpectedWorker{
        .{ .kind = .cpu, .ordinal = 0, .global_relations = .{ .ram = true, .kio = false, .wire = false }, .mass = .{ .ram = 0, .kio = 0, .wire = 0 }, .statement = @splat(1), .fixed = @splat(2), .local_instances = instances },
        .{ .kind = .keccak, .ordinal = 1, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .mass = .{ .ram = 0, .kio = 0, .wire = 0 }, .statement = @splat(3), .fixed = @splat(4), .local_instances = null },
    };
    const stages = [_]CPU.rv64_gkr_manifest.StageOne{
        .{ .main = std.mem.sliceAsBytes(exchange[root.offset..][0..8])[0..32].*, .local = .{ .proof = proof, .receipt_digest = digest } },
        .{ .main = std.mem.sliceAsBytes(exchange[truth.offset..][0..8])[0..32].*, .local = null },
    };
    const execution: [32]u8 = @splat(0x63);
    var program = try MW.build(std.testing.allocator, execution, &entries, ex);
    defer program.deinit();
    const expected = try CPU.rv64_gkr_manifest_wire.encode(a, execution, &workers, &stages);
    try std.testing.expectEqualSlices(u8, expected, try MW.emit(a, program.words, exchange, tag));
    exchange[child.flag] = 0;
    try std.testing.expectError(error.GlobalGkrManifestNotLanded, MW.emit(a, program.words, exchange, tag));
    exchange[child.flag] = tag;
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.openNamed("stage_one_manifest_wire")) orelse return;
    defer gpu.close();
    const output = try a.alloc(u32, 2 + (program.max_bytes + 3) / 4);
    const copy = gpu.libs.base.lookup(Commit.CopyD2d, "stwo_exec_context_memcpy_d2d_async") orelse return error.MissingTraceCommitSymbol;
    for (0..2) |device| {
        const worker = try Worker.create(std.testing.allocator, &gpu.libs.ops, .{ .device = @intCast(device), .arena_words = 1 << 20, .pinned_slot_words = 1 << 17, .max_outstanding = 1 });
        defer worker.destroy();
        var probe = ManifestProbe{ .encode = try MW.load(&gpu.libs.addon), .copy = copy, .program = program.words, .exchange = exchange, .tag = tag, .output = output };
        try run(worker, &probe);
        try std.testing.expectEqual(@as(u32, 0), output[output.len - 1]);
        try std.testing.expectEqual(expected.len, output[0]);
        try std.testing.expectEqualSlices(u8, expected, std.mem.sliceAsBytes(output[1..])[0..expected.len]);
        exchange[child.flag] = 0;
        try run(worker, &probe);
        exchange[child.flag] = tag;
        try std.testing.expectEqual(@as(u32, 0x01030001), output[output.len - 1]);
        try std.testing.expectEqual(@as(u32, 0), output[0]);
        exchange[child.offset] = @intCast(child_bytes.len + 4);
        try run(worker, &probe);
        exchange[child.offset] = @intCast(child_bytes.len);
        try std.testing.expectEqual(@as(u32, 0x01030004), output[output.len - 1]);
        probe.prior_verdict = 0x01030003;
        try run(worker, &probe);
        try std.testing.expectEqual(@as(u32, 0x01030003), output[output.len - 1]);
        try std.testing.expectEqual(@as(u32, 0), output[0]);
        std.debug.print("GPU_M8_MANIFEST_WIRE_PARITY device={} bytes={} missing_flag_rejected=1 oversized_child_rejected=1 seal_rejection_preserved=1\n", .{ device, expected.len });
    }
}

fn gpuParity(program: W.Program, section: []u32, scope: []const u32, marginals: []u32, expected: []const u8, digest: [32]u8, bad: usize) !void {
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.openNamed("local_gkr_receipt_wire")) orelse return;
    defer gpu.close();
    const a = std.testing.allocator;
    const output = try a.alloc(u32, 17 + program.wireWords());
    defer a.free(output);
    const bad_word = section[bad];
    for (0..2) |device| {
        const worker = try Worker.create(a, &gpu.libs.ops, .{ .device = @intCast(device), .arena_words = 1 << 20, .pinned_slot_words = 1 << 17, .max_outstanding = 1 });
        defer worker.destroy();
        var probe = Probe{ .encode = try W.load(&gpu.libs.addon), .program = program.words, .section = section, .scope = scope, .marginals = marginals, .wire_words = program.wireWords(), .output = output };
        try run(worker, &probe);
        try std.testing.expectEqual(@as(u32, 0), output[output.len - 1]);
        try std.testing.expectEqualSlices(u8, &digest, std.mem.sliceAsBytes(output[0..8]));
        try std.testing.expectEqual(expected.len, output[16]);
        try std.testing.expectEqualSlices(u8, expected, std.mem.sliceAsBytes(output[17..])[0..expected.len]);
        section[bad] = 5;
        try run(worker, &probe);
        section[bad] = bad_word;
        try std.testing.expectEqual(@as(u32, 0x02090002), output[output.len - 1]);
        try std.testing.expectEqual(@as(u32, 0), output[16]);
        const saved = marginals[0];
        marginals[0] = 0x7fffffff;
        try run(worker, &probe);
        marginals[0] = saved;
        try std.testing.expectEqual(@as(u32, 0x02090003), output[output.len - 1]);
        try std.testing.expectEqual(@as(u32, 0), output[16]);
        std.debug.print("GPU_M8_LOCAL_GKR_WIRE_PARITY device={} wire_bytes={} digest_equal=1 invalid_length_rejected=1 noncanonical_rejected=1\n", .{ device, expected.len });
    }
}

fn parity(v3: bool) !void {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const tmp = arena.allocator();
    const instances = [_]NG.Instance{
        .{ .origin = .{ .core = .cpu }, .row_log = 5, .terms = 2, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = if (v3) .{ .dword = 0 } else .{ .core = .multiplication }, .row_log = 6, .terms = 4, .fixed_offset = 12, .main_offset = 25 },
    };
    var variables: [instances.len]u32 = undefined;
    var max: u32 = 0;
    for (instances, &variables) |instance, *v| {
        v.* = try instance.variables();
        max = @max(max, v.*);
    }
    const fields = NG.Fields{ .base = 0, .layers = max };
    var layout = Slab.ProofLayout{};
    const roots_at = try layout.add(.gkr_section, fields.roots(), 16 * instances.len);
    const layers = try tmp.alloc(Results.Layer, max);
    for (0..max) |d| {
        _ = try layout.add(.gkr_section, fields.records(@intCast(d)), 44 * d);
        var active: usize = 0;
        for (variables) |v| active += @intFromBool(v >= max - d);
        _ = try layout.add(.gkr_section, fields.masks(@intCast(d)), 32 * active);
    }
    const section = try tmp.alloc(u32, layout.words);
    @memset(section, 0);
    for (section[roots_at..][0 .. 16 * instances.len], 0..) |*word, i| word.* = @intCast(i + 1);
    for (layers, 0..) |*layer, d| {
        const records = try layout.get(.gkr_section, fields.records(@intCast(d)));
        const masks = try layout.get(.gkr_section, fields.masks(@intCast(d)));
        for (0..d) |r| {
            const record = section[records.offset + 44 * r ..][0..44];
            const n = (r + d) % 5;
            for (record[0 .. 8 * n], 0..) |*word, i| word.* = @intCast(1 + i + 17 * r + 31 * d);
            for (record[32..40], 0..) |*word, i| word.* = @intCast(i + r + 7);
            record[40] = @intCast(n);
            record[41] = @intCast(r);
        }
        for (section[masks.offset..][0..masks.words], 0..) |*word, i| word.* = @intCast(100 + i + d);
        layer.* = .{ .records = section[records.offset..][0..records.words], .masks = section[masks.offset..][0..masks.words] };
    }
    var proof = try Results.assemble(a, .{ .variables = &variables, .roots = section[roots_at..][0 .. 16 * instances.len], .layers = layers });
    defer proof.deinit(a);
    var scope: [25]u32 = undefined;
    for (&scope, 0..) |*word, i| word.* = @intCast(0x8abc0000 + i);
    scope[24] = 7;
    const native_scope = CPU.rv64_gkr_receipt.Scope{ .statement = std.mem.sliceAsBytes(scope[0..8])[0..32].*, .fixed = std.mem.sliceAsBytes(scope[8..16])[0..32].*, .main = std.mem.sliceAsBytes(scope[16..24])[0..32].*, .ordinal = scope[24] };
    var marginals: [16 * instances.len]u32 = undefined;
    var claims: [instances.len][2]O = undefined;
    var slices: [instances.len][]const O = undefined;
    for (&marginals, 0..) |*word, i| word.* = @intCast(i + 303);
    for (&claims, &slices, 0..) |*pair, *slice, i| {
        for (pair, 0..) |*felt, j| {
            var coords: [8]M = undefined;
            for (&coords, 0..) |*m, k| m.* = M.fromCanonical(marginals[16 * i + 8 * j + k]);
            felt.* = O.fromM31Array(coords);
        }
        slice.* = pair;
    }
    var program = try W.build(a, &instances, &variables, fields, &layout);
    defer program.deinit();
    const encoded = try W.emit(a, program.words, true, section, &scope, &marginals);
    defer a.free(encoded);
    const expected = try CPU.rv64_gkr_wire.encode(a, &instances, &proof);
    defer a.free(expected);
    try std.testing.expectEqualSlices(u8, expected, encoded);
    const receipt = try W.emit(a, program.words, false, section, &scope, &marginals);
    defer a.free(receipt);
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(receipt, &digest, .{});
    try std.testing.expectEqualSlices(u8, &try CPU.rv64_gkr_receipt.digest(native_scope, &instances, &proof, &slices), &digest);
    try manifestParity(tmp, &instances, &proof, expected, digest, scope);
    // Non-canonical coordinates and invalid polynomial lengths reject.
    const bad = try layout.get(.gkr_section, fields.records(1));
    try gpuParity(program, section, &scope, &marginals, expected, digest, bad.offset + 40);
    const saved = section[bad.offset + 40];
    section[bad.offset + 40] = 5;
    try std.testing.expectError(error.LocalGkrReceiptShape, W.emit(a, program.words, true, section, &scope, &marginals));
    section[bad.offset + 40] = saved;
    marginals[0] = 0x7fffffff;
    try std.testing.expectError(error.NoncanonicalLocalGkrCoordinate, W.emit(a, program.words, false, section, &scope, &marginals));
}

test "local GKR wire/receipt programs equal native codecs, V1 and V3, including short and zero polynomials" {
    try parity(false);
    try parity(true);
}
