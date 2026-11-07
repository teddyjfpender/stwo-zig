//! n-stage2 kernels on a REAL GPU worker versus the host/legacy references:
//!   encoder   device bytes == WP.encodePhysical(decodeWords(words)) for many
//!             class shapes (fold 1/4, blowup 1/2, 1..1024 queries with
//!             duplicates); every legacy-rejected fault is rejected on device
//!             (named verdict, length 0); a short region overruns closed.
//!   checks    root_match / words_zero / public_claims / patch vs host values,
//!             with negatives.
//!   seal      device chi == manifest.verifyAndSealFor(.m6_v2_gkr).digest and
//!             device shared == manifest.drawShared(chi); an unlanded root
//!             slot rejects global_seal.
//! CUDA-event GPU time of the encoder on segment-scale shapes [M] is printed
//! as GPU_M8_NATIVE_ENCODE_TIMING lines.
//! Opt-in (skipped otherwise): STWO_RV64_M8_GPU_BASE, STWO_RV64_M8_JOBS_LIBRARY.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("api.zig");
const W = @import("worker.zig");
const O = @import("ops.zig");
const G = @import("gpu_native.zig");
const NE = @import("native_encode.zig");
const NS2 = @import("native_device_stage2.zig");
const Support = @import("native_gpu_support_test.zig");
const CPU = @import("stwo_riscv_cpu_integration");
const Manifest = CPU.rv64_gkr_manifest;
const M = core.fields.m31.M31;
const OM = core.fields.om31.OM31;

const Done = struct {
    n: std.atomic.Value(usize) = .init(0),
    err: ?anyerror = null,
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        if (c.result) |_| {} else |err| self.err = err;
        _ = self.n.fetchAdd(1, .seq_cst);
    }
};

const EventFns = struct {
    create: *const fn (*?*anyopaque) callconv(.c) c_int,
    elapsed: *const fn (*anyopaque, *anyopaque, *u64) callconv(.c) c_int,
    fn load(addon: *std.DynLib) !EventFns {
        return .{
            .create = addon.lookup(@FieldType(EventFns, "create"), "stwo_rv64_jobs_event_create_timed") orelse return error.MissingEventSymbol,
            .elapsed = addon.lookup(@FieldType(EventFns, "elapsed"), "stwo_rv64_jobs_event_elapsed_us") orelse return error.MissingEventSymbol,
        };
    }
};

/// One encoder run: program + words staged, region + 2 verdicts in the slab.
const EncodeProbe = struct {
    sym: *const NE.Symbols,
    ops: *const O.Ops,
    events: ?EventFns = null,
    program: *const NE.Program,
    words: []const u32,
    region_words: usize,
    repeat: u32 = 1,
    staged_program: ?api.DeviceBuffer = null,
    staged_words: ?api.DeviceBuffer = null,
    start: ?*anyopaque = null,
    end: ?*anyopaque = null,
    result: []u32,
    us: u64 = 0,
    pub fn classKey(_: *EncodeProbe) [32]u8 {
        return @splat(0x45);
    }
    pub fn footprint(self: *EncodeProbe) api.Footprint {
        const n = self.program.words.len + self.words.len + 256;
        return .{ .device_words = n + NE.scratch_words + 4096, .staged_words = n, .slab_words = self.region_words + 64, .pinned_words = n };
    }
    pub fn stage(self: *EncodeProbe, s: *api.Stager) !void {
        const p = try s.alloc(self.program.words.len);
        try s.upload(p, self.program.words);
        self.staged_program = p;
        const w = try s.alloc(self.words.len);
        try s.upload(w, self.words);
        self.staged_words = w;
    }
    pub fn enqueue(self: *EncodeProbe, e: *api.Enqueue) !void {
        const scratch = try e.alloc(NE.scratch_words);
        const region = try e.slab.device.slice(64, self.region_words);
        var enc = NE.Encoder{ .sym = self.sym, .program = self.staged_program.?, .host = self.program, .pcs = self.staged_words.?, .scratch = scratch, .pcs_status = try e.slab.device.slice(0, 1) };
        if (self.events) |ev| {
            try O.check(ev.create(&self.start));
            try O.check(ev.create(&self.end));
            try O.check(self.ops.exec.event_record(self.start.?, e.stream()));
        }
        for (0..self.repeat) |_| try enc.enqueue(e.ctx(), region, try e.slab.device.slice(1, 1));
        if (self.events != null) try O.check(self.ops.exec.event_record(self.end.?, e.stream()));
        e.free(scratch);
    }
    pub fn finish(self: *EncodeProbe, v: api.SlabView) !void {
        @memcpy(self.result, v.words[0..self.result.len]);
        if (self.events) |ev| try O.check(ev.elapsed(self.start.?, self.end.?, &self.us));
    }
    pub fn abort(_: *EncodeProbe) void {}
};

fn runJob(w: *W.Worker, job: api.Job) !void {
    var done: Done = .{};
    try w.submit(job, .{ .ctx = &done, .done = Done.onDone });
    while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
    if (done.err) |err| return err;
}

const Case = struct { seed: u64, degree: u32, cols: []const u32, fold: u32, q: usize, beta: u32 };

fn cfg(fold: u32, queries: usize, beta: u32) core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = beta, .log_last_layer_degree_bound = 0, .n_queries = queries, .fold_step = fold } };
}

/// Encode on device; returns the region words (length word first) and the
/// two verdicts.
fn deviceEncode(a: std.mem.Allocator, w: *W.Worker, libs: *O.Libraries, sym: *const NE.Symbols, program: *const NE.Program, words: []const u32, region_words: usize) !struct { region: []u32, pcs: u32, enc: u32 } {
    const result = try a.alloc(u32, 64 + region_words);
    errdefer a.free(result);
    var probe = EncodeProbe{ .sym = sym, .ops = &libs.ops, .program = program, .words = words, .region_words = region_words, .result = result };
    try runJob(w, api.Job.from(EncodeProbe, &probe));
    const region = try a.dupe(u32, result[64..]);
    defer a.free(result);
    return .{ .region = region, .pcs = result[0], .enc = result[1] };
}

test "GPU: device ProofEncoder bytes equal encodePhysical(decodeWords) and faults fail closed" {
    var gpu = (try Support.Gpu.openNamed("native_encode_test.encoder")) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.testing.allocator;
    const sym = try NE.Symbols.load(&gpu.libs.addon);
    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 1 << 26, .pinned_slot_words = 1 << 24, .max_outstanding = 2 });
    defer w.destroy();
    const cases = [_]Case{
        .{ .seed = 1, .degree = 6, .cols = &.{ 3, 5, 2, 4 }, .fold = 1, .q = 7, .beta = 1 },
        .{ .seed = 2, .degree = 9, .cols = &.{ 7, 11, 3, 8 }, .fold = 4, .q = 33, .beta = 1 },
        .{ .seed = 3, .degree = 8, .cols = &.{ 1, 2 }, .fold = 4, .q = 70, .beta = 2 },
        .{ .seed = 4, .degree = 5, .cols = &.{ 4, 4, 4 }, .fold = 1, .q = 1, .beta = 1 },
        .{ .seed = 5, .degree = 12, .cols = &.{ 20, 60, 30, 16 }, .fold = 4, .q = 128, .beta = 1 },
        .{ .seed = 6, .degree = 7, .cols = &.{ 9, 9, 9, 9 }, .fold = 4, .q = 1024, .beta = 1 },
        .{ .seed = 7, .degree = 10, .cols = &.{ 5, 40, 10, 8 }, .fold = 3, .q = 100, .beta = 2 },
        .{ .seed = 8, .degree = 11, .cols = &.{2}, .fold = 2, .q = 64, .beta = 1 },
    };
    var ok_cases: usize = 0;
    var neg_cases: usize = 0;
    for (cases) |c| {
        var ts = try NE.TestShape.init(a, c.seed, c.degree, c.cols, cfg(c.fold, c.q, c.beta));
        defer ts.deinit();
        var program = try NE.Program.build(a, ts.shape);
        defer program.deinit();
        const queries = try NE.testQueries(a, c.seed, c.q, c.degree + c.beta);
        defer a.free(queries);
        const faults = [_]NE.Synthetic.Fault{ .none, .trace_value, .trace_path, .fri_value, .fri_path, .noncanonical, .query_range, .status, .channel, .header };
        for (faults) |fault| {
            const words = NE.Synthetic.words(a, &program, ts.shape, queries, c.seed, fault) catch |err| switch (err) {
                error.SyntheticNeedsDuplicate => continue,
                else => return err,
            };
            defer a.free(words);
            const legacy = NE.legacyBytes(a, ts.shape, words) catch null;
            defer if (legacy) |b| a.free(b);
            const got = try deviceEncode(a, w, &gpu.libs, &sym, &program, words, program.regionWords());
            defer a.free(got.region);
            if (legacy) |bytes| {
                if (fault != .none) {
                    std.debug.print("legacy accepted fault {s}\n", .{@tagName(fault)});
                    return error.TestUnexpectedResult;
                }
                try std.testing.expectEqual(@as(u32, 0), got.pcs);
                try std.testing.expectEqual(@as(u32, 0), got.enc);
                try std.testing.expectEqual(@as(u32, @intCast(bytes.len)), got.region[0]);
                try std.testing.expectEqualSlices(u8, bytes, std.mem.sliceAsBytes(got.region[1..])[0..bytes.len]);
                ok_cases += 1;
            } else {
                // Rejected by the device with a named check, length 0.
                try std.testing.expect(got.pcs != 0 or got.enc != 0);
                try std.testing.expectEqual(@as(u32, 0), got.region[0]);
                const which = if (got.pcs != 0) G.Verdict.checkOf(got.pcs) else G.Verdict.checkOf(got.enc);
                try std.testing.expect(which == .pcs_status or which == .encode_bounds);
                neg_cases += 1;
            }
        }
        // Overrun: a region one word short of the encoded size.
        {
            const words = try NE.Synthetic.words(a, &program, ts.shape, queries, c.seed, .none);
            defer a.free(words);
            const bytes = try NE.legacyBytes(a, ts.shape, words);
            defer a.free(bytes);
            const got = try deviceEncode(a, w, &gpu.libs, &sym, &program, words, bytes.len / 4);
            defer a.free(got.region);
            try std.testing.expectEqual(G.Verdict.reject(.encode_bounds, 1), got.enc);
            try std.testing.expectEqual(@as(u32, 0), got.region[0]);
            neg_cases += 1;
        }
    }
    std.debug.print("GPU_M8_NATIVE_ENCODE_PARITY byte_identical={} rejected={} shapes={}\n", .{ ok_cases, neg_cases, cases.len });
}

test "GPU: encoder CUDA-event time on segment-scale classes [M]" {
    var gpu = (try Support.Gpu.openNamed("native_encode_test.timing")) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.testing.allocator;
    const sym = try NE.Symbols.load(&gpu.libs.addon);
    const ev = try EventFns.load(&gpu.libs.addon);
    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 1 << 27, .pinned_slot_words = 1 << 25, .max_outstanding = 2 });
    defer w.destroy();
    // Segment-scale geometry: 4 trees (FIXED/MAIN/INTER/composition-like
    // column counts), 2^20-2^22 degree, beta 1, fold 4.
    const cases = [_]Case{
        .{ .seed = 11, .degree = 20, .cols = &.{ 120, 600, 400, 16 }, .fold = 4, .q = 128, .beta = 1 },
        .{ .seed = 12, .degree = 22, .cols = &.{ 200, 1200, 900, 16 }, .fold = 4, .q = 128, .beta = 1 },
        .{ .seed = 13, .degree = 22, .cols = &.{ 200, 1200, 900, 16 }, .fold = 4, .q = 256, .beta = 1 },
    };
    for (cases) |c| {
        var ts = try NE.TestShape.init(a, c.seed, c.degree, c.cols, cfg(c.fold, c.q, c.beta));
        defer ts.deinit();
        var program = try NE.Program.build(a, ts.shape);
        defer program.deinit();
        const queries = try NE.testQueries(a, c.seed, c.q, c.degree + c.beta);
        defer a.free(queries);
        const words = try NE.Synthetic.words(a, &program, ts.shape, queries, c.seed, .none);
        defer a.free(words);
        var timer = try std.time.Timer.start();
        const bytes = try NE.legacyBytes(a, ts.shape, words);
        const host_ns = timer.read();
        defer a.free(bytes);
        const result = try a.alloc(u32, 64 + program.regionWords());
        defer a.free(result);
        const repeat: u32 = 20;
        var probe = EncodeProbe{ .sym = &sym, .ops = &gpu.libs.ops, .events = ev, .program = &program, .words = words, .region_words = program.regionWords(), .repeat = repeat, .result = result };
        try runJob(w, api.Job.from(EncodeProbe, &probe));
        try std.testing.expectEqual(@as(u32, 0), result[1]);
        try std.testing.expectEqualSlices(u8, bytes, std.mem.sliceAsBytes(result[65..])[0..bytes.len]);
        std.debug.print("GPU_M8_NATIVE_ENCODE_TIMING degree={} queries={} columns={} pcs_words={} proof_bytes={} device_us_per_proof={d:.1} host_decode_encode_us={d:.1}\n", .{ c.degree, c.q, c.cols[0] + c.cols[1] + c.cols[2] + c.cols[3], words.len, bytes.len, @as(f64, @floatFromInt(probe.us)) / repeat, @as(f64, @floatFromInt(host_ns)) / 1000.0 });
    }
}

/// Generic check probe: staged input words, a slab of output words, and a
/// callback that enqueues the check(s).
const CheckProbe = struct {
    inputs: []const u32,
    out_words: usize,
    call: *const fn (*CheckProbe, *api.Enqueue, api.DeviceBuffer, api.DeviceBuffer) anyerror!void,
    user: *anyopaque,
    staged: ?api.DeviceBuffer = null,
    result: []u32,
    pub fn classKey(_: *CheckProbe) [32]u8 {
        return @splat(0x43);
    }
    pub fn footprint(self: *CheckProbe) api.Footprint {
        return .{ .device_words = self.inputs.len + (1 << 16), .staged_words = self.inputs.len + 64, .slab_words = self.out_words, .pinned_words = self.inputs.len + 64 };
    }
    pub fn stage(self: *CheckProbe, s: *api.Stager) !void {
        const b = try s.alloc(self.inputs.len);
        try s.upload(b, self.inputs);
        self.staged = b;
    }
    pub fn enqueue(self: *CheckProbe, e: *api.Enqueue) !void {
        try self.call(self, e, self.staged.?, e.slab.device);
    }
    pub fn finish(self: *CheckProbe, v: api.SlabView) !void {
        @memcpy(self.result, v.words[0..self.result.len]);
    }
    pub fn abort(_: *CheckProbe) void {}
};

fn feltWords(x: OM) [8]u32 {
    var w: [8]u32 = undefined;
    for (&w, x.toM31Array()) |*o, m| o.* = m.v;
    return w;
}

test "GPU: Stage-2 device checks equal the host checks (root_match, words_zero, public_claims, patch)" {
    var gpu = (try Support.Gpu.openNamed("native_encode_test.checks")) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.testing.allocator;
    const sym = try NE.Symbols.load(&gpu.libs.addon);
    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 1 << 22, .pinned_slot_words = 1 << 20, .max_outstanding = 2 });
    defer w.destroy();
    var prng = std.Random.DefaultPrng.init(0x5332);
    const rnd = prng.random();
    // Inputs: [0,63) PCS prefix (4 trees), [64,96) 4 committed roots, [96,104) zeros,
    // [104,112) one nonzero, then RAM challenges (15 felts), claims (4 felts),
    // initial tuples (n x 14), terminal tuples (m x 14), patch src/index/dst.
    const n_init: usize = 777;
    const n_term: usize = 300;
    var in: std.ArrayListUnmanaged(u32) = .empty;
    defer in.deinit(a);
    try in.appendNTimes(a, 0, 64);
    in.items[7] = 4;
    for (0..32) |i| in.items[31 + i] = rnd.int(u32);
    var rebuilt: [32]u32 = undefined;
    @memcpy(&rebuilt, in.items[31..63]);
    try in.appendSlice(a, &rebuilt); // committed == rebuilt
    try in.appendNTimes(a, 0, 8);
    try in.appendSlice(a, &.{ 0, 0, 0, 5, 0, 0, 0, 0 });
    const ram_at = in.items.len;
    var ram: [15]OM = undefined;
    for (&ram) |*r| {
        var limbs: [8]M = undefined;
        for (&limbs) |*l| l.* = M.fromCanonical(rnd.uintLessThan(u32, core.fields.m31.Modulus));
        r.* = OM.fromM31Array(limbs);
        try in.appendSlice(a, &feltWords(r.*));
    }
    const tuples_at = in.items.len;
    var sums: [2]OM = .{ OM.zero(), OM.zero() };
    for ([2]usize{ n_init, n_term }, 0..) |n, rel| for (0..n) |_| {
        var tuple: [14]u32 = undefined;
        for (&tuple) |*t| t.* = rnd.uintLessThan(u32, core.fields.m31.Modulus);
        try in.appendSlice(a, &tuple);
        var d = ram[0];
        for (tuple, 0..) |t, k| d = d.sub(ram[1 + k].mulM31(M.fromCanonical(t)));
        sums[rel] = sums[rel].add(try d.inv());
    };
    const claims_at = in.items.len;
    const claims = [4]OM{ OM.zero().sub(sums[0]), ram[3], sums[1], OM.zero() };
    for (claims) |cl| try in.appendSlice(a, &feltWords(cl));
    const bad_claims_at = in.items.len;
    var bad = claims;
    bad[2] = bad[2].add(OM.one());
    for (bad) |cl| try in.appendSlice(a, &feltWords(cl));
    const patch_at = in.items.len;
    try in.appendSlice(a, &.{ 2, 0, 14 }); // index
    try in.appendSlice(a, &.{ 16, 0, 8 }); // dst (words)
    const Ctx = struct {
        sym: *const NE.Symbols,
        ram_at: usize,
        tuples_at: usize,
        claims_at: usize,
        bad_at: usize,
        patch_at: usize,
        fn call(p: *CheckProbe, e: *api.Enqueue, input: api.DeviceBuffer, out: api.DeviceBuffer) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(p.user));
            const s = self.sym;
            const pcs = try input.slice(0, 64);
            const roots = [4]api.DeviceBuffer{ try input.slice(64, 8), try input.slice(72, 8), try input.slice(80, 8), try input.slice(88, 8) };
            try NE.rootMatch(s, e.ctx(), pcs, &roots, null, try out.slice(0, 1));
            const swapped = [4]api.DeviceBuffer{ roots[0], roots[2], roots[1], roots[3] };
            try NE.rootMatch(s, e.ctx(), pcs, &swapped, null, try out.slice(1, 1));
            try NE.wordsZero(s, e.ctx(), try input.slice(96, 8), .global_status, try out.slice(2, 1));
            try NE.wordsZero(s, e.ctx(), try input.slice(104, 8), .composition_accept, try out.slice(3, 1));
            const ramb = try input.slice(self.ram_at, 120);
            const bi = NE.BoundaryInput{ .claim = 0, .tuples = try input.slice(self.tuples_at, 777 * 14), .cells = 777 };
            const bt = NE.BoundaryInput{ .claim = 2, .tuples = try input.slice(self.tuples_at + 777 * 14, 300 * 14), .cells = 300 };
            const scratch = try e.alloc(NE.publicClaimsScratch(s, bi, bt));
            try NE.publicClaims(s, e.ctx(), try input.slice(self.claims_at, 32), 4, ramb, bi, bt, scratch, try out.slice(4, 1));
            const scratch2 = try e.alloc(NE.publicClaimsScratch(s, bi, bt));
            try NE.publicClaims(s, e.ctx(), try input.slice(self.bad_at, 32), 4, ramb, bi, bt, scratch2, try out.slice(5, 1));
            try NE.patchFelts(s, e.ctx(), ramb, try input.slice(self.patch_at, 3), try input.slice(self.patch_at + 3, 3), try out.slice(16, 32));
            e.free(scratch2);
            e.free(scratch);
        }
    };
    var c = Ctx{ .sym = &sym, .ram_at = ram_at, .tuples_at = tuples_at, .claims_at = claims_at, .bad_at = bad_claims_at, .patch_at = patch_at };
    const result = try a.alloc(u32, 48);
    defer a.free(result);
    var probe = CheckProbe{ .inputs = in.items, .out_words = 64, .call = Ctx.call, .user = &c, .result = result };
    try runJob(w, api.Job.from(CheckProbe, &probe));
    try std.testing.expectEqual(@as(u32, 0), result[0]);
    try std.testing.expectEqual(G.Verdict.reject(.root_match, 0x11), result[1]);
    try std.testing.expectEqual(@as(u32, 0), result[2]);
    try std.testing.expectEqual(G.Verdict.reject(.composition_accept, 4), result[3]);
    try std.testing.expectEqual(@as(u32, 0), result[4]);
    try std.testing.expectEqual(G.Verdict.reject(.public_claims, 4), result[5]);
    // patch: out[16..24) = ram[2] -> slot 16 - 16 = 0; out[16+0..] ... (dst relative to out slice at 16)
    try std.testing.expectEqualSlices(u32, &feltWords(ram[2]), result[32..40]);
    try std.testing.expectEqualSlices(u32, &feltWords(ram[0]), result[16..24]);
    try std.testing.expectEqualSlices(u32, &feltWords(ram[14]), result[24..32]);
    std.debug.print("GPU_M8_NATIVE_CHECKS_PARITY root_match=1 words_zero=1 public_claims=1 patch=1 negatives=3 boundary_cells={}\n", .{n_init + n_term});
}

/// Seal probe: staged [entries | replica copy 0 | replica copy 1]; the seal
/// writes its slot inside each staged replica (copy 1 misses one root flag),
/// then the slots and the shared draws are copied into the slab.
const SealProbe = struct {
    ssym: *const NS2.SealSymbols,
    ops: *const O.Ops,
    constants: NS2.SealConstants,
    entries: []const NS2.SealEntry,
    inputs: []const u32,
    xw: usize,
    seal: G.Exchange.Slot,
    staged: ?api.DeviceBuffer = null,
    result: []u32,
    pub fn classKey(_: *SealProbe) [32]u8 {
        return @splat(0x53);
    }
    pub fn footprint(self: *SealProbe) api.Footprint {
        return .{ .device_words = self.inputs.len + 4096, .staged_words = self.inputs.len + 64, .slab_words = 64 + 8 * NS2.shared_felts, .pinned_words = self.inputs.len + 64 };
    }
    pub fn stage(self: *SealProbe, s: *api.Stager) !void {
        const b = try s.alloc(self.inputs.len);
        try s.upload(b, self.inputs);
        self.staged = b;
    }
    pub fn enqueue(self: *SealProbe, e: *api.Enqueue) !void {
        const st = self.staged.?;
        const ew = self.entries.len * 48;
        const out = e.slab.device;
        for (0..2) |copy| {
            const x = try st.slice(ew + copy * self.xw, self.xw);
            const slot = try x.slice(self.seal.offset, 16);
            try NS2.rcOf(self.ssym.seal(e.ctx(), 0, @ptrCast(st.ptr), x.ptr, x.words, &self.constants, slot.ptr, (try out.slice(copy, 1)).ptr, self.entries.ptr));
            try O.check(self.ops.exec.copy_async(@ptrCast(out.ptr + 16 + 16 * copy), @ptrCast(slot.ptr), 64, 3, e.stream()));
            if (copy == 0) try NS2.rcOf(self.ssym.shared(e.ctx(), 0, slot.ptr, &self.constants, out.ptr + 64, 8 * NS2.shared_felts));
        }
    }
    pub fn finish(self: *SealProbe, v: api.SlabView) !void {
        @memcpy(self.result, v.words[0..self.result.len]);
    }
    pub fn abort(_: *SealProbe) void {}
};

test "GPU: device seal chi and shared draws equal the manifest authority; unlanded root rejects" {
    var gpu = (try Support.Gpu.openNamed("native_encode_test.seal")) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.testing.allocator;
    const ssym = try NS2.SealSymbols.load(&gpu.libs.addon);
    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 1 << 22, .pinned_slot_words = 1 << 20, .max_outstanding = 2 });
    defer w.destroy();
    const n = 7;
    var roster: [n]NS2.RosterEntry = undefined;
    var workers: [n]Manifest.ExpectedWorker = undefined;
    var stages: [n]Manifest.StageOne = undefined;
    NS2.testRoster(11, n, &roster, &workers, &stages);
    const execution: [32]u8 = @splat(0x77);
    var pending = try Manifest.verifyAndSealFor(.m6_v2_gkr, a, execution, &workers, &stages);
    defer pending.deinit(a);
    const sh = Manifest.drawShared(pending.digest);
    const ex = G.Exchange{ .segments = n, .claims_per_segment = 3, .devices = 2 };
    const entries = try NS2.sealEntries(a, &roster, ex);
    defer a.free(entries);
    const tag = G.Exchange.flagTag(5);
    const identity = try CPU.rv64_gkr_chain.versionIdentity(.m6_v2_gkr);
    const xw = ex.words();
    var inputs: std.ArrayListUnmanaged(u32) = .empty;
    defer inputs.deinit(a);
    try inputs.appendSlice(a, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(entries)));
    const base = inputs.items.len;
    try inputs.appendNTimes(a, 0, 2 * xw);
    for (0..2) |copy| for (roster, 0..) |r, s| {
        const slot = try ex.root(@intCast(s));
        @memcpy(inputs.items[base + copy * xw + slot.offset ..][0..8], &NS2.words8(r.root));
        if (!(copy == 1 and s == 4)) inputs.items[base + copy * xw + slot.flag] = tag;
    };
    const result = try a.alloc(u32, 64 + 8 * NS2.shared_felts);
    defer a.free(result);
    var probe = SealProbe{ .ssym = &ssym, .ops = &gpu.libs.ops, .constants = NS2.sealConstants(identity, execution, n, tag), .entries = entries, .inputs = inputs.items, .xw = xw, .seal = ex.seal(), .result = result };
    try runJob(w, api.Job.from(SealProbe, &probe));
    try std.testing.expectEqual(@as(u32, 0), result[0]);
    try std.testing.expectEqual(G.Verdict.reject(.global_seal, 1), result[1]);
    try std.testing.expectEqualSlices(u32, &NS2.words8(pending.digest), result[16..24]);
    try std.testing.expectEqualSlices(u32, &([_]u32{0} ** 8), result[24..32]);
    var want: std.ArrayListUnmanaged(u32) = .empty;
    defer want.deinit(a);
    try want.appendSlice(a, &feltWords(sh.ram.offset));
    for (sh.ram.coefficients) |x| try want.appendSlice(a, &feltWords(x));
    try want.appendSlice(a, &feltWords(sh.kio.offset));
    for (sh.kio.coefficients) |x| try want.appendSlice(a, &feltWords(x));
    try want.appendSlice(a, &feltWords(sh.wire.offset));
    for (sh.wire.coefficients) |x| try want.appendSlice(a, &feltWords(x));
    try std.testing.expectEqualSlices(u32, want.items, result[64..]);
    std.debug.print("GPU_M8_NATIVE_SEAL_PARITY entries={} chi_equal=1 shared_equal=1 shared_felts={} unlanded_rejected=1\n", .{ n, NS2.shared_felts });
}
