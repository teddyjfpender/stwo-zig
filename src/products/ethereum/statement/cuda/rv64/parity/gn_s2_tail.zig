//! Parity tail sealing, adversarial mutations and exact receipt comparison.
const CPU = @import("stwo_riscv_cpu_integration");
const Events = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.cuda_events;
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const ManifestM = CPU.rv64_gkr_manifest;
const NE = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_encode;
const NO = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_encode_oods;
const Peer = @import("gn_s2_common.zig").Peer;
const Recorder = @import("gn_s2_capture.zig").Recorder;
const S2D = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage2;
const Seg = @import("gn_s2_capture.zig").Seg;
const W = jobs.worker;
const api = jobs.api;
const core = @import("stwo_core");
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const run = @import("gn_s2_common.zig").run;
const std = @import("std");
const words8 = @import("gn_s2_common.zig").words8;

pub const Fault = enum { none, sample, parameter, hc_row, alpha, point_status, noncanonical_sample, composition_sample, descriptor, pcs_header, seal_flag, seal_receipt };
/// Slab words of the tail job.
pub const T = struct {
    const oods = 0;
    const pcs_status = 1;
    const encode = 2;
    const seal = 3;
    const root_match = 4;
    const diag = 8; // 16
    const shared = 64; // 8 * shared_felts
    const replica = 1024;
};

pub const TailJob = struct {
    a: std.mem.Allocator,
    seg: *const Seg,
    rec: *const Recorder,
    esym: *const NE.Symbols,
    osym: *const NO.Symbols,
    ssym: *const S2D.SealSymbols,
    events: *const Events.Api,
    peer: Peer,
    fault: Fault = .none,
    // replica + script (host)
    exchange: G.Exchange,
    replica: []u32,
    script: S2D.FlatScript,
    constants: S2D.SealConstants,
    tag: u32,
    region_at: usize = 0,
    // staged
    s_desc: ?api.DeviceBuffer = null,
    s_table: ?api.DeviceBuffer = null,
    s_words: ?api.DeviceBuffer = null,
    s_prog: ?api.DeviceBuffer = null,
    s_alpha: ?api.DeviceBuffer = null,
    s_point: ?api.DeviceBuffer = null,
    s_replica: ?api.DeviceBuffer = null,
    s_ops: ?api.DeviceBuffer = null,
    s_pool: ?api.DeviceBuffer = null,
    s_roots: ?api.DeviceBuffer = null,
    ev: [8]?*anyopaque = @splat(null),
    // results
    out: []u32 = &.{},
    ms: [3]f32 = .{ -1, -1, -1 }, // seal+shared, oods, encode

    pub fn classKey(_: *TailJob) [32]u8 {
        var k: [32]u8 = @splat(0);
        @memcpy(k[0..15], "rv64-gn-s2-tail");
        return k;
    }
    pub fn regionWords(self: *const TailJob) usize {
        return self.seg.encode.?.regionWords();
    }
    pub fn footprint(self: *TailJob) api.Footprint {
        const g = 64;
        const staged = self.seg.desc.len + self.seg.table.len + self.seg.words.len + self.seg.encode.?.words.len + self.replica.len + self.script.ops.len + self.script.pool.len + 32 + 64 + 40 + 10 * g;
        return .{ .device_words = staged + NO.scratchWords(self.seg.desc) + NE.scratch_words + 8 * S2D.shared_felts + 64 * g, .staged_words = staged, .slab_words = self.region_at + self.regionWords(), .pinned_words = staged };
    }
    pub fn up(s: *api.Stager, w: []const u32) !api.DeviceBuffer {
        const b = try s.alloc(@max(1, w.len));
        if (w.len != 0) try s.upload(try b.slice(0, w.len), w);
        return try b.slice(0, w.len);
    }
    pub fn stage(self: *TailJob, s: *api.Stager) !void {
        for (&self.ev) |*e| if (self.events.create(e, 0) != 0 or e.* == null) return error.CudaTimingFailed;
        const a = self.a;
        const seg = self.seg;
        const enc = &seg.encode.?;
        // Faults are applied to private copies of the recorded inputs.
        const desc = try a.dupe(u32, seg.desc);
        defer a.free(desc);
        const table = try a.dupe(u32, seg.table);
        defer a.free(table);
        const words = try a.dupe(u32, seg.words);
        defer a.free(words);
        var alpha = words8(seg.alpha);
        var point = seg.oods_field;
        const samples_at = enc.get(.off_samples);
        const first_role = desc[NO.H.header_words..][0..NO.Role.words];
        switch (self.fault) {
            .sample => {
                // The first sample read by the first role.
                const ins = desc[first_role[NO.Role.inputs_at]..];
                var idx: ?u32 = null;
                for (0..first_role[NO.Role.n_inputs]) |i| if (ins[2 * i] == @intFromEnum(NO.InputKind.sample)) {
                    idx = ins[2 * i + 1];
                    break;
                };
                const at = samples_at + 8 * (idx orelse return error.ParityNoSampleRead);
                words[at] = (words[at] + 1) % core.fields.m31.Modulus;
            },
            .parameter => {
                var done = false;
                var r: usize = 0;
                while (r < desc[NO.H.roles] and !done) : (r += 1) {
                    const row = desc[NO.H.header_words + r * NO.Role.words ..][0..NO.Role.words];
                    if (row[NO.Role.n_params] == 0) continue;
                    // A parameter the program reads (first .parameter node).
                    const nodes = desc[row[NO.Role.nodes_at]..];
                    for (0..row[NO.Role.n_nodes]) |k| if (nodes[4 * k] == @intFromEnum(NO.ir.Op.parameter)) {
                        const at = row[NO.Role.params_at] + 8 * nodes[4 * k + 3];
                        table[at] = (table[at] + 1) % core.fields.m31.Modulus;
                        done = true;
                        break;
                    };
                }
                if (!done) return error.ParityNoParameterRead;
            },
            .hc_row => {
                var r: usize = 0;
                while (r < desc[NO.H.roles]) : (r += 1) {
                    const row = desc[NO.H.header_words + r * NO.Role.words ..][0..NO.Role.words];
                    if (row[NO.Role.flags] & NO.flag_aux == 0) continue;
                    table[row[NO.Role.hc_at]] = (table[row[NO.Role.hc_at]] + 1) % core.fields.m31.Modulus;
                    break;
                } else return error.ParityNoAuxRole;
            },
            .alpha => alpha[0] = (alpha[0] + 1) % core.fields.m31.Modulus,
            .point_status => point[32] = 1,
            .noncanonical_sample => {
                const ins = desc[first_role[NO.Role.inputs_at]..];
                for (0..first_role[NO.Role.n_inputs]) |i| if (ins[2 * i] == @intFromEnum(NO.InputKind.sample)) {
                    words[samples_at + 8 * ins[2 * i + 1] + 3] = core.fields.m31.Modulus;
                    break;
                };
            },
            .composition_sample => {
                const at = samples_at + 8 * desc[NO.H.composition_sample];
                words[at] = (words[at] + 1) % core.fields.m31.Modulus;
            },
            .descriptor => desc[NO.H.header_words + NO.Role.regs_at] = 0x7fff_0000,
            .pcs_header => words[0] ^= 1,
            .seal_flag, .seal_receipt, .none => {},
        }
        self.s_desc = try up(s, desc);
        self.s_table = try up(s, table);
        self.s_words = try up(s, words);
        self.s_prog = try up(s, enc.words);
        self.s_alpha = try up(s, &alpha);
        self.s_point = try up(s, &point);
        self.s_replica = try up(s, self.replica);
        self.s_ops = try up(s, self.script.ops);
        self.s_pool = try up(s, self.script.pool);
        var roots: [32]u32 = undefined;
        for (seg.roots, 0..) |r, t| roots[8 * t ..][0..8].* = S2D.words8(r);
        self.s_roots = try up(s, &roots);
    }
    pub fn mark(self: *TailJob, e: *api.Enqueue, i: usize) !void {
        if (self.events.record(self.ev[i].?, e.stream()) != 0) return error.CudaTimingFailed;
    }
    pub fn enqueue(self: *TailJob, e: *api.Enqueue) !void {
        const slab = e.slab.device;
        const seg = self.seg;
        const enc = &seg.encode.?;
        // Replica into the slab (the seal slot must lie inside its replica).
        const x = try slab.slice(T.replica, self.replica.len);
        try self.peer.local(e, x.ptr, self.s_replica.?.ptr, self.replica.len);
        // ---- seal (flat digest script) + shared draws
        try self.mark(e, 0);
        const seal = self.exchange.seal();
        try S2D.sealFlat(try self.ssym.flatFn(), e.ctx(), self.s_ops.?, self.s_pool.?, self.script.pool_bytes, x, self.tag, try x.slice(seal.offset, 16), try slab.slice(T.seal, 1), self.script.ops);
        try S2D.rcOf(self.ssym.shared(e.ctx(), 0, (try x.slice(seal.offset, 8)).ptr, &self.constants, (try slab.slice(T.shared, 8 * S2D.shared_felts)).ptr, 8 * S2D.shared_felts));
        try self.mark(e, 1);
        // ---- oods_constraint
        try self.mark(e, 2);
        const samples = try self.s_words.?.slice(enc.get(.off_samples), 8 * @as(usize, enc.get(.sample_count)));
        const scratch = try e.alloc(NO.scratchWords(seg.desc));
        try NO.enqueue(self.osym, e.ctx(), self.s_desc.?, samples, self.s_table.?, self.s_alpha.?, self.s_point.?, scratch, try slab.slice(T.oods, 1), try slab.slice(T.diag, 16));
        try self.mark(e, 3);
        // ---- encoder (+ pcs_status, encode_bounds)
        try self.mark(e, 4);
        const escratch = try e.alloc(NE.scratch_words);
        var encoder = NE.Encoder{ .sym = self.esym, .program = self.s_prog.?, .host = enc, .pcs = self.s_words.?, .scratch = escratch, .pcs_status = try slab.slice(T.pcs_status, 1) };
        try encoder.enqueue(e.ctx(), try slab.slice(self.region_at, self.regionWords()), try slab.slice(T.encode, 1));
        try self.mark(e, 5);
        // ---- root_match: the image's tree roots vs the recorded roots
        const r = self.s_roots.?;
        try NE.rootMatch(self.esym, e.ctx(), self.s_words.?, &.{ try r.slice(0, 8), try r.slice(8, 8), try r.slice(16, 8), try r.slice(24, 8) }, seg.roots[0], try slab.slice(T.root_match, 1));
        e.free(escratch);
        e.free(scratch);
    }
    pub fn finish(self: *TailJob, v: api.SlabView) !void {
        self.out = try self.a.dupe(u32, v.words);
        for (0..3) |i| if (self.events.elapsed(&self.ms[i], self.ev[2 * i].?, self.ev[2 * i + 1].?) != 0) {
            self.ms[i] = -1;
        };
    }
    pub fn abort(_: *TailJob) void {}
    pub fn deinit(self: *TailJob) void {
        for (self.ev) |e| if (e) |x| {
            _ = self.events.destroy(x);
        };
        self.a.free(self.out);
    }
};

/// The exchange replica + flat script of the recorded manifest (every CPU
/// entry a segment, every other entry a two-stage truth root slot).
pub fn sealInputs(a: std.mem.Allocator, rec: *const Recorder, cpu: usize, tag: u32, fault: Fault) !struct { exchange: G.Exchange, replica: []u32, script: S2D.FlatScript } {
    const n = rec.flat.len;
    var max_claims: u32 = 0;
    for (rec.flat) |e| if (e.local_instances) |m| {
        max_claims = @max(max_claims, 2 * m);
    };
    const ex = G.Exchange{ .segments = @intCast(cpu), .claims_per_segment = @max(1, max_claims), .devices = 1, .truths = @intCast(n - cpu), .receipts = true };
    try ex.validate();
    const x = try a.alloc(u32, ex.words());
    @memset(x, 0);
    const entries = try a.dupe(S2D.FlatEntry, rec.flat);
    defer a.free(entries);
    for (entries, 0..) |*e, k| {
        if (k < cpu) {
            e.segment = @intCast(k);
            const root = try ex.root(@intCast(k));
            x[root.flag] = tag;
            @memcpy(x[root.offset..][0..8], &S2D.words8(rec.mains[k]));
            const rcpt = try ex.receipt(@intCast(k));
            x[rcpt.flag] = tag;
            @memcpy(x[rcpt.offset..][0..8], &S2D.words8(rec.receipts[k]));
            const cl = try ex.claims(@intCast(k));
            x[cl.flag] = tag;
            @memcpy(x[cl.offset..][0..rec.marginals[k].len], rec.marginals[k]);
        } else {
            if (e.local_instances != null) return error.ParityTruthWithLocal;
            e.truth = @intCast(k - cpu);
            const tr = try ex.truthRoot(@intCast(k - cpu));
            x[tr.flag] = tag;
            @memcpy(x[tr.offset..][0..8], &S2D.words8(rec.mains[k]));
        }
    }
    switch (fault) {
        .seal_flag => x[(try ex.truthRoot(0)).flag] = tag +% 1,
        .seal_receipt => x[(try ex.receipt(0)).offset] ^= 1,
        else => {},
    }
    return .{ .exchange = ex, .replica = x, .script = try S2D.FlatScript.build(a, ManifestM.PROFILE, rec.execution, entries, ex) };
}

pub const NegativeRow = struct { fault: []const u8, expected: []const u8, fired: bool, words: [5]u32, error_name: []const u8 = "" };
pub const Row = struct {
    ordinal: u32,
    roles: usize,
    nodes: usize,
    samples: u32,
    mask_log: u32,
    split: u32,
    oods_replay_equal: bool,
    host_accept: bool,
    mirror_word: u32,
    mirror_eval_equal: bool,
    words: [5]u32 = @splat(G.Verdict.unset),
    diag_equal: bool = false,
    seal_digest_equal: bool = false,
    shared_equal: bool = false,
    bytes_equal: bool = false,
    legacy_bytes: usize = 0,
    device_bytes: usize = 0,
    seal_shared_gpu_ms: [4]f32 = @splat(-1),
    oods_gpu_ms: [4]f32 = @splat(-1),
    encode_gpu_ms: [4]f32 = @splat(-1),
    stage_ns: [4]u64 = @splat(0),
    enqueue_ns: [4]u64 = @splat(0),
    wait_ns: [4]u64 = @splat(0),
    host_waits: u32 = 0,
    pcs_gpu_ms: f32 = -1,
    host_check_ns: u64 = 0,
    class_build_ns: u64 = 0,
    flat_script_ns: u64 = 0,
    negatives: []const NegativeRow = &.{},
    error_name: []const u8 = "",
};

pub fn runTail(a: std.mem.Allocator, worker: *W.Worker, rec: *const Recorder, seg: *const Seg, esym: *const NE.Symbols, osym: *const NO.Symbols, ssym: *const S2D.SealSymbols, events: *const Events.Api, peer: Peer, constants: S2D.SealConstants, cpu: usize, tag: u32, fault: Fault) !struct { job: TailJob, receipt: api.Receipt } {
    const si = try sealInputs(a, rec, cpu, tag, fault);
    var job = TailJob{ .a = a, .seg = seg, .rec = rec, .esym = esym, .osym = osym, .ssym = ssym, .events = events, .peer = peer, .fault = fault, .exchange = si.exchange, .replica = si.replica, .script = si.script, .constants = constants, .tag = tag };
    job.region_at = std.mem.alignForward(usize, T.replica + si.replica.len, 64);
    errdefer {
        job.script.deinit();
        a.free(job.replica);
        job.deinit();
    }
    const receipt = try run(worker, api.Job.from(TailJob, &job));
    return .{ .job = job, .receipt = receipt };
}
pub fn freeTail(a: std.mem.Allocator, job: *TailJob) void {
    job.script.deinit();
    a.free(job.replica);
    job.deinit();
}

pub fn tailOne(a: std.mem.Allocator, worker: *W.Worker, rec: *const Recorder, seg: *const Seg, esym: *const NE.Symbols, osym: *const NO.Symbols, ssym: *const S2D.SealSymbols, events: *const Events.Api, peer: Peer, constants: S2D.SealConstants, cpu: usize, tag: u32, digest: [32]u8, proof_dir: []const u8, repeat: usize, negatives: bool, row: *Row) !void {
    if (seg.encode == null or seg.desc.len == 0 or seg.words.len == 0) return error.ParitySegmentNotRecorded;
    var nb: [64]u8 = undefined;
    const path = try std.fs.path.join(a, &.{ proof_dir, try std.fmt.bufPrint(&nb, "cpu-{d}.bin", .{seg.ordinal}) });
    const legacy = try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
    defer a.free(legacy);
    row.legacy_bytes = legacy.len;
    for (0..@max(1, @min(repeat, 4))) |k| {
        var t = try runTail(a, worker, rec, seg, esym, osym, ssym, events, peer, constants, cpu, tag, .none);
        defer freeTail(a, &t.job);
        row.seal_shared_gpu_ms[k] = t.job.ms[0];
        row.oods_gpu_ms[k] = t.job.ms[1];
        row.encode_gpu_ms[k] = t.job.ms[2];
        row.stage_ns[k] = t.receipt.stage_ns;
        row.enqueue_ns[k] = t.receipt.enqueue_ns;
        row.wait_ns[k] = t.receipt.wait_ns;
        row.host_waits = t.receipt.host_waits;
        if (k != 0) continue;
        const out = t.job.out;
        row.words = .{ out[T.oods], out[T.pcs_status], out[T.encode], out[T.seal], out[T.root_match] };
        row.diag_equal = std.mem.eql(u32, out[T.diag..][0..8], &seg.host_eval) and std.mem.eql(u32, out[T.diag + 8 ..][0..8], &seg.host_extracted);
        const seal = t.job.exchange.seal();
        row.seal_digest_equal = std.mem.eql(u32, out[T.replica + seal.offset ..][0..8], &S2D.words8(digest));
        row.shared_equal = std.mem.eql(u32, out[T.shared..][0 .. 8 * S2D.shared_felts], &rec.pending_shared);
        const region = out[t.job.region_at..];
        const n = region[0];
        row.device_bytes = n;
        row.bytes_equal = n == legacy.len and std.mem.eql(u8, std.mem.sliceAsBytes(region[1..])[0..n], legacy);
    }
    if (!negatives) return;
    // index: oods, pcs_status, encode_bounds, global_seal, root_match
    const Case = struct { fault: Fault, expect: u5, allow: u5 = 0, name: []const u8 };
    const cases = [_]Case{
        .{ .fault = .sample, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .parameter, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .hc_row, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .alpha, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .point_status, .expect = 1, .name = "oods_constraint" },
        // The encoder refuses non-canonical image values too (encode_bounds).
        .{ .fault = .noncanonical_sample, .expect = 1, .allow = 4, .name = "oods_constraint" },
        .{ .fault = .composition_sample, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .descriptor, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .pcs_header, .expect = 2, .allow = 4 | 16, .name = "pcs_status" },
        .{ .fault = .seal_flag, .expect = 8, .name = "global_seal" },
        .{ .fault = .seal_receipt, .expect = 0, .name = "seal digest != manifest digest" },
    };
    var list: std.ArrayListUnmanaged(NegativeRow) = .empty;
    for (cases) |c| {
        var neg = NegativeRow{ .fault = @tagName(c.fault), .expected = c.name, .fired = false, .words = @splat(G.Verdict.unset) };
        if (runTail(a, worker, rec, seg, esym, osym, ssym, events, peer, constants, cpu, tag, c.fault)) |res| {
            var t = res;
            defer freeTail(a, &t.job);
            const out = t.job.out;
            neg.words = .{ out[T.oods], out[T.pcs_status], out[T.encode], out[T.seal], out[T.root_match] };
            var ok = true;
            for (neg.words, 0..) |w, i| {
                const bit = @as(u5, 1) << @intCast(i);
                if (c.expect & bit != 0) ok = ok and w != G.Verdict.accepted and w != G.Verdict.unset else if (c.allow & bit == 0) ok = ok and w == G.Verdict.accepted;
            }
            if (c.fault == .seal_receipt) ok = ok and !std.mem.eql(u32, out[T.replica + t.job.exchange.seal().offset ..][0..8], &S2D.words8(digest));
            neg.fired = ok;
        } else |err| neg.error_name = @errorName(err);
        // A fault the segment cannot express (no aux role) is skipped, not counted.
        if (std.mem.eql(u8, neg.error_name, "ParityNoAuxRole")) continue;
        std.debug.print("GPU_M8_GN_S2_NEGATIVE ordinal={} fault={s} expected={s} fired={} words={any} error={s}\n", .{ seg.ordinal, neg.fault, neg.expected, neg.fired, neg.words, neg.error_name });
        try list.append(a, neg);
    }
    row.negatives = list.items;
}
