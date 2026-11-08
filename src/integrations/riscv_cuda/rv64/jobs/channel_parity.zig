//! Channel parity harness (spec §3.3): the byte-identity contract between the
//! host `raw_mod_m31.Om31Channel` and the job path's `DeviceChannel`.
//!
//! A `Script` is a transcript op sequence, either written directly or
//! recorded from any host Om31Channel through the `om31_observer` hook
//! (`Recorder`, the same hook device_fs_check.zig uses). `ParityJob` replays it
//! as an ordinary job: inputs staged once, every op enqueued on the device
//! channel, a boundary snapshot of every op and every draw output written into
//! the slab, one D2H. `finish` replays the host channel op by op and requires
//! every boundary snapshot to equal the host word for word (digest, draws) and
//! the ordering guard (cursor, chain, status) to be exact.
const std = @import("std");
const Raw = @import("stwo_core").channel.raw_mod_m31;
const api = @import("api.zig");
const Ch = @import("channel.zig");
const S = @import("slab.zig");

pub const Op = union(enum) {
    mix_words: []const u32,
    mix_felts: []const u32, // 8 canonical words per OM31
    mix_root: [8]u32,
    draw_felts: u32, // count
    draw_raw,
    queries: struct { log: u32, count: u32 },
    pow: u32, // bits
};

pub const Script = struct {
    seed: Raw.Om31Checkpoint,
    ops: []const Op,
    pub fn inputWords(self: Script) usize {
        var n: usize = 9;
        for (self.ops) |op| n += switch (op) {
            .mix_words => |w| w.len,
            .mix_felts => |w| w.len,
            .mix_root => 8,
            else => 0,
        };
        return n;
    }
    pub fn outputWords(op: Op) usize {
        return switch (op) {
            .draw_felts => |n| @as(usize, n) * 8,
            .draw_raw => 8,
            .queries => |q| q.count,
            .pow => Ch.DeviceChannel.pow_workspace_words,
            else => 0,
        };
    }
};

fn seedWords(c: Raw.Om31Checkpoint) [9]u32 {
    var out: [9]u32 = undefined;
    for (0..8) |i| out[i] = std.mem.readInt(u32, c.digest[4 * i ..][0..4], .little);
    out[8] = c.draws;
    return out;
}

fn hostChannel(c: Raw.Om31Checkpoint) Raw.Om31Channel {
    var ch = Raw.Om31Channel.init();
    ch.inner.digest = c.digest;
    ch.inner.n_draws = c.draws;
    return ch;
}

pub const ParityJob = struct {
    script: Script,
    layout: S.ProofLayout = .{},
    seed: api.DeviceBuffer = undefined,
    inputs: api.DeviceBuffer = undefined,
    checked_ops: usize = 0,
    failure: ?anyerror = null,
    mismatch_op: ?usize = null,
    expected_chain_base: u64 = 0,
    /// Test knobs: take mix inputs from worker-persistent memory keyed by
    /// `persistent_key` (uploaded only when fresh), or fail enqueue after n ops.
    persistent_key: ?[32]u8 = null,
    used_warm_inputs: bool = false,
    fail_after_ops: ?usize = null,
    aborted: bool = false,

    pub fn init(script: Script) !ParityJob {
        var self = ParityJob{ .script = script };
        for (script.ops, 0..) |op, i| {
            _ = try self.layout.add(.snapshot, @intCast(i), Ch.snapshot_words);
            const out = Script.outputWords(op);
            if (out != 0) _ = try self.layout.add(.opaque_words, @intCast(i), out);
        }
        return self;
    }
    pub fn classKey(_: *ParityJob) [32]u8 {
        return @splat(0x50);
    }
    pub fn footprint(self: *ParityJob) api.Footprint {
        const staged = std.mem.alignForward(usize, self.script.inputWords(), 64) + 64;
        return .{ .device_words = staged + 1024, .staged_words = staged, .slab_words = self.layout.words, .pinned_words = self.script.inputWords() };
    }
    pub fn stage(self: *ParityJob, s: *api.Stager) !void {
        if (self.persistent_key) |key| return self.stagePersistent(s, key);
        const host = try s.pinned(self.script.inputWords());
        self.fillInputs(host);
        const device = try s.alloc(host.len);
        try s.upload(device, host);
        self.seed = try device.slice(0, 9);
        self.inputs = try device.slice(9, host.len - 9);
    }
    fn fillInputs(self: *ParityJob, host: []u32) void {
        @memcpy(host[0..9], &seedWords(self.script.seed));
        var at: usize = 9;
        for (self.script.ops) |*op| {
            const words: []const u32 = switch (op.*) {
                .mix_words => |w| w,
                .mix_felts => |w| w,
                .mix_root => |*r| r,
                else => &.{},
            };
            @memcpy(host[at..][0..words.len], words);
            at += words.len;
        }
    }
    fn stagePersistent(self: *ParityJob, s: *api.Stager, key: [32]u8) !void {
        const p = try s.persistent(key, self.script.inputWords());
        self.used_warm_inputs = !p.fresh;
        if (p.fresh) {
            const host = try s.pinned(self.script.inputWords());
            self.fillInputs(host);
            try s.upload(p.buffer, host);
        }
        self.seed = try p.buffer.slice(0, 9);
        self.inputs = try p.buffer.slice(9, p.buffer.words - 9);
    }
    pub fn enqueue(self: *ParityJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        const ch = e.channel;
        try ch.initFromCheckpoint(self.seed);
        self.expected_chain_base = ch.chain_base;
        var at: usize = 0;
        for (self.script.ops, 0..) |op, i| {
            if (self.fail_after_ops) |n| if (i == n) return error.InjectedMidEnqueueFailure;
            const index: u32 = @intCast(i);
            switch (op) {
                .mix_words => |w| {
                    try ch.mixWords(try self.inputs.slice(at, w.len));
                    at += w.len;
                },
                .mix_felts => |w| {
                    try ch.mixFelts(try self.inputs.slice(at, w.len));
                    at += w.len;
                },
                .mix_root => {
                    try ch.mixRootFromTree(try self.inputs.slice(at, 8));
                    at += 8;
                },
                .draw_felts => |n| try ch.drawSecureFelts(n, try e.slab.field(.opaque_words, index)),
                .draw_raw => try ch.drawRaw(try e.slab.field(.opaque_words, index)),
                .queries => |q| try ch.drawQueries(q.log, q.count, try e.slab.field(.opaque_words, index)),
                .pow => |bits| try ch.pow(bits, try e.slab.field(.opaque_words, index)),
            }
            try ch.snapshot(e.slab, (try self.layout.get(.snapshot, index)).offset);
        }
    }
    pub fn finish(self: *ParityJob, view: api.SlabView) !void {
        self.compare(view) catch |err| {
            self.failure = err;
            return err;
        };
    }
    fn compare(self: *ParityJob, view: api.SlabView) !void {
        var host = hostChannel(self.script.seed);
        var steps: u32 = 0;
        for (self.script.ops, 0..) |op, i| {
            const index: u32 = @intCast(i);
            const out: []const u32 = if (Script.outputWords(op) != 0) try S.read(view, .opaque_words, index) else &.{};
            switch (op) {
                .mix_words => |w| host.mixU32s(w),
                .mix_felts => |w| {
                    var felts: [64]@TypeOf(host).SecureField = undefined;
                    if (w.len / 8 > felts.len) return error.ParityScriptTooLarge;
                    for (0..w.len / 8) |f| {
                        var limbs: [8]@import("stwo_core").fields.m31.M31 = undefined;
                        for (&limbs, w[8 * f ..][0..8]) |*l, v| l.* = .fromCanonical(v);
                        felts[f] = .fromM31Array(limbs);
                    }
                    host.mixFelts(felts[0 .. w.len / 8]);
                },
                .mix_root => |r| host.mixU32s(&r),
                .draw_felts => |n| for (0..n) |f| {
                    const v = host.drawSecureFelt();
                    for (v.toM31Array(), 0..) |limb, c| if (limb.v != out[8 * f + c]) return self.fail(i, error.ParityDrawMismatch);
                },
                .draw_raw => {
                    const v = host.drawU32s();
                    if (!std.mem.eql(u32, &v, out[0..8])) return self.fail(i, error.ParityDrawMismatch);
                },
                .queries => |q| {
                    const positions = try @import("stwo_core").queries.drawQueries(&host, std.heap.page_allocator, q.log, q.count);
                    defer std.heap.page_allocator.free(positions);
                    for (positions, out) |p, d| if (p != d) return self.fail(i, error.ParityQueryMismatch);
                },
                .pow => |bits| {
                    const nonce = @as(u64, out[10]) | @as(u64, out[11]) << 32;
                    if (!host.verifyPowNonce(bits, nonce)) return self.fail(i, error.ParityPowInvalid);
                    host.mixU64(nonce);
                },
            }
            steps += 1;
            const snap = Ch.Snapshot.fromWords(try S.read(view, .snapshot, index));
            const want = seedWords(Raw.om31Checkpoint(&host));
            if (!std.mem.eql(u32, &snap.digest, want[0..8]) or snap.draws != want[8]) return self.fail(i, error.ParitySnapshotMismatch);
            if (snap.status != 0 or snap.reserved != 0 or snap.cursor != steps or snap.chain != self.expected_chain_base +% steps) return self.fail(i, error.ParityOrderMismatch);
            self.checked_ops += 1;
        }
    }
    fn fail(self: *ParityJob, op: usize, err: anyerror) anyerror {
        self.mismatch_op = op;
        return err;
    }
    pub fn abort(self: *ParityJob) void {
        self.aborted = true;
    }
};

/// Records a host Om31Channel's op sequence through `raw_mod_m31.om31_observer`.
/// Secure draws are recorded one per felt (`draw_felts = 1`), raw draws as
/// `draw_raw`; inputs are copied. Install with `observer()` for one channel.
pub const Recorder = struct {
    a: std.mem.Allocator,
    seed: ?Raw.Om31Checkpoint = null,
    ops: std.ArrayListUnmanaged(Op) = .empty,
    words: std.ArrayListUnmanaged([]u32) = .empty,
    failure: ?anyerror = null,

    pub fn observer(self: *Recorder, target: *const Raw.Om31Channel) Raw.Om31Observer {
        self.seed = Raw.om31Checkpoint(target);
        return .{ .context = self, .target = target, .start = start, .record = record, .before_pcs = before, .finish = finishFn, .destroy = destroyFn };
    }
    pub fn script(self: *const Recorder) !Script {
        if (self.failure) |err| return err;
        return .{ .seed = self.seed orelse return error.RecorderNotStarted, .ops = self.ops.items };
    }
    pub fn deinit(self: *Recorder) void {
        for (self.words.items) |w| self.a.free(w);
        self.words.deinit(self.a);
        self.ops.deinit(self.a);
    }
    fn of(raw: *anyopaque) *Recorder {
        return @ptrCast(@alignCast(raw));
    }
    fn start(raw: *anyopaque, initial: Raw.Om31Checkpoint) void {
        of(raw).seed = initial;
    }
    fn record(raw: *anyopaque, event: Raw.Om31Event, _: Raw.Om31Checkpoint) void {
        const self = of(raw);
        self.append(event) catch |err| {
            self.failure = err;
        };
    }
    fn append(self: *Recorder, event: Raw.Om31Event) !void {
        const op: Op = switch (event) {
            .mix_words => |v| .{ .mix_words = try self.keep(v) },
            .mix_felts => |values| blk: {
                const w = try self.a.alloc(u32, values.len * 8);
                errdefer self.a.free(w);
                for (values, 0..) |v, i| for (v.toM31Array(), 0..) |limb, c| {
                    w[8 * i + c] = limb.v;
                };
                try self.words.append(self.a, w);
                break :blk .{ .mix_felts = w };
            },
            .draw_raw => .draw_raw,
            .draw_om31 => .{ .draw_felts = 1 },
        };
        try self.ops.append(self.a, op);
    }
    fn keep(self: *Recorder, v: []const u32) ![]const u32 {
        const w = try self.a.dupe(u32, v);
        errdefer self.a.free(w);
        try self.words.append(self.a, w);
        return w;
    }
    fn before(_: *anyopaque, _: Raw.Om31Checkpoint) !void {}
    fn finishFn(_: *anyopaque) !void {}
    fn destroyFn(_: *anyopaque) void {}
};

/// A deterministic script exercising every op kind (PoW optional: the host
/// model cannot grind; the pod run includes it).
pub fn coverageScript(a: std.mem.Allocator, with_pow: bool) !Script {
    var ops: std.ArrayListUnmanaged(Op) = .empty;
    var rng = std.Random.DefaultPrng.init(0x4d38);
    const r = rng.random();
    const words = try a.alloc(u32, 4096);
    for (words) |*w| w.* = r.int(u32);
    const felts = try a.alloc(u32, 64);
    for (felts) |*w| w.* = r.uintLessThan(u32, 0x7fffffff);
    var root: [8]u32 = undefined;
    for (&root) |*w| w.* = r.int(u32);
    try ops.appendSlice(a, &.{
        .{ .mix_words = words[0..13] }, .{ .draw_felts = 1 },
        .{ .mix_root = root },          .{ .draw_felts = 2 },
        .{ .mix_felts = felts[0..24] }, .{ .draw_raw = {} },
        .{ .draw_raw = {} },               .{ .draw_felts = 129 }, // > one block of 128 threads
        .{ .mix_words = words[13..15] },   .{ .queries = .{ .log = 19, .count = 70 } },
        .{ .mix_words = words[15..1039] }, .{ .draw_felts = 3 },
        .{ .mix_words = &.{} },            .{ .queries = .{ .log = 28, .count = 8 } },
        .{ .mix_felts = felts[24..64] },   .{ .draw_felts = 1 },
    });
    if (with_pow) try ops.appendSlice(a, &.{ .{ .pow = 12 }, .{ .queries = .{ .log = 21, .count = 108 } }, .{ .pow = 20 }, .{ .draw_felts = 1 } });
    var seed: Raw.Om31Checkpoint = .{ .digest = undefined, .draws = 5 };
    r.bytes(&seed.digest);
    return .{ .seed = seed, .ops = try ops.toOwnedSlice(a) };
}

test {
    _ = @import("channel_parity_test.zig");
}
