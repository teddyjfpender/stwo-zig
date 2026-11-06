//! FIXED precommit as a job (M8 wire-outer): commits one recursion node's
//! FIXED (preprocessed) columns on a DeviceWorker and returns the tree root,
//! replacing the legacy owner's device FIXED precommit (outer_fixed.zig) in
//! hybrid mode. The root is the only output: the authority identity and the
//! host transcript prefix need it before the node job is prepared; the node
//! job (outer_job.zig) commits FIXED again into its own memory and checks the
//! root it gets against this one, so no device tree crosses job boundaries.
//!
//!   stage   - upload the raw FIXED evaluations (sorted commit layout), the
//!             sorted log table and the eval-height twiddles;
//!   enqueue - outer_trace_commit (B2N -> LDE -> Merkle), root -> slab;
//!   finish  - read the root.
const std = @import("std");
const api = @import("api.zig");
const Plan = @import("outer_plan.zig");
const K = @import("outer_kernels.zig");
const TC = @import("outer_trace_commit.zig");

pub const root_index: u32 = 0x4649_5852; // "FIXR"

pub const Inputs = struct {
    plan: *const Plan.TreePlan,
    /// Raw FIXED evaluations per ORIGINAL column (len 1 << plan.logs[i]).
    raw: []const []const u32,
    /// TC.sortedLogs(plan) (plan.order.len words).
    sorted_logs: []const u32,
    twiddles: []const u32,
    itwiddles: []const u32,
};

pub const FixedJob = struct {
    in: Inputs,
    kernels: *const K.Kernels,
    layout: api.ProofLayout = .{},
    evaluations: [*]const u32 = undefined,
    logs: [*]const u32 = undefined,
    twiddles: [*]const u32 = undefined,
    itwiddles: [*]const u32 = undefined,
    root: ?[32]u8 = null,
    receipt: api.Receipt = .{},

    pub fn init(in: Inputs, kernels: *const K.Kernels) !FixedJob {
        if (in.raw.len != in.plan.offsets.len or in.sorted_logs.len != in.plan.order.len) return error.InvalidOuterFixedGather;
        var out = FixedJob{ .in = in, .kernels = kernels };
        _ = try out.layout.add(.opaque_words, root_index, 8);
        return out;
    }
    pub fn job(self: *FixedJob) api.Job {
        return api.Job.from(FixedJob, self);
    }
    pub fn classKey(self: *FixedJob) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/m8/outer-job/fixed-precommit/v1\x00");
        h.update(std.mem.sliceAsBytes(self.in.plan.logs));
        return h.finalResult();
    }
    fn g(words: u64) u64 {
        return std.mem.alignForward(u64, @max(words, 1), 64);
    }
    fn stagedWords(self: *const FixedJob) u64 {
        const p = self.in.plan;
        return g(p.coefficient_words) + g(self.in.sorted_logs.len) + g(self.in.twiddles.len) + g(self.in.itwiddles.len);
    }
    pub fn footprint(self: *FixedJob) api.Footprint {
        const p = self.in.plan;
        // Staged inputs + coefficients + tree/prefix + the LDE scratch TC
        // allocates and frees inside (one evaluation image).
        const device = self.stagedWords() + g(p.coefficient_words) + g(p.tree_words + p.prefix_words) + g(p.evaluation_words);
        return .{ .device_words = @intCast(device), .staged_words = @intCast(self.stagedWords()), .slab_words = self.layout.words, .pinned_words = @intCast(p.coefficient_words + self.in.sorted_logs.len + self.in.twiddles.len + self.in.itwiddles.len) };
    }
    fn upload(s: *api.Stager, words: []const u32) ![*]const u32 {
        const d = try s.alloc(@max(words.len, 1));
        if (words.len != 0) {
            const pinned = try s.pinned(words.len);
            @memcpy(pinned, words);
            try s.upload(d, pinned);
        }
        return d.ptr;
    }
    pub fn stage(self: *FixedJob, s: *api.Stager) !void {
        const p = self.in.plan;
        if (p.beta != 1) return error.UnsupportedOuterJobBlowup;
        const d = try s.alloc(@intCast(p.coefficient_words));
        const pinned = try s.pinned(@intCast(p.coefficient_words));
        for (self.in.raw, p.offsets, p.logs) |column, off, log| {
            if (column.len != @as(usize, 1) << @intCast(log)) return error.InvalidOuterFixedGather;
            @memcpy(pinned[@intCast(off)..][0..column.len], column);
        }
        try s.upload(d, pinned);
        self.evaluations = d.ptr;
        self.logs = try upload(s, self.in.sorted_logs);
        self.twiddles = try upload(s, self.in.twiddles);
        self.itwiddles = try upload(s, self.in.itwiddles);
    }

    const View = struct {
        e: *api.Enqueue,
        const vtable = K.Device.VTable{ .alloc = alloc, .free = free, .mix = mix, .draw = draw };
        fn of(raw: *anyopaque) *View {
            return @ptrCast(@alignCast(raw));
        }
        fn alloc(raw: *anyopaque, words: usize) anyerror!K.Buffer {
            const b = try of(raw).e.alloc(words);
            return .{ .ptr = b.ptr, .words = b.words };
        }
        fn free(raw: *anyopaque, b: K.Buffer) void {
            of(raw).e.free(.{ .ptr = b.ptr, .words = b.words });
        }
        fn mix(_: *anyopaque, _: [*]const u32, _: u32, _: bool) anyerror!void {
            return error.FixedJobHasNoTranscript;
        }
        fn draw(_: *anyopaque, _: u32, _: [*]u32) anyerror!void {
            return error.FixedJobHasNoTranscript;
        }
    };

    pub fn enqueue(self: *FixedJob, e: *api.Enqueue) !void {
        try e.waitStaged();
        try e.slab.bind(&self.layout);
        const out = try e.slab.field(.opaque_words, root_index);
        const p = self.in.plan;
        var view = View{ .e = e };
        var device = K.Device{ .ctx = e.ctx(), .stream = e.stream(), .impl = &view, .vtable = &View.vtable, .kernels = self.kernels };
        // Tree below the coefficients' LIFO scratch (TC frees its LDE inside).
        const tree = try device.alloc(@intCast(p.tree_words + p.prefix_words));
        const coefficients = try device.alloc(@intCast(p.coefficient_words));
        try TC.enqueue(&device, p, .{ .evaluations = self.evaluations, .coefficients = coefficients.ptr, .tree = tree, .statics = .{
            .sorted_logs = self.logs,
            .twiddles = self.twiddles,
            .twiddle_words = @intCast(self.in.twiddles.len),
            .itwiddles = self.itwiddles,
            .itwiddle_words = @intCast(self.in.itwiddles.len),
        } });
        try device.copy(out.ptr, TC.rootPointer(p, tree), 8);
    }
    pub fn finish(self: *FixedJob, view: api.SlabView) !void {
        self.receipt = view.receipt;
        const words = try @import("slab.zig").read(view, .opaque_words, root_index);
        var root: [32]u8 = undefined;
        for (0..8) |i| std.mem.writeInt(u32, root[4 * i ..][0..4], words[i], .little);
        self.root = root;
    }
    pub fn abort(_: *FixedJob) void {}
};
