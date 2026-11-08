//! Install-time FIXED commitment and immutable device resources for a truth.
const std = @import("std");
const api = @import("api.zig");
const K = @import("truth_class.zig");
const TJ = @import("truth_job.zig");
const C = @import("native_commit.zig");
const I = @import("truth_interaction.zig");
const NC = @import("native_composition.zig");
const Slab = @import("slab.zig");
pub const Job = struct {
    a: std.mem.Allocator,
    class: *const K.Class,
    sym: *const TJ.Symbols,
    fixed: C.CommitPlan = undefined,
    main: C.CommitPlan = undefined,
    inter: C.CommitPlan = undefined,
    composition: NC.Plan = undefined,
    inputs: []C.Input = &.{},
    region: ?api.Persistent = null,
    layout: Slab.ProofLayout = .{},
    pub fn init(self: *Job) !void {
        self.fixed = try K.jobPlan(self.a, &self.class.fixed_plan);
        errdefer K.freeJobPlan(self.a, &self.fixed);
        self.main = try K.jobPlan(self.a, &self.class.main_plan);
        errdefer K.freeJobPlan(self.a, &self.main);
        self.inter = try K.jobPlan(self.a, &self.class.inter_plan);
        errdefer K.freeJobPlan(self.a, &self.inter);
        self.composition = self.class.composition;
        self.composition.table_device = null;
        self.composition.tw_device = null;
        self.inputs = try self.a.alloc(C.Input, self.class.fixed_host.len);
        for (self.inputs, self.class.fixed_host) |*input, words| input.* = .{ .host = words };
        _ = try self.layout.add(.root, 0, 8);
    }
    pub fn deinit(self: *Job) void {
        self.a.free(self.inputs);
        K.freeJobPlan(self.a, &self.inter);
        K.freeJobPlan(self.a, &self.main);
        K.freeJobPlan(self.a, &self.fixed);
    }
    pub fn classKey(self: *Job) [32]u8 {
        return self.class.fixed_key;
    }
    pub fn footprint(self: *Job) api.Footprint {
        return classFootprint(self.class, self.layout.words);
    }
    pub fn stage(self: *Job, s: *api.Stager) !void {
        const c = self.class;
        const p = try s.persistent(c.fixed_key, c.fixed_plan.coefficient_cells + 8);
        self.region = p;
        if (p.fresh) try self.fixed.stage(s, self.inputs);
        const inputs = try self.a.alloc(C.Input, @max(c.main_logs.len, c.inter_logs.len));
        defer self.a.free(inputs);
        @memset(inputs, .{ .device = @ptrFromInt(@alignOf(u32)) });
        try self.main.stage(s, inputs[0..c.main_logs.len]);
        try self.inter.stage(s, inputs[0..c.inter_logs.len]);
        try self.composition.stage(s);
        for (c.roles) |r| _ = try I.stageTwiddles(self.a, s, r.interaction.log);
        const od = try s.persistent(c.oods.key(c.key), c.oods.words.len);
        if (od.fresh) try s.upload(od.buffer, c.oods.words);
        const ep = try s.persistent(TJ.encodeKey(c), c.encode.words.len);
        if (ep.fresh) try s.upload(ep.buffer, c.encode.words);
    }
    pub fn enqueue(self: *Job, e: *api.Enqueue) !void {
        const p = self.region orelse return error.TruthClassNotWarmed;
        const root = try p.buffer.slice(self.class.fixed_plan.coefficient_cells, 8);
        if (p.fresh) _ = try self.fixed.enqueueInto(self.sym.commit, e, self.inputs, try p.buffer.slice(0, self.class.fixed_plan.coefficient_cells), root, false);
        try e.slab.bind(&self.layout);
        if (self.sym.copy_d2d(e.ctx(), (try e.slab.field(.root, 0)).ptr, root.ptr, 32) != 0) return error.CudaEnqueueFailed;
    }
    pub fn finish(self: *Job, v: api.SlabView) !void {
        if (!std.mem.eql(u8, std.mem.sliceAsBytes(try Slab.read(v, .root, 0)), &self.class.fixed_root)) return error.TruthFixedRootMismatch;
    }
    pub fn abort(_: *Job) void {}
};

/// Immutable warming has its own allocation schedule, independent of request padding.
pub fn resourceWords(c: *const K.Class) !usize {
    var layout = Slab.ProofLayout{};
    _ = try layout.add(.root, 0, 8);
    return classFootprint(c, layout.words).peakWords();
}

fn classFootprint(c: *const K.Class, slab_words: usize) api.Footprint {
    const staged = c.fixed_plan.stagedWords(c.fixed_words) + c.main_plan.stagedWords(0) + c.inter_plan.stagedWords(0) + c.composition.stagedWords() + 1024;
    var pinned = c.fixed_words + c.composition.pinnedWords() + c.oods.words.len + c.encode.words.len + 1024;
    for ([_]*const C.CommitPlan{ &c.fixed_plan, &c.main_plan, &c.inter_plan }) |p| pinned += p.twiddleWords() + 8 * p.logs.len;
    for (c.roles) |r| pinned += r.interaction.twiddleWords();
    return .{ .device_words = staged + c.fixed_plan.deviceWords() + 1024, .staged_words = staged, .slab_words = slab_words, .pinned_words = pinned };
}

test "truth warm job type checks all worker phases" {
    _ = api.Job.from(Job, undefined);
}
