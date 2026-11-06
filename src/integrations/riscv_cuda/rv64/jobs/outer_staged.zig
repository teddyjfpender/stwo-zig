//! What the OuterNodeJob pre-stage hands to phase 1: plain words and plans,
//! no legacy types. Built on a host pool by rv64/outer_job_prestage.zig (the
//! only outer-job file that touches legacy host preparation), consumed by
//! stage() (upload) and the enqueue body (pointers into the uploads).
//!
//! Three upload regions, by lifetime:
//!   node      - this node only (channel seed, assignment seeds, Blake tapes;
//!               a leaf's tasks/indices, since a leaf is its own class);
//!   class     - every node of a fold class (gathered FIXED raw evaluations,
//!               sorted log tables, a fold's tasks/indices/chain ends);
//!               worker-persistent, uploaded by the first node of the class;
//!   twiddles  - per evaluation height, worker-persistent, shared by classes.
const std = @import("std");
const Plan = @import("outer_plan.zig");
const K = @import("outer_kernels.zig");
const Comp = @import("outer_composition.zig");

pub const Region = enum(u2) { node, class, twiddles, fixed };
/// Regions packed from host images (FIXED coefficients are produced on device).
pub const uploaded = [_]Region{ .node, .class, .twiddles };

pub const Range = struct {
    region: Region = .node,
    offset: u64 = 0,
    words: u64 = 0,
};

pub const Image = struct {
    /// Composition statics (class region offset 0, so Comp ranges are absolute).
    rc_blob: Range = .{},
    channel_seed: Range = .{},
    seeds: Range = .{},
    sample_tape: Range = .{},
    sample_map: Range = .{},
    tasks: Range = .{},
    indices: Range = .{},
    chain_ends: Range = .{},
    gathered_fixed: Range = .{},
    main_logs: Range = .{},
    inter_logs: Range = .{},
    fixed_logs: Range = .{},
    /// Forward/inverse twiddle trees per height (twiddle region).
    twiddles: [29]Range = @splat(.{}),
    itwiddles: [29]Range = @splat(.{}),
    words: [4]u64 = .{ 0, 0, 0, 0 },
    pub fn take(self: *Image, region: Region, words: u64) Range {
        const at = &self.words[@intFromEnum(region)];
        const r = Range{ .region = region, .offset = at.*, .words = words };
        // 64 words = 256 B, the allocation alignment every legacy upload
        // had: kernels may use 16-byte vector loads on any staged input.
        at.* = std.mem.alignForward(u64, at.* + words, 64);
        return r;
    }
};

pub const RunKind = enum { ordinary, narrow, chain };
pub const Run = struct { kind: RunKind, first_task: u32, task_count: u32, first_level: u32, level_count: u32 };

/// The device assignment schedule of one node (outer_assignment.zig Prepared,
/// flattened). Launch entry points are the ones Prepared resolved.
pub const Assignment = struct {
    count: usize,
    seeds: []const u32, // 5 words per seed
    tasks: []const u32, // 8 words per task
    indices: []const u32,
    /// Grouped runs (chain/narrow/ordinary); empty means one launch per level.
    runs: []const Run,
    level_ends: []const usize,
    /// Absolute level ends (host copy for narrow runs, uploaded for chain runs).
    ends: []const u32,
    needs_device_ends: bool,
    seed: K.Launch,
    level: K.Launch,
    wide: ?K.Launch,
    narrow: ?K.LaunchRun,
    chain: ?K.LaunchChain,
    /// Blake sample prefill/check (leaves): 26-word records, optional map.
    sample_tape: ?[]const u32 = null,
    sample_map: ?[]const u32 = null,
    sample_first_gg: u32 = 0,
    /// A fold's static schedule is class data; a leaf's is its own.
    reusable: bool,
    pub fn taskCount(self: *const Assignment) u32 {
        return @intCast(self.tasks.len / 8);
    }
    pub fn seedCount(self: *const Assignment) u32 {
        return @intCast(self.seeds.len / 5);
    }
    pub fn sampleRecords(self: *const Assignment) u32 {
        return if (self.sample_tape) |t| @intCast(t.len / 26) else 0;
    }
};

pub const Twiddles = struct { twiddles: []const u32, itwiddles: []const u32 };

/// Class statics: pure functions of the class authority and the profile.
pub const Statics = struct {
    identity: [32]u8,
    plan: Plan.ClassPlan,
    gather: [Plan.n_components][]const u32,
    gathered_fixed: []const u32,
    main_logs: [Plan.main_columns]u32,
    inter_logs: [Plan.inter_columns]u32,
    /// Every height the node transforms at (TC eval height, RC role heights,
    /// composition and commit heights), with its twiddle trees.
    tables: [29]?Twiddles = @splat(null),
    /// FIXED tree commit geometry (original-order logs = authority fixed_logs),
    /// its sorted log table (class region) and the raw FIXED evaluations
    /// (host PP columns, original order), committed on device by the first node
    /// of a class on a worker into the persistent `.fixed` region.
    fixed_plan: ?Plan.TreePlan = null,
    fixed_raw: []const []const u32 = &.{},
    fixed_sorted_logs: []const u32 = &.{},
    /// Composition statics and their packed class-region blob (null: prefix only).
    composition: ?Comp.Static = null,
    rc_blob: []const u32 = &.{},
    pub fn table(self: *const Statics, log: u32) !Twiddles {
        return (if (log < 29) self.tables[log] else null) orelse error.MissingOuterTwiddles;
    }
};

pub const Staged = struct {
    assignment: Assignment,
    statics: *const Statics,
    /// Host transcript checkpoint after the FIXED root: digest[8] ++ draws.
    checkpoint: [9]u32,
    /// Expected public outputs, 4 canonical M31 words each.
    expected: []const u32,
    class_key: [32]u8,
    /// Enqueue topology (geometry + assignment run structure + Blake sample
    /// shape), independent of node values: nodes that share it (e.g. leaves of
    /// one shape, each its own class) share one rebindable CUDA graph.
    graph_key: [32]u8 = @splat(0),
    ordinal: u32,
    image: Image,
    /// FIXED tree root (host authority) and the PCS sample points of this
    /// class at native_pcs.placeholderPoint() (`*const core.pcs.TreeVec([][]D.Point)`),
    /// for whole-node jobs; null for prefix-only staging.
    fixed_root: [32]u8 = @splat(0),
    fixed_logs: []const u32 = &.{},
    pcs_points: ?*const anyopaque = null,
    /// Releases the legacy host preparation that owns the slices above.
    owner: *anyopaque,
    release: *const fn (*anyopaque) void,

    pub fn plan(self: *const Staged) *const Plan.ClassPlan {
        return &self.statics.plan;
    }
    pub fn deinit(self: *Staged) void {
        self.release(self.owner);
        self.* = undefined;
    }
    /// Persistent keys of the class and twiddle regions.
    pub fn classRegionKey(self: *const Staged) [32]u8 {
        return regionKey("rv64/m8/outer-job/class-region/v1", &self.statics.identity, self.image.words[@intFromEnum(Region.class)]);
    }
    pub fn fixedRegionKey(self: *const Staged) [32]u8 {
        return regionKey("rv64/m8/outer-job/fixed-coefficients/v1", &self.fixed_root, if (self.statics.fixed_plan) |fp| fp.coefficient_words else 0);
    }
    /// Raw FIXED evaluations in the FIXED commit's sorted layout.
    pub fn packFixed(self: *const Staged, out: []u32) !void {
        const fp = &(self.statics.fixed_plan orelse return error.OuterJobWholeStagingMissing);
        if (out.len < fp.coefficient_words or self.statics.fixed_raw.len != fp.offsets.len) return error.OuterStagedImageTooSmall;
        for (self.statics.fixed_raw, fp.offsets, fp.logs) |column, off, log| {
            if (column.len != @as(usize, 1) << @intCast(log)) return error.InvalidOuterFixedGather;
            @memcpy(out[@intCast(off)..][0..column.len], column);
        }
    }
    pub fn twiddleRegionKey(self: *const Staged) [32]u8 {
        var logs: [29]u8 = undefined;
        for (&logs, self.statics.tables) |*l, t| l.* = @intFromBool(t != null);
        return regionKey("rv64/m8/outer-job/twiddles/v2", &logs, self.image.words[@intFromEnum(Region.twiddles)]);
    }
    fn regionKey(tag: []const u8, id: []const u8, words: u64) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(tag);
        h.update(id);
        var w: [8]u8 = undefined;
        std.mem.writeInt(u64, &w, words, .little);
        h.update(&w);
        return h.finalResult();
    }

    /// Lays out every section. Class sections hold a fold's schedule only
    /// when it is reusable; otherwise the node region carries it.
    pub fn layout(assignment: *const Assignment, statics: *const Statics) Image {
        var i = Image{};
        i.rc_blob = i.take(.class, statics.rc_blob.len);
        i.channel_seed = i.take(.node, 9);
        i.seeds = i.take(.node, assignment.seeds.len);
        if (assignment.sample_tape) |t| i.sample_tape = i.take(.node, t.len);
        if (assignment.sample_map) |m| i.sample_map = i.take(.node, m.len);
        const schedule: Region = if (assignment.reusable) .class else .node;
        i.tasks = i.take(schedule, assignment.tasks.len);
        i.indices = i.take(schedule, assignment.indices.len);
        if (assignment.needs_device_ends) i.chain_ends = i.take(schedule, assignment.ends.len);
        i.gathered_fixed = i.take(.class, statics.gathered_fixed.len);
        i.main_logs = i.take(.class, Plan.main_columns);
        i.inter_logs = i.take(.class, Plan.inter_columns);
        i.fixed_logs = i.take(.class, statics.fixed_sorted_logs.len);
        for (statics.tables, 0..) |t, log| if (t) |tw| {
            i.twiddles[log] = i.take(.twiddles, tw.twiddles.len);
            i.itwiddles[log] = i.take(.twiddles, tw.itwiddles.len);
        };
        return i;
    }

    /// Packs `region` into `out` (job pinned memory of `image.words[region]`).
    pub fn pack(self: *const Staged, region: Region, out: []u32) !void {
        if (out.len < self.image.words[@intFromEnum(region)]) return error.OuterStagedImageTooSmall;
        const i = self.image;
        const a = self.assignment;
        const s = self.statics;
        for (s.tables, 0..) |t, log| if (t) |tw| if (region == .twiddles) {
            @memcpy(out[@intCast(i.twiddles[log].offset)..][0..tw.twiddles.len], tw.twiddles);
            @memcpy(out[@intCast(i.itwiddles[log].offset)..][0..tw.itwiddles.len], tw.itwiddles);
        };
        const sections = [_]struct { Range, []const u32 }{
            .{ i.rc_blob, s.rc_blob },
            .{ i.channel_seed, &self.checkpoint },
            .{ i.seeds, a.seeds },
            .{ i.sample_tape, a.sample_tape orelse &.{} },
            .{ i.sample_map, a.sample_map orelse &.{} },
            .{ i.tasks, a.tasks },
            .{ i.indices, a.indices },
            .{ i.chain_ends, if (a.needs_device_ends) a.ends else &.{} },
            .{ i.gathered_fixed, s.gathered_fixed },
            .{ i.main_logs, &s.main_logs },
            .{ i.inter_logs, &s.inter_logs },
            .{ i.fixed_logs, s.fixed_sorted_logs },
        };
        for (sections) |entry| {
            const r, const src = entry;
            if (r.region != region or r.words == 0) continue;
            if (r.words != src.len) return error.OuterStagedSectionMismatch;
            @memcpy(out[@intCast(r.offset)..][0..src.len], src);
        }
    }
};

/// Device base pointer of each region, filled by stage().
pub const Bases = struct {
    regions: [4][*]const u32,
    pub fn at(self: Bases, r: Range) [*]const u32 {
        return self.regions[@intFromEnum(r.region)] + @as(usize, @intCast(r.offset));
    }
};

test "image regions are disjoint, 2-word aligned, and a leaf keeps its schedule node-local" {
    var statics: Statics = undefined;
    statics.gathered_fixed = &.{ 1, 2, 3 };
    statics.rc_blob = &.{};
    statics.fixed_sorted_logs = &.{};
    statics.tables = @splat(null);
    statics.tables[5] = .{ .twiddles = &.{ 1, 2, 3, 4 }, .itwiddles = &.{ 1, 2, 3, 4 } };
    var assignment: Assignment = undefined;
    assignment.seeds = &.{ 1, 2, 3, 4, 5 };
    assignment.tasks = &.{ 0, 0, 0, 0, 0, 0, 0, 0 };
    assignment.indices = &.{};
    assignment.ends = &.{ 1, 2, 3 };
    assignment.needs_device_ends = true;
    assignment.sample_tape = null;
    assignment.sample_map = null;
    assignment.reusable = false;
    const leaf = Staged.layout(&assignment, &statics);
    try std.testing.expectEqual(Region.node, leaf.tasks.region);
    try std.testing.expectEqual(@as(u64, 10), leaf.seeds.offset);
    try std.testing.expectEqual(@as(u64, 16), leaf.tasks.offset);
    assignment.reusable = true;
    const fold = Staged.layout(&assignment, &statics);
    try std.testing.expectEqual(Region.class, fold.tasks.region);
    try std.testing.expectEqual(@as(u64, 0), fold.tasks.offset);
    try std.testing.expectEqual(@as(u64, 8), fold.twiddles[5].words + fold.itwiddles[5].words);
    try std.testing.expectEqual(@as(u64, 4), fold.itwiddles[5].offset);
}
