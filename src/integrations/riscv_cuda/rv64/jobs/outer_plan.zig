//! OuterNodeJob class plan: every number the enqueue sequence needs, computed
//! on the host before phase 1 from class geometry alone (component row logs,
//! FIXED column logs, PCS blowup). Pure host; no device, no allocator custody
//! beyond the plan's own slices. One plan is shared by every node of a class.
//!
//! The plan fixes three things the legacy path decides at run time:
//!  * the commit layout of MAIN/INTER/FIXED (sorted-by-height column order,
//!    coefficient offsets, LDE segments) - identical to trace_commit.zig's
//!    non-streamed path, so roots are byte-identical;
//!  * the transcript schedule up to the PCS boundary - identical, op for op,
//!    to device_prove.zig proveOwnedDirect + prove_family.zig (host prefix is
//!    computed in pre-stage, device suffix is enqueued);
//!  * the outer section of the proof slab (claims, status, roots, challenges,
//!    channel boundary snapshots for the parity harness).
const std = @import("std");

pub const n_components = 11;
/// Native MAIN roster: component widths (traceWidths) sum to 114.
pub const main_columns = 114;
/// Native INTER roster: 8 coordinates per lookup pair, 304 columns.
pub const inter_columns = 304;
/// MAIN columns written by the base gate kernels (components 0..4). The last
/// 22 MAIN columns are the table multiplicities of components 5..10.
pub const gate_components = 5;
pub const count_columns = 22;
/// Widths of the FIXED columns each base gate kernel reads (base_witness.cu).
pub const gate_fixed_widths = [gate_components]u32{ 1, 7, 4, 1, 10 };
pub const om31_words = 8;

pub const Component = struct {
    log: u32,
    width: u32,
    pairs: u32,
    /// First column of this component in the native (unsorted) MAIN roster.
    main_first: u32,
    /// First column of this component in the native INTER roster.
    inter_first: u32,
};

/// Class geometry. Everything here is a function of the class authority
/// (row logs, FIXED logs, gather indices) and the PCS profile; nothing is
/// node data. `gather[c]` are FIXED column indices read by component c in
/// canonical tuple order (outer_source.zig lookupIndices).
pub const Geometry = struct {
    components: [n_components]Component,
    fixed_logs: []const u32,
    gather: [n_components][]const u32,
    n_outputs: u32,
    beta: u32,
    total_constraints: u32,
    composition_log: u32,
    first_permutation_row: u32,

    pub fn init(logs: [n_components]u32, widths: [n_components]usize, pairs: [n_components]usize) !Geometry {
        var g: Geometry = undefined;
        var main_at: u32 = 0;
        var inter_at: u32 = 0;
        for (&g.components, logs, widths, pairs) |*c, log, width, pair| {
            if (log < 4 or log > 27 or width == 0 or width > 52) return error.InvalidOuterClassGeometry;
            c.* = .{ .log = log, .width = @intCast(width), .pairs = @intCast(pair), .main_first = main_at, .inter_first = inter_at };
            main_at += @intCast(width);
            inter_at += @intCast(8 * pair);
        }
        if (main_at != main_columns or inter_at != inter_columns) return error.InvalidOuterClassRoster;
        g.fixed_logs = &.{};
        g.gather = @splat(&.{});
        g.n_outputs = 0;
        g.beta = 1;
        g.total_constraints = 0;
        g.composition_log = 0;
        g.first_permutation_row = 0;
        return g;
    }
    pub fn mainLogs(self: *const Geometry, out: *[main_columns]u32) void {
        for (self.components) |c| @memset(out[c.main_first..][0..c.width], c.log);
    }
    pub fn interLogs(self: *const Geometry, out: *[inter_columns]u32) void {
        for (self.components) |c| @memset(out[c.inter_first..][0 .. 8 * c.pairs], c.log);
    }
};

/// Commit geometry of one trace tree, exactly as trace_commit.zig orders it:
/// columns sorted by (log, original index); coefficients packed in that
/// order; evaluations at `beta` packed in the same order; one Merkle segment
/// per distinct evaluation height (ascending), which is what the legacy
/// segment merge produces for a sorted roster.
pub const TreePlan = struct {
    order: []u32,
    /// Coefficient (and evaluation-image) word offset of each ORIGINAL column.
    offsets: []u64,
    logs: []u32,
    coefficient_words: u64,
    evaluation_words: u64,
    eval_log: u32,
    beta: u32,
    groups: []Group,
    tree_words: u64,
    /// Two prefix-state banks of 48 words per row at the largest non-final
    /// height (trace_commit.zig fallback bound; the runtime query may shrink it).
    prefix_words: u64,

    pub const Group = struct {
        /// First column in sorted order and column count; all share `log`.
        first: u32,
        count: u32,
        log: u32,
        coefficient_offset: u64,
        evaluation_offset: u64,
    };

    pub fn init(a: std.mem.Allocator, logs: []const u32, beta: u32) !TreePlan {
        if (logs.len == 0 or logs.len > 65535 or beta < 1 or beta > 4) return error.InvalidOuterTreePlan;
        const order = try a.alloc(u32, logs.len);
        errdefer a.free(order);
        const offsets = try a.alloc(u64, logs.len);
        errdefer a.free(offsets);
        const owned_logs = try a.dupe(u32, logs);
        errdefer a.free(owned_logs);
        for (order, 0..) |*o, i| o.* = @intCast(i);
        const Sort = struct {
            logs: []const u32,
            fn less(s: @This(), x: u32, y: u32) bool {
                return s.logs[x] < s.logs[y] or (s.logs[x] == s.logs[y] and x < y);
            }
        };
        std.mem.sort(u32, order, Sort{ .logs = logs }, Sort.less);
        var groups: std.ArrayList(Group) = .empty;
        errdefer groups.deinit(a);
        var cells: u64 = 0;
        var max_log: u32 = 0;
        for (order, 0..) |original, sorted| {
            const log = logs[original];
            if (log < 1 or log + beta > 28) return error.InvalidOuterTreePlan;
            offsets[original] = cells;
            if (groups.items.len == 0 or groups.items[groups.items.len - 1].log != log)
                try groups.append(a, .{ .first = @intCast(sorted), .count = 0, .log = log, .coefficient_offset = cells, .evaluation_offset = cells << @intCast(beta) });
            groups.items[groups.items.len - 1].count += 1;
            cells += @as(u64, 1) << @intCast(log);
            max_log = @max(max_log, log);
        }
        const eval_log = max_log + beta;
        var prefix_rows: u64 = 0;
        for (groups.items[0 .. groups.items.len - 1]) |group| prefix_rows = @max(prefix_rows, @as(u64, 1) << @intCast(group.log + beta));
        return .{
            .order = order,
            .offsets = offsets,
            .logs = owned_logs,
            .coefficient_words = cells,
            .evaluation_words = cells << @intCast(beta),
            .eval_log = eval_log,
            .beta = beta,
            .groups = try groups.toOwnedSlice(a),
            .tree_words = ((@as(u64, 2) << @intCast(eval_log)) - 1) * 8,
            .prefix_words = prefix_rows * 48,
        };
    }
    pub fn deinit(self: *TreePlan, a: std.mem.Allocator) void {
        a.free(self.order);
        a.free(self.offsets);
        a.free(self.logs);
        a.free(self.groups);
        self.* = undefined;
    }
    /// Device root lives in the last 8 words of the tree buffer.
    pub fn rootOffset(self: *const TreePlan) u64 {
        return self.tree_words - 8;
    }
    pub fn scratchWords(self: *const TreePlan) u64 {
        return self.evaluation_words + self.tree_words + self.prefix_words;
    }
};

/// Pre-PCS transcript operations in host order. `host` ops run in pre-stage
/// on the host channel; `device` ops are enqueued on the device channel.
pub const Op = struct {
    kind: Kind,
    words: u32,
    what: What,
    pub const Kind = enum { mix_words, mix_felts, draw_om31 };
    pub const What = enum { config, profile_tag, profile_identity, statement, fixed_root, main_root, lookup_challenges, claims, inter_root, composition_coefficient, composition_root, oods_seed };
};

pub const host_prefix_max = 5;
/// Host prefix: PcsConfig.mixInto (one or two OM31 felts), mixProfile's two
/// word mixes, the statement (identity, n_outputs, outputs), FIXED root.
pub fn hostPrefix(n_outputs: u32, config_felts: u32, out: *[host_prefix_max]Op) []const Op {
    out.* = .{
        .{ .kind = .mix_felts, .words = 8 * config_felts, .what = .config },
        .{ .kind = .mix_words, .words = 3, .what = .profile_tag },
        .{ .kind = .mix_words, .words = 8, .what = .profile_identity },
        .{ .kind = .mix_words, .words = 9 + 4 * n_outputs, .what = .statement },
        .{ .kind = .mix_words, .words = 8, .what = .fixed_root },
    };
    return out[0..];
}
/// Device suffix up to the PCS boundary. The two lookup challenges are one
/// counter-based draw of 2 felts (channel.cu draws first..first+count-1 from
/// the same digest, which is exactly two successive host drawSecureFelt).
pub const device_ops = [_]Op{
    .{ .kind = .mix_words, .words = 8, .what = .main_root },
    .{ .kind = .draw_om31, .words = 16, .what = .lookup_challenges },
    .{ .kind = .mix_felts, .words = 8 * n_components, .what = .claims },
    .{ .kind = .mix_words, .words = 8, .what = .inter_root },
    .{ .kind = .draw_om31, .words = 8, .what = .composition_coefficient },
    .{ .kind = .mix_words, .words = 8, .what = .composition_root },
    .{ .kind = .draw_om31, .words = 8, .what = .oods_seed },
};
/// Host-equivalent draw count of the device suffix (n_draws advance).
pub fn deviceDraws() u32 {
    var draws: u32 = 0;
    for (device_ops) |op| if (op.kind == .draw_om31) {
        draws += op.words / 8;
    };
    return draws;
}

/// The outer section of the proof slab, in words. Offsets are static per
/// class; the runtime's ProofSlab places this section and the PCS section.
pub const Section = struct {
    /// Kernel status latches, all must be 0: [0] assignment, [1] INTER,
    /// [2] FS parameters/powers, [3] MAIN gates and Blake sample check.
    pub const status = 0;
    pub const status_words = 4;
    pub const claims = status + status_words;
    pub const claims_words = 8 * n_components;
    pub const challenges = claims + claims_words; // z, alpha, coefficient, oods seed
    pub const challenges_words = 32;
    pub const main_root = challenges + challenges_words;
    pub const inter_root = main_root + 8;
    pub const composition_root = inter_root + 8;
    /// FIXED root the job recommitted (first node of a class on a worker).
    pub const fixed_root = composition_root + 8;
    pub const boundaries = fixed_root + 8;
    pub const boundary_words = 16;
    pub const words = boundaries + device_ops.len * boundary_words;
};

/// Largest single device buffer (words) a job hands to a kernel. Several
/// reused legacy kernels form element indices in signed 32-bit arithmetic,
/// so a node buffer of 2^31 words or more would wrap silently (the whole-LDE
/// INTER of a 26235156 fold is 2.36e9 words; the chunk-bounded node never
/// holds it: its largest buffer is the in-place INTER coefficient region,
/// [M] 1.25e9 words on 26235156 folds). Enforced fail-closed on every single
/// device allocation of a job: outer_heap.Heap.alloc (node transients, PCS
/// scratch through PcsEnqueue, the full-LDE scratch) and FixedJob's view;
/// outer_job.zig holdBuffers also refuses a node whose held buffers, stream
/// scratch or full-LDE images cross it before the body starts.
pub const max_indexable_words: u64 = 1 << 31;
pub fn requireIndexable(words: []const u64) !void {
    for (words) |w| if (w >= max_indexable_words) return error.OuterBufferExceedsInt32Index;
}

/// Static launch accounting for one node (host-API launches without graph
/// capture). The tree kernel, LDE and B2N report their internal launches at
/// enqueue; this is the floor the plan can predict.
pub const LaunchFloor = struct {
    assignment: u32,
    gates: u32,
    inter: u32,
    commits: u32,
    channel: u32,
    pub fn total(self: LaunchFloor) u32 {
        return self.assignment + self.gates + self.inter + self.commits + self.channel;
    }
};

pub const ClassPlan = struct {
    geometry: Geometry,
    main: TreePlan,
    inter: TreePlan,
    /// Words of the gathered FIXED raw evaluations (per component blocks).
    gathered_fixed_words: u64,
    gathered_offsets: [n_components]u64,
    /// INTER generation order: components by (log, index), i.e. physical
    /// order in the packed coefficient buffer. Each component's kernels also
    /// write 8 scratch columns past its own block, which only ever land on
    /// the not-yet-generated suffix or on the trailing `inter_tail_words`
    /// (trace_input_reuse.zig Layout, qualified M7 packed-INTER layout).
    inter_order: [n_components]u8,
    inter_tail_words: u64,
    /// MAIN evaluation image laid out in MAIN commit order (sorted), so the
    /// base kernels write straight into the B2N input and INTER reads each
    /// component's columns contiguously.
    pub fn init(a: std.mem.Allocator, geometry: Geometry) !ClassPlan {
        var logs: [main_columns]u32 = undefined;
        geometry.mainLogs(&logs);
        var main = try TreePlan.init(a, &logs, geometry.beta);
        errdefer main.deinit(a);
        var inter_logs: [inter_columns]u32 = undefined;
        geometry.interLogs(&inter_logs);
        var inter = try TreePlan.init(a, &inter_logs, geometry.beta);
        errdefer inter.deinit(a);
        var plan = ClassPlan{ .geometry = geometry, .main = main, .inter = inter, .gathered_fixed_words = 0, .gathered_offsets = undefined, .inter_order = undefined, .inter_tail_words = 0 };
        for (&plan.inter_order, 0..) |*o, i| o.* = @intCast(i);
        const ByLog = struct {
            fn less(cs: *const [n_components]Component, x: u8, y: u8) bool {
                return cs[x].log < cs[y].log or (cs[x].log == cs[y].log and x < y);
            }
        };
        std.mem.sort(u8, &plan.inter_order, &geometry.components, ByLog.less);
        for (geometry.components) |c| {
            if (c.pairs == 0) return error.InvalidOuterClassRoster;
            plan.inter_tail_words = @max(plan.inter_tail_words, @as(u64, 8) << @intCast(c.log));
        }
        for (geometry.components, geometry.gather, 0..) |c, indices, i| {
            plan.gathered_offsets[i] = plan.gathered_fixed_words;
            for (indices) |index| if (index >= geometry.fixed_logs.len or geometry.fixed_logs[index] != c.log) return error.InvalidOuterFixedGather;
            plan.gathered_fixed_words += @as(u64, indices.len) << @intCast(c.log);
        }
        try plan.requireContiguousComponents();
        return plan;
    }
    pub fn deinit(self: *ClassPlan, a: std.mem.Allocator) void {
        self.main.deinit(a);
        self.inter.deinit(a);
        self.* = undefined;
    }
    /// INTER and the fraction kernels read a component's MAIN columns as one
    /// stride-`rows` block, and the commit order must keep each component's
    /// columns adjacent. Sorting by (log, index) does, because a component's
    /// columns share a log and are adjacent in the native roster.
    fn requireContiguousComponents(self: *const ClassPlan) !void {
        for (self.geometry.components) |c| {
            const rows = @as(u64, 1) << @intCast(c.log);
            for (1..@max(1, c.width)) |k| if (self.main.offsets[c.main_first + k] != self.main.offsets[c.main_first] + k * rows) return error.OuterMainComponentNotContiguous;
            for (1..@max(1, 8 * c.pairs)) |k| if (self.inter.offsets[c.inter_first + k] != self.inter.offsets[c.inter_first] + k * rows) return error.OuterInterComponentNotContiguous;
        }
    }
    pub fn mainColumnOffset(self: *const ClassPlan, column: usize) u64 {
        return self.main.offsets[column];
    }
    pub fn componentMain(self: *const ClassPlan, component: usize) u64 {
        return self.main.offsets[self.geometry.components[component].main_first];
    }
    pub fn componentInter(self: *const ClassPlan, component: usize) u64 {
        return self.inter.offsets[self.geometry.components[component].inter_first];
    }
    /// Contiguous runs of MAIN columns (in evaluation-image words) holding the
    /// 22 table multiplicities, cleared before the gate kernels count into them.
    pub fn countRuns(self: *const ClassPlan, out: *[count_columns][2]u64) [][2]u64 {
        var n: usize = 0;
        var cols: [count_columns]u64 = undefined;
        for (&cols, main_columns - count_columns..) |*o, column| o.* = self.main.offsets[column];
        std.mem.sort(u64, &cols, {}, std.sort.asc(u64));
        for (cols) |start| {
            const column = for (main_columns - count_columns..main_columns) |c| {
                if (self.main.offsets[c] == start) break c;
            } else unreachable;
            const words = @as(u64, 1) << @intCast(self.main.logs[column]);
            if (n != 0 and out[n - 1][0] + out[n - 1][1] == start) out[n - 1][1] += words else {
                out[n] = .{ start, words };
                n += 1;
            }
        }
        return out[0..n];
    }
    pub fn launchFloor(self: *const ClassPlan, assignment_runs: u32) LaunchFloor {
        var inter: u32 = 0;
        for (self.geometry.components) |_| inter += 3; // fractions, pairs scan, cumulative
        return .{
            .assignment = 2 + assignment_runs, // seed, status clear, runs
            .gates = gate_components + 1, // five gate kernels, count clear runs merged below
            .inter = inter + 1,
            .commits = @intCast(2 * (self.main.groups.len + self.inter.groups.len) + 2),
            .channel = device_ops.len + 2, // + lookup params, composition powers
        };
    }
    /// Static device words one node holds at its peak (MAIN eval image +
    /// MAIN coefficients + INTER coefficients + the larger commit scratch).
    pub fn peakWords(self: *const ClassPlan) u64 {
        const resident = self.main.coefficient_words * 2 + self.inter.coefficient_words + self.gathered_fixed_words;
        return resident + @max(self.main.scratchWords(), self.inter.scratchWords());
    }
};

// ---------------------------------------------------------------------------
const testing = std.testing;
fn testGeometry() !Geometry {
    // Native widths/pairs (component_list facts): MAIN 4,12,20,4,52 + 22 counts.
    const widths = [_]usize{ 4, 12, 20, 4, 52, 3, 4, 3, 3, 3, 6 };
    // Synthetic pairs summing to the 38-pair (304-column) INTER roster.
    const p = [_]usize{ 2, 6, 10, 2, 12, 1, 1, 1, 1, 1, 1 };
    const logs = [_]u32{ 18, 20, 16, 18, 23, 16, 24, 8, 14, 18, 16 };
    return Geometry.init(logs, widths, p);
}

test "tree plan sorts by height, packs offsets and merges one segment per height" {
    const a = testing.allocator;
    var plan = try TreePlan.init(a, &.{ 5, 4, 5, 4, 6 }, 1);
    defer plan.deinit(a);
    try testing.expectEqualSlices(u32, &.{ 1, 3, 0, 2, 4 }, plan.order);
    try testing.expectEqualSlices(u64, &.{ 32, 0, 64, 16, 96 }, plan.offsets);
    try testing.expectEqual(@as(u64, 160), plan.coefficient_words);
    try testing.expectEqual(@as(u64, 320), plan.evaluation_words);
    try testing.expectEqual(@as(u32, 7), plan.eval_log);
    try testing.expectEqual(@as(usize, 3), plan.groups.len);
    try testing.expectEqual(@as(u64, 64), plan.groups[1].evaluation_offset);
    try testing.expectEqual(((@as(u64, 2) << 7) - 1) * 8, plan.tree_words);
    try testing.expectEqual(@as(u64, 64 * 48), plan.prefix_words);
    try testing.expectError(error.InvalidOuterTreePlan, TreePlan.init(a, &.{28}, 1));
}

test "class plan keeps every component contiguous in both commit orders" {
    const a = testing.allocator;
    var g = try testGeometry();
    g.beta = 1;
    var plan = try ClassPlan.init(a, g);
    defer plan.deinit(a);
    var runs: [count_columns][2]u64 = undefined;
    var words: u64 = 0;
    for (plan.countRuns(&runs)) |r| words += r[1];
    var expected: u64 = 0;
    for (g.components[gate_components..]) |c| expected += @as(u64, c.width) << @intCast(c.log);
    try testing.expectEqual(expected, words);
    for (plan.inter_order[1..], plan.inter_order[0..10]) |next, prev| try testing.expect(g.components[prev].log < g.components[next].log or (g.components[prev].log == g.components[next].log and prev < next));
    for (plan.inter_order) |c| try testing.expectEqual(plan.componentInter(c), plan.inter.offsets[g.components[c].inter_first]);
    const floor = plan.launchFloor(12);
    try testing.expect(floor.total() > 50); // un-captured nodes exceed the target; capture is required
}

test "device transcript suffix draws four felts and ends at the PCS boundary" {
    try testing.expectEqual(@as(u32, 4), deviceDraws());
    try testing.expectEqual(@as(usize, 7), device_ops.len);
    try testing.expectEqual(Op.What.oods_seed, device_ops[device_ops.len - 1].what);
    var buffer: [host_prefix_max]Op = undefined;
    const prefix = hostPrefix(8, 1, &buffer);
    try testing.expectEqual(@as(u32, 41), prefix[3].words);
    try testing.expectEqual(@as(usize, Section.boundaries + 7 * 16), Section.words);
}

test "node buffers stay below the signed 32-bit element index" {
    // [M] 26235156 fold plan_words: INTER coefficients 1.245e9, LDE 2.356e9.
    try requireIndexable(&.{ 583745792, 1245317120, 268435448, (1 << 31) - 1 });
    try testing.expectError(error.OuterBufferExceedsInt32Index, requireIndexable(&.{ 1245317120, 2356416512 }));
    try testing.expectError(error.OuterBufferExceedsInt32Index, requireIndexable(&.{1 << 31}));
}
