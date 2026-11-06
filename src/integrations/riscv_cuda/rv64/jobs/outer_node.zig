//! OuterNodeJob enqueue body: one recursion node from staged inputs to the
//! PCS boundary, on one stream, with no host wait. It replaces the legacy
//! controller sequence (outer_source.zig prepareImpl -> outer_source_main ->
//! TC MAIN -> host FS -> outer_source_interaction -> TC INTER -> host FS)
//! while running the same kernels on the same inputs:
//!
//!   1 MAIN assignment (seed, Blake sample prefill, chain/narrow/level runs)
//!   2 MAIN gate kernels into the sorted MAIN evaluation image (+ sample check)
//!   3 TC MAIN (enqueue-only), root left on device
//!   4 device channel: mix MAIN root, draw z, alpha -> lookup params on device
//!   5 INTER (fractions, pairs scan, cumulative) into the packed INTER image,
//!     claims into the slab section
//!   6 device channel: mix claims; TC INTER in place; mix INTER root
//!   7 draw composition coefficient -> composition powers on device
//!   8 tail (composition -> mix root -> OODS seed -> enqueue-only PCS), when bound
//!
//! The host prefix (config, profile, statement, FIXED root) was mixed in
//! pre-stage; the device channel starts from that checkpoint. lookupSum == 0
//! and claim canonicality are checked by `decode` on the slab after the single
//! wait, before any proof is assembled (same accept/reject outcome as the
//! legacy host check, which ran before the claims mix).
//!
//! Allocation order follows the worker's LIFO arena: long-lived buffers
//! first, then a stack of transients each freed in reverse order.
const std = @import("std");
const Abi = @import("../abi.zig");
const Prefix = @import("../prefix_plan.zig");
const Plan = @import("outer_plan.zig");
const K = @import("outer_kernels.zig");
const TC = @import("outer_trace_commit.zig");
const St = @import("outer_staged.zig");
const S = Plan.Section;

/// Node buffers that outlive the prefix (consumed by composition and PCS).
/// Whole-node jobs allocate them in stage() (Stager.alloc) so the PCS framing
/// can name their addresses before enqueue; prefix runs allocate them here.
pub const Long = struct {
    main_coef: K.Buffer,
    inter_coef: K.Buffer,
    main_tree: K.Buffer,
    inter_tree: K.Buffer,
    parameters: K.Buffer,
    powers: K.Buffer,
    pub fn words(p: *const Plan.ClassPlan) [6]usize {
        return .{ @intCast(p.main.coefficient_words), @intCast(p.inter.coefficient_words + p.inter_tail_words), @intCast(p.main.tree_words + p.main.prefix_words), @intCast(p.inter.tree_words + p.inter.prefix_words), 56, @as(usize, p.geometry.total_constraints) * 8 };
    }
};

/// Everything the composition/OODS/PCS tail consumes, all device resident.
pub const TailInputs = struct {
    staged: *const St.Staged,
    bases: St.Bases,
    section: [*]u32,
    main_coefficients: [*]const u32,
    inter_coefficients: [*]const u32,
    main_tree: K.Buffer,
    inter_tree: K.Buffer,
    /// Composition coefficient (8 words) and its `total_constraints` powers.
    coefficient: [*]const u32,
    powers: [*]const u32,
    /// z, alpha (16 words) and the 11 claims (88 words), for RC parameters.
    lookup: [*]const u32,
    claims: [*]const u32,
};

/// Enqueue-only composition + OODS + PCS. Bound by outer_job.zig once the
/// enqueue-only RC/PCS exist (native-job's PCS; see M8-INTERFACES outer-job).
pub const Tail = struct {
    context: *anyopaque,
    enqueue: *const fn (*anyopaque, *K.Device, *const TailInputs) anyerror!void,
};

pub const Mode = enum {
    /// Whole node through PCS. Requires a tail.
    full,
    /// Stop after the composition powers (parity / measurement of the prefix).
    prefix,
};

pub const Node = struct {
    staged: *const St.Staged,
    bases: St.Bases,
    /// Device outer slab section (Plan.Section.words).
    section: [*]u32,
    mode: Mode,
    tail: ?Tail = null,
    long: ?Long = null,
    /// Snapshot hook after each device channel step (parity mode only).
    after_step: ?*const fn (*anyopaque, u32) anyerror!void = null,
    after_step_context: ?*anyopaque = null,

    fn at(self: *const Node, r: St.Range) [*]const u32 {
        return self.bases.at(r);
    }
    fn gathered(self: *const Node, component: usize) [*]const u32 {
        const p = self.staged.plan();
        const base = self.at(self.staged.image.gathered_fixed);
        // An empty gather still needs a live pointer for custody (legacy: 1 word).
        return if (self.staged.statics.gather[component].len == 0) base else base + @as(usize, @intCast(p.gathered_offsets[component]));
    }
    fn stepped(self: *Node, step: u32) !void {
        if (self.after_step) |hook| try hook(self.after_step_context.?, step);
    }

    /// Enqueues the node and returns the host-API launches it issued. Every
    /// node-local allocation is freed (stream ordered) before return, so a
    /// recorded-but-discarded graph attempt leaves nothing behind and the
    /// body can be re-run directly.
    pub fn enqueue(self: *Node, device: *K.Device) !u32 {
        if (self.mode == .full and self.tail == null) return error.OuterJobTailUnbound;
        const p = self.staged.plan();
        const staged = self.staged;
        const asg = &staged.assignment;
        const img = staged.image;
        const k = device.kernels;
        const status = self.section + S.status;
        const before = device.counters.total();
        const total = p.geometry.total_constraints;
        if (total == 0 or total > (1 << 20)) return error.InvalidOuterCompositionAuthority;

        // Long-lived buffers (freed last, in reverse).
        var owned: [6]?K.Buffer = @splat(null);
        defer {
            var i: usize = owned.len;
            while (i > 0) {
                i -= 1;
                if (owned[i]) |b| device.free(b);
            }
        }
        const long = self.long orelse blk: {
            const w = Long.words(p);
            for (&owned, w) |*o, n| o.* = try device.alloc(n);
            break :blk Long{ .main_coef = owned[0].?, .inter_coef = owned[1].?, .main_tree = owned[2].?, .inter_tree = owned[3].?, .parameters = owned[4].?, .powers = owned[5].? };
        };
        const main_coef = long.main_coef;
        const inter_coef = long.inter_coef;
        const main_tree = long.main_tree;
        const inter_tree = long.inter_tree;
        const parameters = long.parameters;
        const powers = long.powers;
        try device.clear(self.section, S.words);

        // 1. MAIN assignment (values above the MAIN evaluation image).
        const main_eval = try device.alloc(@intCast(p.main.coefficient_words));
        var main_eval_live = true;
        defer if (main_eval_live) device.free(main_eval);
        const values = try device.alloc(asg.count * 4);
        var values_live = true;
        defer if (values_live) device.free(values);
        var job = K.AssignmentJob{ .values = values.ptr, .records = self.at(img.seeds), .indices = null, .status = @ptrCast(status), .value_count = @intCast(asg.count), .record_count = asg.seedCount(), .index_count = 0, .first = 0, .count = asg.seedCount() };
        try device.check(asg.seed(device.ctx, K.lane, &job));
        if (asg.sample_map != null) {
            const prefill = k.prefill orelse return error.MissingBlakeSamplePrefillKernel;
            try device.check(prefill(device.ctx, K.lane, values.ptr, @intCast(asg.count), self.at(img.sample_tape), self.at(img.sample_map), asg.sampleRecords(), status));
        }
        job.records = self.at(img.tasks);
        job.record_count = asg.taskCount();
        if (asg.indices.len != 0) {
            job.indices = self.at(img.indices);
            job.index_count = @intCast(asg.indices.len);
        }
        if (asg.runs.len != 0) {
            for (asg.runs) |run| {
                job.first = run.first_task;
                job.count = run.task_count;
                try device.check(switch (run.kind) {
                    .narrow => (asg.narrow orelse return error.MissingCircuitAssignmentNarrowRunKernel)(device.ctx, K.lane, &job, asg.ends[run.first_level..].ptr, run.level_count),
                    .chain => (asg.chain orelse return error.MissingCircuitAssignmentChainKernel)(device.ctx, K.lane, &job, self.at(img.chain_ends), run.first_level, run.level_count),
                    .ordinary => (asg.wide orelse asg.level)(device.ctx, K.lane, &job),
                });
            }
        } else {
            var begin: usize = 0;
            for (asg.level_ends) |end| {
                if (end != begin) {
                    job.first = @intCast(begin);
                    job.count = @intCast(end - begin);
                    try device.check(asg.level(device.ctx, K.lane, &job));
                }
                begin = end;
            }
        }

        // 2. MAIN gate kernels into the sorted evaluation image.
        var runs: [Plan.count_columns][2]u64 = undefined;
        for (p.countRuns(&runs)) |r| try device.clear(main_eval.at(r[0]), r[1]);
        var counts: [Plan.count_columns][*]u32 = undefined;
        for (&counts, Plan.main_columns - Plan.count_columns..) |*out, column| out.* = main_eval.at(p.main.offsets[column]);
        const gate_status = status + 3;
        for (0..Plan.gate_components) |c| {
            const comp = p.geometry.components[c];
            const rows = @as(usize, 1) << @intCast(comp.log);
            var pp: [11][*]const u32 = undefined;
            const fixed = self.gathered(c);
            for (pp[0..Plan.gate_fixed_widths[c]], 0..) |*out, i| out.* = fixed + i * rows;
            var outputs: [52][*]u32 = undefined;
            for (outputs[0..comp.width], 0..) |*out, j| out.* = main_eval.at(p.main.offsets[comp.main_first + j]);
            try device.check(k.base(@intCast(c), values.ptr, @intCast(asg.count), @intCast(rows), p.geometry.first_permutation_row, &pp, Plan.gate_fixed_widths[c], &outputs, comp.width, &counts, Plan.count_columns, gate_status, device.stream));
        }
        if (asg.sample_tape != null) {
            const kernel = k.sample_check orelse return error.MissingBlakeSampleCheckKernel;
            const rows = @as(usize, 1) << @intCast(p.geometry.components[4].log);
            var pp: [10][*]const u32 = undefined;
            for (&pp, 0..) |*out, i| out.* = self.gathered(4) + i * rows;
            try device.check(kernel(device.ctx, K.lane, values.ptr, @intCast(asg.count), &pp, @intCast(rows), asg.sample_first_gg, self.at(img.sample_tape), asg.sampleRecords(), gate_status));
        }
        device.free(values);
        values_live = false;

        // 3. TC MAIN; the evaluation image stays live for INTER.
        try TC.enqueue(device, &p.main, .{ .evaluations = main_eval.ptr, .coefficients = main_coef.ptr, .tree = main_tree, .statics = try self.statics(.main) });

        // 4. MAIN root -> z, alpha -> lookup parameters, all on device.
        const lookup = self.section + S.challenges;
        var step: u32 = 0;
        try device.mix(TC.rootPointer(&p.main, main_tree), 8, false);
        try self.stepped(step);
        step += 1;
        try device.draw(2, lookup);
        try self.stepped(step);
        step += 1;
        try device.check(k.lookup_params(device.ctx, K.lane, lookup, parameters.ptr, status + 2));

        // 5. INTER in physical (sorted) order into the packed image + tail.
        const inter_status = status + 1;
        for (p.inter_order) |ci| {
            const comp = p.geometry.components[ci];
            const rows = @as(u64, 1) << @intCast(comp.log);
            const pairs: u64 = comp.pairs;
            const output = inter_coef.at(p.componentInter(ci));
            const indices: u64 = staged.statics.gather[ci].len;
            const numerators = try device.alloc(@intCast(8 * pairs * rows));
            const prefix = try Prefix.Plan.init(comp.log);
            const scratch = try device.alloc(prefix.scratch_words);
            const claim = self.section + S.claims + 8 * @as(usize, ci);
            const fractions = K.Fractions{ .fixed = self.gathered(ci), .main = main_eval.at(p.componentMain(ci)), .parameters = parameters.ptr, .numerators = numerators.ptr, .denominators = output, .status = @ptrCast(inter_status), .fixed_words = indices * rows, .main_words = comp.width * rows, .numerator_words = 8 * pairs * rows, .denominator_words = 8 * pairs * rows, .component = ci, .row_log = comp.log };
            try device.check(k.fractions(device.ctx, K.lane, &fractions));
            const global = Abi.GlobalPairs{ .output = output, .contributions = numerators.ptr, .scan_scratch = scratch.ptr, .claim = claim, .status = inter_status, .stride = rows, .scan_words = prefix.scratch_words, .row_log = comp.log, .pairs = @intCast(pairs) };
            try device.check(k.global_pairs(device.ctx, K.lane, &global));
            const cumulative = K.Cumulative{ .output = output, .contributions = numerators.ptr, .claim = claim, .stride = rows, .row_log = comp.log, .pairs = @intCast(pairs) };
            try device.check(k.cumulative(device.ctx, K.lane, &cumulative));
            device.free(scratch);
            device.free(numerators);
        }
        device.free(main_eval);
        main_eval_live = false;

        // 6. Claims -> TC INTER (in place) -> INTER root.
        try device.mix(self.section + S.claims, S.claims_words, true);
        try self.stepped(step);
        step += 1;
        try TC.enqueue(device, &p.inter, .{ .evaluations = inter_coef.ptr, .coefficients = inter_coef.ptr, .tree = inter_tree, .statics = try self.statics(.inter) });
        try device.mix(TC.rootPointer(&p.inter, inter_tree), 8, false);
        try self.stepped(step);
        step += 1;

        // 7. Composition coefficient and its powers on device.
        const coefficient = self.section + S.challenges + 16;
        try device.draw(1, coefficient);
        try self.stepped(step);
        step += 1;
        try device.check(k.powers(device.ctx, K.lane, coefficient, 0, total, powers.ptr, status + 2));
        try device.copy(self.section + S.main_root, TC.rootPointer(&p.main, main_tree), 8);
        try device.copy(self.section + S.inter_root, TC.rootPointer(&p.inter, inter_tree), 8);

        // 8. Composition, OODS seed and PCS.
        if (self.mode == .full) try self.tail.?.enqueue(self.tail.?.context, device, &.{
            .staged = staged,
            .bases = self.bases,
            .section = self.section,
            .main_coefficients = main_coef.ptr,
            .inter_coefficients = inter_coef.ptr,
            .main_tree = main_tree,
            .inter_tree = inter_tree,
            .coefficient = coefficient,
            .powers = powers.ptr,
            .lookup = lookup,
            .claims = self.section + S.claims,
        });
        return device.counters.total() - before;
    }

    fn statics(self: *const Node, which: enum { main, inter }) !TC.Statics {
        const i = self.staged.image;
        const p = self.staged.plan();
        const log = if (which == .main) p.main.eval_log else p.inter.eval_log;
        const tw = try self.staged.statics.table(log);
        return .{
            .sorted_logs = self.at(if (which == .main) i.main_logs else i.inter_logs),
            .twiddles = self.at(i.twiddles[log]),
            .twiddle_words = @intCast(tw.twiddles.len),
            .itwiddles = self.at(i.itwiddles[log]),
            .itwiddle_words = @intCast(tw.itwiddles.len),
        };
    }
};

/// Device channel steps the prefix enqueues (plan device_ops minus the
/// composition root and OODS seed, which the tail owns).
pub const prefix_steps: u32 = 5;
