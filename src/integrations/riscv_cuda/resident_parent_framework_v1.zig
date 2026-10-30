//! Resident original-framework execution. All values, claims, polynomial work
//! and normalization remain inside the caller's single proof-owned arena.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Transform = @import("resident_parent_transform_v1.zig");
const Lift = cuda.runtime.stages.composition_lift.Native;
const Split = cuda.runtime.stages.composition_split.Native;
const Code = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
const Memory = @import("resident_parent_memory_v1.zig");
pub const Cold = @import("resident_parent_framework_plan_v1.zig");
pub const Plan = Cold.Plan;
pub const Slot = Cold.Slot;
const Stage = cuda.runtime.telemetry.Stage;
extern fn stwo_resident_framework_counts_wide_on(u32, [*]const u32, [*]const u64, [*]const u32, [*]const u32, [*]u64, [*]u64, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_resident_framework_wide_reduce_on([*]const u64, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_resident_framework_counts_on(u32, [*]const u32, [*]const u64, [*]const u32, [*]const u32, [*]u32, [*]u32, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_resident_framework_relations_on([*]const u32, [*]const Cold.RelationRoute, u32, [*]u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_resident_framework_powers_on([*]const u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_resident_framework_claim_on([*]const u32, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_resident_framework_add_on([*]const u32, [*]u32, u32, ?*anyopaque) c_int;
pub const Bound = struct {
    plan: *const Plan,
    slots: [std.meta.fields(Slot).len]common.Words,
    primed: bool = false,
    counted: bool = false,
    interacted: bool = false,
    composed: bool = false,
    pub fn init(plan: *const Plan, tx: anytype) !Bound {
        var result: Bound = .{ .plan = plan, .slots = undefined };
        inline for (std.meta.tags(Slot), 0..) |which, i| result.slots[i] = try tx.slot(Cold.id(which));
        for (result.slots, plan.requirements) |v, r| if (v.len != r.words) return error.InvalidResidentFrameworkBinding;
        return result;
    }
    fn slot(self: *const Bound, which: Slot) common.Words {
        return self.slots[@intFromEnum(which)];
    }
    fn meta(self: *const Bound, start: usize, len: usize) !common.Words {
        return self.slot(.metadata).sub(start, len);
    }
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.InvalidResidentFrameworkState;
        try common.requireStage(session, .ingress);
        try session.context.uploadSlice(u32, self.slot(.metadata), self.plan.metadata);
        self.primed = true;
    }
    fn relations(self: *Bound, session: anytype, views: *const Memory.Views, index: usize, stage: Stage) !void {
        const c = self.plan.cohorts[index];
        const route = try (try self.meta(c.routes_start, c.routes.len * 3)).cast(Cold.RelationRoute);
        const draws = try views.relations.cast(u32);
        if (views.relations.len != 94 or views.claims.len != 25) return error.InvalidResidentFrameworkBinding;
        try common.record(session, stage, stwo_resident_framework_relations_on(try pointer(session, draws), try session.context.deviceSlicePointer(Cold.RelationRoute, route, route.len), @intCast(route.len), try pointer(session, self.slot(.relations)), try pointer(session, views.error_flag), session.context.stream));
        if (stage == .constraint_evaluation) {
            const p = &self.plan.program.view().programs[index];
            const claim = try (try views.claims.sub(index, 1)).cast(u32);
            const dest = try self.slot(.relations).sub(4 * c.relation_count, 4);
            const log = self.plan.program.view().cohorts[index].trace_log;
            const factor: u32 = if (p.layout == .same_row_prefix_v1) @as(u32, 1) << @intCast(31 - log) else 1;
            try common.record(session, stage, stwo_resident_framework_claim_on(try pointer(session, claim), try pointer(session, dest), factor, session.context.stream));
        }
    }
    pub fn generateCounters(self: *Bound, session: anytype, views: *const Memory.Views) !void {
        if (!self.primed or self.counted or self.interacted) return error.InvalidResidentFrameworkState;
        try common.requireStage(session, .trace_generation);
        const p = self.plan.program.view();
        const bitwise = views.sources[1][p.cohorts[23].first_column[1]];
        const range = views.sources[1][p.cohorts[24].first_column[1]];
        if (bitwise.len != pow(18) or range.len != pow(16)) return error.InvalidResidentFrameworkBinding;
        try session.zeroResidentSlice(u32, .trace_generation, bitwise);
        try session.zeroResidentSlice(u32, .trace_generation, range);
        if (self.plan.wide_counters) {
            try session.zeroResidentSlice(u32, .trace_generation, self.slot(.wide_bitwise));
            try session.zeroResidentSlice(u32, .trace_generation, self.slot(.wide_range));
        }
        try session.zeroResidentSlice(u32, .trace_generation, self.slot(.relations));
        for (p.cohorts[0..23], self.plan.cohorts[0..23], 0..) |cohort, c, i| {
            const rows = pow(cohort.trace_log);
            var cursor: usize = 0;
            for (0..2) |tree| for (0..cohort.columns[tree]) |col| {
                const src = views.sources[tree][cohort.first_column[tree] + col];
                if (src.len != rows) return error.InvalidResidentFrameworkBinding;
                try session.context.copyDeviceSlice(u32, try self.slot(.source).sub(cursor * rows, rows), src);
                cursor += 1;
            };
            const offsets = try (try self.meta(c.trace_offsets_start, c.offsets_trace.len * 2)).cast(u64);
            if (self.plan.wide_counters) {
                const wb = try self.slot(.wide_bitwise).cast(u64);
                const wr = try self.slot(.wide_range).cast(u64);
                try common.record(session, .trace_generation, stwo_resident_framework_counts_wide_on(@intCast(i), try pointer(session, self.slot(.source)), try session.context.deviceSlicePointer(u64, offsets, offsets.len), try pointer(session, try self.meta(c.profile_start, @max(1, c.profile.len))), try pointer(session, self.slot(.relations)), try session.context.deviceSlicePointer(u64, wb, wb.len), try session.context.deviceSlicePointer(u64, wr, wr.len), try pointer(session, views.error_flag), @intCast(rows), session.context.stream));
            } else try common.record(session, .trace_generation, stwo_resident_framework_counts_on(@intCast(i), try pointer(session, self.slot(.source)), try session.context.deviceSlicePointer(u64, offsets, offsets.len), try pointer(session, try self.meta(c.profile_start, @max(1, c.profile.len))), try pointer(session, self.slot(.relations)), try pointer(session, bitwise), try pointer(session, range), try pointer(session, views.error_flag), @intCast(rows), session.context.stream));
        }
        if (self.plan.wide_counters) {
            const wb = try self.slot(.wide_bitwise).cast(u64);
            const wr = try self.slot(.wide_range).cast(u64);
            try common.record(session, .trace_generation, stwo_resident_framework_wide_reduce_on(try session.context.deviceSlicePointer(u64, wb, wb.len), try pointer(session, bitwise), @intCast(bitwise.len), session.context.stream));
            try common.record(session, .trace_generation, stwo_resident_framework_wide_reduce_on(try session.context.deviceSlicePointer(u64, wr, wr.len), try pointer(session, range), @intCast(range.len), session.context.stream));
        }
        self.counted = true;
    }
    pub fn generateInteractions(self: *Bound, session: anytype, views: *const Memory.Views) !void {
        if (!self.primed or !self.counted or self.interacted) return error.InvalidResidentFrameworkState;
        try common.requireStage(session, .trace_commit);
        const p = self.plan.program.view();
        for (p.cohorts, self.plan.cohorts, 0..) |cohort, c, i| {
            const rows = pow(cohort.trace_log);
            var cursor: usize = 0;
            for (0..2) |tree| for (0..cohort.columns[tree]) |col| {
                const source = views.sources[tree][cohort.first_column[tree] + col];
                if (source.len != rows) return error.InvalidResidentFrameworkBinding;
                try session.context.copyDeviceSlice(u32, try self.slot(.source).sub(cursor * rows, rows), source);
                cursor += 1;
            };
            try self.relations(session, views, i, .trace_commit);
            var src = try pointer(session, self.slot(.source));
            var offsets = try pointer(session, try self.meta(c.trace_offsets_start, c.offsets_trace.len * 2));
            var profile = try pointer(session, try self.meta(c.profile_start, @max(1, c.profile.len)));
            var rel = try pointer(session, self.slot(.relations));
            var output = try pointer(session, self.slot(.output));
            var status = try pointer(session, views.error_flag);
            var n: u32 = @intCast(rows);
            const args = [_]?*anyopaque{ @ptrCast(&src), @ptrCast(&src), @ptrCast(&offsets), @ptrCast(&profile), @ptrCast(&rel), @ptrCast(&output), @ptrCast(&status), @ptrCast(&n) };
            try launch(session, .trace_commit, c.interaction_id, c.interaction_name, .framework_interaction_fractions_v1, .{ @intCast((rows + 127) / 128), 1, 1 }, .{ 128, 1, 1 }, &args);
            var sums = try pointer(session, self.slot(.scan));
            var blocks: u32 = @intCast((rows + 255) / 256);
            var batches: u32 = @intCast(p.programs[i].batches.len);
            var layout: u32 = @intFromEnum(p.programs[i].layout);
            const scan_args = [_]?*anyopaque{ @ptrCast(&output), @ptrCast(&sums), @ptrCast(&n), @ptrCast(&blocks), @ptrCast(&batches), @ptrCast(&layout) };
            const grids = [_][3]u32{ .{ blocks, 1, 1 }, .{ 1, 1, 1 }, .{ @intCast((rows + 127) / 128), 1, 1 } };
            for (0..3) |j| try launch(session, .trace_commit, self.plan.scan_ids[j], self.plan.scan_names[j], .framework_interaction_scan_v1, grids[j], .{ if (j == 0) @as(u32, 256) else 128, 1, 1 }, &scan_args);
            for (0..cohort.columns[2]) |col| try session.context.copyDeviceSlice(u32, views.sources[2][cohort.first_column[2] + col], try self.slot(.output).sub(col * rows, rows));
            try session.context.copyDeviceSlice(u32, try (try views.claims.sub(i, 1)).cast(u32), try self.slot(.output).sub(cohort.columns[2] * rows, 4));
        }
        self.interacted = true;
    }
    pub fn compose(self: *Bound, session: anytype, views: *const Memory.Views) !void {
        if (!self.interacted or self.composed) return error.InvalidResidentFrameworkState;
        try common.requireStage(session, .constraint_evaluation);
        const p = self.plan.program.view();
        const stage = Stage.constraint_evaluation;
        const alpha = try views.composition_alpha.cast(u32);
        try common.record(session, stage, stwo_resident_framework_powers_on(try pointer(session, alpha), p.total_constraints, try pointer(session, self.slot(.powers)), session.context.stream));
        try session.zeroResidentSlice(u32, stage, self.slot(.aggregate));
        for (p.cohorts, self.plan.cohorts, 0..) |cohort, c, i| {
            const rows = pow(cohort.evaluation_log);
            const stride = rows / 2;
            const coefficients = try self.slot(.coefficients).sub(0, c.columns * stride);
            const evaluations = try self.slot(.source).sub(0, c.columns * rows);
            var cursor: usize = 0;
            for (0..3) |tree| for (0..cohort.columns[tree]) |col| {
                const src = views.coefficient_columns[tree][cohort.first_column[tree] + col];
                if (src.len != pow(cohort.trace_log)) return error.InvalidResidentFrameworkBinding;
                try session.context.copyDeviceSlice(u32, try coefficients.sub(cursor * stride, src.len), src);
                cursor += 1;
            };
            try Transform.extend(session, stage, .{ .storage = coefficients, .column_stride_words = stride }, try self.meta(c.logs_start, c.columns), .{ .storage = evaluations, .column_stride_words = rows }, cohort.evaluation_log, views.twiddles_forward, false);
            try self.relations(session, views, i, stage);
            const out = try self.slot(.output).sub(0, 4 * rows);
            try session.zeroResidentSlice(u32, stage, out);
            var src = try pointer(session, evaluations);
            var off = try pointer(session, try self.meta(c.evaluation_offsets_start, c.offsets_evaluation.len * 2));
            var prof = try pointer(session, try self.meta(c.profile_start, @max(1, c.profile.len)));
            var rel = try pointer(session, self.slot(.relations));
            const first_power = p.total_constraints - cohort.first_constraint - cohort.constraints;
            var powers = try pointer(session, try self.slot(.powers).sub(4 * first_power, 4 * cohort.constraints));
            var output = try pointer(session, out);
            var n: u32 = @intCast(rows);
            var den = try pointer(session, try self.meta(c.denominators_start, 8));
            var dc = c.denominator_count;
            const args = [_]?*anyopaque{ @ptrCast(&src), @ptrCast(&src), @ptrCast(&src), @ptrCast(&off), @ptrCast(&prof), @ptrCast(&rel), @ptrCast(&powers), @ptrCast(&output), @ptrCast(&n), @ptrCast(&den), @ptrCast(&dc) };
            try launch(session, stage, c.composition_id, c.composition_name, .framework_polynomial_composition_v1, .{ @intCast((rows + 127) / 128), 1, 1 }, .{ 128, 1, 1 }, &args);
            const normalized_log = cohort.trace_log + p.composition_split;
            var normalized = out;
            if (normalized_log > cohort.evaluation_log) {
                const half = pow(normalized_log - 1);
                const coeff = try self.slot(.coefficients).sub(0, 4 * half);
                normalized = try self.slot(.normalized).sub(0, 4 * pow(normalized_log));
                try Transform.inverseCompact(session, stage, .{ .storage = out, .column_stride_words = rows }, .{ .storage = coeff, .column_stride_words = half }, cohort.evaluation_log, views.twiddles_inverse);
                try Transform.extend(session, stage, .{ .storage = coeff, .column_stride_words = half }, try self.meta(c.extension_logs_start, 4), .{ .storage = normalized, .column_stride_words = pow(normalized_log) }, normalized_log, views.twiddles_forward, false);
            } else if (normalized_log != cohort.evaluation_log) return error.InvalidResidentFrameworkBinding;
            if (normalized_log < p.composition_log) {
                try Lift.accumulate(session, .{ .storage = normalized, .column_stride_words = pow(normalized_log) }, normalized_log, .{ .storage = self.slot(.aggregate), .column_stride_words = pow(p.composition_log) }, p.composition_log);
            } else try common.record(session, stage, stwo_resident_framework_add_on(try pointer(session, normalized), try pointer(session, self.slot(.aggregate)), @intCast(normalized.len), session.context.stream));
        }
        const input = common.WordMatrix{ .storage = self.slot(.aggregate), .column_stride_words = pow(p.composition_log) };
        const output = common.WordMatrix{ .storage = views.commits[3].coefficients, .column_stride_words = pow(p.composition_log - p.composition_split) };
        if (p.composition_split == 1) try Split.interpolateAndSplit(session, input, output, p.composition_log, views.twiddles_inverse) else try Split.interpolateAndSplitDepthTwo(session, input, output, p.composition_log, views.twiddles_inverse);
        self.composed = true;
    }
};
fn pointer(session: anytype, words: common.Words) ![*]u32 {
    return session.context.deviceSlicePointer(u32, words, words.len);
}
fn launch(session: anytype, stage: Stage, identity: [32]u8, name: [:0]const u8, schema: cuda.abi.schema.KernelSchema, grid: [3]u32, block: [3]u32, args: []const ?*anyopaque) !void {
    try session.launchKernel(.{ .stage = stage, .abi_schema = schema, .cache_key = Code.cacheKey(identity), .name = name, .grid = grid, .block = block, .argument_count = @intCast(args.len) }, args);
}
fn pow(log: u32) usize {
    return @as(usize, 1) << @intCast(log);
}
fn forceNative(b: *Bound, s: *cuda.runtime.NativeSession, v: *const Memory.Views) !void {
    try b.prime(s);
    try b.generateCounters(s, v);
    try b.generateInteractions(s, v);
    try b.compose(s, v);
}
test "resident framework native path compiles without host value APIs" {
    _ = &forceNative;
}
