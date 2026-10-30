//! Exact original native intrinsic evaluation, polynomial extension and global
//! composition lift. Every numerical operand comes from the proof arena.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Program = @import("resident_native_program_v1.zig");
const Producer = @import("resident_native_producer_v1.zig");
const Transform = @import("resident_parent_transform_v1.zig");
const Geometry = core.poly.circle.quotient_geometry;
pub const FIRST_ID: u32 = (1 << 28) + 73728;
pub const Slot = enum(u32) { metadata, coefficients, evaluations, output, normalized, aggregate, powers, parameters, claims };
const Ref = struct { tree: usize, column: usize };
const Cohort = struct { sources: []Ref, logs: usize, offsets: usize, denominators: usize, denominator_count: u32, extension_logs: usize, main: usize, fixed: usize, witness: usize, interaction: usize };
pub const Limits = struct { max_extra_bytes: usize = 16 << 30, max_log: u32 = 27 };
extern fn stwo_resident_framework_powers_on([*]const u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_resident_framework_add_on([*]const u32, [*]u32, u32, ?*anyopaque) c_int;
extern fn stwo_native_code_identity([*]u8) void;
extern fn stwo_native_program_on(u32, u32, ?[*]const u32, [*]const u32, ?[*]const u32, ?[*]const u32, ?[*]const u32, ?[*]const u64, ?[*]const u32, [*]u32, u32, u32, ?[*]const u32, u32, ?*anyopaque) c_int;
extern fn stwo_native_access_parameters_on([*]const u32, u32, u64, ?[*]const u32, u32, [*]u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_native_projection_parameters_on([*]const u32, u32, u32, ?[*]const u32, u32, [*]u32, [*]u32, ?*anyopaque) c_int;
fn pow(log: u32) usize {
    return @as(usize, 1) << @intCast(log);
}
pub fn ForCommitments(comptime N: usize) type {
    return struct {
        const P = Program.ForCommitments(N);
        pub const Views = struct { coefficients: [N - 1][]const common.Words, draws: common.Words, claims: common.Words, alpha: common.Words, error_flag: common.Words, twiddles_forward: common.Words, twiddles_inverse: common.Words, composition_coefficients: common.Words };
        pub const Plan = struct {
            backing: std.mem.Allocator,
            arena: std.heap.ArenaAllocator,
            program: *const P.Owned,
            cohorts: []Cohort,
            metadata: []u32,
            requirements: [std.meta.fields(Slot).len]cuda.runtime.arena.Requirement,
            base_clock: u64,
            extra_bytes: usize,
            pub fn init(backing: std.mem.Allocator, p: *const P.Owned, limits: Limits) !Plan {
                const d = p.view();
                if (d.composition_log > limits.max_log or d.composition_split < 1 or d.composition_split > 3) return error.UnsupportedNativeCompositionSplit;
                var arena = std.heap.ArenaAllocator.init(backing);
                errdefer arena.deinit();
                const a = arena.allocator();
                var metadata: std.ArrayList(u32) = .empty;
                const cohorts = try a.alloc(Cohort, d.components.len);
                var max_coeff: usize = 4 * pow(d.composition_log - 1);
                var max_eval: usize = 1;
                var max_output: usize = 1;
                for (d.components, cohorts) |c, *cohort| {
                    if (c.intrinsic_evaluation_log < c.trace_log + 1 or c.evaluation_log != c.intrinsic_evaluation_log + c.extension_delta or c.evaluation_log > d.composition_log) return error.InvalidNativeCompositionGeometry;
                    var refs: std.ArrayList(Ref) = .empty;
                    var main: usize = 0;
                    var fixed: usize = 0;
                    var witness: usize = 0;
                    var interaction: usize = 0;
                    if (c.kind == .frame) {
                        try refs.append(a, .{ .tree = 0, .column = c.fixed_selector.? });
                        main = 1;
                    }
                    for (0..c.main_width) |i| try refs.append(a, .{ .tree = 1, .column = c.main_first + i });
                    if (c.kind == .opcode or c.kind == .clock) {
                        fixed = refs.items.len;
                        try refs.append(a, .{ .tree = 0, .column = c.fixed_selector.? });
                    }
                    if (c.kind == .access) {
                        witness = refs.items.len;
                        for (0..48) |i| try refs.append(a, .{ .tree = 2, .column = c.witness_first.? + i });
                    }
                    if (c.kind == .projection or c.kind == .access or c.kind == .frame) {
                        interaction = refs.items.len;
                        const count: usize = if (c.kind == .access) 49 else if (c.kind == .frame) 1 else 4;
                        for (0..count) |i| try refs.append(a, .{ .tree = N - 2, .column = c.interaction_first.? + i });
                    }
                    for (refs.items) |r| if (r.column >= d.trees[r.tree].base_logs.len or d.trees[r.tree].base_logs[r.column] != c.trace_log) return error.InvalidNativeCompositionGeometry;
                    const logs = metadata.items.len;
                    for (refs.items) |_| try metadata.append(a, c.trace_log);
                    while (metadata.items.len % 2 != 0) try metadata.append(a, 0);
                    const offsets = metadata.items.len;
                    for (refs.items, 0..) |_, i| {
                        const v: @TypeOf(@as(u64, 0)) = i * pow(c.intrinsic_evaluation_log);
                        try metadata.append(a, @truncate(v));
                        try metadata.append(a, @truncate(v >> 32));
                    }
                    const geometry = try Geometry.derive(c.trace_log, c.intrinsic_evaluation_log);
                    const denominators = metadata.items.len;
                    try metadata.appendSlice(a, &Geometry.words(geometry));
                    const extension = metadata.items.len;
                    try metadata.appendNTimes(a, c.intrinsic_evaluation_log, 4);
                    cohort.* = .{ .sources = try refs.toOwnedSlice(a), .logs = logs, .offsets = offsets, .denominators = denominators, .denominator_count = geometry.count, .extension_logs = extension, .main = main, .fixed = fixed, .witness = witness, .interaction = interaction };
                    max_coeff = @max(max_coeff, cohort.sources.len * pow(c.intrinsic_evaluation_log - 1));
                    max_eval = @max(max_eval, cohort.sources.len * pow(c.intrinsic_evaluation_log));
                    max_output = @max(max_output, 4 * pow(c.intrinsic_evaluation_log));
                }
                const meta = try metadata.toOwnedSlice(a);
                const sizes = [_]usize{ meta.len, max_coeff, max_eval, max_output, 4 * pow(d.composition_log), 4 * pow(d.composition_log), 4 * d.constraints, 164, 40 };
                var requirements: [std.meta.fields(Slot).len]cuda.runtime.arena.Requirement = undefined;
                var bytes: usize = 0;
                for (sizes, &requirements, 0..) |words, *r, i| {
                    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, words, 4));
                    r.* = .{ .id = FIRST_ID + @as(u32, @intCast(i)), .words = @max(1, words), .alignment_words = 64, .live_from = if (i == 0) .ingress else .constraint_evaluation, .live_through = .constraint_evaluation };
                }
                if (bytes > limits.max_extra_bytes) return error.NativeCompositionResourceLimit;
                return .{ .backing = backing, .arena = arena, .program = p, .cohorts = cohorts, .metadata = meta, .requirements = requirements, .base_clock = try @import("../../frontends/riscv/prover/block_execution_integer_bridge_v2.zig").baseClockFromPublicFrame(d.profile.pin.frame), .extra_bytes = bytes };
            }
            pub fn deinit(self: *Plan) void {
                self.arena.deinit();
                self.* = undefined;
            }
        };
        pub const Bound = struct {
            plan: *const Plan,
            slots: [std.meta.fields(Slot).len]common.Words,
            primed: bool = false,
            completed: bool = false,
            pub fn init(plan: *const Plan, tx: anytype) !Bound {
                var actual: [32]u8 = undefined;
                stwo_native_code_identity(&actual);
                if (!std.mem.eql(u8, &actual, &plan.program.view().code_identity)) return error.WrongNativeProgramLibrary;
                var out: Bound = .{ .plan = plan, .slots = undefined };
                for (&out.slots, plan.requirements) |*v, r| {
                    v.* = try tx.slot(r.id);
                    if (v.len != r.words) return error.InvalidNativeCompositionBinding;
                }
                return out;
            }
            fn slot(self: *const Bound, s: Slot) common.Words {
                return self.slots[@intFromEnum(s)];
            }
            fn meta(self: *const Bound, first: usize, n: usize) !common.Words {
                return self.slot(.metadata).sub(first, n);
            }
            pub fn prime(self: *Bound, s: anytype) !void {
                if (self.primed) return error.InvalidNativeCompositionState;
                try common.requireStage(s, .ingress);
                try s.context.uploadSlice(u32, self.slot(.metadata), self.plan.metadata);
                self.primed = true;
            }
            pub fn compose(self: *Bound, s: anytype, v: *const Views) !void {
                const d = self.plan.program.view();
                const stage = cuda.runtime.telemetry.Stage.constraint_evaluation;
                if (!self.primed or self.completed or v.draws.len != 424 or v.claims.len != 4 * d.physical_claim_count or v.alpha.len != 4 or v.error_flag.len != 1 or v.composition_coefficients.len != 4 * pow(d.composition_log)) return error.InvalidNativeCompositionState;
                try common.requireStage(s, stage);
                for (v.coefficients, d.trees[0 .. N - 1]) |columns, t| {
                    if (columns.len != t.base_logs.len) return error.InvalidNativeCompositionBinding;
                    for (columns, t.base_logs) |c, log| if (c.len != pow(log)) return error.InvalidNativeCompositionBinding;
                }
                try common.record(s, stage, stwo_resident_framework_powers_on(try ptr(s, v.alpha), @intCast(d.constraints), try ptr(s, self.slot(.powers)), s.context.stream));
                try s.zeroResidentSlice(u32, stage, self.slot(.aggregate));
                for (d.components, self.plan.cohorts, 0..) |c, cohort, i| {
                    const n = pow(c.intrinsic_evaluation_log);
                    const stride = n / 2;
                    const coeff = try self.slot(.coefficients).sub(0, cohort.sources.len * stride);
                    const eval = try self.slot(.evaluations).sub(0, cohort.sources.len * n);
                    for (cohort.sources, 0..) |r, j| try s.context.copyDeviceSlice(u32, try coeff.sub(j * stride, pow(c.trace_log)), v.coefficients[r.tree][r.column]);
                    try Transform.extend(s, stage, .{ .storage = coeff, .column_stride_words = stride }, try self.meta(cohort.logs, cohort.sources.len), .{ .storage = eval, .column_stride_words = n }, c.intrinsic_evaluation_log, v.twiddles_forward, false);
                    if (c.kind == .projection) {
                        const claim = try v.claims.sub(4 * c.physical_claim_first, 4);
                        try common.record(s, stage, stwo_native_projection_parameters_on(try ptr(s, v.draws), 424, @intFromEnum(@import("resident_native_projection_program_v1.zig").domain(c.program.projection.equation.slot)), try ptr(s, claim), @intCast(pow(c.trace_log)), try ptr(s, self.slot(.parameters)), try ptr(s, v.error_flag), s.context.stream));
                    }
                    if (c.kind == .access) {
                        for (Producer.ACCESS_ORIGINAL_ORDER, 0..) |original, j| try s.context.copyDeviceSlice(u32, try self.slot(.claims).sub(4 * original, 4), try v.claims.sub(4 * (c.physical_claim_first + j), 4));
                        try common.record(s, stage, stwo_native_access_parameters_on(try ptr(s, v.draws), 416, self.plan.base_clock, try ptr(s, self.slot(.claims)), @intCast(pow(c.trace_log)), try ptr(s, self.slot(.parameters)), try ptr(s, v.error_flag), s.context.stream));
                    }
                    const output = try self.slot(.output).sub(0, 4 * n);
                    try s.zeroResidentSlice(u32, stage, output);
                    const offsets = try (try self.meta(cohort.offsets, cohort.sources.len * 2)).cast(u64);
                    const first_power = d.constraints - c.first_constraint - c.constraints;
                    try common.record(s, stage, stwo_native_program_on(@intCast(i), 1, try ptr(s, try eval.sub((if (c.kind == .opcode) @as(usize, 0) else cohort.fixed) * n, n)), try ptr(s, try eval.sub(cohort.main * n, c.main_width * n)), try ptr(s, try eval.sub(cohort.witness * n, if (c.kind == .access) 48 * n else n)), try ptr(s, try eval.sub(cohort.interaction * n, if (c.kind == .access) 49 * n else if (c.kind == .projection) 4 * n else n)), try ptr(s, self.slot(.parameters)), try s.context.deviceSlicePointer(u64, offsets, offsets.len), try ptr(s, try self.slot(.powers).sub(4 * first_power, 4 * c.constraints)), try ptr(s, output), @intCast(n), @intCast(pow(c.trace_log)), try ptr(s, try self.meta(cohort.denominators, 8)), cohort.denominator_count, s.context.stream));
                    var normalized = output;
                    if (c.extension_delta > 0) {
                        const half = pow(c.evaluation_log - 1);
                        const values = try self.slot(.coefficients).sub(0, 4 * half);
                        normalized = try self.slot(.normalized).sub(0, 4 * pow(c.evaluation_log));
                        try Transform.inverseCompact(s, stage, .{ .storage = output, .column_stride_words = n }, .{ .storage = values, .column_stride_words = half }, c.intrinsic_evaluation_log, v.twiddles_inverse);
                        try Transform.extend(s, stage, .{ .storage = values, .column_stride_words = half }, try self.meta(cohort.extension_logs, 4), .{ .storage = normalized, .column_stride_words = pow(c.evaluation_log) }, c.evaluation_log, v.twiddles_forward, false);
                    }
                    if (c.evaluation_log < d.composition_log) try cuda.runtime.stages.composition_lift.Native.accumulate(s, .{ .storage = normalized, .column_stride_words = pow(c.evaluation_log) }, c.evaluation_log, .{ .storage = self.slot(.aggregate), .column_stride_words = pow(d.composition_log) }, d.composition_log) else try common.record(s, stage, stwo_resident_framework_add_on(try ptr(s, normalized), try ptr(s, self.slot(.aggregate)), @intCast(normalized.len), s.context.stream));
                }
                const input = common.WordMatrix{ .storage = self.slot(.aggregate), .column_stride_words = pow(d.composition_log) };
                const output = common.WordMatrix{ .storage = v.composition_coefficients, .column_stride_words = pow(d.composition_log - d.composition_split) };
                if (d.composition_split == 1) try cuda.runtime.stages.composition_split.Native.interpolateAndSplit(s, input, output, d.composition_log, v.twiddles_inverse) else if (d.composition_split == 2) try cuda.runtime.stages.composition_split.Native.interpolateAndSplitDepthTwo(s, input, output, d.composition_log, v.twiddles_inverse) else try cuda.runtime.stages.composition_split.Native.interpolateAndSplitDepthThree(s, input, output, d.composition_log, v.twiddles_inverse);
                self.completed = true;
            }
        };
    };
}
fn ptr(s: anytype, w: common.Words) ![*]u32 {
    return s.context.deviceSlicePointer(u32, w, w.len);
}
fn force(b: *ForCommitments(5).Bound, s: *cuda.runtime.NativeSession, v: *const ForCommitments(5).Views) !void {
    try b.prime(s);
    try b.compose(s, v);
}
test "resident native composition original intrinsic domain path compiles" {
    _ = &force;
}
