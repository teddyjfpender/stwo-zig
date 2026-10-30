//! One device witness schedule: raw packet bytes -> hash/arithmetic/direct rows
//! -> original parent MAIN. No dynamic field value is read or computed on CPU.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Program = @import("resident_parent_program_v1.zig");
const PCS = @import("resident_parent_pcs_v1.zig");
const Memory = @import("resident_parent_memory_v1.zig");
const Framework = @import("resident_parent_framework_v1.zig");
const Paths = @import("resident_parent_child_paths_runtime_v1.zig");
const FriExpand = @import("resident_parent_fri_expand_v1.zig");
const Child = @import("resident_parent_child_runtime_v1.zig");
const Resolve = @import("resident_parent_wire_resolve_v1.zig");
const Readonly = @import("resident_parent_readonly_v1.zig");
const Arithmetic = @import("resident_parent_arithmetic_v1.zig");
const Hash = @import("resident_parent_hash_witness_v1.zig");
const HashPlan = @import("resident_parent_hash_plan_v1.zig");
pub const Cold = @import("resident_parent_composite_plan_v1.zig");
pub const Types = Cold.Types;
const Routes = @import("resident_parent_value_routes_v1.zig");
extern fn stwo_resident_parent_write_on([*]const Types.Write, u32, [*]const u8, u32, [*]u32, u32, [*]const u32, u32, [*]const u32, u32, [*]const u32, u32, [*]const u32, u32, [*]u8, u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_resident_parent_direct_routes_on([*]const Routes.Call, u32, [*]const Routes.Source, u32, [*]const u32, u32, [*]const u8, u32, [*]const u32, u32, [*]const u32, u32, [*]const u32, u32, [*]const u32, u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_resident_parent_hash_scatter_on([*]const Types.HashRow, u32, [*]const Types.Cohort, [*]const u32, u32, [*]const u32, u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
pub const Plan = struct {
    cold: *const Cold.Plan,
    pub fn requirements(self: *const Plan, a: std.mem.Allocator, program: *const Program.Owned, _: *const PCS.Plans) ![]cuda.runtime.arena.Requirement {
        if (program != self.cold.program) return error.InvalidResidentComposite;
        return a.dupe(cuda.runtime.arena.Requirement, self.cold.requirements);
    }
    pub fn bind(self: *const Plan, _: std.mem.Allocator, tx: *cuda.runtime.proof_transaction.ResidentProofTransaction, program: *const Program.Owned, _: *const PCS.Plans, views: *const Memory.Views) !Bound {
        if (program != self.cold.program or views.raw_input.len != (self.cold.routes.view().bounds.raw_bytes + 3) / 4) return error.InvalidResidentComposite;
        var result = Bound{ .plan = self.cold, .slots = undefined, .framework = try Framework.Bound.init(&self.cold.framework, tx), .arithmetic = try Arithmetic.Bound.init(self.cold.arithmetic, tx), .readonly = if (self.cold.readonly) |ro| try Readonly.Bound.init(ro, self.cold.readonly_requirements.?, tx) else null, .resolver = if (self.cold.resolver) |rp| try Resolve.Bound.init(rp, tx) else null, .child = if (self.cold.child) |cp| try Child.Bound.init(cp, tx) else null, .fri_expand = if (self.cold.fri_expand) |fp| try FriExpand.Bound.init(fp, tx) else null, .paths = if (self.cold.paths) |pp| try Paths.Bound.init(pp, tx) else null };
        inline for (std.meta.tags(Cold.Slot), 0..) |s, i| result.slots[i] = try tx.slot(Cold.id(s));
        return result;
    }
};
pub const Bound = struct {
    plan: *const Cold.Plan,
    slots: [std.meta.fields(Cold.Slot).len]common.Words,
    framework: Framework.Bound,
    arithmetic: Arithmetic.Bound,
    readonly: ?Readonly.Bound,
    resolver: ?Resolve.Bound,
    child: ?Child.Bound,
    fri_expand: ?FriExpand.Bound,
    paths: ?Paths.Bound,
    primed: bool = false,
    witness_done: bool = false,
    answer_destination: ?u32 = null,
    pub fn deinit(_: *Bound, _: std.mem.Allocator) void {}
    pub fn slot(self: *const Bound, s: Cold.Slot) common.Words {
        return self.slots[@intFromEnum(s)];
    }
    pub fn prime(self: *Bound, session: *cuda.runtime.NativeSession) !void {
        if (self.primed) return error.InvalidResidentComposite;
        try self.framework.prime(session);
        try self.arithmetic.prime(session);
        if (self.readonly) |*ro| try ro.prime(session);
        if (self.resolver) |*rp| try rp.prime(session);
        if (self.child) |*cp| try cp.prime(session);
        if (self.paths) |*pp| try pp.prime(session);
        const r = self.plan.routes.view();
        const h = self.plan.hash.view();
        try self.upload(session, Types.Write, .writes, self.plan.writes);
        try self.upload(session, Types.HashRow, .hash_rows, self.plan.hash_rows);
        try self.upload(session, Types.Cohort, .cohorts, &self.plan.cohorts);
        try self.upload(session, Routes.Call, .calls, r.calls);
        try self.upload(session, Routes.Source, .sources, r.sources);
        try self.upload(session, u32, .fixed, r.fixed);
        try self.upload(session, HashPlan.Source, .hash_sources, h.sources);
        try self.upload(session, HashPlan.Call, .hash_calls, h.calls);
        try self.upload(session, u32, .hash_levels, h.level_calls);
        try self.upload(session, u32, .hash_phases, h.phase_calls);
        self.primed = true;
    }
    fn upload(self: *const Bound, session: anytype, comptime T: type, s: Cold.Slot, values: []const T) !void {
        if (values.len == 0) return;
        const dst = try (try self.slot(s).sub(0, values.len * @sizeOf(T) / 4)).cast(T);
        try session.context.uploadSlice(T, dst, values);
    }
    fn typed(self: *const Bound, session: anytype, comptime T: type, s: Cold.Slot, n: usize) ![]T {
        const w = try (try self.slot(s).sub(0, n * @sizeOf(T) / 4)).cast(T);
        const ptr = try session.context.deviceSlicePointer(T, w, n);
        return ptr[0..n];
    }
    fn hashDevice(self: *const Bound, session: anytype, error_flag: common.Words) !Hash.Device {
        const h = self.plan.hash.view();
        const bytes = try session.context.deviceSlicePointer(u32, self.slot(.hash_input), self.slot(.hash_input).len);
        return .{ .input = @as([*]const u8, @ptrCast(bytes))[0..h.input_bytes], .sources = try self.typed(session, HashPlan.Source, .hash_sources, h.sources.len), .calls = try self.typed(session, HashPlan.Call, .hash_calls, h.calls.len), .level_calls = try self.typed(session, u32, .hash_levels, h.level_calls.len), .phase_calls = try self.typed(session, u32, .hash_phases, h.phase_calls.len), .wires = try self.typed(session, u32, .hash_wires, h.wire_count), .g_main = try self.typed(session, u32, .hash_g, self.slot(.hash_g).len), .xor_main = try self.typed(session, u32, .hash_xor, self.slot(.hash_xor).len), .status = (try pointer(session, error_flag))[0..1] };
    }
    pub fn witness(self: *Bound, session: *cuda.runtime.NativeSession, views: *const Memory.Views) !void {
        if (!self.primed or self.witness_done) return error.InvalidResidentComposite;
        try common.requireStage(session, .trace_generation);
        for ([_]Cold.Slot{ .main, .resident, .hash_wires, .hash_g, .hash_xor }) |s| try session.zeroResidentSlice(u32, .trace_generation, self.slot(s));
        const hash_device = try self.hashDevice(session, views.error_flag);
        const r = self.plan.routes.view();
        const h = self.plan.hash.view();
        const raw = @as([*]const u8, @ptrCast(try pointer(session, views.raw_input)));
        const resident = try pointer(session, self.slot(.resident));
        const hash = try pointer(session, self.slot(.hash_wires));
        const arithmetic = try pointer(session, self.arithmetic.slot(.values));
        const main = try pointer(session, self.slot(.main));
        const status = try pointer(session, views.error_flag);
        const readonly_words = if (self.readonly) |*ro| ro.slot(.arguments) else self.slot(.resident);
        const readonly = try pointer(session, readonly_words);
        for (self.plan.tasks) |task| switch (task.operation) {
            .write => |range| {
                const writes = try (try self.slot(.writes).sub(@as(usize, range.first) * @sizeOf(Types.Write) / 4, @as(usize, range.count) * @sizeOf(Types.Write) / 4)).cast(Types.Write);
                try common.record(session, .trace_generation, stwo_resident_parent_write_on(try session.context.deviceSlicePointer(Types.Write, writes, writes.len), range.count, raw, @intCast(r.bounds.raw_bytes), resident, @intCast(r.bounds.resident_words), hash, h.wire_count, arithmetic, @intCast(self.plan.arithmetic.value_words), main, @intCast(self.plan.main_words), readonly, @intCast(r.bounds.readonly_words), @ptrCast(try pointer(session, self.slot(.hash_input))), @intCast(h.input_bytes), try pointer(session, self.arithmetic.slot(.inputs)), @intCast(self.plan.arithmetic.input_words), status, session.context.stream));
            },
            .hash_frame => |index| {
                const stats = try Hash.executeFrameNative(self.plan.hash, hash_device, index, session.context.stream);
                try session.recordOrdinaryKernels(.trace_generation, 0, @intCast(stats.launches));
            },
            .arithmetic => |range| try self.arithmetic.evaluateRange(session, range.first, range.count, views.error_flag),
            .child_paths => |dest| {
                const cp = if (self.child) |*v| v else return error.InvalidResidentComposite;
                if (self.paths) |*pp| {
                    const queries = try cp.slot(.output).sub(cp.plan.transcript.query_first, cp.plan.packet.query_count);
                    try pp.execute(session, cp.slot(.packet), queries, self.slot(.resident), views.error_flag);
                    try session.context.copyDeviceSlice(u32, try self.slot(.resident).sub(dest.destination_first, pp.output().len), pp.output());
                } else return error.InvalidResidentComposite;
            },
            .zero_answers => |dest| {
                const ap = self.plan.answers orelse return error.InvalidResidentComposite;
                if (self.answer_destination != null) return error.InvalidResidentComposite;
                try session.zeroResidentSlice(u32, .trace_generation, try self.slot(.resident).sub(dest.destination_first, ap.output_words));
                self.answer_destination = dest.destination_first;
            },
            .derive_answers => {
                const ap = self.plan.answers orelse return error.InvalidResidentComposite;
                const first = self.answer_destination orelse return error.InvalidResidentComposite;
                try self.arithmetic.deriveAnswers(session, ap.graph_index, ap.answers, try self.slot(.resident).sub(first, ap.output_words), views.error_flag);
            },
            .fri_expand => |dest| {
                const cp = if (self.child) |*v| v else return error.InvalidResidentComposite;
                if (self.fri_expand) |*fp| {
                    const queries = try cp.slot(.output).sub(cp.plan.transcript.query_first, fp.plan.query_count);
                    try fp.execute(session, cp.slot(.packet), queries, try self.slot(.resident).sub(dest.deep_first, @as(usize, fp.plan.query_count) * 4), try self.slot(.resident).sub(dest.alpha_first, fp.plan.layers.len * 4), try self.slot(.resident).sub(dest.destination_first, fp.plan.output_words), views.error_flag);
                } else return error.InvalidResidentComposite;
            },
            .child_replay => |dest| {
                if (self.child) |*cp| {
                    try cp.replay(session, views.error_flag);
                    try session.context.copyDeviceSlice(u32, try self.slot(.resident).sub(dest.output_first, cp.slot(.output).len), cp.slot(.output));
                    try session.context.copyDeviceSlice(u32, try self.slot(.resident).sub(dest.trace_first, cp.slot(.trace).len), cp.slot(.trace));
                } else return error.InvalidResidentComposite;
            },
            .child_gather => |graph| {
                if (self.child) |*cp| try cp.gather(session, @enumFromInt(@intFromEnum(graph)), self.slot(.resident), self.arithmetic.slot(.inputs), views.error_flag) else return error.InvalidResidentComposite;
            },
            .resolve => |request| {
                if (self.resolver) |*rp| {
                    const first = rp.next * 4;
                    try rp.resolve(session, task.phase, request.count, self.slot(.main), views.error_flag);
                    const count = @as(usize, request.count) * 4;
                    try session.context.copyDeviceSlice(u32, try self.slot(.resident).sub(request.resident_first, count), try rp.slot(.outputs).sub(first, count));
                } else return error.InvalidResidentComposite;
            },
            .readonly => {
                if (self.readonly) |*ro| {
                    const c = self.plan.cohorts[17];
                    try ro.execute(session, try self.slot(.main).sub(@intCast(c.first_word), @as(usize, c.rows) * c.columns), views.error_flag);
                } else return error.InvalidResidentComposite;
            },
            .direct_group => |index| {
                const group = r.groups[index];
                const calls = try (try self.slot(.calls).sub(@as(usize, group.first) * @sizeOf(Routes.Call) / 4, @as(usize, group.count) * @sizeOf(Routes.Call) / 4)).cast(Routes.Call);
                const sources = try self.typed(session, Routes.Source, .sources, r.sources.len);
                try common.record(session, .trace_generation, stwo_resident_parent_direct_routes_on(try session.context.deviceSlicePointer(Routes.Call, calls, calls.len), group.count, sources.ptr, @intCast(sources.len), try pointer(session, self.slot(.fixed)), @intCast(r.fixed.len), raw, @intCast(r.bounds.raw_bytes), resident, @intCast(r.bounds.resident_words), hash, h.wire_count, arithmetic, @intCast(self.plan.arithmetic.value_words), readonly, @intCast(r.bounds.readonly_words), main, @intCast(self.plan.main_words), status, session.context.stream));
            },
            .scatter_hash => |range| {
                const maps = try (try self.slot(.hash_rows).sub(@as(usize, range.first) * @sizeOf(Types.HashRow) / 4, @as(usize, range.count) * @sizeOf(Types.HashRow) / 4)).cast(Types.HashRow);
                const cohorts = try self.typed(session, Types.Cohort, .cohorts, 23);
                try common.record(session, .trace_generation, stwo_resident_parent_hash_scatter_on(try session.context.deviceSlicePointer(Types.HashRow, maps, maps.len), range.count, cohorts.ptr, hash_device.g_main.ptr, h.g_log, hash_device.xor_main.ptr, h.xor_log, main, @intCast(self.plan.main_words), status, session.context.stream));
            },
        };
        if (self.paths) |*pp| if (!pp.executed) return error.IncompleteResidentComposite;
        try self.arithmetic.requireComplete();
        if (self.fri_expand) |*fp| try fp.requireComplete();
        if (self.child) |*cp| try cp.requireComplete();
        if (self.resolver) |*rp| try rp.requireComplete();
        if (self.readonly) |*ro| try ro.requireComplete();
        var offset: usize = 0;
        for (self.plan.program.view().cohorts[0..23]) |c| for (0..c.columns[1]) |column| {
            const dst = views.sources[1][c.first_column[1] + column];
            try session.context.copyDeviceSlice(u32, dst, try self.slot(.main).sub(offset, dst.len));
            offset += dst.len;
        };
        if (offset != self.plan.main_words) return error.InvalidResidentComposite;
        // Only the device counter kernel constructs the two table MAINs.
        for (self.plan.program.view().cohorts[23..]) |c| for (0..c.columns[1]) |column| try session.zeroResidentSlice(u32, .trace_generation, views.sources[1][c.first_column[1] + column]);
        try self.framework.generateCounters(session, views);
        self.witness_done = true;
    }
    pub fn interactions(self: *Bound, session: *cuda.runtime.NativeSession, views: *const Memory.Views) !void {
        if (!self.witness_done) return error.InvalidResidentComposite;
        try self.framework.generateInteractions(session, views);
    }
    pub fn composition(self: *Bound, session: *cuda.runtime.NativeSession, views: *const Memory.Views) !void {
        try self.framework.compose(session, views);
    }
};
fn pointer(session: anytype, words: common.Words) ![*]u32 {
    return session.context.deviceSlicePointer(u32, words, words.len);
}
