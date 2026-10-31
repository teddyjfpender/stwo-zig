//! Full execution CPU AIR: one shared polynomial authority for prover and OODS.
//! The immutable ROM, byte, AND and shift providers share the PCS transaction.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const E = @import("../evaluation.zig");
const L = E.L;
const Encoding = @import("../encoding.zig");
const Plan = Encoding.Plan;
const geometry = @import("../geometry.zig");
const frame = @import("frame.zig");
const relation = @import("../relations.zig");
const cyclic = @import("../state_cyclic.zig");
const compact = @import("../program/compact.zig");
const rom = @import("../program/setup.zig");
const rom_provider = @import("../program/provider.zig");
const bytes = @import("../range/cpu.zig");
const tables = @import("../providers/tables.zig");
const table_cpu = @import("../range/table_cpu.zig");
const points = @import("../../../air/component_point_support.zig");
const lane = @import("../lane.zig");
const division = @import("../delegations/division/mod.zig");
const keccak_bus = @import("../delegations/keccak/cpu_bus.zig");
const multiplication = @import("../delegations/multiplication/mod.zig");
const secp = @import("../delegations/secp256k1/mod.zig");
pub const MAX_INTERACTION = 1024;
pub const Offsets = struct { fixed: usize = 0, main: usize = 0, interaction: usize = 0 };
/// CPU lookup challenges over constant lane C (QM31 natively, external wires otherwise).
pub fn ChallengesFor(comptime C: type) type {
    return struct { state: relation.ChallengesFor(C), rom: rom_provider.ChallengesFor(C), bytes: C, bitwise: tables.ChallengesFor(C), shifts: tables.ChallengesFor(C) };
}
pub const Challenges = ChallengesFor(Q);
pub fn ClaimsFor(comptime C: type) type {
    return struct { state: C, rom: C, bytes: C, bitwise: C, shifts: C };
}
pub const Claims = ClaimsFor(Q);
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        log_size: u32,
        plan: *const Plan,
        public: frame.PublicFor(Lane),
        challenges: ChallengesFor(Lane),
        claims: ClaimsFor(Lane),
        offsets: Offsets,
        constraint_count: usize,
        inflation: @import("../encoding.zig").Inflation,
        byte_alpha: bytes.PreparedAlphaFor(Lane),
        division_bus: ?division.cpu_bus.BusFor(Lane) = null,
        keccak_bus: ?keccak_bus.BusFor(Lane) = null,
        multiplication_bus: ?multiplication.cpu_bus.BusFor(Lane) = null,
        secp_bus: ?secp.cpu_bus.BusFor(Lane) = null,
        stage_recorder: ?*engine.stage_profile.Recorder = null,
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn init(log_size: u32, plan: *const Plan, public: frame.Public, challenges: Challenges, claims: Claims, offsets: Offsets) !Self {
            if (plan.execution_profile != .rv64im or plan.arithmetic_policy != .inline_v4) return error.InvalidRv64FullPlan;
            return initPolicy(log_size, plan, public, challenges, claims, offsets, null, null, null, null);
        }
        pub fn initWithDivision(log_size: u32, plan: *const Plan, public: frame.Public, challenges: Challenges, claims: Claims, offsets: Offsets, bus: division.cpu_bus.Bus) !Self {
            if (plan.execution_profile != .rv64im or plan.arithmetic_policy != .division_service_v2) return error.InvalidRv64FullPlan;
            return initPolicy(log_size, plan, public, challenges, claims, offsets, bus, null, null, null);
        }
        pub fn initWithKeccak(log_size: u32, plan: *const Plan, public: frame.Public, challenges: Challenges, claims: Claims, offsets: Offsets, bus: division.cpu_bus.Bus, service: keccak_bus.Bus) !Self {
            if (plan.execution_profile != .keccak_service_v1 or plan.arithmetic_policy != .division_service_v2) return error.InvalidRv64FullPlan;
            try service.validate(public.steps);
            return initPolicy(log_size, plan, public, challenges, claims, offsets, bus, service, null, null);
        }
        pub fn initWithKeccakAndMultiplication(log_size: u32, plan: *const Plan, public: frame.Public, challenges: Challenges, claims: Claims, offsets: Offsets, bus: division.cpu_bus.Bus, service: keccak_bus.Bus, mul: multiplication.cpu_bus.Bus) !Self {
            if (plan.execution_profile != .keccak_service_v1 or plan.arithmetic_policy != .division_multiplication_services_v3) return error.InvalidRv64FullPlan;
            try service.validate(public.steps);
            return initPolicy(log_size, plan, public, challenges, claims, offsets, bus, service, mul, null);
        }
        pub fn initWithEthereum(log_size: u32, plan: *const Plan, public: frame.Public, challenges: Challenges, claims: Claims, offsets: Offsets, bus: division.cpu_bus.Bus, service: keccak_bus.Bus, mul: ?multiplication.cpu_bus.Bus, elliptic: secp.cpu_bus.Bus) !Self {
            if ((plan.execution_profile != .ethereum_services_v1 and plan.execution_profile != .ethereum_services_v2) or elliptic.execution_profile != plan.execution_profile or plan.arithmetic_policy == .inline_v4) return error.InvalidRv64FullPlan;
            try service.validate(public.steps);
            try elliptic.validate(public.steps);
            if (@as(u64, service.calls) + elliptic.calls[0] + elliptic.calls[1] > public.steps) return error.InvalidRv64FullPlan;
            return initPolicy(log_size, plan, public, challenges, claims, offsets, bus, service, mul, elliptic);
        }
        fn initPolicy(log_size: u32, plan: *const Plan, public: frame.Public, challenges: Challenges, claims: Claims, offsets: Offsets, bus: ?division.cpu_bus.Bus, service: ?keccak_bus.Bus, mul: ?multiplication.cpu_bus.Bus, elliptic: ?secp.cpu_bus.Bus) !Self {
            try public.validate(log_size);
            if ((plan.execution_profile == .ethereum_services_v1 or plan.execution_profile == .ethereum_services_v2) != (elliptic != null)) return error.InvalidRv64FullPlan;
            if ((plan.execution_profile == .rv64im) != (service == null)) return error.InvalidRv64FullPlan;
            if ((plan.arithmetic_policy == .division_multiplication_services_v3) != (mul != null)) return error.InvalidRv64FullPlan;
            if ((plan.arithmetic_policy == .inline_v4) != (bus == null)) return error.InvalidRv64FullPlan;
            if (!plan.wide_clocks or !plan.byte_operations or plan.main_count + frame.widthWithControl(plan.execution_profile, plan.control_policy) > L.MAIN + frame.WIDTH) return error.InvalidRv64FullPlan;
            var self = Self{ .log_size = log_size, .plan = plan, .public = public, .challenges = challenges, .claims = claims, .offsets = offsets, .constraint_count = 0, .division_bus = bus, .keccak_bus = service, .multiplication_bus = mul, .secp_bus = elliptic, .inflation = plan.inflation(), .byte_alpha = bytes.PreparedAlpha.init(challenges.bytes) };
            if (self.interactionCount() > MAX_INTERACTION) return error.InvalidRv64FullPlan;
            const main: [L.MAIN + frame.WIDTH]Q = @splat(Q.zero());
            const interaction: [MAX_INTERACTION]Q = @splat(Q.zero());
            var sink = E.Sink{ .values = null };
            self.emit(.{ Q.zero(), Q.zero(), Q.zero() }, main[0..self.mainCount()], main[0..self.mainCount()], interaction[0..self.interactionCount()], interaction[0..self.interactionCount()], &sink);
            self.constraint_count = sink.count;
            return self;
        }
        pub fn mainCount(self: *const Self) usize {
            return self.plan.main_count + frame.widthWithControl(self.plan.execution_profile, self.plan.control_policy);
        }
        pub fn byteStart(self: *const Self) usize {
            return self.plan.stateInteractionCount() + 8;
        }
        pub fn andStart(self: *const Self) usize {
            return self.byteStart() + bytes.interactionCount(self.plan);
        }
        pub fn shiftStart(self: *const Self) usize {
            return self.andStart() + table_cpu.interactionCount(self.plan, .byte_and);
        }
        pub fn divisionStart(self: *const Self) usize {
            return self.shiftStart() + table_cpu.interactionCount(self.plan, .byte_shift);
        }
        pub fn keccakStart(self: *const Self) usize {
            return self.divisionStart() + (if (self.division_bus != null) @as(usize, 8) else 0);
        }
        pub fn multiplicationStart(self: *const Self) usize {
            return self.keccakStart() + (if (self.keccak_bus != null) @as(usize, 8) else 0);
        }
        pub fn secpStart(self: *const Self) usize {
            return self.multiplicationStart() + (if (self.multiplication_bus != null) @as(usize, 8) else 0);
        }
        pub fn interactionCount(self: *const Self) usize {
            return self.secpStart() + (if (self.secp_bus != null) @as(usize, 4) else 0);
        }
        pub fn needsPreviousMain(self: *const Self, column: usize) bool {
            if (self.keccak_bus != null and column == self.plan.main_count + frame.keccakCount(self.plan.control_policy)) return true;
            if (self.secp_bus != null and column >= self.plan.main_count + frame.secpCounters(self.plan.control_policy) and column < self.plan.main_count + frame.secpCounters(self.plan.control_policy) + 2) return true;
            return column >= self.plan.main_count and column < self.plan.main_count + frame.bodyWidth(self.plan.control_policy) and frame.needsPreviousWithControl(column - self.plan.main_count, self.plan.control_policy);
        }
        pub fn needsPreviousInteraction(self: *const Self, column: usize) bool {
            const state_end = self.plan.stateInteractionCount();
            if (column >= state_end - 4 and column < state_end) return true;
            if (column >= state_end + 4 and column < state_end + 8) return true;
            const byte_end = self.andStart();
            if (column >= byte_end - 4 and column < byte_end) return true;
            const and_end = self.shiftStart();
            if (and_end > byte_end and column >= and_end - 4 and column < and_end) return true;
            const shift_end = self.divisionStart();
            if (shift_end > and_end and column >= shift_end - 4 and column < shift_end) return true;
            if (self.division_bus != null and column >= shift_end + 4 and column < shift_end + 8) return true;
            if (self.keccak_bus != null and column >= self.keccakStart() + 4 and column < self.keccakStart() + 8) return true;
            if (self.multiplication_bus != null and column >= self.multiplicationStart() + 4 and column < self.multiplicationStart() + 8) return true;
            return self.secp_bus != null and column >= self.secpStart() and column < self.secpStart() + 4;
        }
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = evaluateParallelErased;
            result.pool_exclusive_domain = true;
            return result;
        }
        fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.evaluateDomain(trace, accumulator, pool);
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.constraint_count;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + L.EXPANSION;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return L.EXPANSION;
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            if (index >= self.constraint_count) return error.InvalidConstraintIndex;
            return L.MAX_DEGREE;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            const fixed = try points.emptyOrFilledLogs(a, frame.FIXED, self.log_size);
            errdefer a.free(fixed);
            const main = try points.emptyOrFilledLogs(a, self.mainCount(), self.log_size);
            errdefer a.free(main);
            const interaction = try points.emptyOrFilledLogs(a, self.interactionCount(), self.log_size);
            errdefer a.free(interaction);
            return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const indices = try a.alloc(usize, frame.FIXED);
            for (indices, 0..) |*index, i| index.* = self.offsets.fixed + i;
            return indices;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            _ = try geometry.localPoint(point, global_log, self.log_size);
            const fixed = try points.currentPointColumns(a, frame.FIXED, point);
            errdefer points.freePointColumns(a, fixed);
            const main = try points.currentPointColumns(a, self.mainCount(), point);
            errdefer points.freePointColumns(a, main);
            const interaction = try points.currentPointColumns(a, self.interactionCount(), point);
            errdefer points.freePointColumns(a, interaction);
            const previous = geometry.previousPoint(point, global_log);
            for (main, 0..) |*column, i| if (self.needsPreviousMain(i)) {
                const replacement = try a.dupe(Point, &.{ point, previous });
                a.free(column.*);
                column.* = replacement;
            };
            for (interaction, 0..) |*column, i| if (self.needsPreviousInteraction(i)) {
                const replacement = try a.dupe(Point, &.{ point, previous });
                a.free(column.*);
                column.* = replacement;
            };
            return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, interaction }));
        }
        /// This is the sole residual dispatcher for both domain and point evaluation.
        pub fn emit(self: *const Self, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, out: *E.Sink) void {
            var main: E.Main = @splat(Q.zero());
            const prepared = self.inflation.applyPrepared(physical[0..self.plan.main_count], &main);
            self.emitInflated(fixed_geometry, physical, previous_main, current, previous, prepared, out);
        }
        pub fn emitWithLogical(self: *const Self, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, main: *const E.Main, out: *E.Sink) void {
            self.emitLogical(fixed_geometry, physical, previous_main, current, previous, main, null, out);
        }
        /// Canonical substitution only. Independently supplied logical coordinates
        /// must continue through emitWithLogical and its reconstruction residuals.
        pub fn emitInflated(self: *const Self, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, prepared: Encoding.Inflation.Result, out: *E.Sink) void {
            return self.emitInflatedGeneric(Q, fixed_geometry, physical, previous_main, current, previous, prepared, out);
        }
        pub fn emitInflatedGeneric(self: *const Self, comptime F: type, fixed_geometry: [frame.FIXED]F, physical: []const F, previous_main: []const F, current: []const F, previous: []const F, prepared: Encoding.Inflation.ResultFor(F), out: *E.SinkFor(F)) void {
            self.emitLogicalGeneric(F, fixed_geometry, physical, previous_main, current, previous, prepared.main, prepared, out);
        }
        fn emitLogical(self: *const Self, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, main: *const E.Main, prepared: ?Encoding.Inflation.Result, out: *E.Sink) void {
            return self.emitLogicalGeneric(Q, fixed_geometry, physical, previous_main, current, previous, main, prepared, out);
        }
        fn emitLogicalGeneric(self: *const Self, comptime F: type, fixed_geometry: [frame.FIXED]F, physical: []const F, previous_main: []const F, current: []const F, previous: []const F, main: *const E.MainFor(F), prepared: ?Encoding.Inflation.ResultFor(F), out: *E.SinkFor(F)) void {
            const advice = physical[self.plan.main_count..][0..frame.bodyWidth(self.plan.control_policy)];
            const fixed = frame.inflateWithControlFor(F, advice, fixed_geometry, self.plan.control_policy);
            const view = E.ViewFor(F){ .f = &fixed, .m = main };
            self.emitPreparedExecutionConstraintsGeneric(F, fixed_geometry, physical, previous_main, current, previous, advice, view, prepared, out);
            bytes.evaluatePreparedFor(F, self.plan, physical[0..self.plan.main_count], current[self.byteStart()..self.andStart()], previous[self.byteStart()..self.andStart()], fixed_geometry[1], fixed_geometry[2], &self.byte_alpha, self.claims.bytes, out);
            self.emitTableLookupConstraintsGeneric(F, fixed_geometry, physical, current, previous, main, out);
            if (self.division_bus) |bus| {
                division.cpu_bus.evaluateGeneric(F, view, current[self.divisionStart()..][0..8], previous[self.divisionStart()..][0..8], fixed_geometry[1], fixed_geometry[2], bus, out);
            }
            if (self.keccak_bus) |bus| {
                const counter = self.plan.main_count + frame.keccakCount(self.plan.control_policy);
                const enabled = if (self.secp_bus != null) physical[self.plan.main_count + frame.serviceFlags(self.plan.control_policy)] else view.op(.ECALL);
                keccak_bus.evaluateWithSelectorGeneric(F, view, fixed_geometry, physical[counter], previous_main[counter], current[self.keccakStart()..][0..8], previous[self.keccakStart()..][0..8], bus, enabled, out);
            }
            if (self.multiplication_bus) |bus| {
                multiplication.cpu_bus.evaluateGeneric(F, view, current[self.multiplicationStart()..][0..8], previous[self.multiplicationStart()..][0..8], fixed_geometry[1], fixed_geometry[2], bus, out);
            }
            if (self.secp_bus) |bus| {
                const flags = physical[self.plan.main_count + frame.serviceFlags(self.plan.control_policy) ..][0..3].*;
                secp.cpu_bus.evaluateSelectorsGeneric(F, view, flags, self.plan.execution_profile, out);
                secp.cpu_bus.evaluateGeneric(F, view, fixed_geometry, flags[1..3].*, physical[self.plan.main_count + frame.secpCounters(self.plan.control_policy) ..][0..2].*, previous_main[self.plan.main_count + frame.secpCounters(self.plan.control_policy) ..][0..2].*, E.secureFor(F, current, self.secpStart()), E.secureFor(F, previous, self.secpStart()), bus, out);
            }
        }
        pub fn emitExecutionConstraints(self: *const Self, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, main: *const E.Main, out: *E.Sink) void {
            const advice = physical[self.plan.main_count..][0..frame.bodyWidth(self.plan.control_policy)];
            const fixed = frame.inflateWithControl(advice, fixed_geometry, self.plan.control_policy);
            self.emitPreparedExecutionConstraints(fixed_geometry, physical, previous_main, current, previous, advice, .{ .f = &fixed, .m = main }, null, out);
        }
        fn emitPreparedExecutionConstraints(self: *const Self, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, advice: []const Q, view: E.View, prepared: ?Encoding.Inflation.Result, out: *E.Sink) void {
            return self.emitPreparedExecutionConstraintsGeneric(Q, fixed_geometry, physical, previous_main, current, previous, advice, view, prepared, out);
        }
        fn emitPreparedExecutionConstraintsGeneric(self: *const Self, comptime F: type, fixed_geometry: [frame.FIXED]F, physical: []const F, previous_main: []const F, current: []const F, previous: []const F, advice: []const F, view: E.ViewFor(F), prepared: ?Encoding.Inflation.ResultFor(F), out: *E.SinkFor(F)) void {
            const prior_advice = previous_main[self.plan.main_count..][0..frame.bodyWidth(self.plan.control_policy)];
            frame.evaluateWithControlFor(F, advice, prior_advice, fixed_geometry, self.public, self.log_size, self.plan.control_policy, out);
            for (self.plan.allowed_opcodes, 0..) |allowed, opcode| if (!allowed) out.emit(advice[frame.SELECTORS + opcode]);
            if (prepared) |result| division.cpu.localInflatedGeneric(F, view.f, result, out, self.plan, physical[0..self.plan.main_count]) else division.cpu.localGeneric(F, view, out, self.plan, physical[0..self.plan.main_count]);
            if (self.plan.control_policy == .limbs24_v2) {
                const control_rom = @import("../program/packed_control.zig");
                const control = @import("packed_frame.zig");
                const entry = control.entryFor(F, advice);
                @import("packed_control_constraints.zig").evaluateGeneric(F, view, control_rom.incrementFor(F, &entry), control_rom.targetFor(F, &entry), advice[control.NEXT_PC..][0..3].*, out);
            }
            switch (self.plan.state_policy) {
                .inverse_v1 => relation.evaluateFor(F, view, current[0..L.INTERACTION], previous[0..L.INTERACTION], self.challenges.state, self.claims.state, out),
                .cyclic_v2, .cyclic_canonical_v3 => cyclic.evaluateFor(F, view, fixed_geometry[0], fixed_geometry[1], current[0..cyclic.INTERACTION], previous[0..cyclic.INTERACTION], self.challenges.state, self.claims.state, out),
            }
            const state_end = self.plan.stateInteractionCount();
            const inverse = E.secureFor(F, current, state_end);
            const sum = E.secureFor(F, current, state_end + 4);
            const prior = E.secureFor(F, previous, state_end + 4);
            const active = advice[frame.ACTIVE];
            out.emit(frame.executionDenominatorWithControlFor(F, self.challenges.rom, advice, self.plan.control_policy).mul(inverse).sub(E.liftFor(F, active)));
            out.emit(E.mulBaseFor(F, inverse, F.one().sub(active)));
            out.emit(sum.sub(E.mulBaseFor(F, prior, F.one().sub(fixed_geometry[1]))).sub(inverse));
            out.emit(E.mulBaseFor(F, sum.sub(E.splatFor(F, self.claims.rom)), fixed_geometry[2]));
        }
        pub fn emitTableLookupConstraints(self: *const Self, fixed_geometry: frame.Geometry, physical: []const Q, current: []const Q, previous: []const Q, main: *const E.Main, out: *E.Sink) void {
            return self.emitTableLookupConstraintsGeneric(Q, fixed_geometry, physical, current, previous, main, out);
        }
        pub fn emitTableLookupConstraintsGeneric(self: *const Self, comptime F: type, fixed_geometry: [frame.FIXED]F, physical: []const F, current: []const F, previous: []const F, main: *const E.MainFor(F), out: *E.SinkFor(F)) void {
            table_cpu.evaluateFor(F, self.plan, .byte_and, main, physical[0..self.plan.main_count], current[self.andStart()..self.shiftStart()], previous[self.andStart()..self.shiftStart()], fixed_geometry[1], fixed_geometry[2], self.challenges.bitwise, self.claims.bitwise, out);
            table_cpu.evaluateFor(F, self.plan, .byte_shift, main, physical[0..self.plan.main_count], current[self.shiftStart()..self.divisionStart()], previous[self.shiftStart()..self.divisionStart()], fixed_geometry[1], fixed_geometry[2], self.challenges.shifts, self.claims.shifts, out);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = E.Sink{ .values = null, .accumulator = accumulator };
            self.evaluateQuotientsAtPointFor(Q, point, global_log, lane.NativeMasks{ .values = mask }, &sink) catch |err| return if (err == error.InvalidRv64MaskShape) error.InvalidRv64FullShape else err;
            std.debug.assert(sink.count == self.constraint_count);
        }
        /// Lane-generic point evaluation (lane.zig accessor contract). Mask map:
        /// fixed[offsets.fixed + i], i < 3, sample 0; main[offsets.main + i] sample 0
        /// plus sample 1 (previous row) when needsPreviousMain(i); interaction
        /// [offsets.interaction + i] sample 0 plus sample 1 when
        /// needsPreviousInteraction(i). The sink's scale is set here.
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != Lane) @compileError("CPU component lane mismatch");
            var fixed: [frame.FIXED]F = undefined;
            for (&fixed, 0..) |*value, i| value.* = try lane.sample(F, masks, 0, self.offsets.fixed + i, 0, 1);
            var main_storage: [L.MAIN + frame.WIDTH]F = undefined;
            var prior_main_storage: [L.MAIN + frame.WIDTH]F = @splat(F.zero());
            const main = main_storage[0..self.mainCount()];
            const prior_main = prior_main_storage[0..self.mainCount()];
            for (main, 0..) |*value, i| {
                const shifted = self.needsPreviousMain(i);
                value.* = try lane.sample(F, masks, 1, self.offsets.main + i, 0, if (shifted) 2 else 1);
                if (shifted) prior_main[i] = try lane.sample(F, masks, 1, self.offsets.main + i, 1, 2);
            }
            var current_storage: [MAX_INTERACTION]F = undefined;
            var prior_storage: [MAX_INTERACTION]F = @splat(F.zero());
            const current = current_storage[0..self.interactionCount()];
            const prior = prior_storage[0..self.interactionCount()];
            for (current, 0..) |*value, i| {
                const shifted = self.needsPreviousInteraction(i);
                value.* = try lane.sample(F, masks, 2, self.offsets.interaction + i, 0, if (shifted) 2 else 1);
                if (shifted) prior[i] = try lane.sample(F, masks, 2, self.offsets.interaction + i, 1, 2);
            }
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            var logical: E.MainFor(F) = @splat(F.zero());
            const prepared = self.inflation.applyPreparedGeneric(F, main[0..self.plan.main_count], &logical);
            self.emitInflatedGeneric(F, fixed, main, prior_main, current, prior, prepared, sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
            return self.evaluateDomain(trace, accumulator, null);
        }
        fn evaluateDomain(self: *const Self, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
            if (trace.polys.items.len != 3 or trace.polys.items[0].len < self.offsets.fixed + frame.FIXED or trace.polys.items[1].len < self.offsets.main + self.mainCount() or trace.polys.items[2].len < self.offsets.interaction + self.interactionCount()) return error.InvalidRv64FullShape;
            const a = accumulator.allocator;
            const total = frame.FIXED + self.mainCount() + self.interactionCount();
            const polys = try a.alloc(cp.Poly, total);
            defer a.free(polys);
            @memcpy(polys[0..frame.FIXED], trace.polys.items[0][self.offsets.fixed..][0..frame.FIXED]);
            @memcpy(polys[frame.FIXED..][0..self.mainCount()], trace.polys.items[1][self.offsets.main..][0..self.mainCount()]);
            @memcpy(polys[frame.FIXED + self.mainCount() ..], trace.polys.items[2][self.offsets.interaction..][0..self.interactionCount()]);
            const previous_columns = try a.alloc(bool, total);
            defer a.free(previous_columns);
            @memset(previous_columns[0..frame.FIXED], false);
            for (previous_columns[frame.FIXED..][0..self.mainCount()], 0..) |*needed, i| needed.* = self.needsPreviousMain(i);
            for (previous_columns[frame.FIXED + self.mainCount() ..], 0..) |*needed, i| needed.* = self.needsPreviousInteraction(i);
            const partition = @import("coset_evaluation.zig");
            var evaluation = try partition.Evaluation.init(a, polys, self.log_size, previous_columns);
            defer evaluation.deinit();
            const columns = try accumulator.columns(a, &.{.{ .log_size = self.log_size + L.EXPANSION, .n_cols = self.constraint_count }});
            defer a.free(columns);
            var output = columns[0];
            // Direct weighted accumulation consumes the assigned global power slice;
            // there is no per-row constraint vector or running extension-field power.
            for (0..partition.PARTS) |part| {
                {
                    var scope = try engine.stage_profile.StageScope.begin(self.stage_recorder, "cpu_coset_fft", "CPU quotient coset FFT");
                    defer scope.end();
                    try evaluation.evaluatePartWithPool(part, pool);
                }
                const inverse = try evaluation.denominatorInverse(part);
                {
                    var scope = try engine.stage_profile.StageScope.begin(self.stage_recorder, "cpu_constraint_rows", "CPU quotient constraint rows");
                    defer scope.end();
                    try @import("parallel.zig").evaluatePart(self, &evaluation, part, &output, inverse, pool);
                }
            }
        }
    };
}
pub const Component = ComponentFor(Q);

test "full CPU adapter reports private-path geometry and all prefix masks" {
    const plan = Plan{ .support = .{ .shifts = false }, .wide_clocks = true, .byte_operations = true };
    const zero = Q.zero();
    const typed = tables.Challenges{ .offset = zero, .coefficients = @splat(zero) };
    const challenges = Challenges{ .state = .{ .offset = zero, .coefficients = @splat(zero) }, .rom = .{ .offset = zero, .coefficients = @splat(zero) }, .bytes = zero, .bitwise = typed, .shifts = typed };
    const claims = Claims{ .state = zero, .rom = zero, .bytes = zero, .bitwise = zero, .shifts = zero };
    const component = try Component.init(10, &plan, .{ .steps = 777, .initial_pc = 0x1000, .final_pc = 0x2000 }, challenges, claims, .{});
    try std.testing.expectEqual(@as(usize, frame.WIDTH), component.mainCount());
    try std.testing.expectEqual(@as(usize, 48), component.interactionCount());
    const prover = component.asProverComponent();
    _ = prover;
    const verifier = component.asVerifierComponent();
    var logs = try verifier.traceLogDegreeBounds(std.testing.allocator);
    defer logs.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), logs.items[0].len);
    const p = core.poly.circle.canonic.CanonicCoset.new(16).circleDomain().at(0);
    var masks = try verifier.maskPoints(std.testing.allocator, .{ .x = Q.fromBase(p.x), .y = Q.fromBase(p.y) }, 14);
    defer masks.deinitDeep(std.testing.allocator);
    for (masks.items[1], 0..) |column, i| try std.testing.expectEqual(@as(usize, if (component.needsPreviousMain(i)) 2 else 1), column.len);
    for (masks.items[2], 0..) |column, i| try std.testing.expectEqual(@as(usize, if (component.needsPreviousInteraction(i)) 2 else 1), column.len);
}

test "full CPU residuals remain quartic with advice selectors and wide ticks" {
    var legacy: @import("../projection.zig").Projection = undefined;
    legacy.support = .{};
    legacy.main_map = @splat(0);
    for (0..16) |i| legacy.main_map[L.productCarry(i)] = Encoding.derived;
    for (0..4) |slot| {
        legacy.main_map[L.previousClock(slot)] = Encoding.derived;
        legacy.main_map[L.gap(slot)] = Encoding.derived;
    }
    var opcodes: [L.fixed.OPCODES]E.O = undefined;
    for (&opcodes, 0..) |*op, i| op.* = @enumFromInt(i);
    var plan = Plan.init(&legacy, &opcodes);
    plan.wideClocks();
    plan.compactProductCarries();
    plan.byteOperations(&opcodes);
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x46554c4c43505534);
    const rng = prng.random();
    const typed = tables.Challenges{ .offset = randomQ(rng), .coefficients = .{Q.fromU32Unchecked(3, 5, 7, 11)} ** tables.MAX_ARITY };
    const challenges = Challenges{ .state = .{ .offset = randomQ(rng), .coefficients = .{Q.fromU32Unchecked(13, 17, 19, 23)} ** relation.ARITY }, .rom = .{ .offset = randomQ(rng), .coefficients = .{Q.fromU32Unchecked(29, 31, 37, 41)} ** rom.field.COUNT }, .bytes = randomQ(rng), .bitwise = typed, .shifts = typed };
    const claims = Claims{ .state = randomQ(rng), .rom = randomQ(rng), .bytes = randomQ(rng), .bitwise = randomQ(rng), .shifts = randomQ(rng) };
    const component = try Component.init(21, &plan, .{ .steps = 1626000, .initial_pc = 0x1000, .final_pc = 0x2000 }, challenges, claims, .{});
    const width = component.mainCount();
    const interaction_width = component.interactionCount();
    const total = frame.FIXED + 2 * width + 2 * interaction_width;
    const intercept = try a.alloc(Q, total);
    defer a.free(intercept);
    const slope = try a.alloc(Q, total);
    defer a.free(slope);
    const point = try a.alloc(Q, total);
    defer a.free(point);
    for (intercept, slope) |*c0, *c1| {
        c0.* = randomQ(rng);
        c1.* = randomQ(rng);
    }
    const residuals = try a.alloc(Q, 6 * component.constraint_count);
    defer a.free(residuals);
    const alpha = randomQ(rng);
    for (0..6) |t| {
        for (point, intercept, slope) |*value, c0, c1| value.* = c0.add(c1.mul(E.q(@intCast(t))));
        var sink = E.Sink{ .values = residuals[t * component.constraint_count ..][0..component.constraint_count] };
        const g: frame.Geometry = point[0..frame.FIXED].*;
        const main = point[frame.FIXED..][0..width];
        const previous_main = point[frame.FIXED + width ..][0..width];
        const current = point[frame.FIXED + 2 * width ..][0..interaction_width];
        const previous = point[frame.FIXED + 2 * width + interaction_width ..][0..interaction_width];
        component.emit(g, main, previous_main, current, previous, &sink);
        try std.testing.expectEqual(component.constraint_count, sink.count);
        var expected = Q.zero();
        for (sink.values.?) |value| expected = expected.mul(alpha).add(value);
        var streaming = core.air.accumulation.PointEvaluationAccumulator.init(alpha);
        var streaming_sink = E.Sink{ .values = null, .accumulator = &streaming };
        component.emit(g, main, previous_main, current, previous, &streaming_sink);
        try std.testing.expect(streaming.finalize().eql(expected));
    }
    // Fifth finite differences vanish for every degree-at-most-four residual.
    for (0..component.constraint_count) |c| {
        var differences: [6]Q = undefined;
        for (&differences, 0..) |*value, t| value.* = residuals[t * component.constraint_count + c];
        for (0..5) |round| for (0..5 - round) |i| {
            differences[i] = differences[i + 1].sub(differences[i]);
        };
        if (!differences[0].isZero()) {
            std.debug.print("full CPU degree exceeds four at constraint {d}\n", .{c});
            return error.FullCpuDegreeTooLarge;
        }
    }
    try std.testing.expect(component.mainCount() < 700);
}
fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
