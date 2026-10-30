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
const Plan = @import("../encoding.zig").Plan;
const geometry = @import("../geometry.zig");
const frame = @import("frame.zig");
const relation = @import("../relations.zig");
const compact = @import("../program/compact.zig");
const rom = @import("../program/setup.zig");
const rom_provider = @import("../program/provider.zig");
const bytes = @import("../range/cpu.zig");
const tables = @import("../providers/tables.zig");
const table_cpu = @import("../range/table_cpu.zig");
const points = @import("../../../air/component_point_support.zig");
pub const MAX_INTERACTION = 1024;
pub const Offsets = struct { fixed: usize = 0, main: usize = 0, interaction: usize = 0 };
pub const Challenges = struct { state: relation.Challenges, rom: rom_provider.Challenges, bytes: Q, bitwise: tables.Challenges, shifts: tables.Challenges };
pub const Claims = struct { state: Q, rom: Q, bytes: Q, bitwise: Q, shifts: Q };
pub const Component = struct {
    log_size: u32,
    plan: *const Plan,
    public: frame.Public,
    challenges: Challenges,
    claims: Claims,
    offsets: Offsets,
    constraint_count: usize,
    inflation: @import("../encoding.zig").Inflation,
    byte_alpha: bytes.PreparedAlpha,
    stage_recorder: ?*engine.stage_profile.Recorder = null,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn init(log_size: u32, plan: *const Plan, public: frame.Public, challenges: Challenges, claims: Claims, offsets: Offsets) !Component {
        try public.validate(log_size);
        if (!plan.wide_clocks or !plan.byte_operations or plan.main_count + frame.WIDTH > L.MAIN + frame.WIDTH) return error.InvalidRv64FullPlan;
        var self = Component{ .log_size = log_size, .plan = plan, .public = public, .challenges = challenges, .claims = claims, .offsets = offsets, .constraint_count = 0, .inflation = plan.inflation(), .byte_alpha = bytes.PreparedAlpha.init(challenges.bytes) };
        if (self.interactionCount() > MAX_INTERACTION) return error.InvalidRv64FullPlan;
        const main: [L.MAIN + frame.WIDTH]Q = @splat(Q.zero());
        const interaction: [MAX_INTERACTION]Q = @splat(Q.zero());
        var sink = E.Sink{ .values = null };
        self.emit(.{ Q.zero(), Q.zero(), Q.zero() }, main[0..self.mainCount()], main[0..self.mainCount()], interaction[0..self.interactionCount()], interaction[0..self.interactionCount()], &sink);
        self.constraint_count = sink.count;
        return self;
    }
    pub fn mainCount(self: *const Component) usize {
        return self.plan.main_count + frame.WIDTH;
    }
    pub fn byteStart(_: *const Component) usize {
        return L.INTERACTION + 8;
    }
    pub fn andStart(self: *const Component) usize {
        return self.byteStart() + bytes.interactionCount(self.plan);
    }
    pub fn shiftStart(self: *const Component) usize {
        return self.andStart() + table_cpu.interactionCount(self.plan, .byte_and);
    }
    pub fn interactionCount(self: *const Component) usize {
        return self.shiftStart() + table_cpu.interactionCount(self.plan, .byte_shift);
    }
    pub fn needsPreviousMain(self: *const Component, column: usize) bool {
        return column >= self.plan.main_count and frame.needsPrevious(column - self.plan.main_count);
    }
    pub fn needsPreviousInteraction(self: *const Component, column: usize) bool {
        if (column >= 32 and column < 36) return true;
        if (column >= 40 and column < 44) return true;
        const byte_end = self.andStart();
        if (column >= byte_end - 4 and column < byte_end) return true;
        const and_end = self.shiftStart();
        if (and_end > byte_end and column >= and_end - 4 and column < and_end) return true;
        const shift_end = self.interactionCount();
        return shift_end > and_end and column >= shift_end - 4 and column < shift_end;
    }
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.domain_parallel_evaluator = evaluateParallelErased;
        return result;
    }
    fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return self.evaluateDomain(trace, accumulator, pool);
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Component) usize {
        return self.constraint_count;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + L.EXPANSION;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return L.EXPANSION;
    }
    pub fn constraintDegreeBound(self: *const Component, index: usize) !u8 {
        if (index >= self.constraint_count) return error.InvalidConstraintIndex;
        return L.MAX_DEGREE;
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        const fixed = try points.emptyOrFilledLogs(a, frame.FIXED, self.log_size);
        errdefer a.free(fixed);
        const main = try points.emptyOrFilledLogs(a, self.mainCount(), self.log_size);
        errdefer a.free(main);
        const interaction = try points.emptyOrFilledLogs(a, self.interactionCount(), self.log_size);
        errdefer a.free(interaction);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const indices = try a.alloc(usize, frame.FIXED);
        for (indices, 0..) |*index, i| index.* = self.offsets.fixed + i;
        return indices;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
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
    pub fn emit(self: *const Component, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, out: *E.Sink) void {
        const main = self.plan.inflateMain(physical[0..self.plan.main_count]);
        self.emitWithLogical(fixed_geometry, physical, previous_main, current, previous, &main, out);
    }
    pub fn emitWithLogical(self: *const Component, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, main: *const E.Main, out: *E.Sink) void {
        self.emitExecutionConstraints(fixed_geometry, physical, previous_main, current, previous, main, out);
        bytes.evaluatePrepared(self.plan, physical[0..self.plan.main_count], current[self.byteStart()..self.andStart()], previous[self.byteStart()..self.andStart()], fixed_geometry[1], fixed_geometry[2], &self.byte_alpha, self.claims.bytes, out);
        self.emitTableLookupConstraints(fixed_geometry, physical, current, previous, main, out);
    }
    pub fn emitExecutionConstraints(self: *const Component, fixed_geometry: frame.Geometry, physical: []const Q, previous_main: []const Q, current: []const Q, previous: []const Q, main: *const E.Main, out: *E.Sink) void {
        const advice = physical[self.plan.main_count..][0..frame.WIDTH].*;
        const prior_advice = previous_main[self.plan.main_count..][0..frame.WIDTH].*;
        const fixed = frame.inflate(&advice, fixed_geometry);
        const view = E.View{ .f = &fixed, .m = main };
        frame.evaluate(&advice, &prior_advice, fixed_geometry, self.public, self.log_size, out);
        for (self.plan.allowed_opcodes, 0..) |allowed, opcode| if (!allowed) out.emit(advice[frame.SELECTORS + opcode]);
        @import("../range/constraints.zig").local(view, out, self.plan, physical[0..self.plan.main_count]);
        relation.evaluate(view, current[0..L.INTERACTION], previous[0..L.INTERACTION], self.challenges.state, self.claims.state, out);
        const rom_entry = frame.entry(&advice);
        const inverse = bytes.secure(current, L.INTERACTION);
        const sum = bytes.secure(current, L.INTERACTION + 4);
        const prior = bytes.secure(previous, L.INTERACTION + 4);
        const active = advice[frame.ACTIVE];
        out.emit(compact.executionDenominator(self.challenges.rom, &rom_entry).mul(inverse).sub(active));
        out.emit(Q.one().sub(active).mul(inverse));
        out.emit(sum.sub(Q.one().sub(fixed_geometry[1]).mul(prior)).sub(inverse));
        out.emit(fixed_geometry[2].mul(sum.sub(self.claims.rom)));
    }
    pub fn emitTableLookupConstraints(self: *const Component, fixed_geometry: frame.Geometry, physical: []const Q, current: []const Q, previous: []const Q, main: *const E.Main, out: *E.Sink) void {
        table_cpu.evaluate(self.plan, .byte_and, main, physical[0..self.plan.main_count], current[self.andStart()..self.shiftStart()], previous[self.andStart()..self.shiftStart()], fixed_geometry[1], fixed_geometry[2], self.challenges.bitwise, self.claims.bitwise, out);
        table_cpu.evaluate(self.plan, .byte_shift, main, physical[0..self.plan.main_count], current[self.shiftStart()..self.interactionCount()], previous[self.shiftStart()..self.interactionCount()], fixed_geometry[1], fixed_geometry[2], self.challenges.shifts, self.claims.shifts, out);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3 or mask.items[0].len < self.offsets.fixed + frame.FIXED or mask.items[1].len < self.offsets.main + self.mainCount() or mask.items[2].len < self.offsets.interaction + self.interactionCount()) return error.InvalidRv64FullShape;
        var fixed: frame.Geometry = undefined;
        for (&fixed, mask.items[0][self.offsets.fixed..][0..frame.FIXED]) |*value, column| {
            if (column.len != 1) return error.InvalidRv64FullShape;
            value.* = column[0];
        }
        var main_storage: [L.MAIN + frame.WIDTH]Q = undefined;
        var prior_main_storage: [L.MAIN + frame.WIDTH]Q = @splat(Q.zero());
        const main = main_storage[0..self.mainCount()];
        const prior_main = prior_main_storage[0..self.mainCount()];
        for (main, mask.items[1][self.offsets.main..][0..self.mainCount()], 0..) |*value, column, i| {
            const shifted = self.needsPreviousMain(i);
            if (column.len != @as(usize, if (shifted) 2 else 1)) return error.InvalidRv64FullShape;
            value.* = column[0];
            if (shifted) prior_main[i] = column[1];
        }
        var current_storage: [MAX_INTERACTION]Q = undefined;
        var prior_storage: [MAX_INTERACTION]Q = @splat(Q.zero());
        const current = current_storage[0..self.interactionCount()];
        const prior = prior_storage[0..self.interactionCount()];
        for (current, mask.items[2][self.offsets.interaction..][0..self.interactionCount()], 0..) |*value, column, i| {
            const shifted = self.needsPreviousInteraction(i);
            if (column.len != @as(usize, if (shifted) 2 else 1)) return error.InvalidRv64FullShape;
            value.* = column[0];
            if (shifted) prior[i] = column[1];
        }
        var sink = E.Sink{ .values = null, .accumulator = accumulator, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        self.emit(fixed, main, prior_main, current, prior, &sink);
        std.debug.assert(sink.count == self.constraint_count);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        return self.evaluateDomain(trace, accumulator, null);
    }
    fn evaluateDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
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
    const Encoding = @import("../encoding.zig");
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
