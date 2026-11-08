//! Original CPU MAIN equations and one 16-base-column late GKR binding pair.
//! All four raw relation kinds share the common row suffix. No classic global
//! interaction columns are admitted by this component.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const Prover = engine.air.component_prover.ForField(O);
const Domain = engine.air.accumulation.ForField(O);
pub const Authority = @import("../gkr_local/constraint_authority.zig");
const Source = Authority.Source;
const Global = Authority.Global;
const Geo = Authority.RoleGeometry;
const MP = Authority.MlePoint;
const B = Authority.Binding;
const Raw = @import("projection.zig");
const Roster = @import("roster.zig");
const Binding = @import("binding.zig");
pub fn terms(descriptor: Source.Descriptor) ![Roster.KINDS]u32 {
    _ = try Authority.shape(descriptor);
    const layout = Global.layout(descriptor.origin);
    return .{ if (Authority.hasLocal(descriptor)) try descriptor.terms() else 0, @intCast(layout.ram_queries), if (Global.isKio(descriptor.origin)) @intCast(layout.other_queries) else 0, if (!Global.isKio(descriptor.origin)) @intCast(layout.other_queries) else 0 };
}
/// Arithmetic and terminal projection have one authority for native point
/// evaluation, symbolic device lowering, and the recursive circuit.
pub fn emitFor(comptime F: type, descriptor: Source.Descriptor, public: Authority.PublicFor(E.ConstFor(F)), source_public: []const F, local: *const Raw.LocalFor(E.ConstFor(F)), shared: *const Authority.SharedFor(E.ConstFor(F)), weights: [Roster.KINDS][]const E.SecureFor(F), gamma: E.SecureFor(F), target_per_row: E.SecureFor(F), masks: B.MaskFor(E.SecureFor(F)), auxiliary: B.AuxFor(E.SecureFor(F)), fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
    try Authority.emitMain(descriptor, F, public, fixed, main, previous, sink);
    var projection = Raw.ProjectionFor(F){ .local = local, .shared = shared, .terms = try terms(descriptor), .weights = weights };
    var local_sink = projection.localSink();
    if (Authority.hasLocal(descriptor)) try descriptor.emit(F, fixed, main, previous, source_public, &local_sink);
    var global_sink = projection.globalSink();
    if (source_public.len != Source.Public.count) return error.InvalidSourceAuthorityShape;
    try Authority.emitGlobalQueries(descriptor, F, fixed, main, source_public[Source.Public.sponge_first_id], &global_sink);
    try projection.finish();
    B.emitFor(F, masks, auxiliary, projection.combine(gamma), target_per_row, sink);
}

pub const Component = struct {
    pub const LOCAL_GKR = true;
    pub const MAX_FIXED = 64;
    pub const MAX_MAIN = 4096;
    pub const MAX_INTER = 16;
    descriptor: Source.Descriptor,
    log: u32,
    offsets: [2]usize,
    inter_offset: usize,
    public: Authority.PublicFor(O),
    source_public: [Source.Public.count]O,
    local: Raw.LocalFor(O),
    shared: Authority.SharedFor(O),
    parameters: *const Binding.ParametersFor(O),
    gamma: O,
    pub fn logSize(self: *const @This()) u32 {
        return self.log;
    }
    pub fn interWidth(_: *const @This()) usize {
        return 16;
    }
    pub fn mainShape(self: *const @This()) A.main_only.authority.Shape {
        return Authority.shape(self.descriptor) catch unreachable;
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return self.offsets;
    }
    pub fn previousMain(self: *const @This(), column: usize) bool {
        return Authority.previousMain(self.descriptor, column);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return self.mainShape().constraints + B.CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log + 1;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const @This(), index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn validate(self: *const @This()) !void {
        const shape = try Authority.shape(self.descriptor);
        if (self.log < 5 or self.log > 23 or shape.fixed > MAX_FIXED or shape.main > MAX_MAIN or self.parameters.point.slice().len != self.log) return error.NativeGkrComponentShape;
        const counts = try terms(self.descriptor);
        var present = false;
        for (counts, self.parameters.weights) |count, weights| {
            if (weights.len != (if (count == 0) @as(usize, 0) else @as(usize, 1) << @intCast(Roster.laneLog(count)))) return error.NativeGkrComponentShape;
            present = present or count != 0;
        }
        if (!present) return error.NativeGkrComponentShape;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        return Geo.bounds(self, a);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        return Geo.masks(self, a, point, global_log);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        return Geo.indices(self, a);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, masks: *const Air.MaskValues, acc: *Acc, global_log: u32) !void {
        try self.validate();
        const shape = self.mainShape();
        const samples = E.lane.NativeMasksForField(O){ .values = masks };
        var fixed: [MAX_FIXED]O = undefined;
        var main: [MAX_MAIN]O = undefined;
        var previous: [MAX_MAIN]O = @splat(O.zero());
        for (fixed[0..shape.fixed], 0..) |*value, c| value.* = try E.lane.sample(O, samples, 0, self.offsets[0] + c, 0, 1);
        for (main[0..shape.main], 0..) |*value, c| {
            const prior = self.previousMain(c);
            value.* = try E.lane.sample(O, samples, 1, self.offsets[1] + c, 0, if (prior) 2 else 1);
            if (prior) previous[c] = try E.lane.sample(O, samples, 1, self.offsets[1] + c, 1, 2);
        }
        var current: [16]O = undefined;
        var shifted: [16]O = undefined;
        for (&current, &shifted, 0..) |*value, *prior, c| {
            value.* = try E.lane.sample(O, samples, 2, self.inter_offset + c, 0, 2);
            prior.* = try E.lane.sample(O, samples, 2, self.inter_offset + c, 1, 2);
        }
        const local_point = try A.geometry.localPointFor(O, point, global_log, self.log);
        const anchors = try MP.evalAnchorsFor(O, self.log, local_point);
        var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, self.log) };
        const weights: [Roster.KINDS][]const O = .{ self.parameters.weights[0], self.parameters.weights[1], self.parameters.weights[2], self.parameters.weights[3] };
        try emitFor(O, self.descriptor, self.public, &self.source_public, &self.local, &self.shared, weights, self.gamma, self.parameters.target_per_row, .{
            .eq = E.secureFromCoordinatesForField(O, O, current[0..8].*),
            .eq_next2 = E.secureFromCoordinatesForField(O, O, shifted[0..8].*),
            .prefix = E.secureFromCoordinatesForField(O, O, current[8..16].*),
            .prefix_previous = E.secureFromCoordinatesForField(O, O, shifted[8..16].*),
        }, .{ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(O, &self.parameters.point, local_point), .eq0 = self.parameters.point.eq0, .eq1 = self.parameters.point.eq1 }, fixed[0..shape.fixed], main[0..shape.main], previous[0..shape.main], &sink);
        if (sink.count != self.nConstraints()) return error.NativeGkrComponentShape;
    }
    pub fn evaluateConstraintQuotientsOnDomain(_: *const @This(), _: *const Prover.Trace, _: *Domain.DomainEvaluationAccumulator) !void {
        return error.NativeGkrDeviceCompositionRequired;
    }
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), Prover.ComponentProver, Prover.Trace, Domain.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) Prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }
};

test "native CPU component census removes all classic global widths" {
    const cases = [_]Source.Descriptor{ .{ .origin = .{ .core = .initial } }, .{ .origin = .{ .core = .ls } }, .{ .origin = .{ .bridge = .keccak } }, .{ .origin = .{ .bridge = .add } }, .{ .origin = .{ .sponge = .call } } };
    for (cases) |descriptor| {
        const counts = try terms(descriptor);
        try std.testing.expect(counts[1] > 0);
        if (descriptor.origin == .core and descriptor.origin.core == .initial) try std.testing.expectEqual([4]u32{ 0, 1, 0, 0 }, counts);
        if (descriptor.origin == .bridge and descriptor.origin.bridge == .keccak) try std.testing.expectEqual(@as(u32, 2), counts[2]);
        if (descriptor.origin == .bridge and descriptor.origin.bridge == .add) try std.testing.expectEqual(@as(u32, 2), counts[3]);
    }
}

test "native reduced CPU verifier adapter is fully typed" {
    var component: Component = undefined;
    _ = component.asVerifierComponent();
}
