//! Original truth MAIN and KIO/Wire constraints with16-column authenticated
//! local-GKR terminal binding. Separate opt-in authority; no default admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Legacy = @import("../../word16_global_execution/services/gkr_local/truth_role.zig");
const Shapes = @import("authority.zig");
const Native = @import("native.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const MP = @import("../../logup_gkr/mle_point.zig");
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Air = core.air.components.ForField(O);
const Point = core.circle.CirclePoint(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
pub const Data = struct {
    allocator: std.mem.Allocator,
    instance: @import("../../word16_global_execution/services/gkr_local/truth_frame.zig").Instance,
    point: MP.MleEvalPointFor(O),
    weights: []O,
    challenges: Native.Challenges,
    eta: O,
    target: O,
    pub fn init(a: std.mem.Allocator, shape: Shapes.Shape, pending: Native.Terminal, index: usize) !Data {
        if (index >= pending.artifact.claims_to_verify_by_instance.len or index >= pending.artifact.n_variables_by_instance.len) return error.LocalGkrProjectionShape;
        const instance = shape.instance();
        const split = try Native.splitPoint(instance, pending.artifact.ood_point, pending.artifact.n_variables_by_instance[index]);
        const claims = pending.artifact.claims_to_verify_by_instance[index];
        if (claims.len != 2) return error.LocalGkrProjectionShape;
        const lanes = @as(usize, 1) << @intCast(try instance.laneLog());
        const weights = try @import("projection.zig").laneWeightsFor(O, a, split.lane);
        errdefer a.free(weights);
        if (weights.len != lanes) return error.LocalGkrProjectionShape;
        return .{ .allocator = a, .instance = instance, .point = try MP.MleEvalPointFor(O).init(split.row), .weights = weights, .challenges = pending.challenges, .eta = pending.eta, .target = claims[0].add(pending.eta.mul(claims[1])).mulM31(try M.fromCanonical(@intCast(try instance.rows())).inv()) };
    }
    pub fn deinit(self: *Data) void {
        self.allocator.free(self.weights);
        self.* = undefined;
    }
};
pub const Component = struct {
    original: Legacy.Component,
    data: *const Data,
    offsets: [3]usize = .{ 0, 0, 0 },
    pub fn descriptor(self: *const @This()) Shapes.Shape {
        return .{ .original = self.original.shape() };
    }
    pub fn widths(self: *const @This()) [3]usize {
        return self.descriptor().widths();
    }
    pub fn shifts(self: *const @This(), tree: usize, col: usize) []const i32 {
        return self.descriptor().shifts(tree, col);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return self.descriptor().constraints();
    }
    pub fn compositionLogSplit(self: *const @This()) u32 {
        return self.original.split;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.original.log_size + self.compositionLogSplit();
    }
    pub fn constraintDegreeBound(self: *const @This(), index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return self.original.shape().maxDegree();
    }
    pub fn validate(self: *const @This()) !void {
        try self.original.validate();
        if (!std.meta.eql(self.original.instance(), self.data.instance) or self.data.point.n != self.original.log_size or self.data.weights.len != @as(usize, 1) << @intCast(try self.data.instance.laneLog())) return error.LocalGkrProjectionShape;
        if (self.original.split != (if (self.original.kind == .keccak or self.original.kind == .chi or self.original.kind == .xor5) @as(u32, 2) else 1)) return error.InvalidLocalGkrTruthShape;
    }
    pub fn Workspace(comptime F: type) type {
        return Legacy.Component.Workspace(F);
    }
    pub fn ParametersFor(comptime C: type) type {
        return struct { original: Legacy.Component.ParametersFor(C), weights: []const C, eta: C, target: C };
    }
    pub fn emitForWithWorkspace(self: *const @This(), comptime F: type, samples: anytype, sink: *E.SinkFor(F), workspace: *Workspace(F)) !void {
        return self.emitWithParameters(F, samples, sink, workspace, .{ .original = .{ .span = .{ .calls = self.original.calls, .first_id = self.original.first_id }, .local = self.data.challenges, .kio = self.original.shared.kio, .wire = self.original.shared.wire, .claim = O.zero(), .global_claim = self.original.global_claim }, .weights = self.data.weights, .eta = self.data.eta, .target = self.data.target }, try samples.aux());
    }
    pub fn emitWithParameters(self: *const @This(), comptime F: type, samples: anytype, sink: *E.SinkFor(F), workspace: *Workspace(F), params: ParametersFor(E.ConstFor(F)), aux: B.AuxFor(E.SecureFor(F))) !void {
        return emitShapeWithParameters(self.descriptor(), self.original.program, F, samples, sink, workspace, params, aux);
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        try self.validate();
        const trees = try a.alloc([]u32, 3);
        errdefer a.free(trees);
        var done: usize = 0;
        errdefer for (trees[0..done]) |v| a.free(v);
        for (trees, self.widths()) |*tree, width| {
            tree.* = try a.alloc(u32, width);
            @memset(tree.*, self.original.log_size);
            done += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.widths()[0]);
        for (out, 0..) |*v, c| v.* = self.offsets[0] + c;
        return out;
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        try self.validate();
        _ = try A.geometry.localPointFor(O, point, global_log, self.original.log_size);
        const trees = try a.alloc([][]Point, 3);
        errdefer a.free(trees);
        var done: usize = 0;
        errdefer for (trees[0..done]) |tree| {
            for (tree) |col| a.free(col);
            a.free(tree);
        };
        const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step;
        const lift = Point{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) };
        for (trees, self.widths(), 0..) |*tree, width, t| {
            tree.* = try a.alloc([]Point, width);
            var assigned: usize = 0;
            errdefer {
                for (tree.*[0..assigned]) |v| a.free(v);
                a.free(tree.*);
            }
            for (tree.*, 0..) |*col, c| {
                const shifts_ = self.shifts(t, c);
                col.* = try a.alloc(Point, shifts_.len);
                for (col.*, shifts_) |*v, shift| v.* = point.add(lift.mulSigned(shift));
                assigned += 1;
            }
            done += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc, global_log: u32) !void {
        try self.validate();
        const Sampler = struct {
            owner: *const Component,
            masks: *const Air.MaskValues,
            last_anchor: O,
            local_point: Point,
            pub fn aux(s: @This()) !B.AuxFor(O) {
                const anchors = try MP.evalAnchorsFor(O, s.owner.original.log_size, s.local_point);
                return .{ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(O, &s.owner.data.point, s.local_point), .eq0 = s.owner.data.point.eq0, .eq1 = s.owner.data.point.eq1 };
            }
            pub fn last(s: @This()) !O {
                return s.last_anchor;
            }
            pub fn get(s: @This(), tree: usize, col: usize, shift: i32) !O {
                const shifts_ = s.owner.shifts(tree, col);
                const at = std.mem.indexOfScalar(i32, shifts_, shift) orelse return error.InvalidWideTruthMask;
                return E.lane.sample(O, E.lane.NativeMasksForField(O){ .values = s.masks }, tree, s.owner.offsets[tree] + col, at, shifts_.len);
            }
        };
        var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, self.original.log_size) };
        const local = try A.geometry.localPointFor(O, point, global_log, self.original.log_size);
        const step = core.poly.circle.canonic.CanonicCoset.new(self.original.log_size).coset().step;
        const last = try MP.evalIsFirstFor(O, core.poly.circle.canonic.CanonicCoset.new(self.original.log_size).coset(), local.add(.{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) }));
        var workspace: Workspace(O) = undefined;
        try self.emitForWithWorkspace(O, Sampler{ .owner = self, .masks = mask, .last_anchor = last, .local_point = local }, &sink, &workspace);
        if (sink.count != self.nConstraints()) return error.WideTruthConstraintCount;
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
        return @import("../../word16_global_execution/services/gkr_local/truth_role_domain.zig").evaluate(self, trace, acc);
    }
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator).asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) P.ComponentProver {
        return core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator).asProverComponent(self);
    }
};

/// Source-only authority for recursive OODS and native row kernels. It needs no
/// fake native component, producer claims or fabricated native challenge data.
pub fn emitShapeWithParameters(descriptor: Shapes.Shape, program: ?*const A.crypto.secp256k1.program.Program, comptime F: type, samples: anytype, sink: *E.SinkFor(F), workspace: *Component.Workspace(F), params: Component.ParametersFor(E.ConstFor(F)), aux: B.AuxFor(E.SecureFor(F))) !void {
    const width = descriptor.widths();
    for (workspace.fixed[0..width[0]], 0..) |*v, c| v.* = try samples.get(0, c, 0);
    for (workspace.main[0..width[1]], 0..) |*v, c| v.* = try samples.get(1, c, 0);
    for (workspace.current[0..width[2]], 0..) |*v, c| {
        v.* = try samples.get(2, c, 0);
        workspace.previous[c] = F.zero();
        if (c >= 8 and descriptor.shifts(2, c).len > 1) workspace.previous[c] = try samples.get(2, c, -1);
    }
    var next: [8]F = undefined;
    for (&next, 0..) |*v, c| v.* = try samples.get(2, c, 2);
    var local = @import("projection.zig").BindingSinkFor(F){ .projection = .{ .challenges = &params.original.local, .weights = params.weights, .terms = descriptor.instance().queries }, .masks = .{ .eq = E.secureFromCoordinatesForField(E.ConstFor(F), F, workspace.current[0..8].*), .eq_next2 = E.secureFromCoordinatesForField(E.ConstFor(F), F, next), .prefix = E.secureFromCoordinatesForField(E.ConstFor(F), F, workspace.current[8..16].*), .prefix_previous = E.secureFromCoordinatesForField(E.ConstFor(F), F, workspace.previous[8..16].*) }, .aux = aux, .eta = E.splatFor(F, params.eta), .target = E.splatFor(F, params.target), .out = sink };
    try Legacy.emitShapeWithLocal(descriptor.original, program, F, samples, sink, workspace, params.original, workspace.current[0..width[2]], workspace.previous[0..width[2]], 16, &local);
}
