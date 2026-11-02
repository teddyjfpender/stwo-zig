//! Receiver-anchored INIT/TEARDOWN: original20 MAIN constraints plus explicit
//! OM RAM claim. No local lookup exists, so no synthetic local GKR is inserted.
//! Acceptance MUST compare the physical claim to the authorized public cell list.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Geo = @import("role_geometry.zig");
const Global = @import("global_cpu.zig");
const Manifest = @import("manifest.zig");
const Frame = @import("frame.zig");
pub const MAIN_SHAPE: A.main_only.authority.Shape = .{ .fixed = 3, .main = 14, .constraints = 20 };
pub const CONSTRAINTS = MAIN_SHAPE.constraints + Global.layout(.{ .core = .initial }).constraints();
pub const MAX_DEGREE: u8 = 3;
pub const Component = struct {
    pub const LOCAL_GKR = false;
    pub const MAX_FIXED = 3;
    pub const MAX_MAIN = 14;
    pub const MAX_INTER = 16;
    origin: Frame.Origin,
    log: u32,
    count: u32,
    offsets: [2]usize,
    inter_offset: usize,
    shared: Manifest.Shared,
    claim: O,
    pub fn logSize(self: *const @This()) u32 {
        return self.log;
    }
    pub fn interWidth(_: *const @This()) usize {
        return 16;
    }
    pub fn mainShape(_: *const @This()) A.main_only.authority.Shape {
        return MAIN_SHAPE;
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return self.offsets;
    }
    pub fn previousMain(_: *const @This(), c: usize) bool {
        return c == 0;
    }
    pub fn previousInter(_: *const @This(), c: usize) bool {
        return c >= 8 and c < 16;
    }
    pub fn nConstraints(_: *const @This()) usize {
        return CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log + 1;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(_: *const @This(), index: usize) !u8 {
        if (index >= CONSTRAINTS) return error.InvalidConstraintIndex;
        return MAX_DEGREE;
    }
    pub fn validate(self: *const @This()) !void {
        if (self.origin != .core or (self.origin.core != .initial and self.origin.core != .terminal) or self.log < 5 or self.log > 22 or self.count >= @as(u32, 1) << @intCast(self.log)) return error.InvalidWideBoundaryGeometry;
    }
    pub fn emitMainFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        A.memory.load_store_v2.equations.emitBoundaryMainFor(F, fixed, main, previous, E.qFor(F, self.count), E.qFor(F, @intFromBool(self.count != 0)), sink);
    }
    pub fn emitGlobalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        try Global.emitFor(F, self.origin, self.shared, .{ .ram = self.claim, .kio = O.zero(), .wire = O.zero() }, fixed, main, current, previous, sink);
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        return Geo.bounds(self, a);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global: u32) !Air.MaskPoints {
        return Geo.masks(self, a, point, global);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        return Geo.indices(self, a);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc, global: u32) !void {
        return @import("role_oods.zig").evaluate(self, point, mask, acc, global);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
        return @import("role_domain.zig").evaluate(self, trace, acc, null);
    }
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) P.ComponentProver {
        return Adapter.asProverComponent(self);
    }
};
