//! Two independently sized source-bound components, sharing the existing
//! packed M31 domain kernel. Multiple local instances are NOT extra proofs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const S = @import("authority.zig");
const Eq = @import("equations.zig");
const Frame = @import("authority.zig");
const Native = @import("native.zig");
const MP = @import("../../logup_gkr/mle_point.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const P = engine.air.component_prover.ForField(O);
const Acc = engine.air.accumulation.ForField(O);
pub const Part = struct {
    allocator: std.mem.Allocator,
    binding: Eq.BindingFor(O),
    point: MP.MleEvalPointFor(O),
    pub fn init(a: std.mem.Allocator, geometry: Frame.Geometry, terminal: Native.Terminal, index: usize) !Part {
        const instances = try geometry.instances();
        if (index >= 8 or terminal.artifact.claims_to_verify_by_instance.len != 8 or terminal.artifact.n_variables_by_instance.len != 8) return error.SpongeLocalProjectionShape;
        const instance = instances[index];
        const split = try Native.splitPoint(instance, terminal.artifact.ood_point, terminal.artifact.n_variables_by_instance[index]);
        const claims = terminal.artifact.claims_to_verify_by_instance[index];
        if (claims.len != 2) return error.SpongeLocalProjectionShape;
        const weights = try @import("projection.zig").laneWeightsFor(O, a, split.lane);
        errdefer a.free(weights);
        return .{ .allocator = a, .point = try MP.MleEvalPointFor(O).init(split.row), .binding = .{ .instance = instance, .weights = weights, .eta = terminal.eta, .target = claims[0].add(terminal.eta.mul(claims[1])).mulM31(try core.fields.m31.M31.fromCanonical(@intCast(try instance.rows())).inv()) } };
    }
    pub fn deinit(self: *Part) void {
        self.allocator.free(self.binding.weights);
        self.* = undefined;
    }
};
pub fn Data(comptime role: S.Role) type {
    return struct {
        parts: [1]Part,
        pub fn init(a: std.mem.Allocator, geometry: Frame.Geometry, terminal: Native.Terminal) !@This() {
            var out: @This() = undefined;
            var done: usize = 0;
            errdefer for (out.parts[0..done]) |*part| part.deinit();
            for (&out.parts) |*part| {
                part.* = try Part.init(a, geometry, terminal, @import("source.zig").Source.index(role));
                done += 1;
            }
            return out;
        }
        pub fn deinit(self: *@This()) void {
            for (&self.parts) |*part| part.deinit();
            self.* = undefined;
        }
    };
}
pub fn Component(comptime role: S.Role) type {
    return struct {
        const Self = @This();
        const L = Eq.Layout(role);
        pub const DOMAIN_BINDINGS = L.LOCAL_INSTANCES;
        log_size: u32,
        public: Eq.PublicFor(O),
        data: *const Data(role),
        challenges: Native.Challenges,
        global_challenges: Eq.GlobalFor(O),
        global_claims: [2]O,
        offsets: [3]usize = .{ 0, 0, 0 },
        kind: enum { serialized_sponge } = .serialized_sponge,
        pub fn domainBindingPoint(self: *const Self, index: usize) *const MP.MleEvalPointFor(O) {
            return &self.data.parts[index].point;
        }
        pub fn validate(self: *const Self) !void {
            const g = S.Geometry{ .calls = self.public.calls, .permutations = self.public.permutations, .first_id = self.public.first_id };
            const instance = (try g.instances())[@import("source.zig").Source.index(role)];
            if (instance.row_log != self.log_size) return error.SpongeLocalProjectionShape;
            inline for (.{ false, true }, 0..) |io, i| if (Eq.globalCount(role, io) == 0 and !self.global_claims[i].isZero()) return error.SpongeNonexistentGlobalClaim;
            for (self.data.parts) |part| {
                if (part.binding.instance.role != role or part.binding.instance.row_log != self.log_size or part.point.n != self.log_size or part.binding.weights.len != @as(usize, 1) << @intCast(part.binding.instance.laneLog())) return error.SpongeLocalProjectionShape;
            }
        }
        pub fn widths(_: *const Self) [3]usize {
            return L.widths();
        }
        pub fn shifts(_: *const Self, tree: usize, column: usize) []const i32 {
            return L.shifts(tree, column);
        }
        pub fn nConstraints(_: *const Self) usize {
            return L.CONSTRAINTS;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 1;
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
            try self.validate();
            const trees = try a.alloc([]u32, 3);
            errdefer a.free(trees);
            var done: usize = 0;
            errdefer for (trees[0..done]) |tree| a.free(tree);
            for (trees, self.widths()) |*tree, width| {
                tree.* = try a.alloc(u32, width);
                @memset(tree.*, self.log_size);
                done += 1;
            }
            return Air.TraceLogDegreeBounds.initOwned(trees);
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const result = try a.alloc(usize, L.FIXED);
            for (result, 0..) |*value, c| value.* = self.offsets[0] + c;
            return result;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
            try self.validate();
            _ = try A.geometry.localPointFor(O, point, global_log, self.log_size);
            const trees = try a.alloc([][]Point, 3);
            errdefer a.free(trees);
            var done: usize = 0;
            errdefer for (trees[0..done]) |tree| {
                for (tree) |column| a.free(column);
                a.free(tree);
            };
            const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step;
            const lift = Point{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) };
            for (trees, self.widths(), 0..) |*tree, width, t| {
                tree.* = try a.alloc([]Point, width);
                var assigned: usize = 0;
                errdefer {
                    for (tree.*[0..assigned]) |column| a.free(column);
                    a.free(tree.*);
                }
                for (tree.*, 0..) |*column, c| {
                    const shifts_ = self.shifts(t, c);
                    column.* = try a.alloc(Point, shifts_.len);
                    for (column.*, shifts_) |*value, shift| value.* = point.add(lift.mulSigned(shift));
                    assigned += 1;
                }
                done += 1;
            }
            return Air.MaskPoints.initOwned(trees);
        }
        pub fn Workspace(comptime F: type) type {
            return @import("../../word16_global_execution/services/gkr_local/truth_role.zig").Component.Workspace(F);
        }
        pub fn emitForWithWorkspace(self: *const Self, comptime F: type, samples: anytype, sink: *E.SinkFor(F), _: *Workspace(F)) !void {
            const View = struct {
                fixed_values: [L.FIXED]F,
                main_values: [L.MAIN]F,
                previous_main: [L.MAIN]F,
                current: [L.INTERACTION]F,
                previous: [L.INTERACTION]F,
                next: [L.INTERACTION]F,
                pub fn fixed(v: *const @This(), c: usize) F {
                    return v.fixed_values[c];
                }
                pub fn main(v: *const @This(), c: usize) F {
                    return v.main_values[c];
                }
                pub fn previousMain(v: *const @This(), c: usize) F {
                    return v.previous_main[c];
                }
                pub fn interactionAt(v: *const @This(), c: usize, comptime shift: i32) F {
                    return switch (shift) {
                        0 => v.current[c],
                        -1 => v.previous[c],
                        2 => v.next[c],
                        else => unreachable,
                    };
                }
            };
            var view: View = undefined;
            for (&view.fixed_values, 0..) |*value, c| value.* = try samples.get(0, c, 0);
            for (&view.main_values, 0..) |*value, c| value.* = try samples.get(1, c, 0);
            for (&view.previous_main, 0..) |*value, c| {
                value.* = view.main_values[c];
                if (self.shifts(1, c).len == 2) value.* = try samples.get(1, c, -1);
            }
            for (&view.current, &view.previous, &view.next, 0..) |*current, *previous, *next, c| {
                current.* = try samples.get(2, c, 0);
                previous.* = current.*;
                next.* = current.*;
                const shifts_ = self.shifts(2, c);
                if (shifts_.len == 2) {
                    const shifted = try samples.get(2, c, shifts_[1]);
                    if (shifts_[1] == -1) previous.* = shifted else next.* = shifted;
                }
            }
            var bindings: [L.LOCAL_INSTANCES]Eq.BindingFor(O) = undefined;
            var aux: [L.LOCAL_INSTANCES]B.AuxFor(E.SecureFor(F)) = undefined;
            for (self.data.parts, &bindings, &aux, 0..) |part, *binding, *helper, index| {
                binding.* = part.binding;
                helper.* = try samples.auxAt(index);
            }
            try Eq.emit(role, F, &view, self.public, self.challenges, self.global_challenges, bindings[0], aux[0], self.global_claims, sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const P.Trace, acc: *Acc.DomainEvaluationAccumulator) !void {
            return @import("../../word16_global_execution/services/gkr_local/truth_role_domain.zig").evaluate(self, trace, acc);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, masks: *const Air.MaskValues, acc: *core.air.accumulation.ForField(O).PointEvaluationAccumulator, global_log: u32) !void {
            try self.validate();
            const local = try A.geometry.localPointFor(O, point, global_log, self.log_size);
            const Sampler = struct {
                owner: *const Self,
                masks: *const Air.MaskValues,
                point: Point,
                pub fn get(s: @This(), tree: usize, c: usize, shift: i32) !O {
                    const columns = s.masks.items;
                    if (tree >= columns.len or s.owner.offsets[tree] + c >= columns[tree].len) return error.InvalidTowerMask;
                    const values = columns[tree][s.owner.offsets[tree] + c];
                    const shifts_ = s.owner.shifts(tree, c);
                    if (values.len != shifts_.len) return error.InvalidTowerMask;
                    for (shifts_, values) |expected, value| if (shift == expected) return value;
                    return error.InvalidTowerMask;
                }
                pub fn auxAt(s: @This(), index: usize) !B.AuxFor(O) {
                    const checked = s.owner.domainBindingPoint(index);
                    const anchors = try MP.evalAnchorsFor(O, s.owner.log_size, s.point);
                    return .{ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(O, checked, s.point), .eq0 = checked.eq0, .eq1 = checked.eq1 };
                }
            };
            var workspace: Workspace(O) = undefined;
            var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, self.log_size) };
            try self.emitForWithWorkspace(O, Sampler{ .owner = self, .masks = masks, .point = local }, &sink, &workspace);
            std.debug.assert(sink.count == self.nConstraints());
        }
        const Adapter = core.air.derive.ForField(O).ComponentAdapter(Self, P.ComponentProver, P.Trace, Acc.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) P.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.pool_exclusive_domain = true;
            result.cooperative_domain = true;
            return result;
        }
        pub fn asVerifierComponent(self: *const Self) Air.Component {
            return Adapter.asVerifierComponent(self);
        }
    };
}
