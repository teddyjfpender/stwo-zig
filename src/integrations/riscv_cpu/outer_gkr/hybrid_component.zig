//! Source-owned hybrid PCS verifier component. Eq carry/anchor inputs are
//! recomputed at the receiver's folded OODS point and excluded from every
//! committed mask/degree roster. Terminal parameters come from verified GKR.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_circuit_cpu_integration");
const Outer = CPU.om31;
const H = @import("hybrid_air.zig");
const B = @import("binding_v2.zig");
const P = @import("profile.zig");
const S = @import("section.zig");
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O);
const Canonic = core.poly.circle.canonic.CanonicCoset;
const Captured = Outer.geometry.Component;
pub const Component = struct {
    allocator: std.mem.Allocator,
    source: *const Captured,
    artifact: *const H.Artifact,
    fixed_logs: []const u32,
    class: *const P.Class,
    verified: *const S.Verified,
    parameters: []const O,
    const ProverAir = @import("stwo_prover_engine").air.component_prover.ForField(O);
    const Domain = @import("stwo_prover_engine").air.accumulation.ForField(O);
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), ProverAir.ComponentProver, ProverAir.Trace, Domain.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const @This()) ProverAir.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn evaluateConstraintQuotientsOnDomain(_: *const @This(), _: *const ProverAir.Trace, _: *Domain.DomainEvaluationAccumulator) !void {
        return error.HybridResidentCompositionRequired;
    }
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return self.artifact.program.roots.len;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.source.trace_log_size + 1;
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.source.preprocessed_indices.len);
        for (out, self.source.preprocessed_indices) |*v, i| v.* = i;
        return out;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        const fixed = try a.alloc(u32, self.source.preprocessed_indices.len);
        errdefer a.free(fixed);
        for (fixed, self.source.preprocessed_indices) |*v, i| {
            if (i >= self.fixed_logs.len) return error.InvalidHybridFixedMask;
            v.* = self.fixed_logs[i];
        }
        const span = try Outer.geometry.span(self.source.*, 1);
        const main = try a.alloc(u32, span.end - span.start);
        errdefer a.free(main);
        @memset(main, self.source.trace_log_size);
        const inter = try a.alloc(u32, H.interactionWidth(self.artifact.component));
        errdefer a.free(inter);
        @memset(inter, self.source.trace_log_size);
        return Air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, inter }));
    }
    fn width(self: *const @This(), tree: u8) !usize {
        return switch (tree) {
            0 => self.source.preprocessed_indices.len,
            1 => b: {
                const span = try Outer.geometry.span(self.source.*, 1);
                break :b span.end - span.start;
            },
            2 => H.interactionWidth(self.artifact.component),
            else => error.InvalidHybridMaskTree,
        };
    }
    fn isPublic(self: *const @This(), input: @import("stwo_prover_engine").air.secure_polynomial_program_v2.Input) bool {
        return P.gkrBound(self.artifact.component) and input.tree == 2 and input.column >= 16;
    }
    fn offsets(self: *const @This(), a: std.mem.Allocator, tree: u8, column: usize) ![]i8 {
        var list: std.ArrayList(i8) = .empty;
        errdefer list.deinit(a);
        for (self.artifact.program.inputs) |input| if (input.tree == tree and input.column == column and !self.isPublic(input)) {
            var found = false;
            for (list.items) |value| if (value == input.offset) {
                found = true;
                break;
            };
            if (!found) try list.append(a, input.offset);
        };
        return list.toOwnedSlice(a);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        if (global_log < self.source.trace_log_size) return error.InvalidHybridMaskGeometry;
        const raw = Canonic.new(global_log).coset().step;
        const step = Point{ .x = O.fromBase(raw.x), .y = O.fromBase(raw.y) };
        var trees: [3][][]Point = undefined;
        var made: usize = 0;
        errdefer for (trees[0..made]) |tree| {
            for (tree) |values| a.free(values);
            a.free(tree);
        };
        for (&trees, 0..) |*tree, t| {
            tree.* = try a.alloc([]Point, try self.width(@intCast(t)));
            var cols: usize = 0;
            errdefer {
                for (tree.*[0..cols]) |values| a.free(values);
                a.free(tree.*);
            }
            for (tree.*, 0..) |*values, c| {
                const shifts = try self.offsets(a, @intCast(t), c);
                defer a.free(shifts);
                values.* = try a.alloc(Point, shifts.len);
                cols += 1;
                for (values.*, shifts) |*v, offset| v.* = point.add(step.mulSigned(offset));
            }
            made += 1;
        }
        return Air.MaskPoints.initOwned(try a.dupe([][]Point, &trees));
    }
    /// This is the only reader used by the PCS component. Committed reads are
    /// located from the pinned source MAIN/FIXED spans and hybrid INTER roster;
    /// public Eq auxiliaries cannot be selected from proof masks at any offset.
    pub fn valuesAtPoint(self: *const @This(), a: std.mem.Allocator, point: Point, mask: *const Air.MaskValues, global_log: u32) ![]O {
        return self.valuesAtPointFor(O, a, point, mask, global_log, self.verified.artifact.ood_point, self.parameters);
    }
    pub fn valuesAtPointFor(self: *const @This(), comptime Lane: type, a: std.mem.Allocator, point: core.circle.CirclePoint(Lane), mask: anytype, global_log: u32, gkr_point: []const Lane, parameters: []const Lane) ![]Lane {
        if (self.class.binding_version != .cyclic_eq_v2 or global_log < self.source.trace_log_size or gkr_point.len != self.class.layers() or self.source.trace_log_size != self.class.row_logs[@intFromEnum(self.artifact.component)]) return error.InvalidHybridMaskGeometry;
        const local = point.repeatedDouble(global_log - self.source.trace_log_size);
        const hybrid = P.gkrBound(self.artifact.component);
        const aux = if (hybrid) try B.auxFor(Lane, gkr_point[gkr_point.len - self.source.trace_log_size ..], local) else undefined;
        const inputs = try a.alloc(Lane, self.artifact.program.inputs.len);
        defer a.free(inputs);
        for (inputs, self.artifact.program.inputs) |*out, input| {
            if (self.isPublic(input)) {
                if (input.offset != 0) return error.InvalidHybridPublicMask;
                out.* = switch (input.column) {
                    16 => aux.first,
                    17 => aux.second,
                    18 => aux.carry,
                    19...25 => Lane.zero(),
                    else => return error.InvalidHybridPublicMask,
                };
                continue;
            }
            const t = input.tree;
            const global = if (t == 0) blk: {
                if (input.column >= self.source.preprocessed_indices.len) return error.InvalidHybridFixedMask;
                break :blk self.source.preprocessed_indices[input.column];
            } else if (t == 1) (try Outer.geometry.span(self.source.*, 1)).start + input.column else H.interactionStart(self.artifact.component) + input.column;
            if (t >= mask.items.len or global >= mask.items[t].len) return error.MissingHybridMask;
            const shifts = try self.offsets(a, t, input.column);
            defer a.free(shifts);
            const values = mask.items[t][global];
            if (values.len != shifts.len) return error.MissingHybridMask;
            var found = false;
            for (shifts, values) |shift, value| if (shift == input.offset) {
                out.* = value;
                found = true;
                break;
            };
            if (!found) return error.MissingHybridMask;
        }
        return self.artifact.evaluateFor(Lane, a, inputs, parameters);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc.PointEvaluationAccumulator, global_log: u32) !void {
        const values = try self.valuesAtPoint(self.allocator, point, mask, global_log);
        defer self.allocator.free(values);
        const local = point.repeatedDouble(global_log - self.source.trace_log_size);
        const inv = try core.constraints.cosetVanishing(O, Canonic.new(self.source.trace_log_size).coset(), local).inv();
        for (values) |value| acc.accumulate(value.mul(inv));
    }
};
