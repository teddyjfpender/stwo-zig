//! Concrete native-PCS OM31 component derived from the original circuit AIR.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const C = @import("stwo_cairo_frontend").witness;
const P = @import("protocol.zig");
const E = @import("program.zig");
const G = @import("geometry.zig");
const O = P.O;
const M = P.M;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O);
const ProverAir = prover.air.component_prover.ForField(O);
const Domain = prover.air.accumulation.ForField(O);
const Canonic = core.poly.circle.canonic.CanonicCoset;
pub const Component = struct {
    allocator: std.mem.Allocator,
    captured: *const C.composition_bundle.Component,
    preprocessed_logs: []const u32,
    z: O,
    alpha: O,
    claim: O,
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), ProverAir.ComponentProver, ProverAir.Trace, Domain.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) ProverAir.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Component) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Component) usize {
        return self.captured.n_constraints;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.captured.evaluation_log_size;
    }
    pub fn validate(self: *const Component) !void {
        if (self.captured.trace_log_size < 4 or self.captured.evaluation_log_size != self.captured.trace_log_size + 1) return error.UnsupportedOm31CircuitDegree;
        _ = try G.span(self.captured.*, 1);
        _ = try G.span(self.captured.*, 2);
        for (self.captured.parts) |part| try E.validateLens(self.allocator, part.program);
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        const fixed = try a.alloc(u32, self.captured.preprocessed_indices.len);
        errdefer a.free(fixed);
        for (fixed, self.captured.preprocessed_indices) |*v, index| {
            if (index >= self.preprocessed_logs.len) return error.InvalidOm31FixedIndex;
            v.* = self.preprocessed_logs[index];
        }
        const ms = try G.span(self.captured.*, 1);
        const is = try G.span(self.captured.*, 2);
        const main = try a.alloc(u32, ms.end - ms.start);
        errdefer a.free(main);
        @memset(main, self.captured.trace_log_size);
        const inter = try a.alloc(u32, is.end - is.start);
        errdefer a.free(inter);
        @memset(inter, self.captured.trace_log_size);
        return Air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, inter }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.captured.preprocessed_indices.len);
        for (out, self.captured.preprocessed_indices) |*v, index| v.* = index;
        return out;
    }
    fn points(a: std.mem.Allocator, offsets: []const std.ArrayList(i32), p: Point, step: Point) ![][]Point {
        const out = try a.alloc([]Point, offsets.len);
        errdefer a.free(out);
        var made: usize = 0;
        errdefer for (out[0..made]) |column| a.free(column);
        for (out, offsets) |*column, list| {
            column.* = try a.alloc(Point, list.items.len);
            made += 1;
            for (column.*, list.items) |*v, offset| v.* = p.add(step.mulSigned(offset));
        }
        return out;
    }
    fn freePoints(a: std.mem.Allocator, tree: [][]Point) void {
        for (tree) |column| a.free(column);
        a.free(tree);
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, p: Point, global_log: u32) !Air.MaskPoints {
        if (global_log < self.captured.trace_log_size) return error.InvalidOm31MaskGeometry;
        const raw = Canonic.new(global_log).coset().step;
        const step = Point{ .x = O.fromBase(raw.x), .y = O.fromBase(raw.y) };
        const fixed = try a.alloc([]Point, self.captured.preprocessed_indices.len);
        errdefer a.free(fixed);
        for (fixed) |*v| v.* = &.{};
        const mo = try G.offsets(a, self.captured.*, 1);
        defer G.freeOffsets(a, mo);
        const io = try G.offsets(a, self.captured.*, 2);
        defer G.freeOffsets(a, io);
        const main = try points(a, mo, p, step);
        errdefer freePoints(a, main);
        const inter = try points(a, io, p, step);
        errdefer freePoints(a, inter);
        return Air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, inter }));
    }
    pub fn extensionParameters(self: *const Component) ![]O {
        return E.parameters(self.allocator, self.captured, self.z, self.alpha, self.claim);
    }
    const PointRead = struct {
        component: *const Component,
        mask: *const Air.MaskValues,
        main_offsets: []const std.ArrayList(i32),
        inter_offsets: []const std.ArrayList(i32),
        fn get(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !O {
            const self: *const PointRead = @ptrCast(@alignCast(raw));
            if (tree >= self.mask.items.len) return error.MissingOm31Mask;
            if (tree == 0) {
                if (offset != 0 or column >= self.component.captured.preprocessed_indices.len) return error.MissingOm31Mask;
                const global = self.component.captured.preprocessed_indices[column];
                if (global >= self.mask.items[0].len or self.mask.items[0][global].len != 1) return error.MissingOm31Mask;
                return self.mask.items[0][global][0];
            }
            const span = try G.span(self.component.captured.*, tree);
            const offsets = if (tree == 1) self.main_offsets else self.inter_offsets;
            if (column >= offsets.len or span.start + column >= self.mask.items[tree].len) return error.MissingOm31Mask;
            const values = self.mask.items[tree][span.start + column];
            if (values.len != offsets[column].items.len) return error.MissingOm31Mask;
            const at = C.resident_geometry.offsetIndex(offsets[column].items, offset) orelse return error.MissingOm31Mask;
            return values[at];
        }
    };
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const Air.MaskValues, acc: *Acc.PointEvaluationAccumulator, global_log: u32) !void {
        if (global_log < self.captured.trace_log_size) return error.InvalidOm31MaskGeometry;
        const parameters = try self.extensionParameters();
        defer self.allocator.free(parameters);
        const mo = try G.offsets(self.allocator, self.captured.*, 1);
        defer G.freeOffsets(self.allocator, mo);
        const io = try G.offsets(self.allocator, self.captured.*, 2);
        defer G.freeOffsets(self.allocator, io);
        const read = PointRead{ .component = self, .mask = mask, .main_offsets = mo, .inter_offsets = io };
        const local = point.repeatedDouble(global_log - self.captured.trace_log_size);
        const inv = try core.constraints.cosetVanishing(O, Canonic.new(self.captured.trace_log_size).coset(), local).inv();
        for (self.captured.parts) |part| {
            const roots = try E.evaluate(self.allocator, part.program, .{ .context = &read, .get = PointRead.get }, parameters);
            defer self.allocator.free(roots);
            for (roots) |value| acc.accumulate(value.mul(inv));
        }
    }
    const DomainRead = struct {
        component: *const Component,
        trace: *const ProverAir.Trace,
        row: usize,
        fn get(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !O {
            const self: *const DomainRead = @ptrCast(@alignCast(raw));
            if (tree >= self.trace.polys.items.len) return error.MissingOm31Trace;
            const global = if (tree == 0) blk: {
                if (column >= self.component.captured.preprocessed_indices.len) return error.MissingOm31Trace;
                break :blk self.component.captured.preprocessed_indices[column];
            } else (try G.span(self.component.captured.*, tree)).start + column;
            if (global >= self.trace.polys.items[tree].len) return error.MissingOm31Trace;
            const poly = self.trace.polys.items[tree][global];
            // The initial native beta1 proof retains its exact2n LDE; no
            // hidden scalar re-expansion or fabricated host device columns.
            if (poly.device != null or poly.values.len == 0) return error.Om31CircuitRequiresHostLde;
            const index = core.utils.offsetBitReversedCircleDomainIndex(self.row, self.component.captured.trace_log_size, self.component.captured.evaluation_log_size, offset);
            return O.fromBase(try poly.valueAtLiftingPosition(self.component.captured.evaluation_log_size, index));
        }
    };
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const ProverAir.Trace, acc: *Domain.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        const requests = [_]Domain.ColumnRequest{.{ .log_size = self.captured.evaluation_log_size, .n_cols = self.captured.n_constraints }};
        const columns = try acc.columns(a, &requests);
        defer a.free(columns);
        const column = &columns[0];
        const params = try self.extensionParameters();
        defer self.allocator.free(params);
        const scratch = try a.alloc(E.Scratch, self.captured.parts.len);
        defer a.free(scratch);
        var made: usize = 0;
        defer for (scratch[0..made]) |*item| item.deinit();
        var max_roots: usize = 0;
        for (scratch, self.captured.parts) |*item, part| {
            item.* = try E.Scratch.init(a, part.program);
            made += 1;
            max_roots = @max(max_roots, part.program.constraint_roots.len);
        }
        const roots = try a.alloc(O, max_roots);
        defer a.free(roots);
        const n = @as(usize, 1) << @intCast(self.captured.evaluation_log_size);
        var read = DomainRead{ .component = self, .trace = trace, .row = 0 };
        for (0..n) |r| {
            read.row = r;
            var value = O.zero();
            for (scratch, self.captured.parts) |*item, part| {
                const values = roots[0..part.program.constraint_roots.len];
                try item.evaluateInto(part.program, .{ .context = &read, .get = DomainRead.get }, params, values);
                for (values, 0..) |root, i| value = value.add(root.mul(column.random_coeff_powers[self.captured.n_constraints - 1 - part.rc_base - i]));
            }
            const inv = M.fromCanonical(self.captured.denominator_inverses[r >> @intCast(self.captured.trace_log_size)]);
            column.accumulate(r, value.mulM31(inv));
        }
    }
};
