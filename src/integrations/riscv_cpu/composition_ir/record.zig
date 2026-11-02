//! Composition IR export for RV64 Word16 components: record a component's own
//! `emitFor` over the symbolic lane, then evaluate the exported DAG with a
//! reference interpreter on the component's evaluation domain.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
pub const E = A.evaluation;
pub const ir = engine.air.secure_polynomial_program_v2;
pub const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
pub const Q = core.fields.qm31.QM31;
pub const M = core.fields.m31.M31;
pub const Program = ir.ProgramFor(Q);
pub const Lane = E.symbolic.SymbolicLane(Q);
pub const Sink = E.SinkFor(Lane);

/// Shape metadata the exporter takes from the component it recorded.
pub const Shape = struct {
    log_size: u32,
    eval_log: u32,
    widths: [3]usize,
    offsets: [3]usize,
    constraints: usize,
    /// Declared per-constraint degree bound, when the component publishes one.
    declared_degree: ?u8 = null,
};

pub const Exported = struct {
    program: Program,
    shape: Shape,
    /// Lane operations the evaluator requested before folding and interning.
    requested_ops: usize,
    pub fn deinit(self: *Exported) void {
        self.program.deinit();
    }
};

pub fn authority(name: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &out, .{});
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/rv64/composition-ir/v1\x00");
    h.update(&out);
    return h.finalResult();
}

/// Records `emit(context, sink)` (which must emit exactly `shape.constraints`
/// residuals in native order) into a validated program.
pub fn record(a: std.mem.Allocator, name: []const u8, shape: Shape, context: anytype, comptime emit: fn (@TypeOf(context), *Sink) anyerror!void) !Exported {
    var recording = E.symbolic.Recording(Q).init(a);
    defer recording.deinit();
    recording.begin();
    defer recording.end();
    const values = try a.alloc(Lane, shape.constraints);
    defer a.free(values);
    var sink = Sink{ .values = values };
    try emit(context, &sink);
    if (sink.count != shape.constraints) return error.CompositionIrConstraintCount;
    const roots = try a.alloc(u32, values.len);
    defer a.free(roots);
    for (values, roots) |v, *r| r.* = v.id;
    const requested = recording.builder.requested;
    const program = try recording.builder.finish(authority(name), roots);
    return .{ .program = program, .shape = shape, .requested_ops = requested };
}

/// Mask inputs for one tree: `current[c]` reads offset 0; `previous[c]` reads
/// offset -1 when `needs(c)` holds and is the lane zero otherwise (the native
/// domain kernels leave such slots zero as well).
pub const Masks = struct {
    current: []Lane,
    previous: []Lane,
    pub fn init(a: std.mem.Allocator, tree: u8, width: usize, context: anytype, comptime needs: fn (@TypeOf(context), usize) bool) !Masks {
        const current = try a.alloc(Lane, width);
        errdefer a.free(current);
        const previous = try a.alloc(Lane, width);
        for (current, previous, 0..) |*c, *p, column| {
            c.* = Lane.input(tree, column, 0);
            p.* = if (needs(context, column)) Lane.input(tree, column, -1) else Lane.zero();
        }
        return .{ .current = current, .previous = previous };
    }
    pub fn deinit(self: Masks, a: std.mem.Allocator) void {
        a.free(self.current);
        a.free(self.previous);
    }
};
pub fn never(_: void, _: usize) bool {
    return false;
}

/// Reference domain interpreter: every row of the exported DAG over committed
/// bit-reversed evaluation-domain columns, folded with reversed random powers
/// and divided by the trace-coset vanishing polynomial, exactly the quotient
/// contribution the prover accumulates for this component.
pub fn evaluateDomain(a: std.mem.Allocator, program: *const Program, shape: Shape, columns: [3][]const []const M, powers: []const Q, out: []Q) !void {
    try program.validate();
    const n = @as(usize, 1) << @intCast(shape.eval_log);
    if (out.len != n or powers.len != program.roots.len) return error.InvalidCompositionIrDomain;
    for (program.inputs) |input| {
        if (input.column >= columns[input.tree].len) return error.InvalidCompositionIrDomain;
        if (columns[input.tree][input.column].len != n) return error.InvalidCompositionIrDomain;
    }
    const inverses = try A.geometry.denominatorInverses(a, shape.log_size, shape.eval_log);
    defer a.free(inverses);
    const values = try a.alloc(Q, program.nodes.len);
    defer a.free(values);
    const inputs = try a.alloc(Q, program.inputs.len);
    defer a.free(inputs);
    const residuals = try a.alloc(Q, program.roots.len);
    defer a.free(residuals);
    for (0..n) |row| {
        for (program.inputs, inputs) |input, *v| v.* = Q.fromBase(rowInput(input, shape, columns, row));
        program.evaluateRow(values, inputs, residuals);
        var folded = Q.zero();
        for (residuals, 0..) |r, j| folded = folded.add(powers[powers.len - 1 - j].mul(r));
        out[row] = folded.mulM31(inverses[row >> @intCast(shape.log_size)]);
    }
}

/// The committed value an IR input reads at evaluation-domain row `row`.
pub fn rowInput(input: ir.Input, shape: Shape, columns: [3][]const []const M, row: usize) M {
    const index = if (input.offset == 0) row else core.utils.offsetBitReversedCircleDomainIndex(row, shape.log_size, shape.eval_log, input.offset);
    return columns[input.tree][input.column][index];
}

/// Random committed-domain columns for one component at offsets zero. By
/// default every column is a random trace polynomial (2^log coefficients)
/// evaluated on the bit-reversed evaluation domain, and the poly carries both
/// views (coset evaluators read coefficients, row kernels read values).
pub const RandomTrace = struct {
    data: [3][][]M,
    coefficients: [3][][]M,
    polys: [3][]cp.Poly,
    pub fn init(a: std.mem.Allocator, rng: std.Random, shape: Shape, fill: ?*const fn (tree: usize, column: usize, row: usize, rng: std.Random) M) !RandomTrace {
        var self: RandomTrace = .{ .data = undefined, .coefficients = undefined, .polys = undefined };
        const n = @as(usize, 1) << @intCast(shape.eval_log);
        const domain = core.poly.circle.canonic.CanonicCoset.new(shape.eval_log).circleDomain();
        var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &tw);
        const tree_view = engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles);
        for (0..3) |tree| {
            const width = shape.offsets[tree] + shape.widths[tree];
            self.data[tree] = try a.alloc([]M, width);
            self.coefficients[tree] = try a.alloc([]M, width);
            self.polys[tree] = try a.alloc(cp.Poly, width);
            for (self.data[tree], self.coefficients[tree], self.polys[tree], 0..) |*column, *coeffs, *poly, c| {
                if (fill) |f| {
                    coeffs.* = &.{};
                    column.* = try a.alloc(M, n);
                    for (column.*, 0..) |*v, row| v.* = f(tree, c, row, rng);
                    poly.* = .{ .log_size = shape.eval_log, .values = column.* };
                    continue;
                }
                coeffs.* = try a.alloc(M, @as(usize, 1) << @intCast(shape.log_size));
                for (coeffs.*) |*v| v.* = M.fromCanonical(rng.uintLessThan(u32, core.fields.m31.Modulus));
                const circle = try engine.poly.circle.CircleCoefficients.initBorrowed(coeffs.*);
                const evaluation = try circle.evaluateWithTwiddles(a, domain, tree_view);
                column.* = @constCast(evaluation.values);
                poly.* = .{ .log_size = shape.eval_log, .values = column.*, .coefficients = circle };
            }
        }
        return self;
    }
    pub fn deinit(self: *RandomTrace, a: std.mem.Allocator) void {
        for (self.data, self.coefficients, self.polys) |tree, coefficients, polys| {
            for (tree) |column| a.free(column);
            for (coefficients) |column| a.free(column);
            a.free(tree);
            a.free(coefficients);
            a.free(polys);
        }
    }
    /// Component-local column views (offsets removed).
    pub fn local(self: *const RandomTrace, shape: Shape) [3][]const []const M {
        var out: [3][]const []const M = undefined;
        for (0..3) |t| out[t] = @ptrCast(self.data[t][shape.offsets[t]..][0..shape.widths[t]]);
        return out;
    }
};

pub const Parity = struct { rows: usize, nonzero_rows: usize };

/// Bit-exact parity: the component's real prover domain evaluator (vtable,
/// packed/native kernels, vanishing division) against the IR interpreter.
pub fn checkDomain(a: std.mem.Allocator, exported: *const Exported, prover: cp.ComponentProver, trace: *const RandomTrace, alpha: Q) !Parity {
    const shape = exported.shape;
    var polys: [3][]const cp.Poly = undefined;
    for (0..3) |t| polys[t] = trace.polys[t];
    const view = cp.Trace{ .polys = core.pcs.TreeVec([]const cp.Poly).initOwned(&polys) };
    var acc = try accumulation.DomainEvaluationAccumulator.init(a, alpha, shape.eval_log, shape.constraints);
    defer acc.deinit();
    const powers = try a.dupe(Q, acc.random_coeff_powers);
    defer a.free(powers);
    try prover.vtable.evaluateConstraintQuotientsOnDomain(prover.ctx, &view, &acc);
    var native = try acc.finalize();
    defer native.deinit(a);
    const n = @as(usize, 1) << @intCast(shape.eval_log);
    if (native.len() != n) return error.CompositionIrParityShape;
    const got = try a.alloc(Q, n);
    defer a.free(got);
    try evaluateDomain(a, &exported.program, shape, trace.local(shape), powers, got);
    var nonzero: usize = 0;
    for (got, 0..) |g, row| {
        const expected = native.at(row);
        if (!expected.eql(g)) {
            std.debug.print("composition IR parity mismatch at row {d}/{d}\n", .{ row, n });
            return error.CompositionIrParityMismatch;
        }
        nonzero += @intFromBool(!g.isZero());
    }
    return .{ .rows = n, .nonzero_rows = nonzero };
}

pub fn randomQ(rng: std.Random) Q {
    const p = core.fields.m31.Modulus;
    return Q.fromU32Unchecked(rng.uintLessThan(u32, p), rng.uintLessThan(u32, p), rng.uintLessThan(u32, p), rng.uintLessThan(u32, p));
}
/// Replaces every QM31 leaf of a challenge/claim structure by a fresh draw.
pub fn randomize(value: anytype, rng: std.Random) void {
    const T = @TypeOf(value.*);
    if (T == Q) {
        value.* = randomQ(rng);
        return;
    }
    switch (@typeInfo(T)) {
        .@"struct" => |s| inline for (s.fields) |field| randomize(&@field(value.*, field.name), rng),
        .array => for (value) |*item| randomize(item, rng),
        .optional => if (value.*) |*inner| randomize(inner, rng),
        else => {},
    }
}
