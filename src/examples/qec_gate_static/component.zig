//! AIR for a fixed CX/CCX wiring. Every gate output has a distinct column.
//! Inputs and terminal qubits are pinned to the public statement.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const input = @import("input.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;

pub const Component = struct {
    program: *const input.Program,
    statement: input.Statement,

    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(
        Self,
        prover.air.component_prover.ComponentProver,
        prover.air.component_prover.Trace,
        prover.air.accumulation.DomainEvaluationAccumulator,
    );

    pub fn asProverComponent(self: *const Self) prover.air.component_prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(self: *const Self) usize {
        const n = self.program.final_columns.len;
        return n * 2 + self.program.gates.len;
    }

    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.statement.log_rows + 2;
    }

    pub fn compositionLogSplit(_: *const Self) u32 {
        return 2;
    }

    pub fn traceLogDegreeBounds(self: *const Self, allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, self.program.columnCount());
        errdefer allocator.free(main);
        @memset(main, self.statement.log_rows);
        return core.air.components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main }),
        );
    }

    pub fn maskPoints(self: *const Self, allocator: std.mem.Allocator, point: CirclePointQM31, _: u32) !core.air.components.MaskPoints {
        const preprocessed = try allocator.alloc([]CirclePointQM31, 0);
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc([]CirclePointQM31, self.program.columnCount());
        var initialized: usize = 0;
        errdefer {
            for (main[0..initialized]) |col| allocator.free(col);
            allocator.free(main);
        }
        for (main) |*col| {
            col.* = try allocator.dupe(CirclePointQM31, &.{point});
            initialized += 1;
        }
        return core.air.components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main }),
        );
    }

    pub fn preprocessedColumnIndices(_: *const Self, allocator: std.mem.Allocator) ![]usize {
        return allocator.alloc(usize, 0);
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core.air.components.MaskValues,
        accumulator: *core.air.accumulation.PointEvaluationAccumulator,
        max_log_size: u32,
    ) !void {
        if (mask.items.len < 2 or mask.items[1].len != self.program.columnCount() or
            max_log_size < self.statement.log_rows) return error.InvalidProofShape;
        const allocator = std.heap.page_allocator;
        const values = try allocator.alloc(QM31, self.program.columnCount());
        defer allocator.free(values);
        for (mask.items[1], values) |sample, *value| {
            if (sample.len != 1) return error.InvalidProofShape;
            value.* = sample[0];
        }
        const constraints = try self.constraintsAt(QM31, allocator, values);
        defer allocator.free(constraints);
        const denominator = try core.constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.statement.log_rows).coset(),
            point.repeatedDouble(max_log_size - self.statement.log_rows),
        ).inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(denominator));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover.air.component_prover.Trace,
        accumulator: *prover.air.accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len != 2 or trace.polys.items[0].len != 0 or
            trace.polys.items[1].len != self.program.columnCount()) return error.InvalidProofShape;
        const allocator = accumulator.allocator;
        const eval_log = self.statement.log_rows + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const eval_size = domain.size();
        const evaluations = try allocator.alloc([]const M31, self.program.columnCount());
        defer allocator.free(evaluations);
        const extensions = try allocator.alloc([]M31, self.program.columnCount());
        var initialized: usize = 0;
        defer {
            for (extensions[0..initialized]) |buffer| allocator.free(buffer);
            allocator.free(extensions);
        }
        for (trace.polys.items[1], evaluations) |poly, *out| {
            try poly.validate();
            if (poly.log_size == eval_log) {
                out.* = poly.values;
                continue;
            }
            const coeffs = poly.coefficients orelse return error.InvalidProofShape;
            if (coeffs.logSize() != self.statement.log_rows) return error.InvalidProofShape;
            const extended = try allocator.alloc(M31, eval_size);
            @memcpy(extended[0..coeffs.coeffs.len], coeffs.coeffs);
            @memset(extended[coeffs.coeffs.len..], M31.zero());
            extensions[initialized] = extended;
            initialized += 1;
            out.* = extended;
        }
        if (initialized != 0) {
            var twiddles = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
            defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
            const view = prover.poly.twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            );
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(extensions[0..initialized], domain, view);
        }
        const coset = canonic.CanonicCoset.new(self.statement.log_rows).coset();
        var inverse: [4]M31 = undefined;
        for (&inverse, 0..) |*value, index| {
            value.* = try core.constraints.cosetVanishing(
                M31,
                coset,
                domain.at(core.utils.bitReverseIndex(index, 2)),
            ).inv();
        }
        var output = try accumulator.columns(allocator, &.{.{
            .log_size = eval_log,
            .n_cols = self.nConstraints(),
        }});
        defer allocator.free(output);
        const column = &output[0];
        const row_values = try allocator.alloc(M31, self.program.columnCount());
        defer allocator.free(row_values);
        const shift: std.math.Log2Int(usize) = @intCast(self.statement.log_rows);
        for (0..eval_size) |row| {
            for (evaluations, row_values) |source, *value| value.* = source[row];
            const constraints = try self.constraintsAt(M31, allocator, row_values);
            defer allocator.free(constraints);
            var folded = QM31.zero();
            for (constraints, 0..) |constraint, index| {
                folded = folded.add(column.random_coeff_powers[constraints.len - 1 - index].mulM31(constraint));
            }
            column.accumulate(row, folded.mulM31(inverse[row >> shift]));
        }
    }

    fn constraintsAt(self: *const Self, comptime F: type, allocator: std.mem.Allocator, values: []const F) ![]F {
        const out = try allocator.alloc(F, self.nConstraints());
        var index: usize = 0;
        for (0..self.program.final_columns.len) |qubit| {
            out[index] = values[qubit].sub(fieldBit(F, input.pin(self.statement, qubit, false)));
            index += 1;
        }
        const two = fieldBit(F, M31.fromCanonical(2));
        for (self.program.gates) |gate| {
            const before = values[gate.target_before];
            const toggle = if (gate.kind == .ccx)
                values[gate.control1].mul(values[gate.control2])
            else
                values[gate.control1];
            const expected = before.add(toggle).sub(two.mul(before).mul(toggle));
            out[index] = values[gate.output].sub(expected);
            index += 1;
        }
        for (self.program.final_columns, 0..) |column, qubit| {
            out[index] = values[column].sub(fieldBit(F, input.pin(self.statement, qubit, true)));
            index += 1;
        }
        std.debug.assert(index == out.len);
        return out;
    }
};

fn fieldBit(comptime F: type, value: M31) F {
    return if (F == M31) value else QM31.fromBase(value);
}

test "CX and CCX constraints reject a changed gate output" {
    const text = "APPEND_TO_REGISTER q0 r0\nREGISTER r0\nAPPEND_TO_REGISTER q1 r1\nREGISTER r1\nCX q1 q0\n";
    var program = try input.parse(std.testing.allocator, text);
    defer program.deinit();
    const statement = input.statement(&program, .{ .target = 1, .offset = 1 });
    const columns = try input.generate(std.testing.allocator, &program, statement);
    defer {
        for (columns) |column| std.testing.allocator.free(column.values);
        std.testing.allocator.free(columns);
    }
    const values = try std.testing.allocator.alloc(M31, columns.len);
    defer std.testing.allocator.free(values);
    for (columns, values) |column, *value| value.* = column.values[0];
    const component = Component{ .program = &program, .statement = statement };
    const valid = try component.constraintsAt(M31, std.testing.allocator, values);
    defer std.testing.allocator.free(valid);
    for (valid) |v| try std.testing.expect(v.isZero());
    values[program.gates[0].output] = M31.one();
    const changed = try component.constraintsAt(M31, std.testing.allocator, values);
    defer std.testing.allocator.free(changed);
    try std.testing.expect(!changed[program.final_columns.len].isZero());
}
