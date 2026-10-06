//! Static gate AIR for 64 distinct public shots with authenticated fixed inputs.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const input = @import("input.zig");
const batch = @import("batch_input.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;

pub const Component = struct {
    program: *const input.Program,
    statement: batch.Statement,

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
        return self.program.gates.len + self.program.final_columns.len;
    }

    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.statement.log_rows + 2;
    }

    pub fn compositionLogSplit(_: *const Self) u32 {
        return 2;
    }

    pub fn traceLogDegreeBounds(self: *const Self, allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        const fixed = try allocator.alloc(u32, self.program.final_columns.len * 2);
        errdefer allocator.free(fixed);
        const main = try allocator.alloc(u32, self.program.gates.len);
        errdefer allocator.free(main);
        @memset(fixed, self.statement.log_rows);
        @memset(main, self.statement.log_rows);
        return core.air.components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ fixed, main }),
        );
    }

    pub fn maskPoints(self: *const Self, allocator: std.mem.Allocator, point: CirclePointQM31, _: u32) !core.air.components.MaskPoints {
        const fixed = try pointColumns(allocator, self.program.final_columns.len * 2, point);
        errdefer freePointColumns(allocator, fixed);
        const main = try pointColumns(allocator, self.program.gates.len, point);
        errdefer freePointColumns(allocator, main);
        return core.air.components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ fixed, main }),
        );
    }

    pub fn preprocessedColumnIndices(self: *const Self, allocator: std.mem.Allocator) ![]usize {
        const indices = try allocator.alloc(usize, self.program.final_columns.len * 2);
        for (indices, 0..) |*value, index| value.* = index;
        return indices;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core.air.components.MaskValues,
        accumulator: *core.air.accumulation.PointEvaluationAccumulator,
        max_log_size: u32,
    ) !void {
        const qubits = self.program.final_columns.len;
        if (mask.items.len < 2 or mask.items[0].len != qubits * 2 or
            mask.items[1].len != self.program.gates.len or max_log_size < self.statement.log_rows)
            return error.InvalidProofShape;
        const allocator = std.heap.page_allocator;
        const fixed = try allocator.alloc(QM31, qubits * 2);
        defer allocator.free(fixed);
        const main = try allocator.alloc(QM31, self.program.gates.len);
        defer allocator.free(main);
        for (mask.items[0], fixed) |sample, *value| {
            if (sample.len != 1) return error.InvalidProofShape;
            value.* = sample[0];
        }
        for (mask.items[1], main) |sample, *value| {
            if (sample.len != 1) return error.InvalidProofShape;
            value.* = sample[0];
        }
        const constraints = try self.constraintsAt(QM31, allocator, fixed, main);
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
        const qubits = self.program.final_columns.len;
        if (trace.polys.items.len != 2 or trace.polys.items[0].len != qubits * 2 or
            trace.polys.items[1].len != self.program.gates.len) return error.InvalidProofShape;
        const allocator = accumulator.allocator;
        const eval_log = self.statement.log_rows + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const eval_size = domain.size();
        const total_sources = qubits * 2 + self.program.gates.len;
        const evaluations = try allocator.alloc([]const M31, total_sources);
        defer allocator.free(evaluations);
        const extensions = try allocator.alloc([]M31, total_sources);
        var initialized: usize = 0;
        defer {
            for (extensions[0..initialized]) |buffer| allocator.free(buffer);
            allocator.free(extensions);
        }
        var source_index: usize = 0;
        for (trace.polys.items) |tree| {
            for (tree) |poly| {
                try poly.validate();
                if (poly.log_size == eval_log) {
                    evaluations[source_index] = poly.values;
                } else {
                    const coeffs = poly.coefficients orelse return error.InvalidProofShape;
                    if (coeffs.logSize() != self.statement.log_rows) return error.InvalidProofShape;
                    const extended = try allocator.alloc(M31, eval_size);
                    @memcpy(extended[0..coeffs.coeffs.len], coeffs.coeffs);
                    @memset(extended[coeffs.coeffs.len..], M31.zero());
                    extensions[initialized] = extended;
                    initialized += 1;
                    evaluations[source_index] = extended;
                }
                source_index += 1;
            }
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
        const fixed_row = try allocator.alloc(M31, qubits * 2);
        defer allocator.free(fixed_row);
        const main_row = try allocator.alloc(M31, self.program.gates.len);
        defer allocator.free(main_row);
        const shift: std.math.Log2Int(usize) = @intCast(self.statement.log_rows);
        for (0..eval_size) |row| {
            for (fixed_row, 0..) |*value, index| value.* = evaluations[index][row];
            for (main_row, 0..) |*value, index| value.* = evaluations[qubits * 2 + index][row];
            const constraints = try self.constraintsAt(M31, allocator, fixed_row, main_row);
            defer allocator.free(constraints);
            var folded = QM31.zero();
            for (constraints, 0..) |constraint, index| {
                folded = folded.add(column.random_coeff_powers[constraints.len - 1 - index].mulM31(constraint));
            }
            column.accumulate(row, folded.mulM31(inverse[row >> shift]));
        }
    }

    pub fn constraintsAt(self: *const Self, comptime F: type, allocator: std.mem.Allocator, fixed: []const F, main: []const F) ![]F {
        const out = try allocator.alloc(F, self.nConstraints());
        const qubits = self.program.final_columns.len;
        const two: F = if (F == M31) M31.fromCanonical(2) else QM31.fromBase(M31.fromCanonical(2));
        for (self.program.gates, 0..) |gate, index| {
            const before = source(F, fixed, main, qubits, gate.target_before);
            const c1 = source(F, fixed, main, qubits, gate.control1);
            const toggle = if (gate.kind == .ccx) c1.mul(source(F, fixed, main, qubits, gate.control2)) else c1;
            const expected = before.add(toggle).sub(two.mul(before).mul(toggle));
            out[index] = main[index].sub(expected);
        }
        for (self.program.final_columns, 0..) |column, qubit| {
            out[self.program.gates.len + qubit] = source(F, fixed, main, qubits, column).sub(fixed[qubits + qubit]);
        }
        return out;
    }
};

fn source(comptime F: type, fixed: []const F, main: []const F, qubits: usize, column: usize) F {
    return if (column < qubits) fixed[column] else main[column - qubits];
}

fn pointColumns(allocator: std.mem.Allocator, count: usize, point: CirclePointQM31) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return columns;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
