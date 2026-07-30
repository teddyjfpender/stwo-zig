//! Exact two-column Plonk LogUp interaction trace from pinned upstream Stwo.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");
const input = @import("input.zig");

pub const LookupElements = struct {
    z: [4]M31,
    alpha: [4]M31,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !LookupElements {
        const draws = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(draws);
        return .{
            .z = stableCoordinates(&draws[0]),
            .alpha = stableCoordinates(&draws[1]),
        };
    }

    pub fn combineBase(self: *const LookupElements, a: M31, b: M31) QM31 {
        return QM31.fromBase(a)
            .add(QM31.fromM31Array(self.alpha).mulM31(b))
            .sub(QM31.fromM31Array(self.z));
    }

    pub fn combineSecure(self: *const LookupElements, a: QM31, b: QM31) QM31 {
        return a.add(QM31.fromM31Array(self.alpha).mul(b))
            .sub(QM31.fromM31Array(self.z));
    }
};

noinline fn stableCoordinates(value: *const QM31) [4]M31 {
    return .{ value.c0.a, value.c0.b, value.c1.a, value.c1.b };
}

pub const PreparedInteraction = struct {
    columns: prover_transaction.OwnedColumns,
    lookup_elements: LookupElements,
    claimed_sum: [4]M31,

    pub fn claimedSum(self: *const PreparedInteraction) QM31 {
        return QM31.fromM31Array(self.claimed_sum);
    }

    pub fn deinit(self: *PreparedInteraction, allocator: std.mem.Allocator) void {
        self.columns.deinit(allocator);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    channel: anytype,
    prepared: *const input.PreparedInput,
) !PreparedInteraction {
    const lookup = try LookupElements.draw(allocator, channel);
    const circuit = prepared.circuit;
    const n = circuit.mult.len;
    if (n == 0 or
        circuit.a_wire.len != n or circuit.b_wire.len != n or
        circuit.c_wire.len != n or circuit.op.len != n or
        circuit.a_val.len != n or circuit.b_val.len != n or
        circuit.c_val.len != n)
    {
        return error.InvalidPreparedGeometry;
    }

    const first = try allocator.alloc(QM31, n);
    defer allocator.free(first);
    const combined = try allocator.alloc(QM31, n);
    defer allocator.free(combined);

    var claimed_sum = QM31.zero();
    for (0..n) |row| {
        const q0 = lookup.combineBase(circuit.a_wire[row], circuit.a_val[row]);
        const q1 = lookup.combineBase(circuit.b_wire[row], circuit.b_val[row]);
        const q2 = lookup.combineBase(circuit.c_wire[row], circuit.c_val[row]);
        const first_value = try q0.add(q1).div(q0.mul(q1));
        const second_value = try QM31.fromBase(circuit.mult[row]).neg().div(q2);
        first[row] = first_value;
        combined[row] = first_value.add(second_value);
        claimed_sum = claimed_sum.add(combined[row]);
    }

    const n_field = M31.fromU64(n);
    const shift = try claimed_sum.divM31(n_field);
    for (combined) |*value| value.* = value.sub(shift);
    try inclusivePrefixSum(allocator, combined);

    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, 8);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (0..4) |coordinate| {
        columns[coordinate] = .{
            .log_size = prepared.request.log_n_rows,
            .values = try coordinateColumn(allocator, first, coordinate),
        };
        initialized += 1;
    }
    for (0..4) |coordinate| {
        columns[4 + coordinate] = .{
            .log_size = prepared.request.log_n_rows,
            .values = try coordinateColumn(allocator, combined, coordinate),
        };
        initialized += 1;
    }

    return .{
        .columns = prover_transaction.OwnedColumns.init(columns),
        .lookup_elements = lookup,
        .claimed_sum = claimed_sum.toM31Array(),
    };
}

/// Matches upstream's prefix sum: storage is bit-reversed circle-domain
/// order, while accumulation follows the underlying canonic coset.
fn inclusivePrefixSum(allocator: std.mem.Allocator, values: []QM31) !void {
    utils.bitReverse(QM31, values);
    const coset = try utils.circleDomainOrderToCosetOrder(QM31, allocator, values);
    defer allocator.free(coset);

    var sum = QM31.zero();
    for (coset) |*value| {
        sum = sum.add(value.*);
        value.* = sum;
    }

    const circle = try utils.cosetOrderToCircleDomainOrder(QM31, allocator, coset);
    defer allocator.free(circle);
    utils.bitReverse(QM31, circle);
    @memcpy(values, circle);
}

fn coordinateColumn(
    allocator: std.mem.Allocator,
    values: []const QM31,
    coordinate: usize,
) ![]M31 {
    const column = try allocator.alloc(M31, values.len);
    for (values, column) |*value, *out| out.* = stableCoordinate(value, coordinate);
    return column;
}

noinline fn stableCoordinate(value: *const QM31, coordinate: usize) M31 {
    return switch (coordinate) {
        0 => value.c0.a,
        1 => value.c0.b,
        2 => value.c1.a,
        3 => value.c1.b,
        else => unreachable,
    };
}

fn validateCumulative(
    allocator: std.mem.Allocator,
    first_storage: []const QM31,
    cumulative_storage: []const QM31,
    claimed_sum: QM31,
    circuit: input.CircuitView,
    lookup: *const LookupElements,
) !void {
    const n = first_storage.len;
    for (0..n) |row| {
        const q0 = lookup.combineBase(circuit.a_wire[row], circuit.a_val[row]);
        const q1 = lookup.combineBase(circuit.b_wire[row], circuit.b_val[row]);
        const first_constraint = first_storage[row].mul(q0).mul(q1).sub(q0.add(q1));
        if (!first_constraint.isZero()) return error.InvalidFirstInteractionTrace;
    }
    const first_circle = try allocator.dupe(QM31, first_storage);
    defer allocator.free(first_circle);
    const cumulative_circle = try allocator.dupe(QM31, cumulative_storage);
    defer allocator.free(cumulative_circle);
    utils.bitReverse(QM31, first_circle);
    utils.bitReverse(QM31, cumulative_circle);
    const first_coset = try utils.circleDomainOrderToCosetOrder(QM31, allocator, first_circle);
    defer allocator.free(first_coset);
    const cumulative_coset = try utils.circleDomainOrderToCosetOrder(
        QM31,
        allocator,
        cumulative_circle,
    );
    defer allocator.free(cumulative_coset);

    const shift = try claimed_sum.divM31(M31.fromU64(n));
    for (0..n) |coset_row| {
        const circle_row = utils.cosetIndexToCircleDomainIndex(
            coset_row,
            @intCast(std.math.log2_int(usize, n)),
        );
        const storage_row = utils.bitReverseIndex(
            circle_row,
            @intCast(std.math.log2_int(usize, n)),
        );
        const q2 = lookup.combineBase(circuit.c_wire[storage_row], circuit.c_val[storage_row]);
        const q0 = lookup.combineBase(circuit.a_wire[storage_row], circuit.a_val[storage_row]);
        const q1 = lookup.combineBase(circuit.b_wire[storage_row], circuit.b_val[storage_row]);
        const first_constraint = first_coset[coset_row].mul(q0).mul(q1).sub(q0.add(q1));
        if (!first_constraint.isZero()) return error.InvalidFirstInteractionTrace;
        const previous = cumulative_coset[(coset_row + n - 1) % n];
        const constraint = cumulative_coset[coset_row].sub(previous)
            .sub(first_coset[coset_row]).add(shift).mul(q2)
            .addM31(circuit.mult[storage_row]);
        if (!constraint.isZero()) return error.InvalidInteractionTrace;
    }
}

test "exact Plonk interaction has two secure columns and shifted last sum" {
    const allocator = std.testing.allocator;
    var prepared = try input.prepare(allocator, .{ .log_n_rows = 4 });
    defer prepared.deinit(allocator);
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Channel{};
    var generated = try generate(allocator, &channel, &prepared);
    defer generated.deinit(allocator);

    const columns = generated.columns.columns.?;
    try std.testing.expectEqual(@as(usize, 8), columns.len);
    const n = @as(usize, 1) << @intCast(prepared.request.log_n_rows);
    const first = try allocator.alloc(QM31, n);
    defer allocator.free(first);
    const combined = try allocator.alloc(QM31, n);
    defer allocator.free(combined);
    for (0..n) |row| {
        first[row] = QM31.fromM31(
            columns[0].values[row],
            columns[1].values[row],
            columns[2].values[row],
            columns[3].values[row],
        );
        combined[row] = QM31.fromM31(
            columns[4].values[row],
            columns[5].values[row],
            columns[6].values[row],
            columns[7].values[row],
        );
    }
    try validateCumulative(
        allocator,
        first,
        combined,
        generated.claimedSum(),
        prepared.circuit,
        &generated.lookup_elements,
    );
}
