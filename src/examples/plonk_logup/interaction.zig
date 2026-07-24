//! Exact two-column Plonk LogUp interaction trace from pinned upstream Stwo.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("stwo_prover_impl").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");
const input = @import("input.zig");

pub const LookupElements = struct {
    z: QM31,
    alpha: QM31,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !LookupElements {
        const values = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(values);
        return .{ .z = values[0], .alpha = values[1] };
    }

    pub fn combine(self: LookupElements, a: M31, b: M31) QM31 {
        return QM31.fromBase(a).add(self.alpha.mulM31(b)).sub(self.z);
    }
};

pub const PreparedInteraction = struct {
    columns: prover_transaction.OwnedColumns,
    lookup_elements: LookupElements,
    claimed_sum: QM31,

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
        const q0 = lookup.combine(circuit.a_wire[row], circuit.a_val[row]);
        const q1 = lookup.combine(circuit.b_wire[row], circuit.b_val[row]);
        const q2 = lookup.combine(circuit.c_wire[row], circuit.c_val[row]);
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
        .claimed_sum = claimed_sum,
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
    for (values, column) |value, *out| out.* = value.toM31Array()[coordinate];
    return column;
}

test "exact Plonk interaction has two secure columns and shifted last sum" {
    const allocator = std.testing.allocator;
    var prepared = try input.prepare(allocator, .{ .log_n_rows = 4 });
    defer prepared.deinit(allocator);
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Channel{};
    var generated = try generate(allocator, &channel, &prepared);
    defer generated.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 8), generated.columns.columns.?.len);
}
