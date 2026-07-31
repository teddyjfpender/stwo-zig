//! Exact two-component LogUp interaction trace from pinned upstream Stwo.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_transaction = @import("stwo_prover_engine").transaction;
const input = @import("input.zig");
const statement_mod = @import("statement.zig");

pub const N_COLUMNS: usize = 8;

pub const PreparedInteraction = struct {
    columns: prover_transaction.OwnedColumns,
    lookup_elements: statement_mod.Elements,
    statement: statement_mod.PreparedStatement,

    pub fn deinit(self: *PreparedInteraction, allocator: std.mem.Allocator) void {
        self.columns.deinit(allocator);
        self.* = undefined;
    }
};

const AxisInteraction = struct {
    values: []QM31,
    claimed_sum: QM31,
};

pub fn generate(
    allocator: std.mem.Allocator,
    channel: anytype,
    prepared: *const input.PreparedInput,
) !PreparedInteraction {
    const request = prepared.request;
    try input.validate(request);
    const elements = try statement_mod.Elements.draw(allocator, channel);
    const transitions = try statement_mod.transitionStates(
        request.log_n_rows,
        request.initial_state,
    );

    const x_axis = try generateAxis(
        allocator,
        request.log_n_rows,
        request.initial_state,
        0,
        elements,
    );
    defer allocator.free(x_axis.values);
    const y_axis = try generateAxis(
        allocator,
        request.log_n_rows - 1,
        transitions.intermediate,
        1,
        elements,
    );
    defer allocator.free(y_axis.values);

    const statement = statement_mod.PreparedStatement{
        .public_input = .{ request.initial_state, transitions.final },
        .stmt0 = .{ .n = request.log_n_rows, .m = request.log_n_rows - 1 },
        .stmt1 = .{
            .x_axis_claimed_sum = x_axis.claimed_sum,
            .y_axis_claimed_sum = y_axis.claimed_sum,
        },
    };
    try statement_mod.verify(statement, elements);

    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, N_COLUMNS);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (0..4) |coordinate| {
        columns[coordinate] = .{
            .log_size = request.log_n_rows,
            .values = try coordinateColumn(allocator, x_axis.values, coordinate),
        };
        initialized += 1;
    }
    for (0..4) |coordinate| {
        columns[4 + coordinate] = .{
            .log_size = request.log_n_rows - 1,
            .values = try coordinateColumn(allocator, y_axis.values, coordinate),
        };
        initialized += 1;
    }

    return .{
        .columns = prover_transaction.OwnedColumns.init(columns),
        .lookup_elements = elements,
        .statement = statement,
    };
}

fn generateAxis(
    allocator: std.mem.Allocator,
    log_size: u32,
    initial_state: input.State,
    coordinate: usize,
    elements: statement_mod.Elements,
) !AxisInteraction {
    const n = try input.checkedPow2(log_size);
    const values = try allocator.alloc(QM31, n);
    errdefer allocator.free(values);

    var claimed_sum = QM31.zero();
    for (0..n) |row| {
        var state = initial_state;
        state[coordinate] = state[coordinate].add(M31.fromU64(row));
        const input_denominator = elements.combine(state);
        state[coordinate] = state[coordinate].add(M31.one());
        const output_denominator = elements.combine(state);
        const fraction = try output_denominator.sub(input_denominator).div(
            input_denominator.mul(output_denominator),
        );
        values[input.storageIndex(row, log_size)] = fraction;
        claimed_sum = claimed_sum.add(fraction);
    }

    const shift = try claimed_sum.divM31(M31.fromU64(n));
    for (values) |*value| value.* = value.sub(shift);
    try inclusivePrefixSum(allocator, values);
    return .{ .values = values, .claimed_sum = claimed_sum };
}

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

test "State Machine interaction emits two secure columns at exact heights" {
    const allocator = std.testing.allocator;
    var prepared = try input.prepare(allocator, .{
        .log_n_rows = 5,
        .initial_state = .{ M31.fromCanonical(9), M31.fromCanonical(3) },
    });
    defer prepared.deinit(allocator);

    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Channel{};
    var generated = try generate(allocator, &channel, &prepared);
    defer generated.deinit(allocator);
    const columns = generated.columns.columns.?;
    try std.testing.expectEqual(N_COLUMNS, columns.len);
    for (columns[0..4]) |column| try std.testing.expectEqual(@as(u32, 5), column.log_size);
    for (columns[4..8]) |column| try std.testing.expectEqual(@as(u32, 4), column.log_size);
}
