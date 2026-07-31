//! Secure-field LogUp interaction for the Native XOR truth-table lookup.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_transaction = @import("stwo_prover_engine").transaction;
const input = @import("input.zig");

pub const N_COLUMNS: usize = 4;

pub const LookupElements = struct {
    z: QM31,
    alpha: QM31,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !LookupElements {
        const values = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(values);
        return .{ .z = values[0], .alpha = values[1] };
    }

    pub fn combineBase(self: LookupElements, a: M31, b: M31, c: M31) QM31 {
        return QM31.fromBase(a)
            .add(self.alpha.mulM31(b))
            .add(self.alpha.square().mulM31(c))
            .sub(self.z);
    }

    pub fn combineSecure(
        self: LookupElements,
        a: QM31,
        b: QM31,
        c: QM31,
    ) QM31 {
        return a.add(self.alpha.mul(b))
            .add(self.alpha.square().mul(c))
            .sub(self.z);
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
    const statement = prepared.request;
    if (statement.log_size >= @bitSizeOf(usize) or
        statement.log_step >= @bitSizeOf(usize))
    {
        return error.InvalidPreparedGeometry;
    }
    const n = @as(usize, 1) << @intCast(statement.log_size);
    const step = @as(usize, 1) << @intCast(statement.log_step);
    const selected_offset = statement.offset % step;

    const denominators = try allocator.alloc(QM31, n);
    defer allocator.free(denominators);
    const numerators = try allocator.alloc(QM31, n);
    defer allocator.free(numerators);

    var counts = [_]u64{0} ** 4;
    for (0..n) |row| {
        const a = (row >> 1) & 1;
        const b: usize = @intFromBool(row % step == selected_offset);
        counts[(a << 1) | b] += 1;
    }
    for (0..n) |row| {
        const storage = input.storageIndex(row, statement.log_size);
        const a: u32 = @intCast((row >> 1) & 1);
        const b: u32 = @intFromBool(row % step == selected_offset);
        const table_a: u32 = if (row < 4) @intCast((row >> 1) & 1) else 0;
        const table_b: u32 = if (row < 4) @intCast(row & 1) else 0;
        const table_denominator = lookup.combineBase(
            M31.fromCanonical(table_a),
            M31.fromCanonical(table_b),
            M31.fromCanonical(table_a ^ table_b),
        );
        const execution_denominator = lookup.combineBase(
            M31.fromCanonical(a),
            M31.fromCanonical(b),
            M31.fromCanonical(a ^ b),
        );
        denominators[storage] = table_denominator.mul(execution_denominator);
        numerators[storage] = execution_denominator
            .mulM31(if (row < 4) M31.fromU64(counts[row]) else M31.zero())
            .sub(table_denominator);
    }
    const inverses = try fields.batchInverse(QM31, allocator, denominators);
    defer allocator.free(inverses);

    const secure_values = try allocator.alloc(QM31, n);
    defer allocator.free(secure_values);
    var claimed_sum = QM31.zero();
    const log_size = statement.log_size;
    for (0..n) |row| {
        const storage = input.storageIndex(row, log_size);
        claimed_sum = claimed_sum.add(numerators[storage].mul(inverses[storage]));
        secure_values[storage] = claimed_sum;
    }

    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, N_COLUMNS);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (0..N_COLUMNS) |coordinate| {
        const values = try allocator.alloc(M31, n);
        for (secure_values, values) |value, *out| {
            out.* = value.toM31Array()[coordinate];
        }
        columns[coordinate] = .{ .log_size = log_size, .values = values };
        initialized += 1;
    }
    return .{
        .columns = prover_transaction.OwnedColumns.init(columns),
        .lookup_elements = lookup,
        .claimed_sum = claimed_sum,
    };
}

test "Native XOR interaction closes the exact truth-table lookup" {
    const allocator = std.testing.allocator;
    var prepared = try input.prepare(allocator, .{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    });
    defer prepared.deinit(allocator);

    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Channel{};
    var generated = try generate(allocator, &channel, &prepared);
    defer generated.deinit(allocator);

    try std.testing.expect(generated.claimed_sum.eql(QM31.zero()));
    try std.testing.expectEqual(N_COLUMNS, generated.columns.columns.?.len);
}

test "Native XOR lookup challenges are bound to the prior transcript" {
    const allocator = std.testing.allocator;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var first = Channel{};
    var second = Channel{};
    second.mixU32s(&.{0x584f52});

    const first_elements = try LookupElements.draw(allocator, &first);
    const second_elements = try LookupElements.draw(allocator, &second);
    try std.testing.expect(
        !first_elements.z.eql(second_elements.z) or
            !first_elements.alpha.eql(second_elements.alpha),
    );
}
