//! Exact 16-tuple Poseidon LogUp interaction from pinned upstream Stwo.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_transaction = @import("../common/prover_transaction.zig");
const input = @import("input.zig");

pub const N_SECURE_COLUMNS: usize = input.N_INSTANCES_PER_ROW;
pub const N_COLUMNS: usize = N_SECURE_COLUMNS * 4;

pub const LookupElements = struct {
    z: QM31,
    alpha: QM31,
    alpha_powers: [input.N_STATE]QM31,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !LookupElements {
        const values = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(values);
        return fromZAlpha(values[0], values[1]);
    }

    pub fn fromZAlpha(z: QM31, alpha: QM31) LookupElements {
        var current = QM31.one();
        var powers: [input.N_STATE]QM31 = undefined;
        for (&powers) |*power| {
            power.* = current;
            current = current.mul(alpha);
        }
        return .{ .z = z, .alpha = alpha, .alpha_powers = powers };
    }

    pub fn combineBase(self: *const LookupElements, values: [input.N_STATE]M31) QM31 {
        var result = QM31.zero();
        for (values, self.alpha_powers) |value, power| {
            result = result.add(power.mulM31(value));
        }
        return result.sub(self.z);
    }

    pub fn combineSecure(
        self: *const LookupElements,
        values: [input.N_STATE]QM31,
    ) QM31 {
        var result = QM31.zero();
        for (values, self.alpha_powers) |value, power| {
            result = result.add(power.mul(value));
        }
        return result.sub(self.z);
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
    const log_n_rows = try input.logNRows(prepared.request);
    const n = @as(usize, 1) << @intCast(log_n_rows);
    for (prepared.lookup_data.initial) |column| {
        if (column.len != n) return error.InvalidPreparedGeometry;
    }
    for (prepared.lookup_data.final) |column| {
        if (column.len != n) return error.InvalidPreparedGeometry;
    }

    const lookup = try LookupElements.draw(allocator, channel);
    const denominators = try allocator.alloc(QM31, n * input.N_INSTANCES_PER_ROW);
    defer allocator.free(denominators);
    const numerators = try allocator.alloc(QM31, denominators.len);
    defer allocator.free(numerators);

    for (0..input.N_INSTANCES_PER_ROW) |rep| {
        const base = rep * input.N_STATE;
        for (0..n) |row| {
            var initial: [input.N_STATE]M31 = undefined;
            var final: [input.N_STATE]M31 = undefined;
            for (0..input.N_STATE) |i| {
                initial[i] = prepared.lookup_data.initial[base + i][row];
                final[i] = prepared.lookup_data.final[base + i][row];
            }
            const d0 = lookup.combineBase(initial);
            const d1 = lookup.combineBase(final);
            const index = rep * n + row;
            denominators[index] = d0.mul(d1);
            numerators[index] = d1.sub(d0);
        }
    }
    const inverses = try fields.batchInverse(QM31, allocator, denominators);
    defer allocator.free(inverses);

    const secure_columns = try allocator.alloc([]QM31, N_SECURE_COLUMNS);
    var secure_initialized: usize = 0;
    errdefer {
        for (secure_columns[0..secure_initialized]) |column| allocator.free(column);
        allocator.free(secure_columns);
    }
    const running = try allocator.alloc(QM31, n);
    defer allocator.free(running);
    @memset(running, QM31.zero());

    for (0..N_SECURE_COLUMNS) |rep| {
        const column = try allocator.alloc(QM31, n);
        secure_columns[rep] = column;
        secure_initialized += 1;
        for (0..n) |row| {
            const index = rep * n + row;
            running[row] = running[row].add(numerators[index].mul(inverses[index]));
            column[row] = running[row];
        }
    }

    var claimed_sum = QM31.zero();
    for (secure_columns[N_SECURE_COLUMNS - 1]) |value| {
        claimed_sum = claimed_sum.add(value);
    }
    const shift = try claimed_sum.divM31(M31.fromU64(n));
    for (secure_columns[N_SECURE_COLUMNS - 1]) |*value| {
        value.* = value.sub(shift);
    }
    try inclusivePrefixSum(allocator, secure_columns[N_SECURE_COLUMNS - 1]);

    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, N_COLUMNS);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (secure_columns, 0..) |secure, secure_index| {
        for (0..4) |coordinate| {
            const values = try allocator.alloc(M31, n);
            for (secure, values) |value, *out| {
                out.* = value.toM31Array()[coordinate];
            }
            columns[secure_index * 4 + coordinate] = .{
                .log_size = log_n_rows,
                .values = values,
            };
            initialized += 1;
        }
    }
    for (secure_columns) |column| allocator.free(column);
    allocator.free(secure_columns);
    secure_initialized = 0;

    return .{
        .columns = prover_transaction.OwnedColumns.init(columns),
        .lookup_elements = lookup,
        .claimed_sum = claimed_sum,
    };
}

/// Matches upstream prefix summation over canonic-coset order.
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

test "exact Poseidon relation expansion has sixteen powers" {
    const elements = LookupElements.fromZAlpha(
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
    );
    try std.testing.expect(elements.alpha_powers[0].eql(QM31.one()));
    try std.testing.expect(elements.alpha_powers[1].eql(elements.alpha));
    try std.testing.expect(
        elements.alpha_powers[15].eql(elements.alpha_powers[14].mul(elements.alpha)),
    );
}

test "exact Poseidon interaction emits eight secure columns" {
    const allocator = std.testing.allocator;
    var prepared = try input.prepare(allocator, .{ .log_n_instances = 7 });
    defer prepared.deinit(allocator);
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    var channel = Channel{};
    var generated = try generate(allocator, &channel, &prepared);
    defer generated.deinit(allocator);

    try std.testing.expectEqual(N_COLUMNS, generated.columns.columns.?.len);
}
