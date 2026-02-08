const std = @import("std");
const qm31 = @import("../../core/fields/qm31.zig");
const secure_column = @import("../secure_column.zig");

const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub const AccumulationError = error{
    InvalidLogSize,
    ShapeMismatch,
    NotEnoughCoefficients,
    UnusedCoefficients,
};

/// Accumulates secure-column evaluations into a random linear combination:
/// `acc <- acc + alpha^(N-1-i) * eval_i` where columns are added in order.
pub const DomainEvaluationAccumulator = struct {
    allocator: std.mem.Allocator,
    max_log_size: u32,
    random_coeff_powers: []QM31,
    next_power_index: usize,
    sub_accumulations: []?SecureColumnByCoords,

    pub fn init(
        allocator: std.mem.Allocator,
        random_coeff: QM31,
        max_log_size: u32,
        total_columns: usize,
    ) !DomainEvaluationAccumulator {
        const powers = try generateSecurePowers(allocator, random_coeff, total_columns);
        errdefer allocator.free(powers);

        const subs = try allocator.alloc(?SecureColumnByCoords, max_log_size + 1);
        errdefer allocator.free(subs);
        @memset(subs, null);

        return .{
            .allocator = allocator,
            .max_log_size = max_log_size,
            .random_coeff_powers = powers,
            .next_power_index = powers.len,
            .sub_accumulations = subs,
        };
    }

    pub fn deinit(self: *DomainEvaluationAccumulator) void {
        for (self.sub_accumulations) |*maybe_col| {
            if (maybe_col.*) |*col| col.deinit(self.allocator);
        }
        self.allocator.free(self.sub_accumulations);
        self.allocator.free(self.random_coeff_powers);
        self.* = undefined;
    }

    pub fn skipCoeffs(self: *DomainEvaluationAccumulator, n_coeffs: usize) AccumulationError!void {
        if (n_coeffs > self.next_power_index) return AccumulationError.NotEnoughCoefficients;
        self.next_power_index -= n_coeffs;
    }

    pub fn accumulateColumn(
        self: *DomainEvaluationAccumulator,
        log_size: u32,
        evaluation: *const SecureColumnByCoords,
    ) (std.mem.Allocator.Error || AccumulationError)!void {
        if (log_size > self.max_log_size) return AccumulationError.InvalidLogSize;
        const expected_len = try checkedPow2(log_size);
        if (evaluation.len() != expected_len) return AccumulationError.ShapeMismatch;
        if (self.next_power_index == 0) return AccumulationError.NotEnoughCoefficients;

        self.next_power_index -= 1;
        const random_coeff = self.random_coeff_powers[self.next_power_index];

        if (self.sub_accumulations[log_size]) |*acc| {
            if (acc.len() != expected_len) return AccumulationError.ShapeMismatch;
            for (0..expected_len) |row| {
                const value = acc.at(row).add(evaluation.at(row).mul(random_coeff));
                acc.set(row, value);
            }
        } else {
            var out = try SecureColumnByCoords.zeros(self.allocator, expected_len);
            errdefer out.deinit(self.allocator);
            for (0..expected_len) |row| {
                out.set(row, evaluation.at(row).mul(random_coeff));
            }
            self.sub_accumulations[log_size] = out;
        }
    }

    /// Lifts all sub-accumulations to max domain size and sums them coordinate-wise.
    pub fn finalize(self: *DomainEvaluationAccumulator) (std.mem.Allocator.Error || AccumulationError)!SecureColumnByCoords {
        if (self.next_power_index != 0) return AccumulationError.UnusedCoefficients;

        const max_size = try checkedPow2(self.max_log_size);
        var out = try SecureColumnByCoords.zeros(self.allocator, max_size);
        errdefer out.deinit(self.allocator);

        for (self.sub_accumulations, 0..) |maybe_sub, log_size_usize| {
            const sub = maybe_sub orelse continue;
            const log_size: u32 = @intCast(log_size_usize);
            for (0..max_size) |position| {
                const lifted = try liftedValueAt(sub, log_size, self.max_log_size, position);
                out.set(position, out.at(position).add(lifted));
            }
        }

        return out;
    }
};

pub fn generateSecurePowers(
    allocator: std.mem.Allocator,
    random_coeff: QM31,
    n_powers: usize,
) ![]QM31 {
    const out = try allocator.alloc(QM31, n_powers);
    var curr = QM31.one();
    for (out) |*value| {
        value.* = curr;
        curr = curr.mul(random_coeff);
    }
    return out;
}

fn liftedValueAt(
    column: SecureColumnByCoords,
    log_size: u32,
    lifting_log_size: u32,
    position: usize,
) AccumulationError!QM31 {
    if (log_size > lifting_log_size) return AccumulationError.InvalidLogSize;
    const lifting_size = try checkedPow2(lifting_log_size);
    if (position >= lifting_size) return AccumulationError.ShapeMismatch;

    const shift = lifting_log_size - log_size;
    if (shift >= @bitSizeOf(usize)) return AccumulationError.InvalidLogSize;
    const idx = ((position >> (@as(usize, @intCast(shift)) + 1)) << 1) + (position & 1);
    if (idx >= column.len()) return AccumulationError.ShapeMismatch;
    return column.at(idx);
}

fn checkedPow2(log_size: u32) AccumulationError!usize {
    if (log_size >= @bitSizeOf(usize)) return AccumulationError.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "prover air accumulation: generate secure powers" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(2, 0, 0, 0);
    const powers = try generateSecurePowers(alloc, alpha, 4);
    defer alloc.free(powers);

    try std.testing.expect(powers[0].eql(QM31.one()));
    try std.testing.expect(powers[1].eql(alpha));
    try std.testing.expect(powers[2].eql(alpha.square()));
    try std.testing.expect(powers[3].eql(alpha.square().mul(alpha)));
}

test "prover air accumulation: lifted combination matches direct formula" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 0, 0, 0);

    var acc = try DomainEvaluationAccumulator.init(
        alloc,
        alpha,
        3,
        2,
    );
    defer acc.deinit();

    const col_large_values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(6, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(8, 0, 0, 0),
    };
    const col_small_values = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(20, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
        QM31.fromU32Unchecked(40, 0, 0, 0),
    };

    var col_large = try SecureColumnByCoords.fromSecureSlice(alloc, col_large_values[0..]);
    defer col_large.deinit(alloc);
    var col_small = try SecureColumnByCoords.fromSecureSlice(alloc, col_small_values[0..]);
    defer col_small.deinit(alloc);

    // First column uses alpha^(2-1)=alpha, second uses alpha^0=1.
    try acc.accumulateColumn(3, &col_large);
    try acc.accumulateColumn(2, &col_small);

    var combined = try acc.finalize();
    defer combined.deinit(alloc);

    const combined_vec = try combined.toVec(alloc);
    defer alloc.free(combined_vec);

    const shift: u32 = 1;
    for (combined_vec, 0..) |value, position| {
        const idx_small = ((position >> (@as(usize, @intCast(shift)) + 1)) << 1) + (position & 1);
        const expected = col_large_values[position].mul(alpha).add(col_small_values[idx_small]);
        try std.testing.expect(value.eql(expected));
    }
}

test "prover air accumulation: detects unused and missing coefficients" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(5, 0, 0, 0);

    var acc = try DomainEvaluationAccumulator.init(alloc, alpha, 2, 1);
    defer acc.deinit();

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    var col = try SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer col.deinit(alloc);

    try std.testing.expectError(AccumulationError.UnusedCoefficients, acc.finalize());

    try acc.accumulateColumn(2, &col);
    try std.testing.expectError(AccumulationError.NotEnoughCoefficients, acc.accumulateColumn(2, &col));
}
