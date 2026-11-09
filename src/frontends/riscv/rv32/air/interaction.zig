//! LogUp interaction trace generation for the RISC-V AIR.
//!
//! Provides the infrastructure for drawing random lookup elements from the
//! Fiat-Shamir channel, computing LogUp denominators for relation entries,
//! generating interaction trace columns from LogUp fractions, and verifying
//! that the total LogUp sum across all components equals zero.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const CM31 = @import("stwo_core").fields.cm31.CM31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const SECURE_EXTENSION_DEGREE = @import("stwo_core").fields.qm31.SECURE_EXTENSION_DEGREE;
const prover_pcs = @import("stwo_prover_engine").pcs;

/// Size of the common lookup random element vector.
/// Must be >= max relation tuple size across all components.
/// The largest relation is MemoryAccessRelation with N_FIELDS = 7,
/// but we over-provision to 16 for future extensibility.
pub const LOOKUP_ELEMENTS_SIZE: usize = 16;

/// Random elements drawn from the Fiat-Shamir channel for LogUp.
///
/// These elements are used to combine relation field values into a single
/// extension-field element (via random linear combination) and then to
/// form the LogUp denominator `z - combo`.
pub const LookupElements = struct {
    /// Random combination coefficient (unused in single-field linear combo,
    /// reserved for multi-relation batching).
    alpha: QM31,
    /// Random evaluation point for LogUp denominators.
    z: QM31,
    /// Per-field random elements for linear combination.
    elements: [LOOKUP_ELEMENTS_SIZE]QM31,

    /// Draw all random elements from a Fiat-Shamir channel.
    ///
    /// The channel must implement `drawSecureFelt() QM31`.
    pub fn draw(channel: anytype) LookupElements {
        var result: LookupElements = undefined;
        result.alpha = channel.drawSecureFelt();
        result.z = channel.drawSecureFelt();
        for (&result.elements) |*e| {
            e.* = channel.drawSecureFelt();
        }
        return result;
    }

    /// Initialize with explicit values (useful for testing).
    pub fn initFromValues(alpha: QM31, z: QM31, elements: [LOOKUP_ELEMENTS_SIZE]QM31) LookupElements {
        return .{
            .alpha = alpha,
            .z = z,
            .elements = elements,
        };
    }

    /// Initialize with all fields set to zero (useful for testing).
    pub fn initZero() LookupElements {
        return .{
            .alpha = QM31.zero(),
            .z = QM31.zero(),
            .elements = [_]QM31{QM31.zero()} ** LOOKUP_ELEMENTS_SIZE,
        };
    }
};

/// Compute the LogUp denominator for a relation entry.
///
/// The denominator is:
///   denom = z - (relation_id + sum_i(elements[i] * values[i]))
///
/// where `relation_id` is the M31 constant identifying the relation bus,
/// `values` are the field elements of the entry, and `elements[i]` / `z`
/// are the random lookup elements drawn from the channel.
pub fn logupDenominator(
    lookup: *const LookupElements,
    relation_id: M31,
    values: []const M31,
) QM31 {
    var acc = QM31.fromBase(relation_id);
    for (values, 0..) |v, i| {
        if (i < LOOKUP_ELEMENTS_SIZE) {
            acc = acc.add(lookup.elements[i].mulM31(v));
        }
    }
    return lookup.z.sub(acc);
}

/// Interaction trace result for one component.
///
/// Contains the 4 M31 columns that encode one QM31 cumulative-sum column,
/// plus the final claimed sum value for this component.
pub const ComponentInteraction = struct {
    /// LogUp cumulative sum columns (4 M31 columns encoding 1 QM31 column).
    columns: [SECURE_EXTENSION_DEGREE][]M31,
    /// The claimed sum for this component (final cumulative value).
    claimed_sum: QM31,

    pub fn deinit(self: *ComponentInteraction, allocator: std.mem.Allocator) void {
        for (&self.columns) |col| allocator.free(col);
        self.* = undefined;
    }
};

/// Generate the interaction trace for a single component.
///
/// Allocates 4 M31 columns of length `n_rows` representing a QM31
/// cumulative-sum column. Each row accumulates the LogUp fraction
/// `numerator_i / denominator_i` on top of the previous row's value.
///
/// The `claimed_sum` is set to the final cumulative value (last row).
///
/// Note: This is a scaffold that allocates and zeros the columns. A full
/// implementation requires the base trace data and the numerator/denominator
/// values for each row, which are component-specific.
pub fn generateInteractionTrace(
    allocator: std.mem.Allocator,
    n_rows: usize,
) !ComponentInteraction {
    // Allocate 4 M31 columns (representing one QM31 cumulative sum).
    var columns: [SECURE_EXTENSION_DEGREE][]M31 = undefined;
    var allocated: usize = 0;
    errdefer {
        for (0..allocated) |i| allocator.free(columns[i]);
    }
    for (0..SECURE_EXTENSION_DEGREE) |i| {
        columns[i] = try allocator.alloc(M31, n_rows);
        allocated += 1;
        @memset(columns[i], M31.zero());
    }

    // The cumulative sum starts at zero and accumulates LogUp fractions.
    // For a proper implementation, each row's fraction is:
    //   frac_i = numerator_i / denominator_i
    // where numerator comes from the enabler column and denominator from
    // logupDenominator.
    //
    // cumsum[0] = frac_0
    // cumsum[i] = cumsum[i-1] + frac_i
    //
    // The claimed_sum = cumsum[n_rows - 1] (final value).

    const claimed_sum = QM31.zero();

    return .{
        .columns = columns,
        .claimed_sum = claimed_sum,
    };
}

/// Result of generating interaction trace columns for one component.
pub const InteractionResult = struct {
    /// Committed column evaluations (n_qm31_cols * 4 M31 columns).
    columns: []prover_pcs.ColumnEvaluation,
    /// The claimed LogUp sum for this component (zero for placeholder).
    claimed_sum: QM31,
};

/// Generate interaction trace columns for a component.
///
/// Each component contributes `n_interaction_qm31_cols` QM31 columns,
/// which are stored as `n_interaction_qm31_cols * 4` M31 columns.
/// For now the columns are zero-filled with `claimed_sum = 0`, which is
/// structurally correct for the commitment scheme. A full implementation
/// would compute the LogUp cumulative sum fractions here.
pub fn generateComponentInteractionColumns(
    allocator: std.mem.Allocator,
    log_size: u32,
    n_interaction_qm31_cols: u32,
) !InteractionResult {
    const n_m31_cols = n_interaction_qm31_cols * SECURE_EXTENSION_DEGREE;
    const n_rows = @as(usize, 1) << @intCast(log_size);
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, n_m31_cols);
    errdefer allocator.free(columns);

    var initialized: usize = 0;
    errdefer {
        for (0..initialized) |i| allocator.free(@constCast(columns[i].values));
    }
    for (0..n_m31_cols) |i| {
        const vals = try allocator.alloc(M31, n_rows);
        @memset(vals, M31.zero());
        columns[i] = .{ .log_size = log_size, .values = vals };
        initialized = i + 1;
    }
    return .{ .columns = columns, .claimed_sum = QM31.zero() };
}

/// Verify that the total LogUp sum across all components equals zero.
///
/// In a valid execution trace, every relation entry that is "sent" by one
/// component must be "received" by another. The LogUp argument encodes sends
/// as +1/denom and receives as -1/denom, so the total sum must cancel to zero.
pub fn verifyLogupSum(claimed_sums: []const QM31) !void {
    var total = QM31.zero();
    for (claimed_sums) |sum| {
        total = total.add(sum);
    }
    if (!total.eql(QM31.zero())) {
        return error.LogupSumNonZero;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "LookupElements: initZero produces all-zero fields" {
    const lookup = LookupElements.initZero();
    try std.testing.expect(lookup.alpha.eql(QM31.zero()));
    try std.testing.expect(lookup.z.eql(QM31.zero()));
    for (lookup.elements) |e| {
        try std.testing.expect(e.eql(QM31.zero()));
    }
}

test "LookupElements: initFromValues round-trips" {
    const alpha = QM31.fromU32Unchecked(1, 2, 3, 4);
    const z = QM31.fromU32Unchecked(5, 6, 7, 8);
    var elems: [LOOKUP_ELEMENTS_SIZE]QM31 = undefined;
    for (&elems, 0..) |*e, i| {
        const val: u32 = @intCast(i + 10);
        e.* = QM31.fromU32Unchecked(val, val + 1, val + 2, val + 3);
    }

    const lookup = LookupElements.initFromValues(alpha, z, elems);
    try std.testing.expect(lookup.alpha.eql(alpha));
    try std.testing.expect(lookup.z.eql(z));
    for (lookup.elements, 0..) |e, i| {
        try std.testing.expect(e.eql(elems[i]));
    }
}

test "LookupElements: draw from mock channel" {
    // A simple mock channel that returns incrementing QM31 values.
    const MockChannel = struct {
        counter: u32 = 0,

        pub fn drawSecureFelt(self: *@This()) QM31 {
            const c = self.counter;
            self.counter += 1;
            return QM31.fromU32Unchecked(c, c +% 1, c +% 2, c +% 3);
        }
    };

    var channel = MockChannel{};
    const lookup = LookupElements.draw(&channel);

    // alpha is the first draw (counter=0)
    try std.testing.expect(lookup.alpha.eql(QM31.fromU32Unchecked(0, 1, 2, 3)));
    // z is the second draw (counter=1)
    try std.testing.expect(lookup.z.eql(QM31.fromU32Unchecked(1, 2, 3, 4)));
    // elements[0] is the third draw (counter=2)
    try std.testing.expect(lookup.elements[0].eql(QM31.fromU32Unchecked(2, 3, 4, 5)));
    // Total draws = 2 + LOOKUP_ELEMENTS_SIZE
    try std.testing.expectEqual(@as(u32, 2 + LOOKUP_ELEMENTS_SIZE), channel.counter);
}

test "logupDenominator: non-zero for non-trivial inputs" {
    const alpha = QM31.fromU32Unchecked(100, 200, 300, 400);
    const z = QM31.fromU32Unchecked(999, 888, 777, 666);
    var elems: [LOOKUP_ELEMENTS_SIZE]QM31 = [_]QM31{QM31.zero()} ** LOOKUP_ELEMENTS_SIZE;
    elems[0] = QM31.fromU32Unchecked(11, 22, 33, 44);
    elems[1] = QM31.fromU32Unchecked(55, 66, 77, 88);

    const lookup = LookupElements.initFromValues(alpha, z, elems);
    const relation_id = M31.fromCanonical(428564188); // OpcodeRelation ID
    const values = [_]M31{ M31.fromCanonical(42), M31.fromCanonical(100) };

    const denom = logupDenominator(&lookup, relation_id, &values);

    // The denominator should not be zero for these non-trivial inputs.
    try std.testing.expect(!denom.eql(QM31.zero()));
}

test "logupDenominator: zero values yield z - relation_id" {
    const z = QM31.fromU32Unchecked(500, 600, 700, 800);
    const lookup = LookupElements.initFromValues(QM31.zero(), z, [_]QM31{QM31.zero()} ** LOOKUP_ELEMENTS_SIZE);
    const relation_id = M31.fromCanonical(42);
    const values = [_]M31{};

    const denom = logupDenominator(&lookup, relation_id, &values);
    const expected = z.sub(QM31.fromBase(relation_id));

    try std.testing.expect(denom.eql(expected));
}

test "logupDenominator: single value uses elements[0]" {
    const z = QM31.fromU32Unchecked(1000, 0, 0, 0);
    var elems: [LOOKUP_ELEMENTS_SIZE]QM31 = [_]QM31{QM31.zero()} ** LOOKUP_ELEMENTS_SIZE;
    elems[0] = QM31.one();
    const lookup = LookupElements.initFromValues(QM31.zero(), z, elems);

    const relation_id = M31.fromCanonical(10);
    const values = [_]M31{M31.fromCanonical(5)};
    const denom = logupDenominator(&lookup, relation_id, &values);

    // acc = fromBase(10) + one() * 5 = fromBase(15)
    // denom = z - acc = (1000,0,0,0) - (15,0,0,0) = (985,0,0,0)
    const expected = QM31.fromU32Unchecked(985, 0, 0, 0);
    try std.testing.expect(denom.eql(expected));
}

test "verifyLogupSum: accepts zero sum" {
    const sums = [_]QM31{QM31.zero()};
    try verifyLogupSum(&sums);
}

test "verifyLogupSum: accepts cancelling sums" {
    const a = QM31.fromU32Unchecked(100, 200, 300, 400);
    const neg_a = a.neg();
    const sums = [_]QM31{ a, neg_a };
    try verifyLogupSum(&sums);
}

test "verifyLogupSum: accepts multiple cancelling sums" {
    const a = QM31.fromU32Unchecked(10, 20, 30, 40);
    const b = QM31.fromU32Unchecked(50, 60, 70, 80);
    const neg_ab = a.add(b).neg();
    const sums = [_]QM31{ a, b, neg_ab };
    try verifyLogupSum(&sums);
}

test "verifyLogupSum: rejects non-zero sum" {
    const sums = [_]QM31{QM31.fromU32Unchecked(1, 0, 0, 0)};
    try std.testing.expectError(error.LogupSumNonZero, verifyLogupSum(&sums));
}

test "verifyLogupSum: rejects partial cancellation" {
    const a = QM31.fromU32Unchecked(100, 200, 300, 400);
    const b = QM31.fromU32Unchecked(50, 60, 70, 80);
    // Only negate a, leaving b un-cancelled.
    const sums = [_]QM31{ a, a.neg(), b };
    try std.testing.expectError(error.LogupSumNonZero, verifyLogupSum(&sums));
}

test "verifyLogupSum: empty slice accepts (trivially zero)" {
    const sums = [_]QM31{};
    try verifyLogupSum(&sums);
}

test "generateInteractionTrace: allocates correct dimensions" {
    const allocator = std.testing.allocator;
    const n_rows: usize = 64;

    var result = try generateInteractionTrace(allocator, n_rows);
    defer result.deinit(allocator);

    // Should have 4 columns (SECURE_EXTENSION_DEGREE).
    try std.testing.expectEqual(@as(usize, SECURE_EXTENSION_DEGREE), result.columns.len);

    // Each column should have n_rows entries.
    for (result.columns) |col| {
        try std.testing.expectEqual(n_rows, col.len);
    }

    // All entries should be zero (scaffold).
    for (result.columns) |col| {
        for (col) |val| {
            try std.testing.expect(val.eql(M31.zero()));
        }
    }

    // Claimed sum should be zero (scaffold).
    try std.testing.expect(result.claimed_sum.eql(QM31.zero()));
}

test "ComponentInteraction: deinit frees memory" {
    const allocator = std.testing.allocator;
    var result = try generateInteractionTrace(allocator, 16);
    result.deinit(allocator);
    // If deinit didn't properly free, the test allocator would detect leaks.
}

test "generateComponentInteractionColumns: allocates correct dimensions" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 3;
    const n_qm31: u32 = 5;
    const n_rows: usize = 1 << log_size;
    const n_m31 = n_qm31 * SECURE_EXTENSION_DEGREE;

    const result = try generateComponentInteractionColumns(allocator, log_size, n_qm31);
    defer {
        for (result.columns) |col| allocator.free(@constCast(col.values));
        allocator.free(result.columns);
    }

    // Should have n_qm31 * 4 M31 columns.
    try std.testing.expectEqual(@as(usize, n_m31), result.columns.len);

    // Each column should have the right log_size and n_rows entries.
    for (result.columns) |col| {
        try std.testing.expectEqual(log_size, col.log_size);
        try std.testing.expectEqual(n_rows, col.values.len);
    }

    // All entries should be zero (placeholder).
    for (result.columns) |col| {
        for (col.values) |val| {
            try std.testing.expect(val.eql(M31.zero()));
        }
    }

    // Claimed sum should be zero (placeholder).
    try std.testing.expect(result.claimed_sum.eql(QM31.zero()));
}
