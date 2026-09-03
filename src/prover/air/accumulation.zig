const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_poly = @import("../poly/circle/poly.zig");
const prover_twiddles = @import("../poly/twiddles.zig");
const secure_column = @import("../secure_column.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub const AccumulationError = error{
    InvalidLogSize,
    ShapeMismatch,
    NotEnoughCoefficients,
    UnusedCoefficients,
    NestedPolynomialExtension,
    PolynomialExtensionRequiresAllocation,
};

pub const ColumnRequest = struct {
    log_size: u32,
    n_cols: usize,
};

/// Domain accumulator for one specific log-size bucket.
pub const ColumnAccumulator = struct {
    random_coeff_powers: []const QM31,
    col: *SecureColumnByCoords,
    /// A newly allocated zero bucket can accept its first sequential pass as
    /// direct stores. Any repeated or out-of-order index disables the fast path
    /// and retains the general additive semantics.
    next_fresh_index: ?usize,

    pub fn accumulate(self: *ColumnAccumulator, index: usize, evaluation: QM31) void {
        if (self.next_fresh_index) |next_index| {
            if (index == next_index) {
                self.col.set(index, evaluation);
                self.next_fresh_index = next_index + 1;
                return;
            }
            self.next_fresh_index = null;
        }
        self.col.set(index, self.col.at(index).add(evaluation));
    }
};

/// Accumulates secure-column evaluations into a random linear combination:
/// `acc <- acc + alpha^(N-1-i) * eval_i` where columns are added in order.
pub const DomainEvaluationAccumulator = struct {
    allocator: std.mem.Allocator,
    max_log_size: u32,
    random_coeff_powers: []QM31,
    next_power_index: usize,
    sub_accumulations: []?SecureColumnByCoords,
    /// Candidate-only buckets whose values must be interpreted as polynomial
    /// evaluations and extended by one log before the ordinary canonical
    /// composition lift.  They are separate so ordinary q1 contributions can
    /// be merged once and transformed once, rather than allocating one q2
    /// column per component.
    polynomial_extension_accumulations: ?[]?SecureColumnByCoords = null,
    constant_accumulations: []QM31,
    polynomial_extension_active: bool = false,
    /// When true this accumulator owns `random_coeff_powers` and will free it
    /// on deinit. Sub-accumulators created via `initForComponent` borrow the
    /// parent's powers and set this to false.
    owns_powers: bool = true,

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
        const constants = try allocator.alloc(QM31, max_log_size + 1);
        errdefer allocator.free(constants);
        @memset(constants, QM31.zero());

        return .{
            .allocator = allocator,
            .max_log_size = max_log_size,
            .random_coeff_powers = powers,
            .next_power_index = powers.len,
            .sub_accumulations = subs,
            .constant_accumulations = constants,
            .owns_powers = true,
        };
    }

    pub fn deinit(self: *DomainEvaluationAccumulator) void {
        for (self.sub_accumulations) |*maybe_col| {
            if (maybe_col.*) |*col| col.deinit(self.allocator);
        }
        if (self.polynomial_extension_accumulations) |extensions| {
            for (extensions) |*maybe_col| {
                if (maybe_col.*) |*col| col.deinit(self.allocator);
            }
            self.allocator.free(extensions);
        }
        self.allocator.free(self.sub_accumulations);
        self.allocator.free(self.constant_accumulations);
        if (self.owns_powers) {
            self.allocator.free(self.random_coeff_powers);
        }
        self.* = undefined;
    }

    pub fn skipCoeffs(self: *DomainEvaluationAccumulator, n_coeffs: usize) AccumulationError!void {
        if (n_coeffs > self.next_power_index) return AccumulationError.NotEnoughCoefficients;
        self.next_power_index -= n_coeffs;
    }

    pub fn logSize(self: DomainEvaluationAccumulator) u32 {
        return self.max_log_size;
    }

    /// Selects true polynomial extension for values accumulated by the next
    /// component callback.  The caller must restore the mode after that
    /// callback returns.  Prepared callbacks may retain pointers into these
    /// buckets; only bucket selection, never their lifetime, is scoped here.
    pub fn beginPolynomialExtensionV1(
        self: *DomainEvaluationAccumulator,
    ) (std.mem.Allocator.Error || AccumulationError)!void {
        if (self.polynomial_extension_active)
            return error.NestedPolynomialExtension;
        if (self.polynomial_extension_accumulations == null) {
            const extensions = try self.allocator.alloc(
                ?SecureColumnByCoords,
                self.max_log_size + 1,
            );
            @memset(extensions, null);
            self.polynomial_extension_accumulations = extensions;
        }
        self.polynomial_extension_active = true;
    }

    pub fn endPolynomialExtensionV1(self: *DomainEvaluationAccumulator) void {
        std.debug.assert(self.polynomial_extension_active);
        self.polynomial_extension_active = false;
    }

    /// Returns mutable bucket accumulators for requested log sizes and allocates
    /// zero-initialized buckets when first accessed.
    ///
    /// Coefficients are assigned from the tail of the powers vector (upstream order).
    pub fn columns(
        self: *DomainEvaluationAccumulator,
        allocator: std.mem.Allocator,
        requests: []const ColumnRequest,
    ) (std.mem.Allocator.Error || AccumulationError)![]ColumnAccumulator {
        const out = try allocator.alloc(ColumnAccumulator, requests.len);
        errdefer allocator.free(out);

        for (requests, 0..) |request, i| {
            if (request.log_size > self.max_log_size) return AccumulationError.InvalidLogSize;
            if (request.n_cols > self.next_power_index) return AccumulationError.NotEnoughCoefficients;

            const buckets = if (self.polynomial_extension_active)
                self.polynomial_extension_accumulations.?
            else
                self.sub_accumulations;
            const fresh_bucket = buckets[request.log_size] == null;
            if (fresh_bucket) {
                buckets[request.log_size] = try SecureColumnByCoords.zeros(
                    self.allocator,
                    try checkedPow2(request.log_size),
                );
            }

            self.next_power_index -= request.n_cols;
            const start = self.next_power_index;
            const end = start + request.n_cols;
            out[i] = .{
                .random_coeff_powers = self.random_coeff_powers[start..end],
                .col = &buckets[request.log_size].?,
                .next_fresh_index = if (fresh_bucket) 0 else null,
            };
        }
        return out;
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

        if (constantColumnValue(evaluation)) |constant| {
            self.constant_accumulations[log_size] = self.constant_accumulations[log_size]
                .add(constant.mul(random_coeff));
            return;
        }

        const buckets = if (self.polynomial_extension_active)
            self.polynomial_extension_accumulations.?
        else
            self.sub_accumulations;
        if (buckets[log_size]) |*acc| {
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
            buckets[log_size] = out;
        }
    }

    /// Accumulates a constant polynomial without materializing a domain-sized
    /// column. Constants remain constant when lifted to larger domains.
    pub fn accumulateConstant(
        self: *DomainEvaluationAccumulator,
        log_size: u32,
        evaluation: QM31,
    ) AccumulationError!void {
        if (log_size > self.max_log_size) return AccumulationError.InvalidLogSize;
        if (self.next_power_index == 0) return AccumulationError.NotEnoughCoefficients;

        self.next_power_index -= 1;
        const random_coeff = self.random_coeff_powers[self.next_power_index];
        self.constant_accumulations[log_size] = self.constant_accumulations[log_size]
            .add(evaluation.mul(random_coeff));
    }

    /// Create a sub-accumulator that owns no memory and shares the pre-computed
    /// power slice of a parent accumulator. Intended for parallel evaluation:
    /// each worker gets its own sub-accumulator that writes to independent
    /// `sub_accumulations` but references the same `random_coeff_powers`.
    ///
    /// `start_power_index` is the value `next_power_index` should begin at for
    /// this component (i.e. the number of remaining powers when this component
    /// starts consuming). `n_powers` is how many powers this component will
    /// consume (== nConstraints).
    ///
    /// The returned accumulator borrows `random_coeff_powers` from the parent;
    /// it must NOT outlive the parent and its `deinit` frees only the
    /// sub_accumulations array (not the powers).
    pub fn initForComponent(
        parent_powers: []QM31,
        allocator: std.mem.Allocator,
        max_log_size: u32,
        start_power_index: usize,
    ) !DomainEvaluationAccumulator {
        const subs = try allocator.alloc(?SecureColumnByCoords, max_log_size + 1);
        errdefer allocator.free(subs);
        @memset(subs, null);
        const constants = try allocator.alloc(QM31, max_log_size + 1);
        errdefer allocator.free(constants);
        @memset(constants, QM31.zero());

        return .{
            .allocator = allocator,
            .max_log_size = max_log_size,
            .random_coeff_powers = parent_powers,
            .next_power_index = start_power_index,
            .sub_accumulations = subs,
            .constant_accumulations = constants,
            .owns_powers = false,
        };
    }

    /// Merge another accumulator's sub_accumulations into this one.
    /// Both accumulators must have the same max_log_size.
    /// After merge, `other`'s slots that were transferred are set to null
    /// so that `other.deinit()` will not double-free them.
    pub fn merge(self: *DomainEvaluationAccumulator, other: *DomainEvaluationAccumulator) void {
        for (0..self.sub_accumulations.len) |i| {
            self.constant_accumulations[i] = self.constant_accumulations[i]
                .add(other.constant_accumulations[i]);
            mergeBucketAt(self.sub_accumulations, other.sub_accumulations, i);
        }
        if (other.polynomial_extension_accumulations) |other_extensions| {
            if (self.polynomial_extension_accumulations) |self_extensions| {
                for (0..self_extensions.len) |i| {
                    mergeBucketAt(self_extensions, other_extensions, i);
                }
            } else {
                self.polynomial_extension_accumulations = other_extensions;
                other.polynomial_extension_accumulations = null;
            }
        }
    }

    pub fn hasPolynomialExtensions(self: *const DomainEvaluationAccumulator) bool {
        const extensions = self.polynomial_extension_accumulations orelse
            return false;
        for (extensions) |bucket| {
            if (bucket != null) return true;
        }
        return false;
    }

    /// Conservative resident reservation for aggregate extension.  Every
    /// source bucket may leave one target secure column resident, while only
    /// the largest target twiddle pair is live at a time.  One max-domain
    /// final output is reserved conservatively because distinct materialized
    /// buckets may need combination. Source buckets are already owned and
    /// accounted by the component preparation that created them.
    pub fn polynomialExtensionResourceBytes(
        self: *const DomainEvaluationAccumulator,
    ) !usize {
        var secure_bytes: usize = 0;
        var max_twiddle_bytes: usize = 0;
        const extensions = self.polynomial_extension_accumulations orelse
            return 0;
        for (extensions, 0..) |bucket, source_log_usize| {
            if (bucket == null) continue;
            const source_log: u32 = @intCast(source_log_usize);
            const target_log = std.math.add(u32, source_log, 1) catch
                return error.InvalidLogSize;
            if (target_log > self.max_log_size) return error.InvalidLogSize;
            const rows = try checkedPow2(target_log);
            const coordinate_values = std.math.mul(
                usize,
                rows,
                qm31.SECURE_EXTENSION_DEGREE,
            ) catch return error.InvalidLogSize;
            const target_bytes = std.math.mul(
                usize,
                coordinate_values,
                @sizeOf(M31),
            ) catch return error.InvalidLogSize;
            secure_bytes = std.math.add(usize, secure_bytes, target_bytes) catch
                return error.InvalidLogSize;
            // A canonic circle domain has a half-domain twiddle tree.  Its
            // twiddles and inverse twiddles together contain exactly `rows`
            // base-field elements.
            const twiddle_bytes = std.math.mul(
                usize,
                rows,
                @sizeOf(M31),
            ) catch return error.InvalidLogSize;
            max_twiddle_bytes = @max(max_twiddle_bytes, twiddle_bytes);
        }
        if (secure_bytes != 0) {
            const final_rows = try checkedPow2(self.max_log_size);
            const final_values = std.math.mul(
                usize,
                final_rows,
                qm31.SECURE_EXTENSION_DEGREE,
            ) catch return error.InvalidLogSize;
            const final_bytes = std.math.mul(
                usize,
                final_values,
                @sizeOf(M31),
            ) catch return error.InvalidLogSize;
            secure_bytes = std.math.add(usize, secure_bytes, final_bytes) catch
                return error.InvalidLogSize;
        }
        return std.math.add(usize, secure_bytes, max_twiddle_bytes) catch
            error.InvalidLogSize;
    }

    /// Lifts all sub-accumulations to max domain size and sums them coordinate-wise.
    pub fn finalize(self: *DomainEvaluationAccumulator) anyerror!SecureColumnByCoords {
        if (self.next_power_index != 0) return AccumulationError.UnusedCoefficients;
        try self.materializePolynomialExtensions();

        const max_size = try checkedPow2(self.max_log_size);
        var constant = QM31.zero();
        for (self.constant_accumulations) |value| constant = constant.add(value);

        var nonconstant_count: usize = 0;
        var only_nonconstant_log_size: usize = 0;
        for (self.sub_accumulations, 0..) |maybe_sub, log_size| {
            if (maybe_sub != null) {
                nonconstant_count += 1;
                only_nonconstant_log_size = log_size;
            }
        }
        const has_nonconstant = nonconstant_count != 0;

        // A sole bucket already on the final domain has the exact requested
        // representation. Transfer its ownership instead of allocating,
        // zeroing, lifting, and adding into an identical-sized column.
        if (nonconstant_count == 1 and only_nonconstant_log_size == self.max_log_size) {
            var out = self.sub_accumulations[only_nonconstant_log_size].?;
            self.sub_accumulations[only_nonconstant_log_size] = null;
            if (!constant.eql(QM31.zero())) {
                for (0..max_size) |position| {
                    out.set(position, out.at(position).add(constant));
                }
            }
            return out;
        }

        var out = if (has_nonconstant)
            try SecureColumnByCoords.zeros(self.allocator, max_size)
        else blk: {
            const constant_out = try SecureColumnByCoords.uninitialized(self.allocator, max_size);
            const coordinates = constant.toM31Array();
            inline for (0..4) |coordinate| {
                @memset(constant_out.columns[coordinate], coordinates[coordinate]);
            }
            break :blk constant_out;
        };
        errdefer out.deinit(self.allocator);

        for (self.sub_accumulations, 0..) |maybe_sub, log_size_usize| {
            const sub = maybe_sub orelse continue;
            const log_size: u32 = @intCast(log_size_usize);
            for (0..max_size) |position| {
                const lifted = try liftedValueAt(sub, log_size, self.max_log_size, position);
                out.set(position, out.at(position).add(lifted));
            }
        }

        if (has_nonconstant and !constant.eql(QM31.zero())) {
            for (0..max_size) |position| {
                out.set(position, out.at(position).add(constant));
            }
        }

        return out;
    }

    /// Writes the finalized composition into caller-owned max-domain storage
    /// without allocating. This is the structured-scheduler boundary: callers
    /// can reserve the only possible general-case output before worker launch,
    /// then merge independent accumulators and finish infallibly with respect
    /// to allocation.
    ///
    /// `out` must not alias an accumulator-owned bucket. Its ownership remains
    /// with the caller, while `self` retains ownership of every bucket. Contract
    /// validation completes before `out` is modified.
    pub fn finalizeInto(
        self: *const DomainEvaluationAccumulator,
        out: *SecureColumnByCoords,
    ) AccumulationError!void {
        if (self.next_power_index != 0) return AccumulationError.UnusedCoefficients;
        if (self.hasPolynomialExtensions())
            return AccumulationError.PolynomialExtensionRequiresAllocation;
        const max_size = try checkedPow2(self.max_log_size);
        if (out.len() != max_size) return AccumulationError.ShapeMismatch;

        var constant = QM31.zero();
        for (self.constant_accumulations) |value| constant = constant.add(value);
        const coordinates = constant.toM31Array();
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            @memset(out.columns[coordinate], coordinates[coordinate]);
        }
        for (self.sub_accumulations, 0..) |maybe_sub, log_size_usize| {
            const sub = maybe_sub orelse continue;
            const log_size: u32 = @intCast(log_size_usize);
            for (0..max_size) |position| {
                const lifted = try liftedValueAt(sub, log_size, self.max_log_size, position);
                out.set(position, out.at(position).add(lifted));
            }
        }
    }

    fn materializePolynomialExtensions(
        self: *DomainEvaluationAccumulator,
    ) anyerror!void {
        const extensions = self.polynomial_extension_accumulations orelse
            return;
        for (extensions, 0..) |*maybe_source, source_log_usize| {
            if (maybe_source.* == null) continue;
            const source_log: u32 = @intCast(source_log_usize);
            const target_log = std.math.add(u32, source_log, 1) catch
                return error.InvalidLogSize;
            if (target_log > self.max_log_size) return error.InvalidLogSize;

            var extended = try extendPolynomialEvaluationOneLog(
                self.allocator,
                source_log,
                maybe_source,
            );
            errdefer extended.deinit(self.allocator);

            if (self.sub_accumulations[target_log]) |*target| {
                if (target.len() != extended.len()) return error.ShapeMismatch;
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    for (target.columns[coordinate], extended.columns[coordinate]) |*dst, value| {
                        dst.* = dst.add(value);
                    }
                }
                extended.deinit(self.allocator);
            } else {
                self.sub_accumulations[target_log] = extended;
            }
        }
        self.allocator.free(extensions);
        self.polynomial_extension_accumulations = null;
    }
};

fn mergeBucketAt(
    destination: []?SecureColumnByCoords,
    source: []?SecureColumnByCoords,
    index: usize,
) void {
    if (source[index]) |*source_column| {
        if (destination[index]) |*destination_column| {
            const col_len = destination_column.len();
            std.debug.assert(source_column.len() == col_len);
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                for (destination_column.columns[coordinate], source_column.columns[coordinate]) |*dst, value| {
                    dst.* = dst.add(value);
                }
            }
        } else {
            destination[index] = source[index];
            source[index] = null;
        }
    }
}

/// Re-evaluates the unique degree-bounded polynomial represented by `source`
/// on the next canonic circle domain.  This is intentionally not the
/// accumulator's repeated-index lift: it performs a real inverse transform,
/// zero-pads the coefficient buffer, and then performs the wider transform.
fn extendPolynomialEvaluationOneLog(
    allocator: std.mem.Allocator,
    source_log: u32,
    source_slot: *?SecureColumnByCoords,
) anyerror!SecureColumnByCoords {
    var source = source_slot.* orelse return error.ShapeMismatch;
    const source_domain = canonic.CanonicCoset.new(source_log).circleDomain();
    if (source.len() != source_domain.size()) return error.ShapeMismatch;
    const target_log = std.math.add(u32, source_log, 1) catch
        return error.InvalidLogSize;
    const target_domain = canonic.CanonicCoset.new(target_log).circleDomain();

    var target = try SecureColumnByCoords.uninitialized(
        allocator,
        target_domain.size(),
    );
    errdefer target.deinit(allocator);
    var coefficient_buffers: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        @memcpy(target.columns[coordinate][0..source.len()], source.columns[coordinate]);
        @memset(
            target.columns[coordinate][source.len()..],
            M31.zero(),
        );
        coefficient_buffers[coordinate] = target.columns[coordinate][0..source.len()];
    }
    // The target now contains a complete copy of the source evaluations. Drop
    // the q1 bucket before allocating either twiddle tree so the aggregate
    // candidate path never retains both secure domains during the FFTs.
    source.deinit(allocator);
    source_slot.* = null;

    {
        var source_twiddles = try prover_twiddles.precomputeM31(
            allocator,
            source_domain.half_coset,
        );
        defer prover_twiddles.deinitM31(allocator, &source_twiddles);
        try prover_poly.interpolateBuffersWithTwiddles(
            &coefficient_buffers,
            source_domain,
            prover_twiddles.TwiddleTree([]const M31).init(
                source_twiddles.root_coset,
                source_twiddles.twiddles,
                source_twiddles.itwiddles,
            ),
        );
    }

    var target_twiddles = try prover_twiddles.precomputeM31(
        allocator,
        target_domain.half_coset,
    );
    defer prover_twiddles.deinitM31(allocator, &target_twiddles);
    try prover_poly.evaluateBuffersWithTwiddles(
        &target.columns,
        target_domain,
        prover_twiddles.TwiddleTree([]const M31).init(
            target_twiddles.root_coset,
            target_twiddles.twiddles,
            target_twiddles.itwiddles,
        ),
    );
    return target;
}

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
    const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);
    const idx = ((position >> shift_amt) << 1) + (position & 1);
    if (idx >= column.len()) return AccumulationError.ShapeMismatch;
    return column.at(idx);
}

fn checkedPow2(log_size: u32) AccumulationError!usize {
    if (log_size >= @bitSizeOf(usize)) return AccumulationError.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn constantColumnValue(column: *const SecureColumnByCoords) ?QM31 {
    std.debug.assert(column.len() != 0);
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        const values = column.columns[coordinate];
        const first = values[0];
        for (values[1..]) |value| {
            if (!value.eql(first)) return null;
        }
    }
    return column.at(0);
}

test "prover air accumulation: polynomial extension is allocated and resource accounted" {
    const allocator = std.testing.allocator;
    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    var source = try SecureColumnByCoords.fromSecureSlice(allocator, &values);
    defer source.deinit(allocator);

    var accumulator = try DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(7, 0, 0, 0),
        3,
        1,
    );
    defer accumulator.deinit();
    try accumulator.beginPolynomialExtensionV1();
    try accumulator.accumulateColumn(2, &source);
    accumulator.endPolynomialExtensionV1();
    try std.testing.expect(accumulator.hasPolynomialExtensions());
    // target secure column: 8 rows * 4 coords * 4B = 128B;
    // target twiddle pair: 8 base values * 4B = 32B;
    // conservative final output: another 128B.
    try std.testing.expectEqual(
        @as(usize, 288),
        try accumulator.polynomialExtensionResourceBytes(),
    );

    var caller_owned = try SecureColumnByCoords.uninitialized(allocator, 8);
    defer caller_owned.deinit(allocator);
    try std.testing.expectError(
        error.PolynomialExtensionRequiresAllocation,
        accumulator.finalizeInto(&caller_owned),
    );

    var extended = try accumulator.finalize();
    defer extended.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 8), extended.len());
    try std.testing.expect(!accumulator.hasPolynomialExtensions());
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
    const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);
    for (combined_vec, 0..) |value, position| {
        const idx_small = ((position >> shift_amt) << 1) + (position & 1);
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

test "prover air accumulation: columns API assigns tail coefficient chunks" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(2, 0, 0, 0);

    var acc = try DomainEvaluationAccumulator.init(alloc, alpha, 2, 3);
    defer acc.deinit();

    const requests = [_]ColumnRequest{
        .{ .log_size = 1, .n_cols = 2 },
        .{ .log_size = 2, .n_cols = 1 },
    };
    const cols = try acc.columns(alloc, requests[0..]);
    defer alloc.free(cols);

    try std.testing.expectEqual(@as(u32, 2), acc.logSize());
    try std.testing.expectEqual(@as(usize, 2), cols[0].random_coeff_powers.len);
    try std.testing.expectEqual(@as(usize, 1), cols[1].random_coeff_powers.len);
    try std.testing.expect(cols[0].random_coeff_powers[0].eql(alpha));
    try std.testing.expect(cols[0].random_coeff_powers[1].eql(alpha.square()));
    try std.testing.expect(cols[1].random_coeff_powers[0].eql(QM31.one()));

    var col0 = cols[0];
    var col1 = cols[1];
    col0.accumulate(0, QM31.fromU32Unchecked(7, 0, 0, 0));
    col0.accumulate(0, QM31.fromU32Unchecked(5, 0, 0, 0));
    col1.accumulate(3, QM31.fromU32Unchecked(9, 0, 0, 0));

    try std.testing.expect(col0.col.at(0).eql(QM31.fromU32Unchecked(12, 0, 0, 0)));
    try std.testing.expect(col1.col.at(3).eql(QM31.fromU32Unchecked(9, 0, 0, 0)));
}

test "prover air accumulation: finalize transfers sole max-domain bucket" {
    const alloc = std.testing.allocator;
    var acc = try DomainEvaluationAccumulator.init(
        alloc,
        QM31.fromU32Unchecked(3, 0, 0, 0),
        3,
        1,
    );
    defer acc.deinit();

    const cols = try acc.columns(alloc, &.{.{ .log_size = 3, .n_cols = 1 }});
    defer alloc.free(cols);
    var column = cols[0];
    for (0..8) |index| {
        column.accumulate(index, QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0));
    }
    const original_ptr = column.col.columns[0].ptr;

    var out = try acc.finalize();
    defer out.deinit(alloc);
    try std.testing.expectEqual(original_ptr, out.columns[0].ptr);
    for (0..8) |index| {
        try std.testing.expect(out.at(index).eql(
            QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0),
        ));
    }
}

test "prover air accumulation: merge combines sub_accumulations" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 0, 0, 0);

    // Create two accumulators that accumulate into the same log_size bucket
    // using initForComponent with pre-assigned power indices.
    const total_constraints: usize = 2;
    const powers = try generateSecurePowers(alloc, alpha, total_constraints);
    defer alloc.free(powers);

    // Accumulator A gets power index 2 (will consume 1 -> lands at index 1 = alpha)
    var acc_a = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 2, 2);
    defer acc_a.deinit();

    // Accumulator B gets power index 1 (will consume 1 -> lands at index 0 = 1)
    var acc_b = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 2, 1);
    defer acc_b.deinit();

    const vals_a = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    const vals_b = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(20, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
        QM31.fromU32Unchecked(40, 0, 0, 0),
    };

    var col_a = try SecureColumnByCoords.fromSecureSlice(alloc, vals_a[0..]);
    defer col_a.deinit(alloc);
    var col_b = try SecureColumnByCoords.fromSecureSlice(alloc, vals_b[0..]);
    defer col_b.deinit(alloc);

    try acc_a.accumulateColumn(2, &col_a);
    try acc_b.accumulateColumn(2, &col_b);

    // Merge B into A
    acc_a.merge(&acc_b);

    // After merge, force next_power_index = 0 for finalize
    acc_a.next_power_index = 0;
    var combined = try acc_a.finalize();
    defer combined.deinit(alloc);

    // Also compute the sequential reference
    var ref_acc = try DomainEvaluationAccumulator.init(alloc, alpha, 2, 2);
    defer ref_acc.deinit();
    try ref_acc.accumulateColumn(2, &col_a);
    try ref_acc.accumulateColumn(2, &col_b);
    var ref_combined = try ref_acc.finalize();
    defer ref_combined.deinit(alloc);

    // Compare
    const combined_vec = try combined.toVec(alloc);
    defer alloc.free(combined_vec);
    const ref_vec = try ref_combined.toVec(alloc);
    defer alloc.free(ref_vec);

    try std.testing.expectEqual(combined_vec.len, ref_vec.len);
    for (combined_vec, ref_vec) |c, r| {
        try std.testing.expect(c.eql(r));
    }
}

test "prover air accumulation: merge transfers ownership for empty slots" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(2, 0, 0, 0);

    const total_constraints: usize = 2;
    const powers = try generateSecurePowers(alloc, alpha, total_constraints);
    defer alloc.free(powers);

    // A writes to log_size 3, B writes to log_size 2 -> non-overlapping buckets
    var acc_a = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 3, 2);
    defer acc_a.deinit();
    var acc_b = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 3, 1);
    defer acc_b.deinit();

    const large_vals = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(6, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(8, 0, 0, 0),
    };
    const small_vals = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(20, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
        QM31.fromU32Unchecked(40, 0, 0, 0),
    };

    var col_large = try SecureColumnByCoords.fromSecureSlice(alloc, large_vals[0..]);
    defer col_large.deinit(alloc);
    var col_small = try SecureColumnByCoords.fromSecureSlice(alloc, small_vals[0..]);
    defer col_small.deinit(alloc);

    try acc_a.accumulateColumn(3, &col_large);
    try acc_b.accumulateColumn(2, &col_small);

    // Merge B into A: A has log_size 3 only, B has log_size 2 only
    // So B's log_size=2 slot should be transferred to A.
    acc_a.merge(&acc_b);

    // B's slot should now be null (ownership transferred)
    try std.testing.expect(acc_b.sub_accumulations[2] == null);
    // A should now have both
    try std.testing.expect(acc_a.sub_accumulations[3] != null);
    try std.testing.expect(acc_a.sub_accumulations[2] != null);
}

test "prover air accumulation: constants match materialized columns after merge" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 1, 0, 0);
    const value_a = QM31.fromU32Unchecked(7, 2, 1, 0);
    const value_b = QM31.fromU32Unchecked(11, 0, 4, 1);

    const powers = try generateSecurePowers(alloc, alpha, 2);
    defer alloc.free(powers);
    var acc_a = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 3, 2);
    defer acc_a.deinit();
    var acc_b = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 3, 1);
    defer acc_b.deinit();
    try acc_a.accumulateConstant(3, value_a);
    try acc_b.accumulateConstant(2, value_b);
    acc_a.merge(&acc_b);
    acc_a.next_power_index = 0;
    var combined = try acc_a.finalize();
    defer combined.deinit(alloc);

    var reference = try DomainEvaluationAccumulator.init(alloc, alpha, 3, 2);
    defer reference.deinit();
    const values_a = [_]QM31{value_a} ** 8;
    const values_b = [_]QM31{value_b} ** 4;
    var col_a = try SecureColumnByCoords.fromSecureSlice(alloc, &values_a);
    defer col_a.deinit(alloc);
    var col_b = try SecureColumnByCoords.fromSecureSlice(alloc, &values_b);
    defer col_b.deinit(alloc);
    try reference.accumulateColumn(3, &col_a);
    try reference.accumulateColumn(2, &col_b);
    var expected = try reference.finalize();
    defer expected.deinit(alloc);

    for (0..combined.len()) |row| {
        try std.testing.expect(combined.at(row).eql(expected.at(row)));
    }
}

test "prover air accumulation: constant columns bypass domain buckets" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 1, 0, 0);
    const constant = QM31.fromU32Unchecked(7, 2, 1, 0);
    const constant_values = [_]QM31{constant} ** 8;
    const varying_values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(6, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(8, 0, 0, 0),
    };
    var constant_column = try SecureColumnByCoords.fromSecureSlice(alloc, &constant_values);
    defer constant_column.deinit(alloc);
    var varying_column = try SecureColumnByCoords.fromSecureSlice(alloc, &varying_values);
    defer varying_column.deinit(alloc);

    try std.testing.expect(constantColumnValue(&constant_column).?.eql(constant));
    try std.testing.expectEqual(null, constantColumnValue(&varying_column));

    var acc = try DomainEvaluationAccumulator.init(alloc, alpha, 3, 2);
    defer acc.deinit();
    try acc.accumulateColumn(3, &constant_column);
    try std.testing.expect(acc.sub_accumulations[3] == null);
    try acc.accumulateColumn(3, &varying_column);
    try std.testing.expect(acc.sub_accumulations[3] != null);

    var combined = try acc.finalize();
    defer combined.deinit(alloc);
    for (0..combined.len()) |row| {
        const expected = constant.mul(alpha).add(varying_values[row]);
        try std.testing.expect(combined.at(row).eql(expected));
    }
}
