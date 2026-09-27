//! A separately committed range16 table supplies all packed integer limbs.
//! Its value column is recomputed by the receiver, never selected by a proof.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const range = @import("block_v5_range16_v1.zig");
const rows = @import("../air/block/memory_component_trace.zig");
const algebra = @import("block_v5_range16_algebra_v1.zig");
pub const Claim = struct { sum: Q, count: u64 };
pub const Spec = struct {
    pub const SECURE_POLYNOMIAL_KIND: @import("stwo_prover_engine").air.secure_polynomial_program_v1.Kind = .range16_equations_v4;
    pub fn exportSecurePolynomial(self: Spec, a: std.mem.Allocator, size: u32) !@import("stwo_prover_engine").air.secure_polynomial_program_v1.Program {
        if (size != range.TABLE_SIZE) return error.InvalidV5Range16Claim;
        return @import("block_v5_word_gpu_program_v1.zig").rangeEquations(a, self);
    }
    pub const FIXED_COUNT = 1;
    pub const MAIN_COUNT = 1;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = .{false};
    pub fn previousMainNeeded(index: usize) bool {
        return PREVIOUS_MAIN_MASK[index];
    }
    pub const INTERACTION_COUNT = 8;
    pub const CONSTRAINT_COUNT = 2;
    pub const DEGREE = 2;
    pub const EXPANSION_BITS = 1;
    claim: Claim,
    challenges: *const protocol.Challenges,
    pub const Domain = struct {
        spec: Spec,
        sum: Q,
        count: Q,
        packed_sum: P,
        packed_count: P,
        packed_challenges: @import("block_v5_word_packed_challenges_v1.zig").Challenges,
        pub fn evaluate(self: Domain, fixed: [1]Q, main: [1]Q, _: [1]Q, current: [8]Q, previous: [8]Q, _: u32) ![2]Q {
            return algebra.equations(Q, fixed, main, current, previous, self.sum, self.count, self.spec.challenges.range16);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [1]P, main: [1]P, _: [1]P, current: [8]P, previous: [8]P) [2]P {
            @setEvalBranchQuota(200000);
            return algebra.equations(P, fixed, main, current, previous, self.packed_sum, self.packed_count, self.packed_challenges.range16);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        if (size != range.TABLE_SIZE or self.claim.count >= core.fields.m31.Modulus) return error.InvalidV5Range16Claim;
        const inverse = try M.fromCanonical(size).inv();
        const sum = self.claim.sum.mulM31(inverse);
        const count = Q.fromBase(M.fromCanonical(@intCast(self.claim.count))).mulM31(inverse);
        return .{ .spec = self, .sum = sum, .count = count, .packed_sum = P.splat(sum), .packed_count = P.splat(count), .packed_challenges = .init(self.challenges) };
    }
    pub fn evaluate(self: Spec, fixed: [1]Q, main: [1]Q, _: [1]Q, current: [8]Q, previous: [8]Q, size: u32) ![2]Q {
        if (size != range.TABLE_SIZE or self.claim.count >= core.fields.m31.Modulus) return error.InvalidV5Range16Claim;
        return algebra.equations(Q, fixed, main, current, previous, try self.claim.sum.divM31(M.fromCanonical(size)), try Q.fromBase(M.fromCanonical(@intCast(self.claim.count))).divM31(M.fromCanonical(size)), self.challenges.range16);
    }
};
pub const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
pub const Generated = struct {
    storage: []M,
    columns: [8][]M,
    claim: Claim,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
};
pub fn generate(a: std.mem.Allocator, counter: *const range.Counter, challenges: *const protocol.Challenges) !Generated {
    var table = try @import("block_v5_range16_inverse_table_v1.zig").Table.init(a, challenges.range16);
    defer table.deinit();
    return generatePrepared(a, counter, challenges, &table);
}
pub fn generatePrepared(a: std.mem.Allocator, counter: *const range.Counter, challenges: *const protocol.Challenges, table: *const @import("block_v5_range16_inverse_table_v1.zig").Table) !Generated {
    if (counter.total > range.MAX_REQUESTS or counter.values.len != range.TABLE_SIZE) return error.InvalidV5Range16Counter;
    try table.requireRelation(challenges.range16);
    const storage = try a.alloc(M, range.TABLE_SIZE * 8);
    errdefer a.free(storage);
    var columns: [8][]M = undefined;
    for (&columns, 0..) |*column, i| column.* = storage[i * range.TABLE_SIZE ..][0..range.TABLE_SIZE];
    var total = Q.zero();
    var observed: u64 = 0;
    for (counter.values, 0..) |multiplicity, index| {
        if (multiplicity >= core.fields.m31.Modulus) return error.InvalidV5Range16Counter;
        observed = try std.math.add(u64, observed, multiplicity);
        const fraction = if (multiplicity == 0) Q.zero() else (try table.inverse(@intCast(index))).mulM31(M.fromCanonical(multiplicity));
        total = total.add(fraction);
        write(&columns, 0, rows.committedRow(index, range.TABLE_LOG), fraction);
    }
    if (observed != counter.total) return error.InvalidV5Range16Counter;
    const sum_mean = try total.divM31(M.fromCanonical(range.TABLE_SIZE));
    const count_mean = try Q.fromBase(M.fromCanonical(@intCast(observed))).divM31(M.fromCanonical(range.TABLE_SIZE));
    var sums = [_]Q{ Q.zero(), Q.zero() };
    for (0..range.TABLE_SIZE) |logical| {
        const physical = rows.committedRow(logical, range.TABLE_LOG);
        sums[0] = sums[0].add(read(&columns, 0, physical)).sub(sum_mean);
        sums[1] = sums[1].add(Q.fromBase(M.fromCanonical(counter.values[logical]))).sub(count_mean);
        write(&columns, 0, physical, sums[0]);
        write(&columns, 4, physical, sums[1]);
    }
    if (!sums[0].isZero() or !sums[1].isZero()) return error.InvalidV5Range16Prefix;
    return .{ .storage = storage, .columns = columns, .claim = .{ .sum = total, .count = observed } };
}
fn secure(values: [8]Q, at: usize) Q {
    return Q.fromPartialEvals(values[at..][0..4].*);
}
fn read(columns: *const [8][]M, at: usize, row: usize) Q {
    return Q.fromM31Array(.{ columns[at][row], columns[at + 1][row], columns[at + 2][row], columns[at + 3][row] });
}
fn write(columns: *[8][]M, at: usize, row: usize, value: Q) void {
    for (value.toM31Array(), 0..) |limb, i| columns[at + i][row] = limb;
}
