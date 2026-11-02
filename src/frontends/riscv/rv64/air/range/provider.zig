//! A fixed 256-row byte table. Counts are committed before alpha is drawn.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const physical = @import("../witness.zig").physical;
const E = @import("../evaluation.zig");
pub const LOG_SIZE: u32 = 8;
pub const SIZE: usize = 256;
pub const N_FIXED = 3;
pub const N_MAIN = 1;
pub const N_INTERACTION = 8;
pub const N_CONSTRAINTS = 4;

pub fn evaluate(value: Q, first: Q, last: Q, multiplicity: Q, inverse: Q, sum: Q, previous: Q, claim: Q, alpha: Q) [N_CONSTRAINTS]Q {
    return evaluateFor(Q, value, first, last, multiplicity, inverse, sum, previous, claim, alpha);
}
/// Same four residuals over any trace lane; alpha and the claim are constants.
pub fn evaluateFor(comptime F: type, value: F, first: F, last: F, multiplicity: F, inverse: E.SecureFor(F), sum: E.SecureFor(F), previous: E.SecureFor(F), claim: E.ConstFor(F), alpha: E.ConstFor(F)) [N_CONSTRAINTS]E.SecureFor(F) {
    const term = E.mulBaseFor(F, inverse, multiplicity);
    return .{
        inverse.mul(E.splatFor(F, alpha).sub(E.liftFor(F, value))).sub(E.SecureFor(F).one()),
        sum.sub(previous).add(E.mulBaseFor(F, previous, first)).add(term),
        E.mulBaseFor(F, sum.add(term), first),
        E.mulBaseFor(F, sum.sub(E.splatFor(F, claim)), last),
    };
}

pub const Trace = struct {
    allocator: std.mem.Allocator,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    claim: Q = Q.zero(),

    /// Counts must be ordinary bounded integers; reduction modulo M31 is forbidden.
    pub fn init(a: std.mem.Allocator, counts: *const [SIZE]u64) !Trace {
        var total: u64 = 0;
        for (counts) |count| {
            total = std.math.add(u64, total, count) catch return error.InvalidByteMultiplicity;
            if (total >= core.fields.m31.Modulus) return error.InvalidByteMultiplicity;
        }
        const fixed = try a.alloc(M, N_FIXED * SIZE);
        errdefer a.free(fixed);
        const main = try a.alloc(M, SIZE);
        errdefer a.free(main);
        @memset(fixed, M.zero());
        for (counts, 0..) |count, i| {
            const row = physical(i, LOG_SIZE);
            fixed[row] = M.fromCanonical(@intCast(i));
            fixed[SIZE + row] = M.fromCanonical(@intFromBool(i == 0));
            fixed[2 * SIZE + row] = M.fromCanonical(@intFromBool(i == SIZE - 1));
            main[row] = M.fromCanonical(@intCast(count));
        }
        return .{ .allocator = a, .fixed = fixed, .main = main };
    }
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.fixed);
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn generateInteraction(self: *Trace, alpha: Q) !Q {
        if (self.interaction.len != 0) return error.InvalidByteProviderPhase;
        const data = try self.allocator.alloc(M, N_INTERACTION * SIZE);
        errdefer self.allocator.free(data);
        var sum = Q.zero();
        for (0..SIZE) |i| {
            const row = physical(i, LOG_SIZE);
            const inverse = try alpha.sub(Q.fromBase(self.fixed[row])).inv();
            sum = sum.sub(inverse.mulM31(self.main[row]));
            store(data, row, 0, inverse);
            store(data, row, 4, sum);
        }
        self.interaction = data;
        self.claim = sum;
        return sum;
    }
    pub fn columns(self: *const Trace, a: std.mem.Allocator, tree: u2) ![]@import("stwo_prover_engine").pcs.ColumnEvaluation {
        const storage = switch (tree) {
            0 => self.fixed,
            1 => self.main,
            2 => self.interaction,
            else => return error.InvalidByteProviderTree,
        };
        const result = try a.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, storage.len / SIZE);
        for (result, 0..) |*column, i| column.* = .{ .log_size = LOG_SIZE, .values = storage[i * SIZE ..][0..SIZE] };
        return result;
    }
};
fn store(data: []M, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| data[(column + i) * SIZE + row] = coordinate;
}
pub fn secure(data: []const M, row: usize, column: usize) Q {
    return Q.fromM31(data[column * SIZE + row], data[(column + 1) * SIZE + row], data[(column + 2) * SIZE + row], data[(column + 3) * SIZE + row]);
}

test "byte provider closes nonuniform multiplicities and rejects forged prefixes" {
    var counts: [SIZE]u64 = @splat(0);
    counts[0] = 7;
    counts[17] = 123;
    counts[255] = 3;
    var trace = try Trace.init(std.testing.allocator, &counts);
    defer trace.deinit();
    const alpha = Q.fromU32Unchecked(911, 3, 5, 7);
    const claim = try trace.generateInteraction(alpha);
    var consumer = Q.zero();
    for (counts, 0..) |count, i| consumer = consumer.add((try alpha.sub(Q.fromBase(M.fromCanonical(@intCast(i)))).inv()).mulM31(M.fromCanonical(@intCast(count))));
    try std.testing.expect(consumer.add(claim).isZero());
    for (0..SIZE) |i| {
        const row = physical(i, LOG_SIZE);
        const previous = physical((i + SIZE - 1) % SIZE, LOG_SIZE);
        const constraints = evaluate(Q.fromBase(trace.fixed[row]), Q.fromBase(trace.fixed[SIZE + row]), Q.fromBase(trace.fixed[2 * SIZE + row]), Q.fromBase(trace.main[row]), secure(trace.interaction, row, 0), secure(trace.interaction, row, 4), secure(trace.interaction, previous, 4), claim, alpha);
        for (constraints) |value| try std.testing.expect(value.isZero());
    }
    const row0 = physical(0, LOG_SIZE);
    const bad = evaluate(Q.zero(), Q.one(), Q.zero(), Q.fromBase(trace.main[row0]), secure(trace.interaction, row0, 0), secure(trace.interaction, row0, 4).add(Q.one()), claim, claim, alpha);
    try std.testing.expect(!bad[1].isZero());
    try std.testing.expect(!bad[2].isZero());
    const last = physical(255, LOG_SIZE);
    const terminal = evaluate(Q.fromBase(M.fromCanonical(255)), Q.zero(), Q.one(), Q.fromBase(trace.main[last]), secure(trace.interaction, last, 0), claim, Q.zero(), claim.add(Q.one()), alpha);
    try std.testing.expect(!terminal[3].isZero());
    counts[5] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidByteMultiplicity, Trace.init(std.testing.allocator, &counts));
}
