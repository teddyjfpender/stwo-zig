const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const lookup_utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const MleError = error{
    NotPowerOfTwo,
    PointDimensionMismatch,
};

/// Multilinear extension values in bit-reversed order.
///
/// Inputs/outputs:
/// - stores evaluations over the boolean hypercube; length must be a non-zero power of two.
/// - `fixFirstVariable` maps an `Mle(F)` to `Mle(QM31)` by fixing the first variable.
///
/// Invariants:
/// - `evals.len` is always a non-zero power of two.
///
/// Failure modes:
/// - construction fails with `NotPowerOfTwo` on invalid length.
/// - `evalAtPoint` fails with `PointDimensionMismatch` if point arity differs from `nVariables`.
pub fn Mle(comptime F: type) type {
    return struct {
        evals: []F,
        owns_evals: bool = true,

        const Self = @This();

        pub fn initOwned(evals: []F) MleError!Self {
            if (evals.len == 0 or !std.math.isPowerOfTwo(evals.len)) return MleError.NotPowerOfTwo;
            return .{
                .evals = evals,
                .owns_evals = true,
            };
        }

        pub fn initBorrowed(evals: []F) MleError!Self {
            if (evals.len == 0 or !std.math.isPowerOfTwo(evals.len)) return MleError.NotPowerOfTwo;
            return .{
                .evals = evals,
                .owns_evals = false,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.owns_evals) allocator.free(self.evals);
            self.* = undefined;
        }

        pub fn cloneOwned(self: Self, allocator: std.mem.Allocator) !Self {
            return try Self.initOwned(try allocator.dupe(F, self.evals));
        }

        pub fn evalsSlice(self: Self) []const F {
            return self.evals;
        }

        pub fn nVariables(self: Self) usize {
            return std.math.log2_int(usize, self.evals.len);
        }

        pub fn intoOwnedEvals(self: *Self) []F {
            std.debug.assert(self.owns_evals);
            const out = self.evals;
            self.evals = &[_]F{};
            self.owns_evals = false;
            return out;
        }

        pub fn fixFirstVariable(
            self: Self,
            allocator: std.mem.Allocator,
            assignment: QM31,
        ) !Mle(QM31) {
            const half = self.evals.len / 2;
            const out = try allocator.alloc(QM31, half);
            for (0..half) |i| {
                const lhs = asSecure(F, self.evals[i]);
                const rhs = asSecure(F, self.evals[i + half]);
                out[i] = lookup_utils.foldMleEvals(QM31, assignment, lhs, rhs);
            }
            return try Mle(QM31).initOwned(out);
        }

        /// Evaluates the multilinear extension at `point`.
        pub fn evalAtPoint(
            self: Self,
            allocator: std.mem.Allocator,
            point: []const QM31,
        ) (std.mem.Allocator.Error || MleError)!QM31 {
            if (point.len != self.nVariables()) return MleError.PointDimensionMismatch;

            var buffer = try allocator.alloc(QM31, self.evals.len);
            defer allocator.free(buffer);
            for (self.evals, 0..) |value, i| {
                buffer[i] = asSecure(F, value);
            }

            var active_len = buffer.len;
            for (point) |assignment| {
                const half = active_len / 2;
                for (0..half) |i| {
                    buffer[i] = lookup_utils.foldMleEvals(
                        QM31,
                        assignment,
                        buffer[i],
                        buffer[i + half],
                    );
                }
                active_len = half;
            }
            return buffer[0];
        }
    };
}

fn asSecure(comptime F: type, value: F) QM31 {
    if (F == QM31) return value;
    if (F == M31) return QM31.fromBase(value);
    @compileError("Mle currently supports M31 and QM31 fields");
}

test "mle: init validates power-of-two length" {
    const alloc = std.testing.allocator;
    const MleM31 = Mle(M31);

    try std.testing.expectError(
        MleError.NotPowerOfTwo,
        MleM31.initOwned(try alloc.alloc(M31, 0)),
    );

    const bad = try alloc.alloc(M31, 3);
    defer alloc.free(bad);
    @memset(bad, M31.zero());
    try std.testing.expectError(MleError.NotPowerOfTwo, MleM31.initOwned(bad));
}

test "mle: fix first variable preserves evaluation semantics" {
    const alloc = std.testing.allocator;
    const MleSecure = Mle(QM31);

    const evals = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    var mle = try MleSecure.initOwned(try alloc.dupe(QM31, evals[0..]));
    defer mle.deinit(alloc);

    const first_assignment = QM31.fromU32Unchecked(5, 0, 0, 0);
    var fixed = try mle.fixFirstVariable(alloc, first_assignment);
    defer fixed.deinit(alloc);

    const second_assignment = QM31.fromU32Unchecked(7, 0, 0, 0);

    const original_eval = try mle.evalAtPoint(
        alloc,
        &[_]QM31{ first_assignment, second_assignment },
    );
    const fixed_eval = try fixed.evalAtPoint(alloc, &[_]QM31{second_assignment});

    try std.testing.expect(original_eval.eql(fixed_eval));
}

test "mle: fix first variable lifts base-field mle" {
    const alloc = std.testing.allocator;
    const MleBase = Mle(M31);

    const evals = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(5),
        M31.fromCanonical(9),
        M31.fromCanonical(13),
    };
    var mle = try MleBase.initOwned(try alloc.dupe(M31, evals[0..]));
    defer mle.deinit(alloc);

    const assignment = QM31.fromU32Unchecked(3, 0, 0, 0);
    var fixed = try mle.fixFirstVariable(alloc, assignment);
    defer fixed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), fixed.evalsSlice().len);

    const expected0 = assignment
        .mul(QM31.fromBase(evals[2].sub(evals[0])))
        .add(QM31.fromBase(evals[0]));
    const expected1 = assignment
        .mul(QM31.fromBase(evals[3].sub(evals[1])))
        .add(QM31.fromBase(evals[1]));

    try std.testing.expect(fixed.evalsSlice()[0].eql(expected0));
    try std.testing.expect(fixed.evalsSlice()[1].eql(expected1));
}

test "mle: evalAtPoint validates dimensions" {
    const alloc = std.testing.allocator;
    const MleSecure = Mle(QM31);

    const evals = [_]QM31{
        QM31.one(),
        QM31.one(),
        QM31.one(),
        QM31.one(),
    };
    var mle = try MleSecure.initOwned(try alloc.dupe(QM31, evals[0..]));
    defer mle.deinit(alloc);

    try std.testing.expectError(
        MleError.PointDimensionMismatch,
        mle.evalAtPoint(alloc, &[_]QM31{QM31.one()}),
    );
}
