const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
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
    return MleFor(QM31, F);
}

pub fn MleFor(comptime Secure: type, comptime F: type) type {
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

        /// Non-owning immutable view; source storage must outlive the view.
        pub fn borrowed(self: Self) Self {
            return .{ .evals = self.evals, .owns_evals = false };
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
            assignment: Secure,
        ) !MleFor(Secure, Secure) {
            const half = self.evals.len / 2;
            const out = try allocator.alloc(Secure, half);
            const Context = struct {
                input: []const F,
                output: []Secure,
                challenge: Secure,
                pub fn fillRange(ctx: @This(), first: usize, end: usize) void {
                    const tail = @import("packed_rows.zig").ForField(Secure).fold(F, ctx.input, ctx.output, ctx.challenge, first, end);
                    for (tail..end) |i| ctx.output[i] = lookup_utils.foldMleEvalsFor(Secure, F, ctx.challenge, ctx.input[i], ctx.input[i + ctx.output.len]);
                }
            };
            @import("row_work.zig").fill(half, Context{ .input = self.evals, .output = out, .challenge = assignment });
            return try MleFor(Secure, Secure).initOwned(out);
        }

        /// Destructively folds an exclusively owned secure vector into its
        /// prefix. Borrowed input is never mutated. On OOM the current owner
        /// remains valid for deinit, but owned prefix contents may have changed;
        /// callers must abort, not retry the failed oracle. Nonresizable
        /// allocators receive an ordinary half-sized owner via a bounded copy.
        pub fn foldOwnedSecure(self: *Self, allocator: std.mem.Allocator, assignment: Secure) !void {
            comptime if (F != Secure) @compileError("owned secure folding requires a secure MLE");
            if (self.evals.len == 1) return;
            if (!self.owns_evals) {
                self.* = try self.fixFirstVariable(allocator, assignment);
                return;
            }
            const input = self.evals;
            const half = input.len / 2;
            const Context = struct {
                input: []const Secure,
                output: []Secure,
                challenge: Secure,
                pub fn fillRange(ctx: @This(), first: usize, end: usize) void {
                    const tail = @import("packed_rows.zig").ForField(Secure).fold(Secure, ctx.input, ctx.output, ctx.challenge, first, end);
                    for (tail..end) |i| ctx.output[i] = lookup_utils.foldMleEvalsFor(Secure, Secure, ctx.challenge, ctx.input[i], ctx.input[i + ctx.output.len]);
                }
            };
            // Each output i reads only its own old prefix i and immutable
            // suffix i+half. Packed ranges never read another task's prefix.
            @import("row_work.zig").fill(half, Context{ .input = input, .output = input[0..half], .challenge = assignment });
            try self.finishOwnedFold(allocator);
        }

        fn finishOwnedFold(self: *Self, allocator: std.mem.Allocator) !void {
            const input = self.evals;
            const half = input.len / 2;
            if (allocator.resize(input, half)) {
                self.evals = input[0..half];
                return;
            }
            const output = try allocator.dupe(Secure, input[0..half]);
            allocator.free(input);
            self.evals = output;
        }

        /// One joined row wave for disjoint, exclusively owned numerator and
        /// denominator planes. The packed/scalar half-split fold is unchanged.
        /// On an allocation failure both owners remain valid for independent
        /// deinit, but their lengths may differ and prefixes may be mutated.
        /// Borrowed planes retain the immutable allocating fold path.
        pub fn foldOwnedSecurePair(self: *Self, other: *Self, allocator: std.mem.Allocator, assignment: Secure) !void {
            comptime if (F != Secure) @compileError("owned pair folding requires secure MLEs");
            if (self.evals.len != other.evals.len or self.evals.len == 0 or !std.math.isPowerOfTwo(self.evals.len)) return error.PairShapeMismatch;
            if (self == other) return error.AliasedMleOwners;
            if (self.owns_evals or other.owns_evals) {
                const bytes = std.math.mul(usize, self.evals.len, @sizeOf(Secure)) catch return error.InvalidOwnerRange;
                const start_a = @intFromPtr(self.evals.ptr);
                const start_b = @intFromPtr(other.evals.ptr);
                const end_a = std.math.add(usize, start_a, bytes) catch return error.InvalidOwnerRange;
                const end_b = std.math.add(usize, start_b, bytes) catch return error.InvalidOwnerRange;
                if (start_a < end_b and start_b < end_a) return error.AliasedMleOwners;
            }
            if (self.evals.len == 1) return;
            if (!self.owns_evals or !other.owns_evals) {
                try self.foldOwnedSecure(allocator, assignment);
                try other.foldOwnedSecure(allocator, assignment);
                return;
            }
            const Context = struct {
                inputs: [2][]const Secure,
                outputs: [2][]Secure,
                challenge: Secure,
                pub fn fillRange(ctx: @This(), first: usize, end: usize) void {
                    inline for (0..2) |plane| {
                        const tail = @import("packed_rows.zig").ForField(Secure).fold(Secure, ctx.inputs[plane], ctx.outputs[plane], ctx.challenge, first, end);
                        for (tail..end) |i| ctx.outputs[plane][i] = lookup_utils.foldMleEvalsFor(Secure, Secure, ctx.challenge, ctx.inputs[plane][i], ctx.inputs[plane][i + ctx.outputs[plane].len]);
                    }
                }
            };
            const half = self.evals.len / 2;
            // Every output reads its own prefix and immutable suffix only;
            // the checked disjoint plane owners exclude cross-plane races.
            @import("row_work.zig").fill(half, Context{ .inputs = .{ self.evals, other.evals }, .outputs = .{ self.evals[0..half], other.evals[0..half] }, .challenge = assignment });
            try self.finishOwnedFold(allocator);
            try other.finishOwnedFold(allocator);
        }

        /// Returns `f(x_0) = sum_{x_1..x_{n-1}} g(x_0, x_1, ..., x_{n-1})`.
        pub fn sumAsPolyInFirstVariable(
            self: Self,
            allocator: std.mem.Allocator,
            claim: Secure,
        ) !lookup_utils.UnivariatePoly(Secure) {
            if (self.evals.len == 1) {
                return lookup_utils.UnivariatePoly(Secure).initOwned(
                    try allocator.dupe(Secure, &[_]Secure{asSecure(Secure, F, self.evals[0])}),
                );
            }

            const half = self.evals.len / 2;
            const eval_at_0 = blk: {
                if (F == M31) {
                    // Delayed reduction: accumulate M31 values as u64,
                    // perform a single modular reduction at the end.
                    // Max sum ≈ 2^31 * 2^30 = 2^61 < 2^64.
                    var acc: u64 = 0;
                    for (self.evals[0..half]) |value| {
                        acc += @as(u64, value.v);
                    }
                    break :blk Secure.fromBase(M31.fromU64(acc));
                } else {
                    var sum = Secure.zero();
                    for (self.evals[0..half]) |value| {
                        sum = sum.add(asSecure(Secure, F, value));
                    }
                    break :blk sum;
                }
            };
            const eval_at_1 = claim.sub(eval_at_0);

            const coeffs = try allocator.alloc(Secure, 2);
            coeffs[0] = eval_at_0;
            coeffs[1] = eval_at_1.sub(eval_at_0);
            return lookup_utils.UnivariatePoly(Secure).initOwned(coeffs);
        }

        /// Evaluates the multilinear extension at `point`.
        pub fn evalAtPoint(
            self: Self,
            allocator: std.mem.Allocator,
            point: []const Secure,
        ) (std.mem.Allocator.Error || MleError)!Secure {
            if (point.len != self.nVariables()) return MleError.PointDimensionMismatch;

            var buffer = try allocator.alloc(Secure, self.evals.len);
            defer allocator.free(buffer);
            for (self.evals, 0..) |value, i| {
                buffer[i] = asSecure(Secure, F, value);
            }

            var active_len = buffer.len;
            for (point) |assignment| {
                const half = active_len / 2;
                for (0..half) |i| {
                    buffer[i] = lookup_utils.foldMleEvalsFor(
                        Secure,
                        Secure,
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

fn asSecure(comptime Secure: type, comptime F: type, value: F) Secure {
    if (F == Secure) return value;
    if (F == M31) return Secure.fromBase(value);
    @compileError("Mle currently supports M31 and Secure fields");
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
