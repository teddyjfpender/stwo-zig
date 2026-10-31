//! External arithmetic lane contract for RV64 constraint evaluation at a point.
//!
//! An external lane is any type declaring `pub const rv64_external_lane = true`
//! (for example an in-circuit verifier's wire type). It is QM31-shaped: the
//! trace lane and the secure lane coincide, every challenge, claim and public
//! scalar is a lane value, and literal constants enter through `fromU32`.
//!
//! Required public declarations, with QM31's signatures:
//!   const rv64_external_lane = true;
//!   fn zero() F;                     additive identity
//!   fn one() F;                      multiplicative identity
//!   fn fromU32(x: u32) F;            canonical small-integer constant
//!   fn fromBase(m: M31) F;           base-field constant (shared Poseidon/secp equations)
//!   fn fromQm31(c: QM31) F;          secure-field constant (flatteners, tests)
//!   fn fromPartialEvals(c: [4]F) F;  c0 + c1*u + c2*v + c3*w in the QM31 basis
//!   fn add(a: F, b: F) F;
//!   fn sub(a: F, b: F) F;
//!   fn mul(a: F, b: F) F;
//!   fn neg(a: F) F;
//!   fn square(a: F) F;               a*a (Poseidon2 S-box equations, circle doubling)
//!   fn inv(a: F) F;                  infallible inverse (vanishing denominators only)
//! The QM31 `inv` is fallible; the lane's is not, because a verifier circuit
//! witnesses the inverse and constrains `a * inv(a) = 1` itself.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;

pub fn isExternal(comptime F: type) bool {
    return @typeInfo(F) == .@"struct" and @hasDecl(F, "rv64_external_lane") and F.rv64_external_lane;
}

/// Compile-time contract check; every missing or mistyped method is reported.
pub fn assertExternalLane(comptime F: type) void {
    comptime {
        if (!isExternal(F)) @compileError(@typeName(F) ++ " does not declare rv64_external_lane = true");
        const nullary = [_][]const u8{ "zero", "one" };
        for (nullary) |name| expectFn(F, name, &.{}, F);
        expectFn(F, "fromU32", &.{u32}, F);
        expectFn(F, "fromBase", &.{M}, F);
        expectFn(F, "fromQm31", &.{Q}, F);
        expectFn(F, "fromPartialEvals", &.{[4]F}, F);
        const binary = [_][]const u8{ "add", "sub", "mul" };
        for (binary) |name| expectFn(F, name, &.{ F, F }, F);
        const unary = [_][]const u8{ "neg", "square", "inv" };
        for (unary) |name| expectFn(F, name, &.{F}, F);
    }
}

fn expectFn(comptime F: type, comptime name: []const u8, comptime params: []const type, comptime Return: type) void {
    if (!@hasDecl(F, name)) @compileError(@typeName(F) ++ " lacks lane method " ++ name);
    const info = @typeInfo(@TypeOf(@field(F, name)));
    if (info != .@"fn") @compileError(@typeName(F) ++ "." ++ name ++ " is not a function");
    const function = info.@"fn";
    if (function.return_type != Return) @compileError(@typeName(F) ++ "." ++ name ++ " must return " ++ @typeName(Return));
    if (function.params.len != params.len) @compileError(@typeName(F) ++ "." ++ name ++ " has the wrong arity");
    for (function.params, params) |actual, expected| {
        if (actual.type != expected) @compileError(@typeName(F) ++ "." ++ name ++ " has a mistyped parameter");
    }
}

/// Square-and-multiply with lane multiplication only; mirrors `QM31.pow`.
pub fn pow(comptime F: type, base: F, exponent: u64) F {
    var acc = F.one();
    var cur = base;
    var e = exponent;
    while (e != 0) : (e >>= 1) {
        if ((e & 1) != 0) acc = acc.mul(cur);
        cur = cur.square();
    }
    return acc;
}

/// Horner accumulator `acc <- acc * alpha + value` over a lane, the exact
/// shape of `core.air.accumulation.PointEvaluationAccumulator`.
pub fn PointAccumulator(comptime F: type) type {
    return struct {
        random_coeff: F,
        accumulation: F,
        pub fn init(random_coeff: F) @This() {
            return .{ .random_coeff = random_coeff, .accumulation = F.zero() };
        }
        pub fn accumulate(self: *@This(), value: F) void {
            self.accumulation = self.accumulation.mul(self.random_coeff).add(value);
        }
        pub fn finalize(self: @This()) F {
            return self.accumulation;
        }
    };
}

/// Point-evaluation sink for an external lane: behaves exactly like the QM31
/// `evaluation.Sink` (scale by the vanishing inverse, then Horner-accumulate).
pub fn Sink(comptime F: type) type {
    return struct {
        values: ?[]F = null,
        count: usize = 0,
        accumulator: ?*PointAccumulator(F) = null,
        scale: ?F = null,
        pub fn zeros(self: *@This(), count: usize) void {
            if (self.values) |values| @memset(values[self.count..][0..count], F.zero());
            if (self.accumulator) |accumulator| accumulator.accumulation = accumulator.accumulation.mul(pow(F, accumulator.random_coeff, count));
            self.count += count;
        }
        pub fn emit(self: *@This(), value: F) void {
            if (self.values) |values| values[self.count] = value;
            if (self.accumulator) |accumulator| accumulator.accumulate(if (self.scale) |scale| value.mul(scale) else value);
            self.count += 1;
        }
    };
}

/// Sampled-mask accessor contract shared by every component's point evaluator:
///   fn count(self, tree: usize, column: usize) !usize
///   fn at(self, tree: usize, column: usize, sample: usize) !F
/// `tree` indexes the proof's sampled_values trees (0 fixed, 1 main,
/// 2 interaction), `column` is the absolute column index inside that tree and
/// `sample` indexes the mask offsets the owning component declared for that
/// column: sample 0 is the current row, sample 1 the previous row, and the
/// Keccak permutation state columns carry offsets [0, -2, -1, +1, +2].
pub fn sample(comptime F: type, masks: anytype, tree: usize, column: usize, index: usize, expected: usize) !F {
    if (try masks.count(tree, column) != expected) return error.InvalidRv64MaskShape;
    return masks.at(tree, column, index);
}

/// Four consecutive base-coordinate columns combine into one secure value.
pub fn secureSample(comptime F: type, masks: anytype, tree: usize, column: usize, index: usize, expected: usize) !F {
    var coordinates: [4]F = undefined;
    for (&coordinates, 0..) |*coordinate, i| coordinate.* = try sample(F, masks, tree, column + i, index, expected);
    return F.fromPartialEvals(coordinates);
}

/// Native adapter over the proof's sampled values.
pub const NativeMasks = struct {
    values: *const core.air.components.MaskValues,
    pub fn count(self: NativeMasks, tree: usize, column: usize) !usize {
        if (tree >= self.values.items.len or column >= self.values.items[tree].len) return error.InvalidRv64MaskShape;
        return self.values.items[tree][column].len;
    }
    pub fn at(self: NativeMasks, tree: usize, column: usize, index: usize) !Q {
        const column_values = self.values.items[tree][column];
        if (index >= column_values.len) return error.InvalidRv64MaskShape;
        return column_values[index];
    }
};

test "lane power matches QM31 exponentiation" {
    const base = Q.fromU32Unchecked(3, 5, 7, 11);
    for ([_]u64{ 0, 1, 2, 3, 17, 2528, 65535 }) |exponent| try std.testing.expect(pow(Q, base, exponent).eql(base.pow(exponent)));
}
